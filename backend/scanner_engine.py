import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from backend.types.models import ScanInput, Finding
from backend.plugins.plugin_manager import PluginManager
from backend.config import settings
import uuid
import json
from enum import Enum
from backend.utils.snapshot_store import save_snapshot
from backend.utils.newsletter_store import store_email
from backend.utils.classifier import load_cheatsheets, Classifier
from backend.utils.enrichment import EnrichmentService
from backend.utils.scanner_concurrency import get_scanner_concurrency_manager, ScannerPriority
from backend.utils.http_client import get_shared_http_client
from backend.utils.vuln_mapper import map_vulnerability_fields, map_severity_from_cvss, deduplicate_vulnerabilities, merge_vulnerability_instances
import time

logger = logging.getLogger(__name__)

# Use env-configurable per-scanner timeout; fallback to 300s (5 minutes)
try:
    from backend.config import settings as _settings
    SCANNER_TIMEOUT = float(getattr(_settings, 'SCANNER_TIMEOUT_SECONDS', 300))
    GLOBAL_HARD_CAP = int(getattr(_settings, 'GLOBAL_SCAN_HARD_CAP_SECONDS', 1800))  # 30 minutes default
except Exception:
    SCANNER_TIMEOUT = 300.0
    GLOBAL_HARD_CAP = 1800

def _transform_finding_for_frontend(finding_data: Dict, target: str) -> Dict:
    """Normalize raw module finding to a frontend-facing structure.

    - Harmonizes severity/category values
    - Chooses best-available location/url
    - Maps recommendation->remediation when needed
    - Ensures evidence is a JSON string
    - Preserves optional classifier/references if present
    """
    severity = finding_data.get("severity")
    if isinstance(severity, Enum):
        severity = severity.value

    # Evidence comes in as dict or string across scanners
    evidence_raw = finding_data.get("evidence", {})
    evidence_dict: Dict[str, Any]
    if isinstance(evidence_raw, dict):
        evidence_dict = evidence_raw
    else:
        # Try to parse JSON strings; otherwise wrap as text field
        try:
            evidence_dict = json.loads(evidence_raw) if isinstance(evidence_raw, str) else {"text": str(evidence_raw)}
        except Exception:
            evidence_dict = {"text": str(evidence_raw)}

    # Determine best location
    location_url = (
        finding_data.get("location")
        or evidence_dict.get("url")
        or finding_data.get("affected_url")
        or target
    )

    # OWASP category can be an Enum, string, or provided by classifier
    owasp_category = (
        (finding_data.get("classifier") or {}).get("owasp")
        or finding_data.get("owasp_category")
    )
    if isinstance(owasp_category, Enum):
        owasp_category = owasp_category.value

    # CWE/CVE can arrive from scanner or classifier
    cwe = finding_data.get("cwe") or (finding_data.get("classifier") or {}).get("cwe") or "N/A"
    cve = finding_data.get("cve") or (finding_data.get("classifier") or {}).get("cve") or "N/A"

    # Remediation fallback to recommendation
    remediation = finding_data.get("remediation") or finding_data.get("recommendation") or ""

    # Confidence can be numeric or label
    confidence = finding_data.get("confidence", 75)
    if isinstance(confidence, str):
        label = confidence.strip().lower()
        confidence = {"low": 50, "medium": 70, "high": 90}.get(label, 75)

    # CVSS fallback
    cvss = finding_data.get("cvss", 0.0)

    normalized = {
        "id": str(uuid.uuid4()),
        "title": finding_data.get("title", "Untitled Finding"),
        "severity": severity or "Info",
        "description": finding_data.get("description", ""),
        "short_description": finding_data.get("short_description") or finding_data.get("description", "")[0:140],
        "remediation": remediation,
        "countermeasures": finding_data.get("countermeasures") or remediation,
        "location": location_url,
        "cwe": cwe,
        "cve": cve,
        "confidence": confidence,
        "category": owasp_category or "Unknown",
        "impact": finding_data.get("impact", "N/A"),
        "cvss": cvss,
        "evidence": json.dumps(evidence_dict, indent=2),
    }

    # Pass through optional enrichments if present
    if finding_data.get("references"):
        normalized["references"] = finding_data["references"]
    if finding_data.get("classifier"):
        normalized["classifier"] = finding_data["classifier"]

    return normalized

def _compute_finding_signature(f: Dict) -> str:
    """Compute a stable signature for deduplication across modules.
    Uses type/title + normalized URL + CWE/CVE when available.
    """
    from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

    url = f.get("location", "") or ""
    try:
        parsed = urlparse(url)
        # Sort query params for stability
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
        normalized_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))
    except Exception:
        normalized_url = url

    title = f.get("title") or f.get("type") or "unknown"
    cwe = f.get("cwe") or ""
    cve = f.get("cve") or ""
    return f"{title}|{normalized_url}|{cwe}|{cve}"

class ScannerEngine:
    """
    Enhanced scanner engine with improved concurrency, HTTP pooling, and performance monitoring.
    """

    def __init__(self, plugin_manager: PluginManager):
        self.plugin_manager = plugin_manager
        self.scanner_registry = None
        self._scan_results: Dict[str, Dict] = {}
        self._active_scans: Dict[str, asyncio.Task] = {}
        self._semaphore = asyncio.Semaphore(10)  # Keep for backward compatibility
        
        # Enhanced components
        self._concurrency_manager = get_scanner_concurrency_manager()
        self._http_client = get_shared_http_client()
        
        # Initialize classifier and enrichment
        # Load cheatsheets and construct classifier
        try:
            cheats = load_cheatsheets()
        except Exception as e:
            logger.warning(f"Failed to load cheatsheets: {e}")
            cheats = {}
        self._classifier = Classifier(cheats)
        self._enrichment = EnrichmentService()
        
        # Performance metrics
        self._performance_metrics = {
            "total_scans": 0,
            "total_findings": 0,
            "avg_scan_duration": 0.0,
            "http_cache_hits": 0,
            "http_cache_misses": 0
        }

    async def configure(self, scanner_registry: Any) -> None:
        """Configure the scanner engine with a registry."""
        self.scanner_registry = scanner_registry
        
        # Start the concurrency manager
        try:
            await self._concurrency_manager.start()
            logger.info("Scanner concurrency manager started successfully")
        except Exception as e:
            logger.warning(f"Failed to start concurrency manager: {e}")

    async def load_scanners(self):
        """Load available scanners from the registry."""
        if self.scanner_registry:
            scanners = self.scanner_registry.get_all_scanners()
            logger.info(f"Loaded {len(scanners)} scanners from registry")
            return scanners
        return {}

    async def start_scan(
        self,
        target: str,
        scan_type: str,
        options: Optional[Dict] = None
    ) -> str:
        """Start a new security scan with enhanced concurrency management."""
        if not self.scanner_registry:
            raise Exception("Scanner registry not configured")
            
        try:
            # Generate scan ID
            scan_id = f"{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Create ScanInput object
            scan_input = ScanInput(target=target, scan_type=scan_type, options=options or {})

            scanners_to_run = []
            if scan_type == "full_scan":
                logger.info(f"Initiating full scan with ID: {scan_id}")
                scanners_to_run = list(self.scanner_registry.get_all_scanners().keys())
                # Prefer stable module-name aliases where available
                scanners_to_run = sorted(set(scanners_to_run))
            elif scan_type == "quick_scan":
                logger.info(f"Initiating quick scan with ID: {scan_id}")
                # Predefined list of fast, non-intrusive scanners
                scanners_to_run = [
                    'robots_txt_sitemap_crawl_scanner',
                    'security_headers_analyzer',
                    'csrf_token_checker',
                    'clickjacking_screenshotter',
                    'js_scanner',
                    'cors_misconfiguration_scanner'
                ]
            elif scan_type == "custom_scan":
                logger.info(f"Initiating custom scan with ID: {scan_id}")
                if options and 'scanners' in options and isinstance(options['scanners'], list):
                    scanners_to_run = options['scanners']
                else:
                    raise Exception("Custom scan requires a 'scanners' list in options.")
            else:
                # Single scanner scan
                scanners_to_run = [scan_type]

            if not scanners_to_run:
                raise Exception(f"No scanners found for scan type: {scan_type}")

            # Initialize results
            self._scan_results[scan_id] = {
                "id": scan_id,
                "target": target,
                "type": scan_type,
                "status": "running",
                "start_time": datetime.now().isoformat(),
                "results": [],
                "errors": [],
                "sub_scans": {},
                "progress": 0,
                "total_modules": len(scanners_to_run),
                "completed_modules": 0,
                # Optional global hard cap; use generous default if not set
                "deadline": (datetime.now()).timestamp() + (GLOBAL_HARD_CAP if GLOBAL_HARD_CAP and GLOBAL_HARD_CAP > 0 else 3600),  # 1 hour default
                "_finding_keys": set(),
                "performance_metrics": {
                    "http_cache_stats": {},
                    "scanner_timing": {},
                    "resource_usage": {}
                },
                "timing_data": {
                    "start_time": datetime.now().timestamp(),
                    "estimated_completion": None,
                    "scanner_estimates": {},
                    "last_progress_update": datetime.now().timestamp()
                }
            }

            # Start all designated scanners using concurrency manager
            try:
                for scanner_name in scanners_to_run:
                    scanner_class = self.scanner_registry.get_scanner(scanner_name)
                    if not scanner_class:
                        logger.warning(f"Scanner '{scanner_name}' not found in registry, skipping.")
                        continue

                    sub_scan_id = f"{scan_id}_{scanner_name}_{datetime.now().strftime('%f')}"
                    logger.info(f"Starting sub-scan for {scanner_name} with ID: {sub_scan_id}")
                    
                    # Determine scanner priority based on type
                    priority = self._get_scanner_priority(scanner_name)
                    
                    # Submit to concurrency manager
                    try:
                        # Create a proper closure to avoid lambda closure issues
                        def create_scanner_coro(scanner_name: str, sub_scan_id: str, scan_input: ScanInput, parent_scan_id: str):
                            async def scanner_wrapper():
                                return await self._run_scan(sub_scan_id, scanner_name, scan_input, parent_scan_id=parent_scan_id)
                            return scanner_wrapper
                        
                        scanner_coro = create_scanner_coro(scanner_name, sub_scan_id, scan_input, scan_id)
                        
                        await self._concurrency_manager.submit_scanner(
                            scanner_id=sub_scan_id,
                            scanner_name=scanner_name,
                            coro=scanner_coro,
                            options=options or {},
                            priority=priority
                        )
                    
                        # Initialize sub-scan results
                        self._scan_results[scan_id]["sub_scans"][sub_scan_id] = {
                            "name": scanner_name,
                            "status": "queued",
                            "results": [],
                            "errors": [],
                            "priority": priority.name
                        }
                        
                    except Exception as e:
                        logger.error(f"Failed to submit scanner {scanner_name}: {e}")
                        # Mark as failed
                        self._scan_results[scan_id]["sub_scans"][sub_scan_id] = {
                            "name": scanner_name,
                            "status": "failed",
                            "results": [],
                            "errors": [str(e)]
                        }
                        self._scan_results[scan_id]["errors"].append(f"Scanner {scanner_name} failed to start: {e}")
                
                # Start a background task to monitor scan completion and force completion if needed
                asyncio.create_task(self._monitor_scan_completion(scan_id, len(scanners_to_run)))
                
            except Exception as e:
                logger.error(f"Failed to start scanners: {e}")
                self._scan_results[scan_id]["status"] = "failed"
                self._scan_results[scan_id]["errors"].append(f"Failed to start scanners: {e}")
                raise
            
            # Update performance metrics
            self._performance_metrics["total_scans"] += 1
            
            return scan_id
            
        except Exception as e:
            logger.error(
                "Error starting scan",
                extra={
                    "target": target,
                    "scan_type": scan_type,
                    "error": str(e)
                },
                exc_info=True
            )
            raise

    def _get_scanner_priority(self, scanner_name: str) -> ScannerPriority:
        """Determine priority for a scanner based on its type and importance."""
        # Critical security scanners
        if any(keyword in scanner_name.lower() for keyword in ['auth', 'security_headers', 'csrf']):
            return ScannerPriority.CRITICAL
        
        # High-priority vulnerability scanners
        if any(keyword in scanner_name.lower() for keyword in ['xss', 'sql', 'ssrf', 'csrf']):
            return ScannerPriority.HIGH
        
        # Medium-priority enumeration and discovery
        if any(keyword in scanner_name.lower() for keyword in ['directory', 'file', 'enum', 'crawl']):
            return ScannerPriority.MEDIUM
        
        # Low-priority analysis and reporting
        if any(keyword in scanner_name.lower() for keyword in ['tech', 'fingerprint', 'report']):
            return ScannerPriority.LOW
        
        # Default to medium priority
        return ScannerPriority.MEDIUM

    async def _run_scan(
        self,
        scan_id: str,
        scan_type: str,
        scan_input: ScanInput,
        parent_scan_id: Optional[str] = None
    ):
        """Run a security scan with enhanced performance monitoring."""
        if not self.scanner_registry:
            logger.error("Scanner registry not configured in _run_scan.")
            raise Exception("Scanner registry not configured")

        broadcast_id = parent_scan_id or scan_id
        from backend.api.websocket import get_connection_manager
        manager = get_connection_manager()

        start_time = time.time()

        try:
            logger.info(f"Starting execution for {scan_type} ({scan_id})")
            
            # Update status to running
            if parent_scan_id and parent_scan_id in self._scan_results:
                self._scan_results[parent_scan_id]["sub_scans"][scan_id]["status"] = "running"
            
            scanner_class = self.scanner_registry.get_scanner(scan_type)
            if not scanner_class:
                raise Exception(f"Scanner not found: {scan_type}")

            scanner_instance = scanner_class()
            # Ensure scanner instance exposes metadata for traceability
            if not hasattr(scanner_instance, 'metadata'):
                scanner_instance.metadata = { 'name': scanner_class.__name__, 'version': '1.0.0' }
            
            await manager.broadcast_scan_update(
                broadcast_id, "module_status", 
                {"name": scan_type, "status": "running", "scan_id": broadcast_id}
            )

            await manager.broadcast_scan_update(
                broadcast_id, "activity_log",
                {"message": f"Executing scanner: {scan_type}"}
            )

            # Hard stop if deadline exceeded for parent
            if parent_scan_id:
                parent = self._scan_results.get(parent_scan_id, {})
                if parent and datetime.now().timestamp() > parent.get("deadline", float("inf")):
                    raise asyncio.TimeoutError("Scan deadline exceeded")

            # Execute scanner with timeout
            results: List[Dict[str, Any]] = await asyncio.wait_for(
                scanner_instance.scan(scan_input), 
                timeout=SCANNER_TIMEOUT
            )

            # Process and transform results
            transformed_results = await self._process_scanner_results(
                results, scan_input.target, scan_type, parent_scan_id, manager, broadcast_id
            )

            # Update performance metrics
            execution_time = time.time() - start_time
            if parent_scan_id and parent_scan_id in self._scan_results:
                self._scan_results[parent_scan_id]["performance_metrics"]["scanner_timing"][scan_type] = execution_time

            # Broadcast module completion immediately
            try:
                await manager.broadcast_scan_update(
                    broadcast_id, "module_status",
                    {"name": scan_type, "status": "completed", "findings_count": len(results), "scan_id": broadcast_id}
                )
            except Exception as e:
                logger.warning(f"Failed to broadcast module completion: {e}")
            
            # Update sub-scan status
            if parent_scan_id and parent_scan_id in self._scan_results:
                sub_scan_data = self._scan_results[parent_scan_id]["sub_scans"].get(scan_id)
                if sub_scan_data:
                    sub_scan_data.update({
                        "status": "completed",
                        "results": transformed_results,
                        "execution_time": execution_time
                    })
                    self._scan_results[parent_scan_id]["results"].extend(transformed_results)
                    
                    # Snapshot after each module completes for resiliency
                    try:
                        snapshot_copy = {k: v for k, v in self._scan_results[parent_scan_id].items() if not k.startswith("_")}
                        save_snapshot(parent_scan_id, snapshot_copy)
                    except Exception:
                        logger.warning("Failed to save snapshot for %s", parent_scan_id)

        except asyncio.TimeoutError:
            error_message = f"Scanner {scan_type} timed out after {SCANNER_TIMEOUT}s"
            logger.warning(error_message)
            
            if parent_scan_id and parent_scan_id in self._scan_results:
                self._scan_results[parent_scan_id]["sub_scans"][scan_id].update({
                    "status": "timeout",
                    "end_time": datetime.now().isoformat(),
                    "errors": [error_message]
                })
                
                # Update parent scan
                scan_data = self._scan_results[parent_scan_id]
                scan_data["errors"].append(error_message)
                
                try:
                    snapshot_copy = {k: v for k, v in scan_data.items() if not k.startswith("_")}
                    if isinstance(snapshot_copy.get("_finding_keys"), set):
                        snapshot_copy.pop("_finding_keys", None)
                    save_snapshot(scan_id, snapshot_copy)
                except Exception:
                    logger.warning("Failed to save snapshot for %s", scan_id)
            
            logger.error(f"Scan failed for {scan_type}", exc_info=True)
            
        except Exception as e:
            error_message = f"Scanner {scan_type} failed with error: {str(e)}"
            logger.error(error_message, exc_info=True)
            
            if parent_scan_id and parent_scan_id in self._scan_results:
                self._scan_results[parent_scan_id]["sub_scans"][scan_id].update({
                    "status": "failed",
                    "end_time": datetime.now().isoformat(),
                    "errors": [error_message]
                })
                
                # Update parent scan
                scan_data = self._scan_results[parent_scan_id]
                scan_data["errors"].append(error_message)
                
                try:
                    snapshot_copy = {k: v for k, v in scan_data.items() if not k.startswith("_")}
                    if isinstance(snapshot_copy.get("_finding_keys"), set):
                        snapshot_copy.pop("_finding_keys", None)
                    save_snapshot(scan_id, snapshot_copy)
                except Exception:
                    logger.warning("Failed to save snapshot for %s", scan_id)
            
        finally:
            logger.info(f"Entering finally block for {scan_type} ({scan_id})")
            
            # Update sub-scan status and completion tracking
            if parent_scan_id and parent_scan_id in self._scan_results:
                parent_scan = self._scan_results[parent_scan_id]
                
                # Ensure the sub-scan is marked as completed (regardless of success/failure)
                if scan_id in parent_scan.get("sub_scans", {}):
                    sub_scan = parent_scan["sub_scans"][scan_id]
                    if sub_scan.get("status") not in ["completed", "failed", "timeout"]:
                        sub_scan["status"] = "failed"
                        sub_scan["end_time"] = datetime.now().isoformat()
                        sub_scan["errors"] = sub_scan.get("errors", []) + ["Scanner terminated unexpectedly"]
                
                # Count all finished modules (completed, failed, timeout)
                finished_modules = sum(
                    1 for sub_scan in parent_scan.get("sub_scans", {}).values()
                    if sub_scan.get("status") in ["completed", "failed", "timeout"]
                )
                
                parent_scan["completed_modules"] = finished_modules
                
                logger.info(f"Module {scan_type} finished. Total progress: {parent_scan['completed_modules']}/{parent_scan['total_modules']}")

                progress = (parent_scan["completed_modules"] / parent_scan["total_modules"]) * 100
                parent_scan["progress"] = progress
                
                # Calculate improved timing estimates
                timing_data = parent_scan.get("timing_data", {})
                current_time = datetime.now().timestamp()
                elapsed_time = current_time - timing_data.get("start_time", current_time)
                
                # Calculate ETA based on current progress and scanner performance
                eta_seconds = self._calculate_accurate_eta(parent_scan, elapsed_time, progress)
                eta_formatted = self._format_eta(eta_seconds)
                
                # Update timing data
                timing_data["last_progress_update"] = current_time
                timing_data["estimated_completion"] = current_time + eta_seconds if eta_seconds > 0 else None
                parent_scan["timing_data"] = timing_data
                
                await manager.broadcast_scan_update(
                    broadcast_id, "scan_progress",
                    {
                        "progress": progress, 
                        "scan_id": broadcast_id,
                        "eta_seconds": eta_seconds,
                        "eta_formatted": eta_formatted,
                        "elapsed_seconds": elapsed_time,
                        "completed_modules": parent_scan["completed_modules"],
                        "total_modules": parent_scan["total_modules"]
                    }
                )

                # Check if all modules have finished (regardless of success/failure)
                if parent_scan["completed_modules"] >= parent_scan["total_modules"]:
                    parent_scan["status"] = "completed"
                    parent_scan["end_time"] = datetime.now().isoformat()
                    
                    # Add final performance metrics
                    http_stats = self._http_client.get_stats()
                    parent_scan["performance_metrics"]["http_cache_stats"] = http_stats
                    
                    # Ensure all findings are properly processed and deduplicated
                    all_findings = parent_scan.get("results", [])
                    if all_findings:
                        # Final deduplication pass
                        unique_findings = []
                        seen_keys = set()
                        for finding in all_findings:
                            key = _compute_finding_signature(finding)
                            if key not in seen_keys:
                                seen_keys.add(key)
                                unique_findings.append(finding)
                        
                        parent_scan["results"] = unique_findings
                        parent_scan["total_findings"] = len(unique_findings)
                        
                        # Send final findings summary
                        await manager.broadcast_scan_update(
                            broadcast_id, "findings_summary",
                            {
                                "total_findings": len(unique_findings),
                                "findings_by_severity": self._categorize_findings_by_severity(unique_findings),
                                "scan_id": broadcast_id
                            }
                        )
                    
                    try:
                        snapshot_copy = {k: v for k, v in parent_scan.items() if not k.startswith("_")}
                        if isinstance(snapshot_copy.get("_finding_keys"), set):
                            snapshot_copy.pop("_finding_keys", None)
                        save_snapshot(broadcast_id, snapshot_copy)
                    except Exception:
                        logger.warning("Failed to save snapshot for %s", broadcast_id)
                    
                    # Send final completion message with comprehensive results
                    await manager.broadcast_scan_update(
                        broadcast_id, "scan_completed",
                        {
                            "scan_id": broadcast_id,
                            "status": "completed",
                            "results": parent_scan["results"],
                            "performance_metrics": parent_scan["performance_metrics"],
                            "total_findings": parent_scan.get("total_findings", 0),
                            "scan_duration": self._calculate_scan_duration(parent_scan),
                            "timestamp": datetime.now().isoformat()
                        }
                    )
                    
                    logger.info(f"Scan {broadcast_id} completed successfully with {len(parent_scan.get('results', []))} findings")
                    
                    # Clean up scan data after completion to prevent memory leaks
                    asyncio.create_task(self._cleanup_completed_scan(broadcast_id))

    async def _cleanup_completed_scan(self, scan_id: str):
        """Clean up completed scan data to prevent memory leaks."""
        try:
            # Wait a bit to ensure all final messages are sent
            await asyncio.sleep(5)
            
            if scan_id in self._scan_results:
                scan_data = self._scan_results[scan_id]
                
                # Keep only essential data for historical purposes
                cleaned_data = {
                    "id": scan_data.get("id"),
                    "target": scan_data.get("target"),
                    "type": scan_data.get("type"),
                    "status": scan_data.get("status"),
                    "start_time": scan_data.get("start_time"),
                    "end_time": scan_data.get("end_time"),
                    "results": scan_data.get("results", []),
                    "total_findings": scan_data.get("total_findings", 0),
                    "performance_metrics": scan_data.get("performance_metrics", {}),
                    "errors": scan_data.get("errors", [])
                }
                
                # Replace with cleaned data
                self._scan_results[scan_id] = cleaned_data
                
                logger.info(f"Cleaned up scan data for {scan_id}")
                
        except Exception as e:
            logger.error(f"Error cleaning up scan {scan_id}: {e}")

    def _categorize_findings_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Categorize findings by severity level."""
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "Info").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts
    
    def _calculate_scan_duration(self, scan_data: Dict) -> float:
        """Calculate the total scan duration in seconds."""
        try:
            start_time = datetime.fromisoformat(scan_data.get("start_time", ""))
            end_time = datetime.fromisoformat(scan_data.get("end_time", ""))
            duration = (end_time - start_time).total_seconds()
            return round(duration, 2)
        except (ValueError, TypeError):
            return 0.0

    async def _process_scanner_results(self, results: List[Dict], target: str, scan_type: str, 
                                     parent_scan_id: str, manager, broadcast_id: str) -> List[Dict]:
        """Process and transform scanner results with enhanced deduplication."""
        transformed_results = []
        
        for finding_data in results:
            frontend_finding = _transform_finding_for_frontend(finding_data, target)
            frontend_finding["scanner"] = scan_type
            
            # Minimal enrichment/classification
            try:
                frontend_finding = self._classifier.classify(scan_type, frontend_finding)
            except Exception:
                pass
            
            # Non-blocking enrichment: add cvss/cvss_vector/references when available
            try:
                if self._enrichment:
                    frontend_finding = await self._enrichment.enrich_finding(frontend_finding)
            except Exception:
                pass

            # If CVSS present, normalize severity from CVSS while preserving higher severity if already set
            try:
                existing = str(frontend_finding.get("severity") or "Info")
                cvss_val = frontend_finding.get("cvss")
                normalized_sev = map_severity_from_cvss(cvss_val, existing)
                frontend_finding["severity"] = normalized_sev
            except Exception:
                pass
            
            # Ensure CWE/CVE and countermeasures mapping
            try:
                frontend_finding = map_vulnerability_fields(frontend_finding)
            except Exception:
                pass

            # Enhanced deduplication using new functions
            key = _compute_finding_signature(frontend_finding)
            parent_store_id = parent_scan_id or broadcast_id
            parent_store = self._scan_results.get(parent_store_id, {})
            keys_set = parent_store.get("_finding_keys")

            # Ensure the dedup set always exists (e.g., after snapshot reloads)
            if not isinstance(keys_set, set):
                keys_set = set()
                parent_store["_finding_keys"] = keys_set
            
            # Check if this finding is a duplicate
            if key in keys_set:
                # Instead of skipping, check if we need to update severity or merge evidence
                existing_findings = parent_store.get("results", [])
                for existing in existing_findings:
                    if _compute_finding_signature(existing) == key:
                        # Update severity if current is higher
                        current_severity = frontend_finding.get("severity", "Info").lower()
                        existing_severity = existing.get("severity", "Info").lower()
                        
                        severity_order = ["critical", "high", "medium", "low", "info"]
                        if severity_order.index(current_severity) < severity_order.index(existing_severity):
                            existing["severity"] = frontend_finding["severity"]
                            existing["cvss"] = max(existing.get("cvss", 0), frontend_finding.get("cvss", 0))
                        
                        # Merge evidence if available
                        if "evidence" in frontend_finding and "evidence" in existing:
                            if isinstance(existing["evidence"], list):
                                existing["evidence"].append(frontend_finding["evidence"])
                            else:
                                existing["evidence"] = [existing["evidence"], frontend_finding["evidence"]]
                        break
                continue
            
            keys_set.add(key)
            transformed_results.append(frontend_finding)
            
            # Broadcast finding immediately for real-time updates
            try:
                await manager.broadcast_scan_update(
                    broadcast_id, "new_finding", frontend_finding
                )
            except Exception as e:
                logger.warning(f"Failed to broadcast finding: {e}")
                # Continue processing even if broadcast fails
        
        # Apply final deduplication to ensure no duplicates remain
        if transformed_results:
            final_deduplicated = deduplicate_vulnerabilities(transformed_results)
            if len(final_deduplicated) != len(transformed_results):
                logger.info(f"Final deduplication: {len(transformed_results)} -> {len(final_deduplicated)} findings")
                transformed_results = final_deduplicated
        
        return transformed_results

    async def get_scan_status(self, scan_id: str) -> Dict:
        """Get the status of a scan."""
        if scan_id not in self._scan_results:
            raise Exception(f"Scan not found: {scan_id}")
        return self._scan_results[scan_id]

    async def get_active_scans(self) -> List[Dict]:
        """Get list of active scans."""
        return [
            {
                "id": scan_id,
                "status": self._scan_results[scan_id]["status"],
                "type": self._scan_results[scan_id]["type"],
                "target": self._scan_results[scan_id]["target"],
                "start_time": self._scan_results[scan_id]["start_time"]
            }
            for scan_id in self._active_scans
        ]

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for monitoring."""
        concurrency_stats = self._concurrency_manager.get_stats()
        http_stats = self._http_client.get_stats()
        
        return {
            "engine_metrics": self._performance_metrics,
            "concurrency_manager": concurrency_stats,
            "http_client": http_stats,
            "active_scans_count": len(self._active_scans),
            "total_scan_results": len(self._scan_results)
        }

    async def cancel_scan(self, scan_id: str):
        """Cancel a running scan and its sub-scans."""
        logger.info(f"Attempting to cancel scan {scan_id}")
        
        # Find all active sub-scans related to the parent scan_id
        sub_scan_ids_to_cancel = [s_id for s_id in self._active_scans if s_id.startswith(scan_id)]
        
        for sub_scan_id in sub_scan_ids_to_cancel:
            task = self._active_scans.get(sub_scan_id)
            if task and not task.done():
                task.cancel()
                logger.info(f"Cancelled sub-scan task: {sub_scan_id}")
            # Remove from active scans right away
            if sub_scan_id in self._active_scans:
                del self._active_scans[sub_scan_id]
        
        # Update the parent scan status
        if scan_id in self._scan_results:
            self._scan_results[scan_id].update({
                "status": "cancelled",
                "end_time": datetime.now().isoformat()
            })
            logger.info(f"Scan {scan_id} marked as cancelled.")
            try:
                save_snapshot(scan_id, self._scan_results[scan_id])
            except Exception:
                logger.warning("Failed to save snapshot for %s", scan_id)

        from backend.api.websocket import get_connection_manager
        manager = get_connection_manager()
        await manager.broadcast_scan_update(
            scan_id, "scan_cancelled",
            {"scan_id": scan_id, "status": "cancelled"}
        )
    
    async def get_historical_scans(self) -> List[Dict]:
        """Get list of completed scans."""
        return [
            {
                "id": scan_id,
                "status": scan_data["status"],
                "type": scan_data["type"],
                "target": scan_data["target"],
                "start_time": scan_data["start_time"],
                "end_time": scan_data.get("end_time"),
                "findings_count": len(scan_data.get("results", [])),
                "performance_metrics": scan_data.get("performance_metrics", {})
            }
            for scan_id, scan_data in self._scan_results.items()
            if scan_data["status"] in ["completed", "cancelled", "failed"]
        ]

    async def _monitor_scan_completion(self, scan_id: str, total_modules: int):
        """Monitor scan completion and force completion if needed."""
        try:
            # Wait for a reasonable time for scans to complete
            # Allow more time per module and ensure all scanners can finish
            max_wait_time = max(600, total_modules * 60)  # At least 10 minutes or 1 minute per module
            start_time = time.time()
            
            while time.time() - start_time < max_wait_time:
                if scan_id not in self._scan_results:
                    logger.info(f"Scan {scan_id} no longer exists, stopping monitor")
                    return
                
                scan_data = self._scan_results[scan_id]
                if scan_data.get("status") in ["completed", "failed", "cancelled"]:
                    logger.info(f"Scan {scan_id} completed normally, stopping monitor")
                    return
                
                # Check if all modules have finished
                finished_modules = sum(
                    1 for sub_scan in scan_data.get("sub_scans", {}).values()
                    if sub_scan.get("status") in ["completed", "failed", "timeout"]
                )
                
                if finished_modules >= total_modules:
                    logger.info(f"All modules finished for scan {scan_id}, triggering completion")
                    await self._force_scan_completion(scan_id)
                    return
                
                await asyncio.sleep(2)  # Reduced from 5 to 2 seconds for faster response
            
            # If we reach here, force completion due to timeout
            logger.warning(f"Scan {scan_id} timed out after {max_wait_time}s, forcing completion")
            await self._force_scan_completion(scan_id)
            
        except Exception as e:
            logger.error(f"Error in scan completion monitor for {scan_id}: {e}")
            # Try to force completion anyway
            try:
                await self._force_scan_completion(scan_id)
            except Exception:
                pass

    async def _force_scan_completion(self, scan_id: str):
        """Force completion of a scan that may be stuck."""
        try:
            if scan_id not in self._scan_results:
                return
            
            scan_data = self._scan_results[scan_id]
            
            # Mark any unfinished sub-scans as failed
            for sub_scan_id, sub_scan in scan_data.get("sub_scans", {}).items():
                if sub_scan.get("status") not in ["completed", "failed", "timeout"]:
                    sub_scan.update({
                        "status": "failed",
                        "end_time": datetime.now().isoformat(),
                        "errors": sub_scan.get("errors", []) + ["Forced completion due to timeout"]
                    })
            
            # Mark scan as completed
            scan_data["status"] = "completed"
            scan_data["end_time"] = datetime.now().isoformat()
            scan_data["completed_modules"] = len(scan_data.get("sub_scans", {}))
            scan_data["progress"] = 100.0
            
            # Send completion notification
            from backend.api.websocket import get_connection_manager
            manager = get_connection_manager()
            
            await manager.broadcast_scan_update(
                scan_id, "scan_completed",
                {
                    "scan_id": scan_id,
                    "status": "completed",
                    "results": scan_data.get("results", []),
                    "performance_metrics": scan_data.get("performance_metrics", {}),
                    "total_findings": len(scan_data.get("results", [])),
                    "scan_duration": self._calculate_scan_duration(scan_data),
                    "timestamp": datetime.now().isoformat()
                }
            )
            
            logger.info(f"Scan {scan_id} force-completed with {len(scan_data.get('results', []))} findings")
            
        except Exception as e:
            logger.error(f"Error forcing completion for scan {scan_id}: {e}")

    async def cleanup(self):
        """Clean up resources and stop the concurrency manager."""
        try:
            # Stop the concurrency manager
            await self._concurrency_manager.stop()
            logger.info("Scanner engine cleanup completed")
        except Exception as e:
            logger.error(f"Error during scanner engine cleanup: {e}")

    def _calculate_accurate_eta(self, scan_data: Dict, elapsed_time: float, progress: float) -> float:
        """Calculate accurate ETA based on current progress and scanner performance."""
        if progress <= 0:
            return 0.0
        
        # Base calculation: if we've made progress, estimate remaining time
        if progress > 0 and elapsed_time > 0:
            total_estimated_time = (elapsed_time / progress) * 100
            remaining_time = total_estimated_time - elapsed_time
            
            # Apply adjustments based on scanner performance
            remaining_time = self._adjust_eta_with_scanner_performance(scan_data, remaining_time, progress)
            
            return max(0.0, remaining_time)
        
        return 0.0

    def _adjust_eta_with_scanner_performance(self, scan_data: Dict, base_eta: float, progress: float) -> float:
        """Adjust ETA based on scanner performance patterns."""
        sub_scans = scan_data.get("sub_scans", {})
        if not sub_scans:
            return base_eta
        
        # Analyze completed scanners to adjust estimate
        completed_scans = [
            scan for scan in sub_scans.values() 
            if scan.get("status") in ["completed", "failed", "timeout"]
        ]
        
        if not completed_scans:
            return base_eta
        
        # Calculate average time per completed scanner
        total_completed_time = 0
        for scan in completed_scans:
            start_time = scan.get("start_time")
            end_time = scan.get("end_time")
            if start_time and end_time:
                try:
                    start_ts = datetime.fromisoformat(start_time.replace('Z', '+00:00')).timestamp()
                    end_ts = datetime.fromisoformat(end_time.replace('Z', '+00:00')).timestamp()
                    total_completed_time += (end_ts - start_ts)
                except Exception:
                    pass
        
        if total_completed_time > 0:
            avg_time_per_scanner = total_completed_time / len(completed_scans)
            remaining_scanners = scan_data.get("total_modules", 0) - len(completed_scans)
            
            # Use the more conservative estimate
            performance_based_eta = avg_time_per_scanner * remaining_scanners
            return min(base_eta, performance_based_eta)
        
        return base_eta

    def _format_eta(self, eta_seconds: float) -> str:
        """Format ETA in a human-readable format."""
        if eta_seconds <= 0:
            return "Completing..."
        
        if eta_seconds < 60:
            return f"{int(eta_seconds)}s"
        
        minutes = int(eta_seconds // 60)
        seconds = int(eta_seconds % 60)
        
        if minutes < 60:
            return f"{minutes}m {seconds}s"
        
        hours = int(minutes // 60)
        minutes = int(minutes % 60)
        return f"{hours}h {minutes}m"
