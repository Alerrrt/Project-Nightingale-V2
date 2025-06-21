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

logger = logging.getLogger(__name__)

SCANNER_TIMEOUT = 300.0  # 5 minutes per scanner

def _transform_finding_for_frontend(finding_data: Dict, target: str) -> Dict:
    severity = finding_data.get("severity")
    if isinstance(severity, Enum):
        severity = severity.value
    
    evidence_dict = finding_data.get("evidence", {})
    location_url = evidence_dict.get("url", target)
    owasp_category = finding_data.get("owasp_category")
    if isinstance(owasp_category, Enum):
        owasp_category = owasp_category.value

    return {
        "id": str(uuid.uuid4()),
        "title": finding_data.get("title", "Untitled Finding"),
        "severity": severity or "Info",
        "description": finding_data.get("description", ""),
        "remediation": finding_data.get("remediation", ""),
        "location": location_url,
        "cwe": finding_data.get("cwe", "N/A"),
        "cve": finding_data.get("cve", "N/A"),
        "confidence": finding_data.get("confidence", 75),
        "category": owasp_category or "Unknown",
        "impact": finding_data.get("impact", "N/A"),
        "cvss": finding_data.get("cvss", 0.0),
        "evidence": json.dumps(evidence_dict, indent=2),
    }

class ScannerEngine:
    def __init__(self, plugin_manager: PluginManager):
        self.plugin_manager = plugin_manager
        self.scanner_registry = None
        self._active_scans: Dict[str, asyncio.Task] = {}
        self._scan_results: Dict[str, Dict] = {}
        self._semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_SCANS)

    def configure(self, scanner_registry: Any) -> None:
        """Configure the scanner engine."""
        self.scanner_registry = scanner_registry
        logger.info("Scanner engine configured")

    async def load_scanners(self):
        """Load all available scanners."""
        if not self.scanner_registry:
            raise Exception("Scanner registry not configured")
        await self.scanner_registry.load_scanners()
        logger.info("Scanners loaded successfully")

    async def start_scan(
        self,
        target: str,
        scan_type: str,
        options: Optional[Dict] = None
    ) -> str:
        """Start a new security scan."""
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
            elif scan_type == "quick_scan":
                logger.info(f"Initiating quick scan with ID: {scan_id}")
                # Predefined list of fast, non-intrusive scanners
                scanners_to_run = [
                    'robots_txt_sitemap_crawl_scanner',
                    'security_headers_analyzer',
                    'csrf_token_checker',
                    'clickjacking_screenshotter',
                    'js_scanner'
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
                "completed_modules": 0
            }

            # Start all designated scanners
            for scanner_name in scanners_to_run:
                scanner_class = self.scanner_registry.get_scanner(scanner_name)
                if not scanner_class:
                    logger.warning(f"Scanner '{scanner_name}' not found in registry, skipping.")
                    continue

                sub_scan_id = f"{scan_id}_{scanner_name}_{datetime.now().strftime('%f')}"
                logger.info(f"Starting sub-scan for {scanner_name} with ID: {sub_scan_id}")
                
                # Create and start sub-scan task
                sub_scan_task = asyncio.create_task(
                    self._run_scan(sub_scan_id, scanner_name, scan_input, parent_scan_id=scan_id)
                )
                self._active_scans[sub_scan_id] = sub_scan_task
                
                # Initialize sub-scan results
                self._scan_results[scan_id]["sub_scans"][sub_scan_id] = {
                    "name": scanner_name,
                    "status": "running",
                    "results": [],
                    "errors": []
                }
            
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

    async def _run_scan(
        self,
        scan_id: str,
        scan_type: str,
        scan_input: ScanInput,
        parent_scan_id: Optional[str] = None
    ):
        """Run a security scan."""
        if not self.scanner_registry:
            logger.error("Scanner registry not configured in _run_scan.")
            # Or raise an exception, depending on desired behavior
            raise Exception("Scanner registry not configured")

        broadcast_id = parent_scan_id or scan_id
        from backend.api.websocket import get_connection_manager
        manager = get_connection_manager()

        try:
            logger.info(f"Starting execution for {scan_type} ({scan_id})")
            async with self._semaphore:
                scanner_class = self.scanner_registry.get_scanner(scan_type)
                if not scanner_class:
                    raise Exception(f"Scanner not found: {scan_type}")

                scanner_instance = scanner_class()
                
                await manager.broadcast_scan_update(
                    broadcast_id, "module_status", 
                    {"name": scan_type, "status": "started", "scan_id": broadcast_id}
                )

                await manager.broadcast_scan_update(
                    broadcast_id, "activity_log",
                    {"message": f"Executing scanner: {scan_type}"}
                )

                results: List[Dict[str, Any]] = await asyncio.wait_for(
                    scanner_instance.scan(scan_input), 
                    timeout=SCANNER_TIMEOUT
                )

                transformed_results = []
                for finding_data in results:
                    frontend_finding = _transform_finding_for_frontend(finding_data, scan_input.target)
                    transformed_results.append(frontend_finding)
                    await manager.broadcast_scan_update(
                        broadcast_id, "new_finding", frontend_finding
                    )

                await manager.broadcast_scan_update(
                    broadcast_id, "module_status",
                    {"name": scan_type, "status": "completed", "findings_count": len(results), "scan_id": broadcast_id}
                )
                
                if parent_scan_id and parent_scan_id in self._scan_results:
                    sub_scan_data = self._scan_results[parent_scan_id]["sub_scans"].get(scan_id)
                    if sub_scan_data:
                        sub_scan_data.update({
                            "status": "completed",
                            "results": transformed_results
                        })
                        self._scan_results[parent_scan_id]["results"].extend(transformed_results)
                else:
                    scan_data = self._scan_results.get(scan_id)
                    if scan_data:
                        scan_data.update({
                            "status": "completed",
                            "end_time": datetime.now().isoformat(),
                            "results": transformed_results
                        })
                
                logger.info(f"Scan completed for {scan_type} on {scan_input.target}")
                
        except Exception as e:
            error_message = f"Timeout after {SCANNER_TIMEOUT}s" if isinstance(e, asyncio.TimeoutError) else str(e)
            await manager.broadcast_scan_update(
                broadcast_id, "module_status",
                {"name": scan_type, "status": "failed", "error": error_message, "scan_id": broadcast_id}
            )
            
            if parent_scan_id and parent_scan_id in self._scan_results:
                sub_scan_data = self._scan_results[parent_scan_id]["sub_scans"].get(scan_id)
                if sub_scan_data:
                    sub_scan_data.update({"status": "failed", "errors": [error_message]})
            else:
                scan_data = self._scan_results.get(scan_id)
                if scan_data:
                    scan_data.update({
                        "status": "failed",
                        "end_time": datetime.now().isoformat(),
                        "errors": [error_message]
                    })
            
            logger.error(f"Scan failed for {scan_type}", exc_info=True)
            
        finally:
            logger.info(f"Entering finally block for {scan_type} ({scan_id})")
            if scan_id in self._active_scans:
                del self._active_scans[scan_id]
            
            if parent_scan_id and parent_scan_id in self._scan_results:
                parent_scan = self._scan_results[parent_scan_id]
                parent_scan["completed_modules"] += 1
                
                logger.info(f"Module {scan_type} completed. Total progress: {parent_scan['completed_modules']}/{parent_scan['total_modules']}")

                progress = (parent_scan["completed_modules"] / parent_scan["total_modules"]) * 100
                parent_scan["progress"] = progress
                
                await manager.broadcast_scan_update(
                    broadcast_id, "scan_progress",
                    {"progress": progress, "scan_id": broadcast_id}
                )

                if parent_scan["completed_modules"] == parent_scan["total_modules"]:
                    parent_scan["status"] = "completed"
                    parent_scan["end_time"] = datetime.now().isoformat()
                    await manager.broadcast_scan_update(
                        broadcast_id, "scan_completed",
                        {
                            "scan_id": broadcast_id,
                            "status": "completed",
                            "results": parent_scan["results"]
                        }
                    )

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

        from backend.api.websocket import get_connection_manager
        manager = get_connection_manager()
        await manager.broadcast_scan_update(
            scan_id,
            "scan_completed",
            {
                "scan_id": scan_id,
                "status": "cancelled",
                "message": "Scan was cancelled by user.",
            },
        )
    
    async def get_historical_scans(self) -> List[Dict]:
        """Retrieve a summary of all historical scans."""
        return list(self._scan_results.values())

    async def cleanup(self):
        """Clean up resources."""
        # Cancel all active scans
        for scan_id, task in self._active_scans.items():
            task.cancel()
        
        # Clear results
        self._scan_results.clear()
        self._active_scans.clear()