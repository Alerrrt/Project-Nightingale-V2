import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Callable, Type
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from contextlib import asynccontextmanager

from backend.types.models import ScanInput, Finding, ModuleStatus
from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry, ScannerRegistryConfig
from backend.plugins.plugin_manager import PluginManager
from backend.utils.scoring import classify_finding, assign_severity_score
from backend.utils.exceptions import ScanTimeoutError, InvalidTargetError
from backend.types.scanner_config import ScannerIntensity, ScannerConfig
from backend.utils.resource_monitor import ResourceMonitor
from backend.utils.logging_config import get_context_logger
from backend.utils.circuit_breaker import circuit_breaker

logger = get_context_logger(__name__)

class ScannerEngine:
    """
    Orchestrates the scanning process by loading and running scanner modules
    and plugins in parallel.
    """

    def __init__(self, plugin_manager: PluginManager):
        """
        Initializes the ScannerEngine with a PluginManager.

        Args:
            plugin_manager: An instance of PluginManager to handle external tools.
        """
        if not isinstance(plugin_manager, PluginManager) and plugin_manager is not None:
            raise TypeError("plugin_manager must be an instance of PluginManager")
        
        self.plugin_manager = plugin_manager
        self.scanner_registry = ScannerRegistry.get_instance()
        self.config: Optional[ScannerRegistryConfig] = None
        self._update_callback: Optional[Callable] = None
        self._active_scans: Dict[str, asyncio.Task] = {}
        self._scan_results: Dict[str, Dict] = {}
        self._resource_monitor: Optional[ResourceMonitor] = None
        self._thread_pool = ThreadPoolExecutor(max_workers=20)
        self._scanner_cache: Dict[str, BaseScanner] = {}
        self._semaphore = asyncio.Semaphore(10)
        self._adaptive_semaphore = asyncio.Semaphore(10)  # Initial value, will be adjusted

    def configure(self, config: ScannerRegistryConfig) -> None:
        """
        Configure the scanner engine.

        Args:
            config: The configuration to apply.
        """
        self.config = config
        self._resource_monitor = ResourceMonitor(config.resource_limits)
        logger.info("Scanner engine configured")

    async def _run_scanner_with_progress(
        self,
        scanner_name: str,
        scan_input: ScanInput,
        scan_id: str,
        config: ScannerConfig
    ) -> List[Finding]:
        """
        Runs a scanner with progress tracking and retries.
        """
        retries = 0
        last_error = None

        while retries <= config.max_retries:
            try:
                async with self._adaptive_semaphore:  # Use adaptive semaphore
                    async with self._get_scanner(scanner_name) as scanner:
                        findings = await asyncio.wait_for(
                            scanner.scan(scan_input),
                            timeout=config.timeout
                        )
                        return findings
            except asyncio.TimeoutError:
                last_error = ScanTimeoutError(f"Scanner {scanner_name} timed out after {config.timeout} seconds")
                logger.warning(f"Scanner {scanner_name} timed out, attempt {retries + 1}/{config.max_retries}")
            except Exception as e:
                last_error = e
                logger.error(f"Scanner {scanner_name} failed, attempt {retries + 1}/{config.max_retries}: {str(e)}")
            
            retries += 1
            if retries <= config.max_retries:
                await asyncio.sleep(1)  # Wait before retrying
        
        raise last_error or Exception(f"Scanner {scanner_name} failed after {config.max_retries} retries")

    async def load_scanners(self):
        """
        Discovers and loads all scanner modules using the scanner registry.
        """
        try:
            await self.scanner_registry.load_scanners()
            logger.info(
                "Scanners loaded successfully",
                extra={"scanner_count": len(self.scanner_registry.get_scanners())}
            )
        except Exception as e:
            logger.error("Error loading scanners", exc_info=True)
            raise

    def register_update_callback(self, callback: Callable):
        """
        Registers a callback function to receive real-time scan updates.

        Args:
            callback: A callable that accepts a dictionary or object containing update data.
        """
        self._update_callback = callback
        if self.plugin_manager:
            self.plugin_manager._update_callback = callback

    @asynccontextmanager
    async def _get_scanner(self, scanner_name: str) -> BaseScanner:
        """
        Get or create a scanner instance with caching.
        """
        if scanner_name not in self._scanner_cache:
            scanner_class = self.scanner_registry.get_scanner(scanner_name)
            if not scanner_class:
                raise ValueError(f"Scanner '{scanner_name}' not found")
            self._scanner_cache[scanner_name] = scanner_class()
        yield self._scanner_cache[scanner_name]

    async def _adjust_concurrency(self):
        """
        Adjusts concurrency based on resource usage.
        """
        if not self._resource_monitor:
            return

        metrics = self._resource_monitor.get_current_metrics()
        if not metrics:
            return

        config = self.scanner_registry.get_config()
        limits = config.resource_limits

        # Calculate resource usage ratios
        cpu_ratio = metrics.cpu_percent / limits['max_cpu_percent']
        memory_ratio = metrics.memory_mb / limits['max_memory_mb']
        network_ratio = metrics.network_connections / limits['max_network_connections']

        # Use the highest ratio to determine concurrency adjustment
        max_ratio = max(cpu_ratio, memory_ratio, network_ratio)

        # Adjust semaphore value based on resource usage
        if max_ratio > 0.9:  # Critical
            new_value = max(1, self._adaptive_semaphore._value - 2)
        elif max_ratio > 0.7:  # High
            new_value = max(2, self._adaptive_semaphore._value - 1)
        elif max_ratio < 0.3:  # Low
            new_value = min(10, self._adaptive_semaphore._value + 1)
        else:
            return  # No adjustment needed

        # Update semaphore value
        if new_value != self._adaptive_semaphore._value:
            old_value = self._adaptive_semaphore._value
            self._adaptive_semaphore = asyncio.Semaphore(new_value)
            logger.info(f"Adjusted concurrency from {old_value} to {new_value} based on resource usage")

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="scanner_engine")
    async def start_scan(
        self,
        target: str,
        scan_type: str,
        options: Optional[Dict] = None
    ) -> str:
        """
        Start a new security scan.
        
        Args:
            target: Target to scan
            scan_type: Type of scan to perform
            options: Additional scan options
            
        Returns:
            Scan ID
        """
        try:
            # Generate scan ID
            scan_id = f"{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Check resource availability
            if self._resource_monitor:
                if not self._resource_monitor.check_resource_availability():
                    raise Exception("Insufficient resources available")
            
            # Create ScanInput object
            scan_input = ScanInput(target=target, options=options or {})

            if scan_type == "full_scan":
                logger.info(f"Initiating full scan with ID: {scan_id}")
                all_scanners = self.scanner_registry.get_all_scanners()
                if not all_scanners:
                    raise Exception("No scanners found to perform a full scan.")

                # Initialize results for the main full_scan ID
                self._scan_results[scan_id] = {
                    "id": scan_id,
                    "target": target,
                    "type": scan_type,
                    "status": "running",
                    "start_time": datetime.now().isoformat(),
                    "results": [],
                    "errors": [],
                    "sub_scans": {}
                }

                for individual_scanner_name in all_scanners.keys():
                    sub_scan_id = f"{scan_id}_{individual_scanner_name}_{datetime.now().strftime('%f')}" # Add microseconds to ensure uniqueness
                    logger.info(f"Starting sub-scan for {individual_scanner_name} with sub-scan ID: {sub_scan_id}")
                    sub_scan_task = asyncio.create_task(
                        self._run_scan(sub_scan_id, individual_scanner_name, scan_input, parent_scan_id=scan_id) # Pass ScanInput and parent_scan_id
                    )
                    self._active_scans[sub_scan_id] = sub_scan_task
                    self._scan_results[scan_id]["sub_scans"][sub_scan_id] = {
                        "name": individual_scanner_name,
                        "status": "running",
                        "results": [],
                        "errors": []
                    }
                # Send an initial update for the full scan
                if self._update_callback:
                    await self._update_callback(scan_id, "started", {"message": "Full scan initiated with multiple sub-scans"})

            else:
                # Create scan task for a single scanner
                scan_task = asyncio.create_task(
                    self._run_scan(scan_id, scan_type, scan_input) # Pass ScanInput
                )
                
                # Store task
                self._active_scans[scan_id] = scan_task
                
                # Initialize results
                self._scan_results[scan_id] = {
                    "id": scan_id,
                    "target": target,
                    "type": scan_type,
                    "status": "running",
                    "start_time": datetime.now().isoformat(),
                    "results": [],
                    "errors": []
                }
                
                logger.info(
                    "Scan started",
                    extra={
                        "scan_id": scan_id,
                        "target": target,
                        "scan_type": scan_type
                    }
                )
                
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
        try:
            # Get scanner
            scanner = self.scanner_registry.get_scanner(scan_type)
            if not scanner:
                raise Exception(f"Scanner not found: {scan_type}")
            
            # Run scan
            results = await scanner.scan(scan_input)
            
            # Update results
            if parent_scan_id and parent_scan_id in self._scan_results and "sub_scans" in self._scan_results[parent_scan_id]:
                if scan_id in self._scan_results[parent_scan_id]["sub_scans"]:
                    self._scan_results[parent_scan_id]["sub_scans"][scan_id].update({
                        "status": "completed",
                        "results": results
                    })
                    # Also append results to the main full_scan results
                    self._scan_results[parent_scan_id]["results"].extend(results)
                else:
                    self._scan_results[scan_id].update({
                        "status": "completed",
                        "end_time": datetime.now().isoformat(),
                        "results": results
                    })
            else:
                self._scan_results[scan_id].update({
                    "status": "completed",
                    "end_time": datetime.now().isoformat(),
                    "results": results
                })
            
            # Send update
            if self._update_callback:
                if parent_scan_id:
                    await self._update_callback(parent_scan_id, "sub_scan_update", {"sub_scan_id": scan_id, "status": "completed", "results": results}) # Update parent for sub-scan
                else:
                    await self._update_callback(scan_id, "completed", {"results": results})
            
            logger.info(
                "Scan completed",
                extra={
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "scan_type": scan_type
                }
            )
            
        except Exception as e:
            # Update results with error
            if parent_scan_id and parent_scan_id in self._scan_results and "sub_scans" in self._scan_results[parent_scan_id]:
                if scan_id in self._scan_results[parent_scan_id]["sub_scans"]:
                    self._scan_results[parent_scan_id]["sub_scans"][scan_id].update({
                        "status": "failed",
                        "errors": [str(e)]
                    })
            else:
                self._scan_results[scan_id].update({
                    "status": "failed",
                    "end_time": datetime.now().isoformat(),
                    "errors": [str(e)]
                })
            
            # Send update
            if self._update_callback:
                if parent_scan_id:
                    await self._update_callback(parent_scan_id, "sub_scan_update", {"sub_scan_id": scan_id, "status": "failed", "error": str(e)}) # Update parent for sub-scan
                else:
                    await self._update_callback(scan_id, "failed", {"error": str(e)})
            
            logger.error(
                "Scan failed",
                extra={
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "scan_type": scan_type,
                    "error": str(e)
                },
                exc_info=True
            )
            
        finally:
            # Cleanup
            if scan_id in self._active_scans:
                del self._active_scans[scan_id]

    async def get_scan_status(self, scan_id: str) -> Dict:
        """
        Get status of a scan.
        """
        if scan_id not in self._scan_results:
            raise Exception(f"Scan not found: {scan_id}")
        return self._scan_results[scan_id]

    async def get_active_scans(self) -> List[Dict]:
        """
        Get list of active scans.
        """
        return [
            {
                "id": scan_id,
                "status": self._scan_results[scan_id]["status"]
            }
            for scan_id in self._active_scans
        ]

    async def cancel_scan(self, scan_id: str):
        """
        Cancel an active scan.
        """
        if scan_id in self._active_scans:
            self._active_scans[scan_id].cancel()
            self._scan_results[scan_id]["status"] = "cancelled"
            logger.info(f"Scan {scan_id} cancelled")
        else:
            logger.warning(f"Attempted to cancel non-existent scan: {scan_id}")

    async def get_historical_scans(self) -> List[Dict]:
        """
        Get all historical scan results.
        """
        # Filter out active scans if needed, or return all completed/failed ones.
        # For now, return all stored scan results.
        return list(self._scan_results.values())

    async def cleanup(self):
        """
        Cleanup scanner engine resources.
        """
        try:
            # Cancel active scans
            for scan_id in list(self._active_scans.keys()):
                await self.cancel_scan(scan_id)
            
            # Stop resource monitoring
            if self._resource_monitor:
                await self._resource_monitor.stop_monitoring()
            
            logger.info("Scanner engine cleanup completed")
            
        except Exception as e:
            logger.error("Error during cleanup", exc_info=True)
            raise

    def _create_scanner_batches(self, enabled_scanners: List[str]) -> List[List[str]]:
        """
        Creates optimized batches of scanners to run concurrently.
        """
        config = self.scanner_registry.get_config()
        batch_size = config.batch_size
        
        # Group scanners by intensity
        scanners_by_intensity: Dict[ScannerIntensity, List[str]] = {
            ScannerIntensity.HEAVY: [],
            ScannerIntensity.MEDIUM: [],
            ScannerIntensity.LIGHT: []
        }
        
        for scanner_name in enabled_scanners:
            intensity = self.scanner_registry.get_scanner_config(scanner_name).intensity
            scanners_by_intensity[intensity].append(scanner_name)
        
        # Create optimized batches with adaptive sizing
        batches = []
        current_semaphore_value = self._adaptive_semaphore._value
        
        # Process heavy scanners in smaller batches
        heavy_batch_size = max(1, current_semaphore_value // 3)
        for i in range(0, len(scanners_by_intensity[ScannerIntensity.HEAVY]), heavy_batch_size):
            batches.append(scanners_by_intensity[ScannerIntensity.HEAVY][i:i + heavy_batch_size])
        
        # Process medium scanners in normal batches
        medium_batch_size = max(2, current_semaphore_value // 2)
        for i in range(0, len(scanners_by_intensity[ScannerIntensity.MEDIUM]), medium_batch_size):
            batches.append(scanners_by_intensity[ScannerIntensity.MEDIUM][i:i + medium_batch_size])
        
        # Process light scanners in larger batches
        light_batch_size = current_semaphore_value
        for i in range(0, len(scanners_by_intensity[ScannerIntensity.LIGHT]), light_batch_size):
            batches.append(scanners_by_intensity[ScannerIntensity.LIGHT][i:i + light_batch_size])
        
        return batches

    async def _send_progress_update(self, scan_id: str):
        """
        Sends progress update through the callback.
        """
        if self._update_callback and scan_id in self._scan_results:
            progress_data = {
                'scan_id': scan_id,
                'type': 'scan_progress',
                'data': {
                    'overall': self._scan_results[scan_id]['status'] == 'completed' and 100 or 0,
                    'modules': {},
                    'elapsed_time': time.time() - self._scan_results[scan_id]['start_time']
                }
            }
            
            # Add resource metrics if available
            if self._resource_monitor:
                metrics = self._resource_monitor.get_current_metrics()
                if metrics:
                    progress_data['data']['resource_metrics'] = {
                        'cpu_percent': metrics.cpu_percent,
                        'memory_mb': metrics.memory_mb,
                        'network_connections': metrics.network_connections
                    }
            
            await self._update_callback(scan_id, 'scan_progress', progress_data['data'])

    @lru_cache(maxsize=1000)
    def _normalize_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Normalizes and deduplicates findings with caching. Handles unhashable types gracefully.
        """
        unique_findings: Dict[str, Finding] = {}
        for finding in findings:
            try:
                # Ensure all key parts are strings and not lists or dicts
                vt = finding.vulnerability_type
                au = finding.affected_url
                desc = finding.description
                if isinstance(vt, list):
                    vt = ",".join(map(str, vt))
                if isinstance(au, list):
                    au = ",".join(map(str, au))
                if isinstance(desc, list):
                    desc = ",".join(map(str, desc))
                vt = str(vt) if vt is not None else ""
                au = str(au) if au is not None else ""
                desc = str(desc) if desc is not None else ""
                unique_key_parts = [vt, au, desc[:50]]
                unique_key = "|".join(unique_key_parts).lower()
                
                if unique_key not in unique_findings:
                    unique_findings[unique_key] = finding
                else:
                    existing = unique_findings[unique_key]
                    if hasattr(finding.severity, 'value') and hasattr(existing.severity, 'value'):
                        if finding.severity.value > existing.severity.value:
                            unique_findings[unique_key] = finding
            except Exception as e:
                logger.error(f"Error normalizing finding: {finding}. Exception: {e}")
                continue
        return list(unique_findings.values())

    def _classify_and_score(self, findings: List[Finding]) -> List[Finding]:
        """
        Classifies vulnerabilities and assigns severity scores.
        """
        return [assign_severity_score(classify_finding(finding)) for finding in findings]

    def __del__(self):
        """
        Cleanup resources when the scanner engine is destroyed.
        """
        if hasattr(self, '_thread_pool'):
            self._thread_pool.shutdown(wait=True)