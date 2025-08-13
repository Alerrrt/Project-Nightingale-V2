import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
from backend.utils.logging_config import get_context_logger
from backend.utils.resource_monitor import ResourceMonitor
from backend.types.models import ScanInput, Finding # Import Finding from centralized models

logger = get_context_logger(__name__)

class BaseScanner(ABC):
    """
    Base class for all scanner modules.
    Each scanner should define a class-level 'metadata' dictionary with keys:
      - name: str
      - description: str
      - owasp_category: str
      - author: str (optional)
      - version: str (optional)
    """
    metadata: Dict[str, Any] = {
        "name": "BaseScanner",
        "description": "Base class for all scanners.",
        "owasp_category": "Unknown",
        "author": "",
        "version": "1.0"
    }

    def __init__(self):
        super().__init__()
        self._config: Optional[Dict] = None
        self._resource_monitor: Optional[ResourceMonitor] = None
        self._metrics: Dict[str, Any] = {
            "total_scans": 0,
            "successful_scans": 0,
            "failed_scans": 0,
            "total_duration": 0,
            "last_scan_time": None
        }

    def configure(self, config: Dict):
        """Configure the scanner."""
        self._config = config
        if "resource_limits" in config:
            self._resource_monitor = ResourceMonitor(config["resource_limits"])
        logger.info(
            "Scanner configured",
            extra={
                "scanner": self.__class__.__name__,
                "config": config
            }
        )

    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        """
        Perform a security scan.
        
        Args:
            scan_input: The input for the scan, including target and options.
            
        Returns:
            List of scan results
        """
        start_time = datetime.now()
        scan_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        
        try:
            logger.info(
                "Starting scan",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target
                }
            )
            
            # Check resource availability
            if self._resource_monitor and not await self._resource_monitor.check_resources_available():
                raise RuntimeError("Insufficient resources available for scan")
            
            # Perform scan
            results = await self._perform_scan(scan_input.target, scan_input.options)
            
            # Update metrics
            self._update_metrics(True, start_time)
            
            logger.info(
                "Scan completed successfully",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "result_count": len(results)
                }
            )
            
            return results
            
        except Exception as e:
            self._update_metrics(False, start_time)
            logger.error(
                "Scan failed",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "error": str(e)
                },
                exc_info=True
            )
            raise

    @abstractmethod
    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Perform the actual scan. Must be implemented by subclasses.
        
        Args:
            target: Target to scan
            options: Scan options
            
        Returns:
            List of scan results
        """
        pass

    async def check_health(self) -> bool:
        """Check scanner health."""
        try:
            # Check resource availability
            if self._resource_monitor:
                if not await self._resource_monitor.check_resources_available():
                    logger.warning(
                        "Health check failed: insufficient resources",
                        extra={"scanner": self.__class__.__name__}
                    )
                    return False
            
            # Perform health check
            health_status = await self._check_health()
            
            if not health_status:
                logger.warning(
                    "Health check failed: scanner reported unhealthy",
                    extra={"scanner": self.__class__.__name__}
                )
            
            return health_status
            
        except Exception as e:
            logger.error(
                "Health check failed with error",
                extra={
                    "scanner": self.__class__.__name__,
                    "error": str(e)
                },
                exc_info=True
            )
            return False

    async def _check_health(self) -> bool:
        """Perform health check. Can be overridden by subclasses."""
        return True

    def get_metrics(self) -> Dict:
        """Get scanner metrics."""
        return self._metrics

    def _update_metrics(self, success: bool, start_time: datetime):
        """Update scanner metrics."""
        duration = (datetime.now() - start_time).total_seconds()
        
        self._metrics["total_scans"] += 1
        if success:
            self._metrics["successful_scans"] += 1
        else:
            self._metrics["failed_scans"] += 1
            
        self._metrics["total_duration"] += duration
        self._metrics["last_scan_time"] = datetime.now().isoformat()

    async def cleanup(self):
        """Cleanup scanner resources."""
        try:
            # Stop resource monitoring
            if self._resource_monitor:
                await self._resource_monitor.stop_monitoring()
            
            # Perform cleanup
            await self._cleanup()
            
            logger.info(
                "Scanner cleanup completed",
                extra={"scanner": self.__class__.__name__}
            )
            
        except Exception as e:
            logger.error(
                "Error during cleanup",
                extra={
                    "scanner": self.__class__.__name__,
                    "error": str(e)
                },
                exc_info=True
            )
            raise

    async def _cleanup(self):
        """Perform cleanup. Can be overridden by subclasses."""
        pass
