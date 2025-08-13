import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
from backend.utils.logging_config import get_context_logger
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.resource_monitor import ResourceMonitor
from backend.types.models import ScanInput

logger = get_context_logger(__name__)

class BasePlugin(ABC):
    """Base class for all security scanner plugins."""

    def __init__(self):
        self._config: Optional[Dict] = None
        self._resource_monitor: Optional[ResourceMonitor] = None
        self._metrics: Dict[str, Any] = {
            "total_runs": 0,
            "successful_runs": 0,
            "failed_runs": 0,
            "total_duration": 0,
            "last_run_time": None
        }

    def configure(self, config: Dict):
        """Configure the plugin."""
        self._config = config
        if "resource_limits" in config:
            self._resource_monitor = ResourceMonitor(config["resource_limits"])
        logger.info(
            "Plugin configured",
            extra={
                "plugin": self.__class__.__name__,
                "config": config
            }
        )

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="plugin")
    async def run(self, scan_input: ScanInput, config: Optional[Dict] = None) -> List[Dict]:
        """
        Run the plugin.
        
        Args:
            scan_input: The input for the scan.
            config: Additional options
            
        Returns:
            List of results
        """
        start_time = datetime.now()
        run_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Check resource availability
            if self._resource_monitor:
                if not await self._resource_monitor.check_resources_available():
                    raise Exception("Insufficient resources available")
            
            # Log run start
            logger.info(
                "Plugin run started",
                extra={
                    "plugin": self.__class__.__name__,
                    "run_id": run_id,
                    "target": scan_input.target,
                    "options": config
                }
            )
            
            # Run plugin
            results = await self._run_plugin(scan_input, config or {})
            
            # Update metrics
            self._update_metrics(True, start_time)
            
            # Log run completion
            logger.info(
                "Plugin run completed",
                extra={
                    "plugin": self.__class__.__name__,
                    "run_id": run_id,
                    "target": scan_input.target,
                    "result_count": len(results)
                }
            )
            
            return results
            
        except Exception as e:
            # Update metrics
            self._update_metrics(False, start_time)
            
            # Log error
            logger.error(
                "Plugin run failed",
                extra={
                    "plugin": self.__class__.__name__,
                    "run_id": run_id,
                    "target": scan_input.target,
                    "error": str(e)
                },
                exc_info=True
            )
            raise

    @abstractmethod
    async def _run_plugin(self, scan_input: ScanInput, config: Dict) -> List[Dict]:
        """
        Run the plugin. Must be implemented by subclasses.
        
        Args:
            scan_input: The input for the scan.
            config: Plugin options
            
        Returns:
            List of results
        """
        pass

    async def check_health(self) -> bool:
        """Check plugin health."""
        try:
            # Check resource availability
            if self._resource_monitor:
                if not await self._resource_monitor.check_resources_available():
                    return False
            
            # Perform health check
            return await self._check_health()
            
        except Exception as e:
            logger.error(
                "Health check failed",
                extra={
                    "plugin": self.__class__.__name__,
                    "error": str(e)
                },
                exc_info=True
            )
            return False

    async def _check_health(self) -> bool:
        """Perform health check. Can be overridden by subclasses."""
        return True

    def get_metrics(self) -> Dict:
        """Get plugin metrics."""
        return self._metrics

    def _update_metrics(self, success: bool, start_time: datetime):
        """Update plugin metrics."""
        duration = (datetime.now() - start_time).total_seconds()
        
        self._metrics["total_runs"] += 1
        if success:
            self._metrics["successful_runs"] += 1
        else:
            self._metrics["failed_runs"] += 1
            
        self._metrics["total_duration"] += duration
        self._metrics["last_run_time"] = datetime.now().isoformat()

    async def cleanup(self):
        """Cleanup plugin resources."""
        try:
            # Stop resource monitoring
            if self._resource_monitor:
                await self._resource_monitor.stop_monitoring()
            
            # Perform cleanup
            await self._cleanup()
            
            logger.info(
                "Plugin cleanup completed",
                extra={"plugin": self.__class__.__name__}
            )
            
        except Exception as e:
            logger.error(
                "Error during cleanup",
                extra={
                    "plugin": self.__class__.__name__,
                    "error": str(e)
                },
                exc_info=True
            )
            raise

    async def _cleanup(self):
        """Perform cleanup. Can be overridden by subclasses."""
        pass 
