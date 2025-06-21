import asyncio
import logging
import importlib
import pkgutil
import inspect
import os
from typing import Dict, Type, List, Optional, Set
from functools import lru_cache
from dataclasses import dataclass, field
from threading import Lock
from backend.scanners.base_scanner import BaseScanner
from backend.types.scanner_config import ScannerRegistryConfig, ScannerConfig, ScannerIntensity
from backend.utils.logging_config import get_context_logger
from backend.utils.resource_monitor import ResourceMonitor
from backend.config import AppConfig

logger = get_context_logger(__name__)

@dataclass
class ScannerRegistryConfig:
    """Configuration for scanner registry."""
    default_timeout: int = 30
    default_max_retries: int = 3
    batch_size: int = 5
    max_concurrent_scans: int = 10
    resource_limits: Dict[str, float] = field(default_factory=dict)

class ScannerRegistry:
    """
    A registry for managing scanner modules.
    """
    _instance: Optional['ScannerRegistry'] = None
    _lock = Lock()
    _scanners: Dict[str, Type[BaseScanner]] = {}
    _scanner_metadata_cache: Dict[str, dict] = {}
    _enabled_scanners_cache: Optional[List[str]] = None
    _resource_monitor: Optional[ResourceMonitor] = None
    _initialized: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config: Optional[AppConfig] = None):
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    self._config = config or AppConfig.load_from_env()
                    self._resource_monitor = ResourceMonitor(self._config.resource_limits)
                    self._scanner_configs: Dict[str, ScannerConfig] = {}
                    self._initialized = True

    @classmethod
    def get_instance(cls, config: Optional[AppConfig] = None) -> 'ScannerRegistry':
        """Get or create the singleton instance of ScannerRegistry."""
        if cls._instance is None:
            cls._instance = cls(config)
        elif config is not None:
            cls._instance.configure(config)
        return cls._instance

    def configure(self, config: AppConfig) -> None:
        """Configure the scanner registry with new settings."""
        self._config = config
        if self._resource_monitor:
            self._resource_monitor = ResourceMonitor(config.resource_limits)
        self._scanner_configs.clear()
        self._scanner_metadata_cache.clear()
        self._enabled_scanners_cache = None

    def get_config(self) -> AppConfig:
        """Get the current configuration."""
        return self._config

    @lru_cache(maxsize=100)
    def get_scanner_config(self, scanner_name: str) -> ScannerConfig:
        """Get configuration for a specific scanner."""
        if scanner_name not in self._scanner_configs:
            self._scanner_configs[scanner_name] = ScannerConfig(
                timeout=self._config.scanner_config.default_timeout,
                max_retries=self._config.scanner_config.default_max_retries,
                options={}
            )
        return self._scanner_configs[scanner_name]

    def register(self, scanner_name: str, scanner_class: Type[BaseScanner]) -> None:
        """
        Register a scanner module.

        Args:
            scanner_name: The name of the scanner.
            scanner_class: The scanner class to register.
        """
        if not issubclass(scanner_class, BaseScanner):
            raise TypeError(f"Scanner class must inherit from BaseScanner: {scanner_name}")
        
        if scanner_name in self._scanners:
            logger.warning(f"Overwriting existing scanner registration: {scanner_name}")
        
        self._scanners[scanner_name] = scanner_class
        self._enabled_scanners_cache = None  # Invalidate cache
        logger.info(
            "Scanner registered",
            extra={
                "scanner_name": scanner_name,
                "class": scanner_class.__name__
            }
        )

    def get_scanner(self, scanner_name: str) -> Optional[Type[BaseScanner]]:
        """
        Get a registered scanner class by name.
        """
        return self._scanners.get(scanner_name)

    def get_all_scanners(self) -> Dict[str, Type[BaseScanner]]:
        """
        Get all registered scanners.
        """
        return self._scanners.copy()

    @lru_cache(maxsize=1)
    def get_all_scanner_metadata(self) -> Dict[str, dict]:
        """
        Get metadata for all registered scanners with caching.
        """
        metadata = {}
        for name, scanner_class in self._scanners.items():
            if hasattr(scanner_class, 'metadata'):
                metadata[name] = scanner_class.metadata
        return metadata

    def get_enabled_scanners(self) -> List[str]:
        """
        Get a list of enabled scanner names.
        """
        if self._enabled_scanners_cache is not None:
            return self._enabled_scanners_cache

        enabled = []
        for scanner_name in self._scanners:
            config = self.get_scanner_config(scanner_name)
            if config.enabled:
                enabled.append(scanner_name)
        
        self._enabled_scanners_cache = enabled
        return enabled

    async def load_scanners(self):
        """Load all available scanners."""
        try:
            scanners_dir = os.path.dirname(os.path.abspath(__file__))
            loaded_count = 0
            
            for filename in os.listdir(scanners_dir):
                if filename.endswith('_scanner.py') and not filename.startswith('__'):
                    module_name = filename[:-3]  # Remove .py extension
                    try:
                        # Import module
                        module = importlib.import_module(f'backend.scanners.{module_name}')
                        
                        # Find scanner classes in the module
                        for name, obj in inspect.getmembers(module):
                            if (inspect.isclass(obj) and 
                                issubclass(obj, BaseScanner) and 
                                obj != BaseScanner):
                                
                                # Use the class name as the scanner name
                                scanner_name = name.lower().replace('scanner', '')
                                self.register(scanner_name, obj)
                                loaded_count += 1
                                
                    except Exception as e:
                        logger.error(
                            f"Error loading scanner module: {module_name}",
                            extra={"error": str(e)},
                            exc_info=True
                        )
            
            logger.info(
                "Scanners loaded",
                extra={
                    "scanner_count": len(self._scanners),
                    "loaded_count": loaded_count
                }
            )
            
        except Exception as e:
            logger.error("Error loading scanners", exc_info=True)
            raise

    def discover_and_register_scanners(self) -> None:
        """
        Deprecated: Use load_scanners() instead.
        This method is kept for backward compatibility.
        """
        logger.warning("discover_and_register_scanners is deprecated, use load_scanners() instead")
        asyncio.create_task(self.load_scanners())

    def clear(self) -> None:
        """
        Clear all registered scanners and caches.
        """
        self._scanners.clear()
        self._scanner_metadata_cache.clear()
        self._enabled_scanners_cache = None
        self.get_scanner_config.cache_clear()
        self.get_all_scanner_metadata.cache_clear()
        logger.info("Scanner registry cleared")

    async def check_scanner_health(self, name: str) -> bool:
        """Check health of a scanner."""
        try:
            scanner = self.get_scanner(name)
            if not scanner:
                return False
                
            # Create instance
            instance = scanner()
            
            # Check health
            return await instance.check_health()
            
        except Exception as e:
            logger.error(
                f"Error checking scanner health: {name}",
                exc_info=True
            )
            return False

    async def get_scanner_metrics(self, name: str) -> Dict:
        """Get metrics for a scanner."""
        try:
            scanner = self.get_scanner(name)
            if not scanner:
                return {}
                
            # Create instance
            instance = scanner()
            
            # Get metrics
            return instance.get_metrics()
            
        except Exception as e:
            logger.error(
                f"Error getting scanner metrics: {name}",
                exc_info=True
            )
            return {}

    def get_scanners(self) -> List[str]:
        """Get list of available scanner names."""
        return list(self._scanners.keys()) 