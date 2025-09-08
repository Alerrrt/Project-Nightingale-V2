from abc import ABC, abstractmethod
from typing import List, Dict, Any
from backend.config_types.models import ScanInput, Finding

class BaseScanner(ABC):
    def __init__(self):
        self.name = self.__class__.__name__
        self.initialized = False

    @abstractmethod
    async def scan(self, scan_input: ScanInput) -> List[Finding]:
        """Perform the security scan."""
        pass

    @abstractmethod
    async def initialize(self):
        """Initialize the scanner."""
        pass

    @abstractmethod
    async def cleanup(self):
        """Cleanup scanner resources."""
        pass

    def get_config(self) -> Dict[str, Any]:
        """Get scanner configuration."""
        return {
            "name": self.name,
            "description": self.__doc__ or "No description available",
            "version": getattr(self, "version", "1.0.0")
        } 
