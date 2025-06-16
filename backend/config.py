from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from backend.types.scanner_config import ScannerRegistryConfig

class AppConfig(BaseModel):
    """Application configuration loaded from environment variables."""
    debug: bool = Field(False, description="Enable debug mode")
    backend_host: str = Field("0.0.0.0", description="Backend host address")
    backend_port: int = Field(8000, description="Backend port")
    resource_limits: Dict[str, Any] = Field(
        default_factory=lambda: {
            'max_cpu_percent': 80,
            'max_memory_mb': 1024,
            'max_network_connections': 100
        },
        description="Resource usage limits"
    )
    scanner_config: ScannerRegistryConfig = Field(
        default_factory=ScannerRegistryConfig,
        description="Scanner registry configuration"
    )

    @classmethod
    def load_from_env(cls) -> 'AppConfig':
        """Load configuration from environment variables."""
        import os
        from dotenv import load_dotenv

        # Load environment variables from .env file
        load_dotenv()

        return cls(
            debug=os.getenv('DEBUG', 'False').lower() == 'true',
            backend_host=os.getenv('BACKEND_HOST', '0.0.0.0'),
            backend_port=int(os.getenv('BACKEND_PORT', '8000')),
            resource_limits={
                'max_cpu_percent': float(os.getenv('MAX_CPU_PERCENT', '80')),
                'max_memory_mb': float(os.getenv('MAX_MEMORY_MB', '1024')),
                'max_network_connections': int(os.getenv('MAX_NETWORK_CONNECTIONS', '100'))
            },
            scanner_config=ScannerRegistryConfig(
                default_timeout=int(os.getenv('SCANNER_DEFAULT_TIMEOUT', '30')),
                default_max_retries=int(os.getenv('SCANNER_MAX_RETRIES', '3')),
                batch_size=int(os.getenv('SCANNER_BATCH_SIZE', '5')),
                max_concurrent_scans=int(os.getenv('MAX_CONCURRENT_SCANS', '10')),
                resource_limits={
                    'max_cpu_percent': float(os.getenv('MAX_CPU_PERCENT', '80')),
                    'max_memory_mb': float(os.getenv('MAX_MEMORY_MB', '1024')),
                    'max_network_connections': int(os.getenv('MAX_NETWORK_CONNECTIONS', '100'))
                }
            )
        ) 