import asyncio
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import os
from typing import Dict, Any, Optional

from backend.config import AppConfig
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.scanner_config import ScannerRegistryConfig
from backend.scanner_engine import ScannerEngine
from backend.plugins.plugin_manager import PluginManager
from backend.utils.logging_config import setup_logging, get_context_logger
from backend.utils.circuit_breaker import CircuitBreaker
from backend.utils.resource_monitor import ResourceMonitor
from backend.api.routes import create_scans_router, create_realtime_router
from backend.api.realtime import send_realtime_update, router as realtime_websocket_router

# Setup logging
setup_logging()
logger = get_context_logger(__name__)

# Global state
app_config: Optional[AppConfig] = None
scanner_registry: Optional[ScannerRegistry] = None
scanner_engine: Optional[ScannerEngine] = None
plugin_manager: Optional[PluginManager] = None
circuit_breaker = None
resource_monitor = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI application.
    Handles startup and shutdown events.
    """
    global app_config, scanner_registry, scanner_engine, plugin_manager, circuit_breaker, resource_monitor

    try:
        # Load configuration
        app_config = AppConfig.load_from_env()
        logger.info("Configuration loaded successfully")

        # Initialize scanner registry
        scanner_registry = ScannerRegistry.get_instance(app_config)
        await scanner_registry.load_scanners()
        logger.info("Scanner registry initialized")

        # Initialize plugin manager
        plugin_manager = PluginManager()
        await plugin_manager.load_plugins()
        logger.info("Plugin manager initialized")

        # Initialize scanner engine
        scanner_engine = ScannerEngine(plugin_manager)
        scanner_engine.configure(app_config.scanner_config)
        await scanner_engine.load_scanners()
        logger.info("Scanner engine initialized")

        # Initialize circuit breaker
        circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=30.0,
            name="main_circuit_breaker"
        )
        
        # Initialize resource monitor
        resource_monitor = ResourceMonitor(app_config.resource_limits)
        
        # Start resource monitoring
        if resource_monitor:
            await resource_monitor.start_monitoring()
        
        # Register update callback for real-time updates
        if scanner_engine:
            scanner_engine.register_update_callback(
                lambda scan_id, update_type, data: asyncio.create_task(
                    send_realtime_update(scan_id, update_type, data)
                )
            )
        
        # Create and include routers here, after all components are initialized
        scans_router_instance = create_scans_router(scanner_engine, plugin_manager)
        realtime_router_instance = create_realtime_router()

        app.include_router(scans_router_instance, prefix="/scans", tags=["Scans"])
        app.include_router(realtime_websocket_router, tags=["Real-time"])

        logger.info("Application components initialized successfully")
        yield
    except Exception as e:
        logger.error("Error during application startup", exc_info=True)
        raise
    finally:
        # Cleanup
        logger.info("Cleaning up application resources")
        if scanner_engine:
            await scanner_engine.cleanup()
        if resource_monitor:
            await resource_monitor.stop_monitoring()
        if plugin_manager:
            await plugin_manager.cleanup()
        logger.info("Application cleanup completed")

# Create FastAPI application
app = FastAPI(
    title="Security Scanner API",
    description="API for security scanning and vulnerability detection",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint returning API information."""
    return {
        "name": "Security Scanner API",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        health_status = {
            "status": "healthy",
            "components": {
                "scanner_registry": scanner_registry is not None,
                "plugin_manager": plugin_manager is not None,
                "scanner_engine": scanner_engine is not None,
                "circuit_breaker": circuit_breaker is not None,
                "resource_monitor": resource_monitor is not None
            }
        }
        
        # Check resource usage
        if resource_monitor:
            metrics = resource_monitor.get_current_metrics()
            if metrics:
                health_status["resources"] = {
                    "cpu_percent": metrics.cpu_percent,
                    "memory_mb": metrics.memory_mb,
                    "network_connections": metrics.network_connections
                }
        return health_status
    except Exception as e:
        logger.error("Error during health check", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

def load_scanner_config() -> ScannerRegistryConfig:
    """Load scanner configuration."""
    try:
        return ScannerRegistryConfig(
            default_timeout=30,
            default_max_retries=3,
            batch_size=5,
            max_concurrent_scans=10,
            resource_limits={
                'max_cpu_percent': 80,
                'max_memory_mb': 1024,
                'max_network_connections': 100
            }
        )
    except Exception as e:
        logger.error("Error loading scanner configuration", exc_info=True)
        raise 