import asyncio
import logging
from typing import Dict, List, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from backend.utils.logging_config import get_context_logger
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.resource_monitor import ResourceMonitor
from backend.types.models import ScanStartRequest

logger = get_context_logger(__name__)

def create_scans_router(scanner_engine, plugin_manager):
    """Create router for scan endpoints."""
    router = APIRouter()
    
    @router.post("/start")
    # @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="start_scan") # Temporarily disabled for debugging
    async def start_scan(
        scan_request: ScanStartRequest,
        background_tasks: BackgroundTasks
    ):
        """Start a new security scan."""
        try:
            logger.info(f"Received scan start request: {scan_request.model_dump_json()}") # Log incoming request
            # Start scan
            scan_id = await scanner_engine.start_scan(
                target=scan_request.target,
                scan_type=scan_request.scan_type,
                options=scan_request.options
            )
            
            logger.info(
                "Scan started",
                extra={
                    "scan_id": scan_id,
                    "target": scan_request.target,
                    "scan_type": scan_request.scan_type
                }
            )
            
            return {"scan_id": scan_id}
            
        except Exception as e:
            logger.error(
                "Error starting scan",
                extra={
                    "target": scan_request.target,
                    "scan_type": scan_request.scan_type,
                    "error": str(e)
                },
                exc_info=True
            )
            raise HTTPException(
                status_code=500,
                detail=f"Error starting scan: {str(e)}"
            )

    @router.get("/status/{scan_id}")
    async def get_scan_status(scan_id: str):
        """Get status of a scan."""
        try:
            status = await scanner_engine.get_scan_status(scan_id)
            
            logger.info(
                "Scan status retrieved",
                extra={
                    "scan_id": scan_id,
                    "status": status["status"]
                }
            )
            
            return status
            
        except Exception as e:
            logger.error(
                "Error getting scan status",
                extra={
                    "scan_id": scan_id,
                    "error": str(e)
                },
                exc_info=True
            )
            raise HTTPException(
                status_code=404,
                detail=f"Scan not found: {scan_id}"
            )

    @router.get("/active")
    async def get_active_scans():
        """Get list of active scans."""
        try:
            scans = await scanner_engine.get_active_scans()
            
            logger.info(
                "Active scans retrieved",
                extra={"scan_count": len(scans)}
            )
            
            return scans
            
        except Exception as e:
            logger.error(
                "Error getting active scans",
                extra={"error": str(e)},
                exc_info=True
            )
            raise HTTPException(
                status_code=500,
                detail=f"Error getting active scans: {str(e)}"
            )

    @router.post("/cancel/{scan_id}")
    async def cancel_scan(scan_id: str):
        """Cancel an active scan."""
        try:
            await scanner_engine.cancel_scan(scan_id)
            
            logger.info(
                "Scan cancelled",
                extra={"scan_id": scan_id}
            )
            
            return {"status": "cancelled"}
            
        except Exception as e:
            logger.error(
                "Error cancelling scan",
                extra={
                    "scan_id": scan_id,
                    "error": str(e)
                },
                exc_info=True
            )
            raise HTTPException(
                status_code=404,
                detail=f"Scan not found: {scan_id}"
            )

    @router.get("/history")
    async def get_historical_scans():
        """Get a list of historical scans."""
        try:
            historical_scans = await scanner_engine.get_historical_scans()
            return historical_scans
        except Exception as e:
            logger.error(
                "Error getting historical scans",
                extra={"error": str(e)},
                exc_info=True
            )
            raise HTTPException(
                status_code=500,
                detail=f"Error getting historical scans: {str(e)}"
            )

    return router

def create_realtime_router():
    """Create router for real-time update endpoints."""
    router = APIRouter()
    
    @router.get("/updates")
    async def get_updates():
        """Get real-time updates."""
        try:
            # This would be implemented with WebSocket or Server-Sent Events
            pass
            
        except Exception as e:
            logger.error(
                "Error getting updates",
                extra={"error": str(e)},
                exc_info=True
            )
            raise HTTPException(
                status_code=500,
                detail=f"Error getting updates: {str(e)}"
            )

    return router 