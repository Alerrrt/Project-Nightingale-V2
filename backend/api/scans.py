from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Dict, Any, List

from backend.scanner_engine import ScannerEngine
from backend.types.models import ScanInput
from backend.scanners.scanner_registry import ScannerRegistry

router = APIRouter()

async def get_scanner_engine(request: Request) -> ScannerEngine:
    """Dependency to get scanner engine instance from app.state."""
    engine = getattr(request.app.state, "scanner_engine", None)
    if engine is None:
        raise Exception("Scanner engine not configured")
    return engine

@router.get("/", response_model=List[Dict])
async def get_active_scans(engine: ScannerEngine = Depends(get_scanner_engine)):
    """Get list of active scans."""
    return await engine.get_active_scans()

@router.get("/scanners", response_model=Dict[str, dict])
async def list_scanners(engine: ScannerEngine = Depends(get_scanner_engine)):
    """
    Lists all registered scanners and their metadata.
    """
    if not engine.scanner_registry:
        raise HTTPException(status_code=500, detail="Scanner registry not initialized")
    return engine.scanner_registry.get_all_scanner_metadata()

@router.get("/history", response_model=List[Dict])
async def get_historical_scans(engine: ScannerEngine = Depends(get_scanner_engine)):
    """
    Retrieves a list of historical scan summaries.
    """
    return await engine.get_historical_scans()

@router.post("/start", response_model=Dict)
async def start_scan(
    scan_input: ScanInput,
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Start a new security scan."""
    try:
        scan_id = await engine.start_scan(
            target=scan_input.target,
            scan_type=scan_input.scan_type,
            options=scan_input.options or {}
        )
        return {"scan_id": scan_id, "status": "started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}", response_model=Dict)
async def get_scan_status(
    scan_id: str,
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Get the status of a scan."""
    try:
        scan_data = await engine.get_scan_status(scan_id)
        # Compose modules list for frontend
        modules = [
            {
                "name": sub["name"],
                "status": sub["status"],
                "error": sub["errors"][0] if sub.get("errors") and len(sub["errors"]) > 0 else None
            }
            for sub in scan_data.get("sub_scans", {}).values()
        ]
        scan_data["modules"] = modules
        return scan_data
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

@router.post("/{scan_id}/cancel", response_model=Dict)
async def cancel_scan(
    scan_id: str,
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Cancel an active scan."""
    try:
        await engine.cancel_scan(scan_id)
        return {"status": "cancelled"}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))