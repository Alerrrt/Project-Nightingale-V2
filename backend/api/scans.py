from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi import Response
from typing import Dict, Any, List

from backend.scanner_engine import ScannerEngine
from backend.config_types.models import ScanInput
from backend.utils.snapshot_store import load_snapshot
from backend.scanners.scanner_registry import ScannerRegistry

router = APIRouter()

async def get_scanner_engine(request: Request) -> ScannerEngine:
    """Dependency to get scanner engine instance from app.state and ensure scanners are loaded."""
    engine = getattr(request.app.state, "scanner_engine", None)
    if engine is None:
        raise Exception("Scanner engine not configured")

    # Ensure the engine is configured with a registry even if startup hasn't finished yet
    try:
        if not getattr(engine, "scanner_registry", None):
            registry = getattr(request.app.state, "scanner_registry", None)
            if registry is None:
                raise Exception("Scanner registry not available on app state")
            # Configure engine (starts concurrency manager and preloads)
            await engine.configure(registry)
        else:
            # Best-effort ensure concurrency manager is running (idempotent)
            try:
                cm = getattr(engine, "_concurrency_manager", None)
                if cm:
                    await cm.start()
            except Exception:
                pass
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Engine configuration on-demand failed: {e}")

    # Ensure all scanners are preloaded when API is accessed
    if engine.scanner_registry and hasattr(engine, 'load_scanners'):
        # Force preload all scanners if not already loaded
        if not getattr(engine, '_scanners_preloaded', False):
            try:
                await engine.load_scanners(preload_all=True)
                # Mark scanners as preloaded to avoid redundant loading
                setattr(engine, '_scanners_preloaded', True)
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Error preloading scanners in API request: {e}")

    return engine

@router.get("/", response_model=List[Dict])
async def get_active_scans(engine: ScannerEngine = Depends(get_scanner_engine)):
    """Get list of active scans."""
    return await engine.get_active_scans()

@router.get("/scanners", response_model=Dict[str, dict])
async def list_scanners(engine: ScannerEngine = Depends(get_scanner_engine)):
    """
    Lists all registered scanners and their metadata.
    Ensures all scanners are fully preloaded when this endpoint is accessed.
    """
    if not engine.scanner_registry:
        raise HTTPException(status_code=500, detail="Scanner registry not initialized")
    
    # Force preload all scanners to ensure they're ready for scanning
    try:
        # Preload essential scanners first
        await engine.scanner_registry.load_scanners(preload_essential=True)
        
        # Then force preload all scanners
        await engine.load_scanners(preload_all=True)
        
        # Mark scanners as preloaded
        setattr(engine, '_scanners_preloaded', True)
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Error preloading scanners in list_scanners endpoint: {e}")
    
    return engine.scanner_registry.get_enhanced_scanner_metadata()

@router.get("/history", response_model=List[Dict])
async def get_historical_scans(engine: ScannerEngine = Depends(get_scanner_engine)):
    """
    Retrieves a list of historical scan summaries.
    """
    return await engine.get_historical_scans()

@router.options("/start")
async def start_scan_preflight(response: Response):
    # Explicit preflight handler to ensure CORS/headers path exists
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "content-type, authorization"
    return {}

@router.post("/start", response_model=Dict)
async def start_scan(
    scan_input: ScanInput,
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Start a new security scan with preloaded scanners."""
    try:
        # Ensure all scanners are preloaded before starting a scan
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Preparing to start {scan_input.scan_type} scan for {scan_input.target}")
        
        # Force preload all scanners if not already done
        if not getattr(engine, '_scanners_preloaded', False):
            logger.info("Preloading all scanners before starting scan...")
            await engine.load_scanners(preload_all=True)
            setattr(engine, '_scanners_preloaded', True)
            logger.info("All scanners preloaded successfully")
        
        # Start the scan with preloaded scanners
        scan_id = await engine.start_scan(
            target=scan_input.target,
            scan_type=scan_input.scan_type,
            options=scan_input.options or {}
        )
        # Immediately nudge websocket subscribers with initial progress if any are connected
        try:
            from backend.api.websocket import get_connection_manager
            mgr = get_connection_manager()
            await mgr.broadcast_scan_update(scan_id, "scan_phase", {"phase": "Initializing...", "scan_id": scan_id})
        except Exception:
            pass
        return {"scan_id": scan_id, "status": "started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}", response_model=Dict)
async def get_scan_status(
    scan_id: str,
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Get the status of a scan (falls back to snapshot if engine state missing)."""
    # Try live engine first
    scan_data: Dict = {}
    try:
        scan_data = await engine.get_scan_status(scan_id)
    except Exception:
        scan_data = {}

    # Fallback to snapshot when live state not available (e.g., after reload)
    if not scan_data:
        snap = load_snapshot(scan_id) or {}
        if not snap:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
        scan_data = snap

    # Compose modules list for frontend
    modules = [
        {
            "name": sub.get("name"),
            "status": sub.get("status"),
            "error": (sub.get("errors") or [None])[0] if isinstance(sub.get("errors"), list) else None
        }
        for sub in (scan_data.get("sub_scans") or {}).values()
    ]
    scan_data["modules"] = modules

    # Provide minimal overview aggregates when available
    results = scan_data.get("results", [])
    try:
        tech = [f for f in results if str(f.get("category", "")).startswith("technology") or f.get("type") == "vulnerable_js_library"]
        headers = [f for f in results if f.get("type") in ("missing_security_header", "misconfigured_security_header")]
        tls = [f for f in results if str(f.get("title", ""))[:3].lower() in ("tls", "ssl")]
        overview = {
            "technologyInfo": tech[:50],
            "headersSummary": {"issues": len(headers)},
            "tlsSummary": {"issues": len(tls)},
        }
        scan_data["overview"] = overview
    except Exception:
        pass

    return scan_data

@router.get("/{scan_id}/overview", response_model=Dict)
async def get_scan_overview(
    scan_id: str,
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Return an aggregated overview for a scan (lightweight summary)."""
    # Try live first, fallback to snapshot
    try:
        scan_data = await engine.get_scan_status(scan_id)
    except Exception:
        scan_data = load_snapshot(scan_id) or {}

    if not scan_data:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    results = scan_data.get("results", [])
    # Severity counts
    by_severity: Dict[str, int] = {}
    for f in results:
        sev = str(f.get("severity", "Info"))
        by_severity[sev] = by_severity.get(sev, 0) + 1
    # Technology/header/tls summaries
    technology_info = [
        {
            "title": r.get("title"),
            "severity": r.get("severity"),
            "location": r.get("location"),
            "evidence": r.get("evidence"),
        }
        for r in results
        if str(r.get("category", "")).startswith("technology") or r.get("type") in ("vulnerable_js_library",)
    ][:50]
    headers_issues = [r for r in results if r.get("type") in ("missing_security_header", "misconfigured_security_header")]
    tls_issues = [r for r in results if str(r.get("title", "")).lower().startswith(("tls", "ssl"))]

    return {
        "scan_id": scan_data.get("id"),
        "target": scan_data.get("target"),
        "status": scan_data.get("status"),
        "summary": {
            "total_findings": len(results),
            "by_severity": by_severity,
        },
        "technologyInfo": technology_info,
        "headersSummary": {"issues": len(headers_issues)},
        "tlsSummary": {"issues": len(tls_issues)},
        "modules": [
            {
                "name": sub.get("name"),
                "status": sub.get("status"),
                "error": (sub.get("errors") or [None])[0] if isinstance(sub.get("errors"), list) else None,
            }
            for sub in (scan_data.get("sub_scans") or {}).values()
        ],
    }

@router.get("/{scan_id}/results", response_model=Dict)
async def get_scan_results(
    scan_id: str,
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Return only results array and status to keep payload small when needed (snapshot fallback)."""
    scan_data: Dict = {}
    try:
        scan_data = await engine.get_scan_status(scan_id)
    except Exception:
        scan_data = {}

    if not scan_data:
        scan_data = load_snapshot(scan_id) or {}

    if not scan_data:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    return {"results": scan_data.get("results", []), "status": scan_data.get("status")}

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
