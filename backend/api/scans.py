from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi import Response
from typing import Dict, Any, List

from backend.scanner_engine import ScannerEngine
from backend.types.models import ScanInput
from backend.utils.snapshot_store import load_snapshot
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
    # Ensure scanners loaded
    try:
        await engine.scanner_registry.load_scanners()
    except Exception:
        pass
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
        # Provide minimal overview aggregates when available
        results = scan_data.get("results", [])
        try:
            tech = [f for f in results if str(f.get("category", "")).startswith("technology") or f.get("type")=="vulnerable_js_library"]
            headers = [f for f in results if f.get("type") in ("missing_security_header","misconfigured_security_header")]
            tls = [f for f in results if str(f.get("title",""))[:3].lower() in ("tls","ssl")]
            overview = {
                "technologyInfo": tech[:50],
                "headersSummary": {"issues": len(headers)},
                "tlsSummary": {"issues": len(tls)},
            }
            scan_data["overview"] = overview
        except Exception:
            pass
        return scan_data
    except Exception:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

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
    """Return only results array and status to keep payload small when needed."""
    try:
        scan_data = await engine.get_scan_status(scan_id)
        return {"results": scan_data.get("results", []), "status": scan_data.get("status")}
    except Exception:
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
