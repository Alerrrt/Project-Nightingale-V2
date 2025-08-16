from fastapi import APIRouter
from typing import Dict, Any

from backend.utils.http_client import get_shared_http_client
from backend.utils.scanner_concurrency import get_scanner_concurrency_manager
from backend.scanner_engine import ScannerEngine

router = APIRouter()

@router.get("/http-client", response_model=Dict[str, Any])
async def get_http_client_metrics() -> Dict[str, Any]:
    client = get_shared_http_client()
    return client.get_stats()


@router.get("/concurrency", response_model=Dict[str, Any])
async def get_concurrency_metrics() -> Dict[str, Any]:
    mgr = get_scanner_concurrency_manager()
    return mgr.get_stats()


@router.get("/engine", response_model=Dict[str, Any])
async def get_engine_metrics() -> Dict[str, Any]:
    # Light placeholder; engine-level stats are already embedded in http/concurrency
    # Could be extended to expose per-scan states if needed
    client = get_shared_http_client()
    mgr = get_scanner_concurrency_manager()
    return {
        "http": client.get_stats(),
        "concurrency": mgr.get_stats(),
    }


