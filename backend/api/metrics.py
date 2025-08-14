from fastapi import APIRouter
from typing import Dict, Any

from backend.utils.http_client import get_shared_http_client
from backend.utils.scanner_concurrency import get_scanner_concurrency_manager

router = APIRouter()

@router.get("/http-client", response_model=Dict[str, Any])
async def get_http_client_metrics() -> Dict[str, Any]:
    client = get_shared_http_client()
    return client.get_stats()


@router.get("/concurrency", response_model=Dict[str, Any])
async def get_concurrency_metrics() -> Dict[str, Any]:
    mgr = get_scanner_concurrency_manager()
    return mgr.get_stats()


