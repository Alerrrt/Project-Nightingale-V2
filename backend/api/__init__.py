from fastapi import APIRouter
from .scans import router as scans_router
from .websocket import router as websocket_router

router = APIRouter()

router.include_router(scans_router, prefix="/scans", tags=["scans"])
router.include_router(websocket_router, tags=["websocket"]) 