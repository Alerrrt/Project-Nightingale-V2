from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from datetime import datetime
from backend.config import settings, AppConfig
from backend.api import router as api_router
from backend.plugins.plugin_manager import PluginManager
from backend.scanner_engine import ScannerEngine
from backend.scanners.scanner_registry import ScannerRegistry
from backend.utils.logging_config import setup_logging, get_context_logger

# Setup structured logging
setup_logging(log_level="INFO", log_dir="logs", app_name="security_scanner")
logger = get_context_logger(__name__)

app = FastAPI(
    title="Security Scanner API",
    description="API for security scanning and analysis",
    version="1.0.0"
)

# --- Engine and Plugin Initialization ---
# This must happen BEFORE routes are included
app_config = AppConfig.load_from_env()
scanner_registry = ScannerRegistry(app_config)
plugin_manager = PluginManager()
scanner_engine = ScannerEngine(plugin_manager)
scanner_engine.configure(scanner_registry)

# Attach engine to app state
app.state.scanner_registry = scanner_registry
app.state.scanner_engine = scanner_engine
# --- End Initialization ---

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Error processing request: {exc}", exc_info=True)
    # Note: For custom error handling, use ErrorHandler from backend/utils/error_handler.py
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )

# Add API routes
app.include_router(api_router, prefix="/api")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/test-root")
async def test_root():
    return {"message": "Hello from root"}

@app.get("/api/test-api")
async def test_api():
    return {"message": "Hello from API"}

@app.on_event("startup")
async def startup_event():
    """Load scanners on startup."""
    try:
        await scanner_engine.load_scanners()
        logger.info("Scanner modules loaded successfully.")
    except Exception as e:
        logger.error(f"Error loading scanner modules during startup: {e}", exc_info=True)
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    try:
        if scanner_engine:
            await scanner_engine.cleanup()
        logger.info("Application shutdown complete")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}", exc_info=True)

# The following websocket endpoint is a duplicate and conflicts with the main API router.
# The correct endpoint is defined in backend/api/websocket.py and included via api_router.
#
# @app.websocket("/ws/{client_id}")
# async def websocket_endpoint(websocket: WebSocket, client_id: str):
#     print(f"WebSocket handler reached for client_id={client_id}")
#     await websocket.accept()
#     try:
#         while True:
#             try:
#                 data = await websocket.receive_text()
#                 print(f"Received from {client_id}: {data}")
#                 await websocket.send_text(f"Echo: {data}")
#             except WebSocketDisconnect:
#                 print(f"Client {client_id} disconnected")
#                 break
#             except Exception as e:
#                 print(f"Error in message loop: {e}")
#                 break
#     except Exception as e:
#         print(f"WebSocket outer error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    ) 