import json
import logging
import asyncio
from typing import Dict, Any, AsyncGenerator, Union, List
from fastapi import WebSocket, WebSocketDisconnect, APIRouter, HTTPException
from starlette.websockets import WebSocketDisconnect
from pydantic.networks import Url

from backend.types.models import Finding, ModuleStatus
from backend.shared_state import historical_scans_db # Import historical_scans_db

# Configure logging
logger = logging.getLogger(__name__)

# Dictionary to hold active WebSocket connections, keyed by scan ID.
# Using a set to store multiple connections for a single scan ID, although typically one per user session.
active_connections: Dict[str, set[WebSocket]] = {}

# WebSocket configuration
WEBSOCKET_TIMEOUT = 60  # seconds
WEBSOCKET_PING_INTERVAL = 30  # seconds
WEBSOCKET_PING_TIMEOUT = 10  # seconds

def recursive_url_to_str(data: Union[Dict, List, Any]) -> Union[Dict, List, Any]:
    logger.debug(f"recursive_url_to_str: Processing data of type {type(data)}")
    """
    Recursively converts Pydantic Url objects to strings within a dictionary or list.
    """
    if isinstance(data, dict):
        return {k: recursive_url_to_str(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [recursive_url_to_str(elem) for elem in data]
    elif isinstance(data, Url):
        logger.debug(f"recursive_url_to_str: Converting Url object: {data} (type: {type(data)}) to string.")
        return str(data) # Convert any Pydantic Url type to string
    return data

async def generate_scan_updates(scan_id: str):
    """
    Generates real-time scan updates for a given scan ID.

    Args:
        scan_id: The unique identifier for the scan.

    Yields:
        JSON strings representing scan progress, findings, metadata, or module status.
    """
    # This function is primarily for SSE. For WebSockets, we'll manage connections directly.
    # In a real application, this would pull updates from a shared state or message queue
    # associated with the scan_id.
    # For now, this function serves as a placeholder to show the structure.
    while True:
        # Replace with logic to wait for and yield real updates
        import asyncio
        await asyncio.sleep(1) # Example: wait for 1 second before checking for updates

async def send_module_status_update(scan_id: str, module_status: ModuleStatus):
    await send_realtime_update(scan_id, "module_status", module_status.model_dump())

async def send_progress_update(scan_id: str, progress_data: Dict[str, Any]):
    # Defensive: ensure modules is a dict of dicts with required fields
    modules = progress_data.get('modules', {})
    for module_id, m in modules.items():
        m['id'] = module_id
        m.setdefault('status', 'pending')
        m.setdefault('progress', 0)
        m.setdefault('lastRun', None)
        m.setdefault('findingsCount', 0)
    progress_data['modules'] = modules
    await send_realtime_update(scan_id, "scan_progress", progress_data)

async def send_new_finding(scan_id: str, finding_data: Dict[str, Any]):
    await send_realtime_update(scan_id, "new_finding", finding_data)

# WebSocket endpoint for real-time updates
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    try:
        await websocket.accept()
        
        # Set timeouts
        # websocket.client.timeout = WEBSOCKET_TIMEOUT
        # websocket.client.ping_interval = WEBSOCKET_PING_INTERVAL
        # websocket.client.ping_timeout = WEBSOCKET_PING_TIMEOUT

        if scan_id not in active_connections:
            active_connections[scan_id] = set()
        active_connections[scan_id].add(websocket)
        logger.info(f"WebSocket connected for scan_id: {scan_id}")

        # Send initial connection success message
        await websocket.send_json({
            "type": "connection_status",
            "data": {"status": "connected", "scan_id": scan_id}
        })
        # Send the current actual scan status from historical_scans_db
        current_scan_summary = next((s for s in historical_scans_db if s.scan_id == scan_id), None)
        if current_scan_summary:
            await websocket.send_json({
                "type": "status",
                "data": current_scan_summary.status
            })

        try:
            while True:
                # Keep connection alive with ping/pong
                await asyncio.sleep(WEBSOCKET_PING_INTERVAL)
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception as e:
                    logger.error(f"Failed to send ping to WebSocket for scan_id {scan_id}: {e}")
                    break
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected for scan_id: {scan_id}")
        except Exception as e:
            logger.error(f"WebSocket error for scan_id {scan_id}: {e}")
            await websocket.send_json({
                "type": "error",
                "data": {"message": "Internal server error"}
            })
        finally:
            if scan_id in active_connections:
                active_connections[scan_id].discard(websocket)
                if not active_connections[scan_id]:
                    del active_connections[scan_id]
                    logger.info(f"Removed scan_id {scan_id} from active connections")
    except Exception as e:
        logger.error(f"Error in websocket_endpoint for scan_id {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="WebSocket connection failed")

async def send_realtime_update(scan_id: str, update_type: str, data: Any):
    """
    Sends a real-time update to the WebSocket connection for a given scan ID.
    """
    logger.info(f"Sending WebSocket update for scan_id: {scan_id}, type: {update_type}")
    
    if scan_id not in active_connections or not active_connections[scan_id]:
        logger.warning(f"No active WebSocket connections for scan_id: {scan_id} when trying to send {update_type} update.")
        return

    message = {
        "type": update_type,
        "data": data
    }
    
    logger.debug(f"Preparing to send message: {message} for scan_id {scan_id}, type {update_type}. Active connections for this ID: {len(active_connections[scan_id])}")
    disconnected_websockets = set()

    for websocket in active_connections[scan_id]:
        try:
            await websocket.send_json(message)
            logger.debug(f"Successfully sent WebSocket update for scan_id: {scan_id}, type: {update_type}")
        except Exception as e:
            logger.error(f"Error sending WebSocket message for scan_id {scan_id}, type {update_type}: {e}")
            disconnected_websockets.add(websocket)

    # Clean up disconnected websockets
    for websocket in disconnected_websockets:
        active_connections[scan_id].discard(websocket)
        if not active_connections[scan_id]:
            del active_connections[scan_id]
            logger.info(f"Removed scan_id {scan_id} from active connections due to disconnections after trying to send {update_type} update.")

router = APIRouter()

@router.websocket("/scans/{scan_id}/realtime")
async def websocket_route(websocket: WebSocket, scan_id: str):
    await websocket_endpoint(websocket, scan_id) 