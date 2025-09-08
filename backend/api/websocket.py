from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from typing import Dict, Set, Optional, List, Any
import json
import logging
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict
import jwt
from backend.utils.logging_config import get_context_logger
from backend.utils.rate_limiter import RateLimiter
from backend.utils.message_queue import MessageQueue
from backend.config import settings
from backend.scanner_engine import ScannerEngine

logger = get_context_logger(__name__)

router = APIRouter()

class WebSocketMessage:
    def __init__(self, type: str, data: dict, priority: int = 0):
        self.type = type
        self.data = data
        self.priority = priority
        self.timestamp = datetime.now()

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.scan_subscriptions: Dict[str, Set[WebSocket]] = {}
        self.client_metadata: Dict[str, Dict] = {}
        from backend.config import settings
        self.rate_limiter = RateLimiter(
            max_requests=getattr(settings, 'WS_MAX_REQUESTS_PER_MINUTE', 100),
            time_window=getattr(settings, 'WS_TIME_WINDOW_SECONDS', 60)
        )
        self.message_queue = MessageQueue(self)
        self.heartbeat_tasks: Dict[str, asyncio.Task] = {}
        self.reconnect_tokens: Dict[str, str] = {}
        self.message_history: Dict[str, List[WebSocketMessage]] = defaultdict(list)
        # Allow larger history window to improve resilience
        self.max_history_size = 5000

    async def connect(self, websocket: WebSocket, client_id: str = None, token: Optional[str] = None):
        """Connect a new client with authentication (FORCED: accept all connections for local dev, never raise)."""
        # Generate UUID for client_id if not provided
        if not client_id or client_id == "anonymous":
            import uuid
            client_id = str(uuid.uuid4())
            logger.info(f"Generated new client_id: {client_id}")
            
        logger.info(f"WebSocket connection attempt: client_id={client_id}, token_present={bool(token)}")
        # Log remote address if possible
        if hasattr(websocket, 'client') and websocket.client:
            logger.info(f"WebSocket remote address: {websocket.client}")
        # FORCED: Bypass token validation for local development
        try:
            await websocket.accept()
        except Exception as e:
            logger.error(f"Error accepting websocket for client {client_id}: {e}")
            return
        try:
            if client_id not in self.active_connections:
                self.active_connections[client_id] = set()
            self.active_connections[client_id].add(websocket)
            # Initialize client metadata
            self.client_metadata[client_id] = {
                "connected_at": datetime.now(),
                "last_activity": datetime.now(),
                "subscriptions": set(),
                "message_count": 0,
                "reconnect_count": 0
            }
            # Start heartbeat
            self.heartbeat_tasks[client_id] = asyncio.create_task(
                self._heartbeat(client_id, websocket)
            )
            logger.info(f"Client {client_id} connected")
            # Send connection acknowledgment
            await self._send_message(websocket, "connection_established", {
                "client_id": client_id,
                "timestamp": datetime.now().isoformat()
            })
            return client_id
        except Exception as e:
            logger.error(f"Error after accepting websocket for client {client_id}: {e}")
            # Do not raise, just log and return
            return client_id

    def disconnect(self, websocket: WebSocket, client_id: str = None):
        """Disconnect a client and clean up resources."""
        # Find client_id if not provided
        if client_id is None:
            for cid, connections in self.active_connections.items():
                if websocket in connections:
                    client_id = cid
                    break
        
        if client_id is None:
            logger.warning(f"Could not find client_id for disconnecting WebSocket")
            return
            
        logger.info(f"WebSocket disconnect: client_id={client_id}")
        if client_id in self.active_connections:
            self.active_connections[client_id].remove(websocket)
            if not self.active_connections[client_id]:
                del self.active_connections[client_id]
        
        # Clean up subscriptions but don't remove scan data
        for scan_id in list(self.scan_subscriptions.keys()):
            if websocket in self.scan_subscriptions[scan_id]:
                self.scan_subscriptions[scan_id].remove(websocket)
                if not self.scan_subscriptions[scan_id]:
                    del self.scan_subscriptions[scan_id]
        
        # Clean up heartbeat task
        if client_id in self.heartbeat_tasks:
            self.heartbeat_tasks[client_id].cancel()
            del self.heartbeat_tasks[client_id]
        
        # Generate reconnect token with longer expiration for scan completion
        if client_id in self.client_metadata:
            # Keep connection alive longer for active scans
            expiration_minutes = 15 if self._has_active_scans(client_id) else 5
            self.reconnect_tokens[client_id] = jwt.encode(
                {
                    "sub": client_id,
                    "exp": datetime.utcnow() + timedelta(minutes=expiration_minutes)
                },
                settings.SECRET_KEY,
                algorithm="HS256"
            )
        
        logger.info(f"Client {client_id} disconnected")
    
    def _has_active_scans(self, client_id: str) -> bool:
        """Check if client has active scan subscriptions."""
        if client_id not in self.client_metadata:
            return False
        return len(self.client_metadata[client_id]["subscriptions"]) > 0

    async def subscribe_to_scan(self, websocket: WebSocket, scan_id: str, options: Optional[Dict] = None):
        """Subscribe to scan updates with advanced options."""
        client_id = self._get_client_id(websocket)
        if not client_id:
            return

        logger.info(f"Subscribing client {client_id} to scan updates for scan_id: {scan_id}")
        
        if scan_id not in self.scan_subscriptions:
            logger.info(f"Creating new subscription set for scan_id: {scan_id}")
            self.scan_subscriptions[scan_id] = set()
        self.scan_subscriptions[scan_id].add(websocket)
        logger.info(f"Client {client_id} subscribed to scan_id: {scan_id}. Total subscribers: {len(self.scan_subscriptions[scan_id])}")
        
        # Update client metadata
        self.client_metadata[client_id]["subscriptions"].add(scan_id)
        
        # Store subscription options
        if options:
            self.client_metadata[client_id]["subscription_options"] = options
        
        # Send subscription acknowledgment
        await self._send_message(websocket, "subscription_established", {
            "scan_id": scan_id,
            "options": options,
            "timestamp": datetime.now().isoformat()
        })
        
        # Send recent history if requested
        if options and options.get("include_history", False):
            history = self.message_history.get(scan_id, [])
            history_limit = options.get("history_limit", 25)
            logger.info(f"Sending {min(len(history), history_limit)} history messages for scan_id: {scan_id}")
            # Replay recent history as individual messages so existing frontend handlers process them
            for msg in history[-history_limit:]:
                try:
                    await self._send_message(websocket, msg.type, msg.data)
                    logger.debug(f"Sent history message of type {msg.type} for scan_id: {scan_id}")
                except Exception as e:
                    logger.error(f"Failed to send history message: {e}")
        else:
            logger.info(f"No history requested for scan_id: {scan_id}")
        
        logger.info(f"Client {client_id} subscribed to scan {scan_id}")
        logger.info(f"Subscription complete for scan_id: {scan_id}")

    async def unsubscribe_from_scan(self, websocket: WebSocket, scan_id: str):
        """Unsubscribe from scan updates."""
        client_id = self._get_client_id(websocket)
        if not client_id:
            return

        if scan_id in self.scan_subscriptions:
            self.scan_subscriptions[scan_id].remove(websocket)
            if not self.scan_subscriptions[scan_id]:
                del self.scan_subscriptions[scan_id]
        
        # Update client metadata
        if client_id in self.client_metadata:
            self.client_metadata[client_id]["subscriptions"].discard(scan_id)
        
        await self._send_message(websocket, "subscription_removed", {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat()
        })
        
        logger.info(f"Client {client_id} unsubscribed from scan {scan_id}")

    async def broadcast_to_client(self, client_id: str, update_type: str, data: dict):
        """Send an update to a specific client."""
        if client_id not in self.active_connections:
            return

        for websocket in self.active_connections[client_id]:
            await self._send_message(websocket, update_type, data)

    async def broadcast_scan_update(self, scan_id: str, update_type: str, data: dict, priority: int = 0):
        """Broadcast scan updates with priority queuing."""
        logger.info(f"Broadcasting {update_type} update for scan {scan_id}")
        
        # Always retain history even if no active subscribers yet
        if scan_id not in self.scan_subscriptions:
            logger.info(f"No subscribers currently for scan {scan_id}; storing history and waiting for clients")

        # Create message
        message = WebSocketMessage(update_type, data, priority)
        
        # Store in history
        self.message_history[scan_id].append(message)
        if len(self.message_history[scan_id]) > self.max_history_size:
            self.message_history[scan_id] = self.message_history[scan_id][-self.max_history_size:]

        # Send immediately to all subscribers for critical updates
        if update_type in ["scan_progress", "scan_phase", "new_finding", "module_status"]:
            subscribers = self.scan_subscriptions.get(scan_id, set())
            logger.info(f"Sending {update_type} to {len(subscribers)} subscribers for scan {scan_id}")
            
            for websocket in subscribers:
                try:
                    await self._send_message(websocket, update_type, data)
                    logger.debug(f"Successfully sent {update_type} to subscriber for scan {scan_id}")
                except Exception as e:
                    logger.warning(f"Failed to send {update_type} to subscriber: {e}")
                    # Remove failed websocket
                    self.scan_subscriptions[scan_id].discard(websocket)
        else:
            # Queue other messages for each subscriber
            for websocket in self.scan_subscriptions.get(scan_id, set()):
                client_id = self._get_client_id(websocket)
                if client_id and self.rate_limiter.check_rate_limit(client_id):
                    await self.message_queue.enqueue(
                        client_id,
                        message,
                        self.client_metadata[client_id].get("subscription_options", {})
                    )

    async def stop_scan(self, scan_id: str, scanner_engine: "ScannerEngine"):
        """Stop a running scan."""
        logger.info(f"Received stop request for scan: {scan_id}")
        await scanner_engine.cancel_scan(scan_id)
        # Optionally broadcast a confirmation message
        await self.broadcast_scan_update(
            scan_id, "scan_cancelled", {"scan_id": scan_id}
        )

    async def handle_scan_completion(self, scan_id: str, results: Dict):
        """Handle scan completion and ensure results are delivered to all subscribers."""
        logger.info(f"Handling scan completion for {scan_id}")
        
        # Get all subscribers for this scan
        subscribers = self.scan_subscriptions.get(scan_id, set()).copy()
        
        # Send completion message to all subscribers
        for websocket in subscribers:
            try:
                await self._send_message(websocket, "scan_completed", results)
                
                # Send a follow-up message to keep connection alive
                await asyncio.sleep(0.1)
                await self._send_message(websocket, "scan_results_ready", {
                    "scan_id": scan_id,
                    "message": "All vulnerability results have been processed and are ready for review",
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Failed to send completion message to subscriber: {e}")
                # Remove failed websocket from subscriptions
                if scan_id in self.scan_subscriptions:
                    self.scan_subscriptions[scan_id].discard(websocket)
        
        # Keep scan data available for a while after completion
        # This allows reconnecting clients to get results
        await asyncio.sleep(30)  # Keep data for 30 seconds after completion
        
        # Clean up scan subscriptions
        if scan_id in self.scan_subscriptions:
            del self.scan_subscriptions[scan_id]

    async def _heartbeat(self, client_id: str, websocket: WebSocket):
        """Maintain connection with heartbeat messages."""
        try:
            while True:
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
                if client_id in self.active_connections and websocket in self.active_connections[client_id]:
                    await self._send_message(websocket, "heartbeat", {
                        "timestamp": datetime.now().isoformat()
                    })
                    self.client_metadata[client_id]["last_activity"] = datetime.now()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in heartbeat for client {client_id}: {e}")

    async def _send_message(self, websocket: WebSocket, type: str, data: dict):
        """Send a message to a specific client."""
        try:
            message = {
                "type": type,
                "timestamp": datetime.now().isoformat(),
                "data": data
            }
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending message to client: {e}")

    def _get_client_id(self, websocket: WebSocket) -> Optional[str]:
        """Get client ID from websocket connection."""
        for client_id, connections in self.active_connections.items():
            if websocket in connections:
                return client_id
        return None

    async def get_client_status(self, client_id: str) -> Dict:
        """Get detailed status for a client."""
        if client_id not in self.client_metadata:
            return {"status": "not_found"}
        
        metadata = self.client_metadata[client_id]
        return {
            "status": "active" if client_id in self.active_connections else "inactive",
            "connected_at": metadata["connected_at"].isoformat(),
            "last_activity": metadata["last_activity"].isoformat(),
            "subscriptions": list(metadata["subscriptions"]),
            "message_count": metadata["message_count"],
            "reconnect_count": metadata["reconnect_count"]
        }

    async def get_scan_subscribers(self, scan_id: str) -> List[Dict]:
        """Get list of subscribers for a scan."""
        if scan_id not in self.scan_subscriptions:
            return []
        
        subscribers = []
        for websocket in self.scan_subscriptions[scan_id]:
            client_id = self._get_client_id(websocket)
            if client_id:
                subscribers.append(await self.get_client_status(client_id))
        return subscribers

async def get_scanner_engine_from_state(request: Request) -> "ScannerEngine":
    return request.app.state.scanner_engine

# The frontend expects the WebSocket endpoint at /api/ws/{scan_id}
# Since the API router is mounted at /api, we need to register this at /ws/{scan_id}
@router.websocket("/ws/{scan_id}")
async def websocket_endpoint(
    websocket: WebSocket, 
    scan_id: str
):
    logger.info(f"WebSocket connection attempt for scan_id: {scan_id}")
    # Log the request headers to debug connection issues
    logger.info(f"WebSocket headers: {websocket.headers}")
    logger.info(f"WebSocket client host: {websocket.client.host if hasattr(websocket, 'client') and websocket.client else 'unknown'}")
    
    # This is not ideal, but it's a way to get the app state without a request object
    # In a real app, you might pass the engine to the manager upon creation
    from backend.main import app 
    scanner_engine = app.state.scanner_engine

    client_id = websocket.headers.get("x-client-id", "anonymous")
    logger.info(f"WebSocket client connecting with client_id: {client_id}")
    
    try:
        # The connection is handled in the manager.connect method
        # No need to call websocket.accept() here as it's done in the manager
        # connect() will return the client_id (which may be generated if not provided)
        client_id = await manager.connect(websocket, client_id) or client_id
        logger.info(f"WebSocket client {client_id} connected successfully")
        logger.info(f"Active WebSocket connections: {len(manager.active_connections)}")
        logger.info(f"Scan subscriptions: {list(manager.scan_subscriptions.keys())}")
        logger.info(f"WebSocket connection established for scan_id: {scan_id}")
        
        # Include recent history so the UI immediately sees initial progress/phase messages
        await manager.subscribe_to_scan(
            websocket,
            scan_id,
            options={"include_history": True, "history_limit": 50}
        )
        logger.info(f"WebSocket client {client_id} subscribed to scan {scan_id}")  
    except Exception as e:
        logger.error(f"Error during WebSocket connection/subscription: {e}", exc_info=True)
        # Ensure proper cleanup on connection error
        try:
            manager.disconnect(websocket, client_id)
        except Exception as cleanup_error:
            logger.error(f"Error during connection cleanup: {cleanup_error}")
        return

    try:
        # No need to send connection confirmation again as it's already sent in connect()
        # Try to send a live snapshot so the UI gets immediate numbers even if history is empty
        try:
            from backend.main import app as _app
            engine = _app.state.scanner_engine
            scan_data = await engine.get_scan_status(scan_id)
            # Compute modules summary
            total_modules = int(scan_data.get("total_modules") or len((scan_data.get("sub_scans") or {})))
            completed_modules = int(scan_data.get("completed_modules") or 0)
            progress = float(scan_data.get("progress") or 0.0)
            # Phase hint
            phase = "Running scanners…" if progress > 0 else "Initializing..."
            await manager._send_message(websocket, "scan_phase", {"phase": phase, "scan_id": scan_id})
            await manager._send_message(websocket, "scan_progress", {
                "progress": progress,
                "completed_modules": completed_modules,
                "total_modules": total_modules,
            })
            # Current target
            if scan_data.get("target"):
                await manager._send_message(websocket, "current_target_url", {"url": scan_data.get("target")})
        except Exception as e:
            logger.warning(f"Failed to send live snapshot for {scan_id}: {e}")
            # Send fallback initial state
            await manager._send_message(websocket, "scan_phase", {"phase": "Initializing...", "scan_id": scan_id})
            await manager._send_message(websocket, "scan_progress", {
                "progress": 0,
                "completed_modules": 0,
                "total_modules": 72,
            })
        
        # Keep connection alive until scan completes or client disconnects
        while True:
            try:
                # Wait for messages with a timeout to allow for graceful handling
                raw_data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
                message = json.loads(raw_data)
                
                if message.get("type") == "stop_scan":
                    logger.info(f"Stop scan message received for {scan_id}")
                    await manager.stop_scan(scan_id, scanner_engine)
                elif message.get("type") == "ping":
                    # Respond to ping with pong to keep connection alive
                    await manager._send_message(websocket, "pong", {
                        "timestamp": datetime.now().isoformat()
                    })
                else:
                    logger.warning(f"Unknown message type received: {message.get('type')}")
                    
            except asyncio.TimeoutError:
                # Send heartbeat to keep connection alive
                await manager._send_message(websocket, "heartbeat", {
                    "timestamp": datetime.now().isoformat()
                })
                continue

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for client {client_id} on scan {scan_id}")
        try:
            manager.disconnect(websocket, client_id)
            logger.info(f"Client {client_id} disconnected and cleaned up")
        except Exception as cleanup_error:
            logger.error(f"Error during disconnection cleanup: {cleanup_error}")
    except Exception as e:
        logger.error(f"Error in WebSocket endpoint for client {client_id}: {e}", exc_info=True)
        # Don't disconnect immediately, try to send error message first
        try:
            await manager._send_message(websocket, "error", {
                "message": "An error occurred",
                "timestamp": datetime.now().isoformat()
            })
        except Exception as msg_error:
            logger.error(f"Failed to send error message: {msg_error}")
        # Ensure connection is properly cleaned up
        try:
            manager.disconnect(websocket, client_id)
            logger.info(f"Cleaned up connection for client {client_id} after error")
        except Exception as cleanup_error:
            logger.error(f"Error during connection cleanup: {cleanup_error}")

manager = ConnectionManager()

def get_connection_manager() -> ConnectionManager:
    return manager
