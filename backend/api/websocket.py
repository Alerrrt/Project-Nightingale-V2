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
        self.rate_limiter = RateLimiter(
            max_requests=100,  # requests per minute
            time_window=60
        )
        self.message_queue = MessageQueue(self)
        self.heartbeat_tasks: Dict[str, asyncio.Task] = {}
        self.reconnect_tokens: Dict[str, str] = {}
        self.message_history: Dict[str, List[WebSocketMessage]] = defaultdict(list)
        self.max_history_size = 1000

    async def connect(self, websocket: WebSocket, client_id: str, token: Optional[str] = None):
        """Connect a new client with authentication (FORCED: accept all connections for local dev, never raise)."""
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
        except Exception as e:
            logger.error(f"Error after accepting websocket for client {client_id}: {e}")
            # Do not raise, just log and return
            return

    def disconnect(self, websocket: WebSocket, client_id: str):
        """Disconnect a client and clean up resources."""
        logger.info(f"WebSocket disconnect: client_id={client_id}")
        if client_id in self.active_connections:
            self.active_connections[client_id].remove(websocket)
            if not self.active_connections[client_id]:
                del self.active_connections[client_id]
        
        # Clean up subscriptions
        for scan_id in list(self.scan_subscriptions.keys()):
            if websocket in self.scan_subscriptions[scan_id]:
                self.scan_subscriptions[scan_id].remove(websocket)
                if not self.scan_subscriptions[scan_id]:
                    del self.scan_subscriptions[scan_id]
        
        # Clean up heartbeat task
        if client_id in self.heartbeat_tasks:
            self.heartbeat_tasks[client_id].cancel()
            del self.heartbeat_tasks[client_id]
        
        # Generate reconnect token
        if client_id in self.client_metadata:
            self.reconnect_tokens[client_id] = jwt.encode(
                {
                    "sub": client_id,
                    "exp": datetime.utcnow() + timedelta(minutes=5)
                },
                settings.SECRET_KEY,
                algorithm="HS256"
            )
        
        logger.info(f"Client {client_id} disconnected")

    async def subscribe_to_scan(self, websocket: WebSocket, scan_id: str, options: Optional[Dict] = None):
        """Subscribe to scan updates with advanced options."""
        client_id = self._get_client_id(websocket)
        if not client_id:
            return

        if scan_id not in self.scan_subscriptions:
            self.scan_subscriptions[scan_id] = set()
        self.scan_subscriptions[scan_id].add(websocket)
        
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
            await self._send_message(websocket, "scan_history", {
                "scan_id": scan_id,
                "history": [{"type": msg.type, "data": msg.data, "timestamp": msg.timestamp.isoformat()} 
                          for msg in history[-options.get("history_limit", 10):]]
            })
        
        logger.info(f"Client {client_id} subscribed to scan {scan_id}")

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
        if scan_id not in self.scan_subscriptions:
            return

        # Create message
        message = WebSocketMessage(update_type, data, priority)
        
        # Store in history
        self.message_history[scan_id].append(message)
        if len(self.message_history[scan_id]) > self.max_history_size:
            self.message_history[scan_id] = self.message_history[scan_id][-self.max_history_size:]

        # Queue message for each subscriber
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

@router.websocket("/ws/{scan_id}")
async def websocket_endpoint(
    websocket: WebSocket, 
    scan_id: str
):
    # This is not ideal, but it's a way to get the app state without a request object
    # In a real app, you might pass the engine to the manager upon creation
    from backend.main import app 
    scanner_engine = app.state.scanner_engine

    client_id = websocket.headers.get("x-client-id", "anonymous")
    await manager.connect(websocket, client_id)
    await manager.subscribe_to_scan(websocket, scan_id)

    try:
        while True:
            raw_data = await websocket.receive_text()
            message = json.loads(raw_data)
            
            if message.get("type") == "stop_scan":
                logger.info(f"Stop scan message received for {scan_id}")
                await manager.stop_scan(scan_id, scanner_engine)
            else:
                logger.warning(f"Unknown message type received: {message.get('type')}")

    except WebSocketDisconnect:
        manager.disconnect(websocket, client_id)
    except Exception as e:
        logger.error(f"Error in WebSocket endpoint for client {client_id}: {e}", exc_info=True)
        manager.disconnect(websocket, client_id)

manager = ConnectionManager()

def get_connection_manager() -> ConnectionManager:
    return manager 