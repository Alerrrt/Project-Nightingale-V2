from typing import Dict, Set, Any
import json
from datetime import datetime
from fastapi import WebSocket

class BroadcastManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: str, event: dict):
        if scan_id not in self.active_connections:
            return
        message = json.dumps(event)
        for websocket in list(self.active_connections[scan_id]):
            try:
                await websocket.send_text(message)
            except Exception:
                self.disconnect(websocket, scan_id)

    async def broadcast_scan_event(self, scan_id: str, event: dict) -> None:
        event["timestamp"] = datetime.utcnow().isoformat()
        await self.broadcast(scan_id, event)

broadcast_manager = BroadcastManager() 