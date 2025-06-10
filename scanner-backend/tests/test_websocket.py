import pytest
import asyncio
import json
from fastapi.testclient import TestClient
from app.broadcast import broadcast_manager
from app.tasks import scan_task

@pytest.mark.asyncio
async def test_websocket_connection(client, auth_headers):
    with client.websocket_connect(
        f"/ws/scans/test-scan-id",
        headers=auth_headers
    ) as websocket:
        # Connection should be established
        assert websocket.client is not None

@pytest.mark.asyncio
async def test_websocket_unauthorized(client):
    with pytest.raises(Exception):  # Should fail without auth
        with client.websocket_connect("/ws/scans/test-scan-id") as websocket:
            pass

@pytest.mark.asyncio
async def test_websocket_celery_task_start(client, auth_headers):
    scan_id = "test-scan-id"
    
    with client.websocket_connect(
        f"/ws/scans/{scan_id}",
        headers=auth_headers
    ) as websocket:
        # Simulate Celery task start event
        task_start_event = {
            "type": "task-started",
            "task_id": scan_id,
            "task": "app.tasks.scan_task",
            "args": [scan_id],
            "kwargs": {},
            "timestamp": 1234567890.0
        }
        
        # Broadcast the task start event
        await broadcast_manager.broadcast(scan_id, task_start_event)
        
        # Wait for and verify the message
        data = websocket.receive_json()
        assert data["type"] == "task-started"
        assert data["task_id"] == scan_id
        assert data["task"] == "app.tasks.scan_task"

@pytest.mark.asyncio
async def test_websocket_celery_task_progress(client, auth_headers):
    scan_id = "test-scan-id"
    
    with client.websocket_connect(
        f"/ws/scans/{scan_id}",
        headers=auth_headers
    ) as websocket:
        # Simulate Celery task progress event
        progress_event = {
            "type": "task-progress",
            "task_id": scan_id,
            "current": 50,
            "total": 100,
            "status": "Processing module: sqli",
            "timestamp": 1234567890.0
        }
        
        # Broadcast the progress event
        await broadcast_manager.broadcast(scan_id, progress_event)
        
        # Wait for and verify the message
        data = websocket.receive_json()
        assert data["type"] == "task-progress"
        assert data["task_id"] == scan_id
        assert data["current"] == 50
        assert data["total"] == 100
        assert "status" in data

@pytest.mark.asyncio
async def test_websocket_celery_task_success(client, auth_headers):
    scan_id = "test-scan-id"
    
    with client.websocket_connect(
        f"/ws/scans/{scan_id}",
        headers=auth_headers
    ) as websocket:
        # Simulate Celery task success event
        success_event = {
            "type": "task-success",
            "task_id": scan_id,
            "result": {
                "status": "completed",
                "findings": [
                    {
                        "type": "sql_injection",
                        "severity": "high",
                        "location": "/search?q=1' OR '1'='1"
                    }
                ]
            },
            "timestamp": 1234567890.0
        }
        
        # Broadcast the success event
        await broadcast_manager.broadcast(scan_id, success_event)
        
        # Wait for and verify the message
        data = websocket.receive_json()
        assert data["type"] == "task-success"
        assert data["task_id"] == scan_id
        assert data["result"]["status"] == "completed"
        assert len(data["result"]["findings"]) > 0

@pytest.mark.asyncio
async def test_websocket_celery_task_failure(client, auth_headers):
    scan_id = "test-scan-id"
    
    with client.websocket_connect(
        f"/ws/scans/{scan_id}",
        headers=auth_headers
    ) as websocket:
        # Simulate Celery task failure event
        failure_event = {
            "type": "task-failure",
            "task_id": scan_id,
            "exception": "ConnectionError",
            "traceback": "Traceback (most recent call last):...",
            "timestamp": 1234567890.0
        }
        
        # Broadcast the failure event
        await broadcast_manager.broadcast(scan_id, failure_event)
        
        # Wait for and verify the message
        data = websocket.receive_json()
        assert data["type"] == "task-failure"
        assert data["task_id"] == scan_id
        assert data["exception"] == "ConnectionError"
        assert "traceback" in data

@pytest.mark.asyncio
async def test_websocket_celery_task_sequence(client, auth_headers):
    scan_id = "test-scan-id"
    
    with client.websocket_connect(
        f"/ws/scans/{scan_id}",
        headers=auth_headers
    ) as websocket:
        # Simulate a sequence of Celery events
        events = [
            {
                "type": "task-started",
                "task_id": scan_id,
                "task": "app.tasks.scan_task",
                "timestamp": 1234567890.0
            },
            {
                "type": "task-progress",
                "task_id": scan_id,
                "current": 25,
                "total": 100,
                "status": "Starting scan",
                "timestamp": 1234567891.0
            },
            {
                "type": "task-progress",
                "task_id": scan_id,
                "current": 50,
                "total": 100,
                "status": "Processing module: sqli",
                "timestamp": 1234567892.0
            },
            {
                "type": "task-success",
                "task_id": scan_id,
                "result": {"status": "completed"},
                "timestamp": 1234567893.0
            }
        ]
        
        # Broadcast each event in sequence
        for event in events:
            await broadcast_manager.broadcast(scan_id, event)
            data = websocket.receive_json()
            assert data["type"] == event["type"]
            assert data["task_id"] == scan_id

@pytest.mark.asyncio
async def test_websocket_scan_update(client, auth_headers):
    scan_id = "test-scan-id"
    
    with client.websocket_connect(
        f"/ws/scans/{scan_id}",
        headers=auth_headers
    ) as websocket:
        # Simulate a scan update event
        update_data = {
            "type": "scan_update",
            "scan_id": scan_id,
            "status": "in_progress",
            "progress": 50
        }
        
        # Broadcast the update
        await broadcast_manager.broadcast(scan_id, update_data)
        
        # Wait for and verify the message
        data = websocket.receive_json()
        assert data["type"] == "scan_update"
        assert data["scan_id"] == scan_id
        assert data["status"] == "in_progress"
        assert data["progress"] == 50

@pytest.mark.asyncio
async def test_websocket_detection_update(client, auth_headers):
    scan_id = "test-scan-id"
    
    with client.websocket_connect(
        f"/ws/scans/{scan_id}",
        headers=auth_headers
    ) as websocket:
        # Simulate a detection event
        detection_data = {
            "type": "detection",
            "scan_id": scan_id,
            "detection": {
                "type": "sql_injection",
                "severity": "high",
                "location": "/search?q=1' OR '1'='1"
            }
        }
        
        # Broadcast the detection
        await broadcast_manager.broadcast(scan_id, detection_data)
        
        # Wait for and verify the message
        data = websocket.receive_json()
        assert data["type"] == "detection"
        assert data["scan_id"] == scan_id
        assert data["detection"]["type"] == "sql_injection"
        assert data["detection"]["severity"] == "high"

@pytest.mark.asyncio
async def test_websocket_multiple_clients(client, auth_headers):
    scan_id = "test-scan-id"
    
    # Connect two clients
    with client.websocket_connect(
        f"/ws/scans/{scan_id}",
        headers=auth_headers
    ) as websocket1, client.websocket_connect(
        f"/ws/scans/{scan_id}",
        headers=auth_headers
    ) as websocket2:
        # Simulate an update
        update_data = {
            "type": "scan_update",
            "scan_id": scan_id,
            "status": "completed"
        }
        
        # Broadcast the update
        await broadcast_manager.broadcast(scan_id, update_data)
        
        # Both clients should receive the message
        data1 = websocket1.receive_json()
        data2 = websocket2.receive_json()
        
        assert data1 == data2
        assert data1["type"] == "scan_update"
        assert data1["status"] == "completed" 