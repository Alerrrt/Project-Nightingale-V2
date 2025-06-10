import pytest
from httpx import AsyncClient
import json

@pytest.mark.asyncio
async def test_create_scan(async_client, auth_headers):
    scan_data = {
        "name": "Test Scan",
        "target_url": "http://example.com",
        "modules": ["sqli", "xss"]
    }
    
    response = await async_client.post(
        "/scans/",
        json=scan_data,
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == scan_data["name"]
    assert data["target_url"] == scan_data["target_url"]
    assert "id" in data
    return data["id"]

@pytest.mark.asyncio
async def test_get_scan(async_client, auth_headers):
    # First create a scan
    scan_id = await test_create_scan(async_client, auth_headers)
    
    # Then get the scan
    response = await async_client.get(
        f"/scans/{scan_id}",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == scan_id
    assert data["name"] == "Test Scan"

@pytest.mark.asyncio
async def test_list_scans(async_client, auth_headers):
    # Create multiple scans
    await test_create_scan(async_client, auth_headers)
    await test_create_scan(async_client, auth_headers)
    
    response = await async_client.get(
        "/scans/",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2
    assert all("id" in scan for scan in data)

@pytest.mark.asyncio
async def test_get_scan_not_found(async_client, auth_headers):
    response = await async_client.get(
        "/scans/nonexistent-id",
        headers=auth_headers
    )
    
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_create_scan_unauthorized(async_client):
    scan_data = {
        "name": "Test Scan",
        "target_url": "http://example.com",
        "modules": ["sqli"]
    }
    
    response = await async_client.post(
        "/scans/",
        json=scan_data
    )
    
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_get_scan_unauthorized(async_client):
    response = await async_client.get("/scans/some-id")
    assert response.status_code == 401 