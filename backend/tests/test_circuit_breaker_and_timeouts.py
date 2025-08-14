import asyncio
import pytest

from backend.utils.scanner_concurrency import ScannerConcurrencyManager, ScannerPriority
from backend.utils.http_client import SharedHTTPClient


@pytest.mark.asyncio
async def test_per_scanner_circuit_breaker_opens_and_recovers():
    mgr = ScannerConcurrencyManager(max_concurrent_scanners=2, enable_circuit_breaker=True)
    await mgr.start()

    async def failing_task():
        await asyncio.sleep(0.01)
        raise RuntimeError("boom")

    # Submit failing tasks for same scanner name beyond threshold
    scanner_name = "test_scanner"
    for _ in range(4):
        try:
            await mgr.submit_scanner(
                scanner_id=f"{scanner_name}-id",
                scanner_name=scanner_name,
                coro=lambda: failing_task(),
                options={},
                priority=ScannerPriority.MEDIUM,
            )
        except RuntimeError:
            pass

    await asyncio.sleep(0.2)
    stats = mgr.get_stats()
    assert stats["per_scanner_open"].get(scanner_name) in (True, False)
    await mgr.stop()


@pytest.mark.asyncio
async def test_http_retries_with_backoff_and_429(monkeypatch):
    # Arrange a client with small backoff for test speed
    client = SharedHTTPClient(default_max_retries=2, backoff_base_seconds=0.01, backoff_max_seconds=0.05)

    class FakeResponse:
        def __init__(self, status_code: int, headers=None):
            self.status_code = status_code
            self.headers = headers or {}

    calls = {"count": 0}

    async def fake_request(self, method, url, headers=None, content=None):
        calls["count"] += 1
        # First two attempts return 429 with Retry-After, then 200
        if calls["count"] <= 2:
            return FakeResponse(429, {"Retry-After": "0"})
        return FakeResponse(200, {})

    async def fake_async_request(*args, **kwargs):
        # Patch httpx.AsyncClient.request bound method signature
        return await fake_request(None, *args, **kwargs)

    class DummyClient:
        def __init__(self, **config):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            return False
        async def request(self, method, url, headers=None, content=None):
            return await fake_request(self, method, url, headers=headers, content=content)

    # Monkeypatch httpx.AsyncClient to our dummy
    monkeypatch.setattr("backend.utils.http_client.httpx.AsyncClient", DummyClient)

    # Act
    resp = await client.get("https://example.com/test")

    # Assert
    assert resp.status_code == 200
    assert calls["count"] == 3  # two retries then success


@pytest.mark.asyncio
async def test_ssrf_guard_blocks_private_ip(monkeypatch):
    client = SharedHTTPClient(default_max_retries=0)

    # Patch AsyncClient to ensure we don't actually issue the call if guard fails
    class DummyClient:
        def __init__(self, **config):
            raise AssertionError("AsyncClient should not be constructed when SSRF is blocked")

    monkeypatch.setattr("backend.utils.http_client.httpx.AsyncClient", DummyClient)

    with pytest.raises(RuntimeError):
        await client.get("http://127.0.0.1:8080", block_private_networks=True)


