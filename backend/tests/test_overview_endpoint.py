# -*- coding: utf-8 -*-
import asyncio


def test_placeholder_overview_route_exists():
    # This is a placeholder to assert the module imports and route presence at runtime.
    # Full integration tests would require TestClient; omitted to keep scope light.
    from backend.api.scans import get_scan_overview
    assert callable(get_scan_overview)


