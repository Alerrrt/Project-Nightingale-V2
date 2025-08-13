# -*- coding: utf-8 -*-
import asyncio
import json

from backend.utils.secrets import scan_text_for_secrets
from backend.utils.enrichment import EnrichmentService


def test_secret_patterns_basic():
    text = """
    const k1 = "AKIAABCDEFGHIJKLMNOP";
    const gkey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
    // not a real key
    """
    found = scan_text_for_secrets(text)
    names = {f["name"] for f in found}
    assert "AWS Access Key ID" in names
    assert "Google API Key" in names


def test_enrichment_nvd_parse_graceful():
    # Use a fake CVE value that won't resolve; ensure graceful
    svc = EnrichmentService(cache_path="backend/data/cache/test_enrichment.json")
    base = {"title": "Tech vuln", "location": "https://ex/", "cve": "CVE-0000-0000"}
    out = asyncio.get_event_loop().run_until_complete(svc.enrich_finding(base))
    assert out.get("title") == "Tech vuln"
    assert "references" in out


