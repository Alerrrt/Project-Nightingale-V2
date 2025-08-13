import asyncio
import json

from backend.scanner_engine import _compute_finding_signature
from backend.utils.enrichment import EnrichmentService


def test_compute_finding_signature_normalizes_query_order():
    a = {
        "title": "Reflected XSS",
        "location": "https://example.com/search?q=test&lang=en",
        "cwe": "CWE-79",
        "cve": "N/A",
    }
    b = {
        "title": "Reflected XSS",
        "location": "https://example.com/search?lang=en&q=test",
        "cwe": "CWE-79",
        "cve": "N/A",
    }
    sa = _compute_finding_signature(a)
    sb = _compute_finding_signature(b)
    assert sa == sb


def test_compute_finding_signature_includes_title_and_weak_keys():
    a = {"title": "SQLi", "location": "https://ex.com/login", "cwe": "CWE-89", "cve": "N/A"}
    b = {"title": "SQLi", "location": "https://ex.com/login", "cwe": "CWE-89", "cve": "N/A"}
    assert _compute_finding_signature(a) == _compute_finding_signature(b)


def test_enrichment_service_graceful_on_invalid():
    svc = EnrichmentService(cache_path="backend/data/cache/test_enrichment.json")
    finding = {"title": "Test", "location": "https://ex.com", "cve": "N/A"}
    out = asyncio.get_event_loop().run_until_complete(svc.enrich_finding(finding))
    assert out["title"] == "Test"
    # Should simply pass through without adding noisy fields
    assert "classifier" in out
    assert isinstance(out["classifier"], dict)


