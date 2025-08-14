import pytest
import asyncio

from backend.utils.enrichment import EnrichmentService


@pytest.mark.asyncio
async def test_enrichment_uses_nvd_for_osv_aliases(monkeypatch):
    es = EnrichmentService()

    # Stub NVD fetch to return a CVSS
    async def fake_fetch_nvd(cve):
        return {"cvss": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "references": []}

    monkeypatch.setattr(es, "_fetch_nvd_by_cve", fake_fetch_nvd)

    finding = {
        "type": "vulnerability",
        "title": "OSV alias CVE",
        "description": "",
        "classifier": {"aliases": ["CVE-2021-12345"]}
    }

    enriched = await es.enrich_finding(finding)
    assert enriched.get("cvss") == 7.5


