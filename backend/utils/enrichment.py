from __future__ import annotations

import os
import json
import logging
from typing import Any, Dict, Optional, Tuple
from datetime import datetime, timedelta

import httpx

logger = logging.getLogger(__name__)


class EnrichmentService:
    """
    Best-effort enrichment using NVD (for CVE→CVSS) and OSV (for package vulns).
    Non-blocking philosophy: errors/timeouts are swallowed; returns original finding.
    Caches results to a JSON file with TTL.
    """

    def __init__(self, cache_path: Optional[str] = None, ttl_days: int = 7, request_timeout_s: float = 4.0):
        self.cache_path = cache_path or os.path.join("backend", "data", "cache", "enrichment.json")
        self.ttl = timedelta(days=ttl_days)
        self.timeout = request_timeout_s
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            if os.path.exists(self.cache_path):
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
        except Exception:
            self._cache = {}

    def _save_cache(self) -> None:
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._cache, f)
        except Exception:
            pass

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        rec = self._cache.get(key)
        if not rec:
            return None
        try:
            ts = datetime.fromisoformat(rec.get("_ts"))
            if datetime.utcnow() - ts > self.ttl:
                return None
            return rec.get("data")
        except Exception:
            return None

    def _cache_set(self, key: str, data: Dict[str, Any]) -> None:
        self._cache[key] = {"_ts": datetime.utcnow().isoformat(), "data": data}
        self._save_cache()

    async def _fetch_nvd_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        cache_key = f"nvd:{cve_id}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return None
                data = resp.json()
                # Parse minimal CVSS and vector
                metrics = None
                items = data.get("vulnerabilities") or data.get("cveItems") or []
                if items:
                    node = items[0]
                    # NVD 2.0 structure
                    cvss = None
                    vector = None
                    try:
                        metric = node.get("cve", {}).get("metrics", {})
                        # Try CVSS v3.1 then v3.0 then v2
                        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            arr = metric.get(key)
                            if isinstance(arr, list) and arr:
                                cvss_data = arr[0].get("cvssData", {})
                                cvss = cvss_data.get("baseScore")
                                vector = cvss_data.get("vectorString")
                                break
                    except Exception:
                        pass
                    refs = []
                    try:
                        for r in node.get("cve", {}).get("references", {}).get("referenceData", []) or []:
                            refs.append({"type": "Advisory", "id": r.get("name") or r.get("url"), "url": r.get("url")})
                    except Exception:
                        pass
                    parsed = {"cvss": cvss, "cvss_vector": vector, "references": refs}
                    self._cache_set(cache_key, parsed)
                    return parsed
        except Exception:
            return None
        return None

    async def _fetch_osv_for_package(self, package: str, version: Optional[str]) -> Optional[Dict[str, Any]]:
        cache_key = f"osv:{package}@{version or 'latest'}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached
        body = {
            "package": {"name": package},
        }
        if version:
            body["version"] = version
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post("https://api.osv.dev/v1/query", json=body)
                if resp.status_code != 200:
                    return None
                data = resp.json() or {}
                vulns = data.get("vulns") or []
                if not vulns:
                    return None
                first = vulns[0]
                refs = [{"type": (ref.get("type") or "Advisory"), "id": ref.get("url"), "url": ref.get("url")} for ref in first.get("references", [])]
                parsed = {"references": refs}
                self._cache_set(cache_key, parsed)
                return parsed
        except Exception:
            return None
        return None

    async def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single normalized finding in-place and return it.

        - If a CVE is present, fetch CVSS and references from NVD
        - If a known vulnerable JS/library style, attempt OSV lookup
        """
        try:
            references = finding.get("references") or []
            classifier = finding.get("classifier") or {}

            cve_id = None
            # finding["cve"] may be a string or list-like from earlier mappers
            cve_val = finding.get("cve")
            if isinstance(cve_val, str) and cve_val.upper().startswith("CVE-"):
                cve_id = cve_val
            elif isinstance(cve_val, list) and cve_val:
                for c in cve_val:
                    if isinstance(c, str) and c.upper().startswith("CVE-"):
                        cve_id = c
                        break
            else:
                # Try evidence.cves
                try:
                    ev = finding.get("evidence")
                    if isinstance(ev, str):
                        ev = json.loads(ev)
                    if isinstance(ev, dict):
                        cves = ev.get("cves")
                        if isinstance(cves, list) and cves:
                            for c in cves:
                                if isinstance(c, str) and c.upper().startswith("CVE-"):
                                    cve_id = c
                                    break
                except Exception:
                    pass

            if cve_id:
                nvd = await self._fetch_nvd_by_cve(cve_id)
                if nvd:
                    if nvd.get("cvss") is not None:
                        finding["cvss"] = max(finding.get("cvss", 0.0) or 0.0, float(nvd["cvss"]))
                        classifier["cvss"] = finding["cvss"]
                    if nvd.get("cvss_vector"):
                        classifier["cvss_vector"] = nvd["cvss_vector"]
                    if nvd.get("references"):
                        # Merge unique references
                        existing = {(r.get("type"), r.get("id"), r.get("url")) for r in references if isinstance(r, dict)}
                        for r in nvd["references"]:
                            key = (r.get("type"), r.get("id"), r.get("url"))
                            if key not in existing:
                                references.append(r)

            # OSV heuristic: if vulnerable JS library or technology component present
            if (finding.get("type") == "vulnerable_js_library"):
                try:
                    ev = finding.get("evidence")
                    if isinstance(ev, str):
                        ev = json.loads(ev)
                    if isinstance(ev, dict):
                        pkg = ev.get("library")
                        ver = ev.get("version")
                        if pkg:
                            osv = await self._fetch_osv_for_package(pkg, ver)
                            if osv and osv.get("references"):
                                existing = {(r.get("type"), r.get("id"), r.get("url")) for r in references if isinstance(r, dict)}
                                for r in osv["references"]:
                                    key = (r.get("type"), r.get("id"), r.get("url"))
                                    if key not in existing:
                                        references.append(r)
                except Exception:
                    pass

            # Fill back
            finding["references"] = references
            finding["classifier"] = classifier
            return finding
        except Exception:
            return finding


