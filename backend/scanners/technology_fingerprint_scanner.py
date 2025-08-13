import asyncio
import httpx
from typing import List, Dict, Any, Optional

from Wappalyzer import Wappalyzer, WebPage

from backend.scanners.base_scanner import BaseScanner
from backend.types.models import ScanInput, Severity, OwaspCategory
from backend.utils.enrichment import EnrichmentService
from backend.utils.logging_config import get_context_logger
from backend.utils import get_http_client

# Mapping from Wappalyzer categories to OSV ecosystems where possible.
# This is a best-effort mapping and might need refinement.
ECOSYSTEM_MAPPING = {
    "javascript-frameworks": "npm",
    "javascript-libraries": "npm",
    "web-servers": None, # e.g., Nginx, Apache - often not in package managers
    "web-frameworks": None, # e.g., Django, Ruby on Rails - could be PyPI, RubyGems etc.
    "programming-languages": None, # e.g., PHP, Python
    "cms": None, # e.g., WordPress, Joomla - often have their own vulnerability databases
    "blogs": "npm", # e.g., Ghost
}

class TechnologyFingerprintScanner(BaseScanner):
    metadata = {
        "name": "Technology Fingerprint Scanner",
        "description": "Identifies technologies and versions used by the target webapp and checks for known vulnerabilities using the OSV.dev database.",
        "owasp_category": OwaspCategory.A06_VULNERABLE_AND_OUTDATED_COMPONENTS,
        "author": "Project Nightingale Team",
        "version": "1.1"
    }

    def __init__(self):
        super().__init__()
        self.logger = get_context_logger(self.__class__.__name__)
        # Initialize Wappalyzer. This can be slow, so we do it once.
        # Wappalyzer.latest(update=True) is blocking, so we avoid it in an async app
        # or would run it in a thread pool on startup. For now, use cached version.
        self.wappalyzer = Wappalyzer.latest()
        self._enrichment = EnrichmentService()

    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        """
        Overrides the base scan method to perform technology fingerprinting.
        """
        try:
            return await self._perform_scan(scan_input.target, scan_input.options or {})
        except Exception as e:
            self.logger.error(f"Technology Fingerprint scan failed: {e}", exc_info=True)
            return [self._create_error_finding(f"Technology Fingerprint scan failed: {e}")]

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Performs the technology detection and vulnerability lookup.
        """
        findings = []
        try:
            async with get_http_client(verify=False, follow_redirects=True, timeout=20.0) as client:
                response = await client.get(target)
                webpage = WebPage(str(response.url), response.text, response.headers)
                technologies = self.wappalyzer.analyze_with_versions_and_categories(webpage)
        except Exception as e:
            self.logger.error(f"Failed to analyze {target}: {e}")
            return [self._create_error_finding(f"Could not fetch or analyze the target URL: {e}")]

        if not technologies:
            return [self._create_info_finding(f"No specific technologies were identified on {target}.", target)]

        # Concurrently look up vulnerabilities for all identified technologies
        lookup_tasks = []
        for tech_name, tech_data in technologies.items():
            versions = tech_data.get("versions", [])
            categories = tech_data.get("categories", [])
            version = versions[0] if versions else None
            lookup_tasks.append(self._lookup_cves(tech_name, version, categories))
        results = await asyncio.gather(*lookup_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                for f in result:
                    try:
                        f = await self._enrichment.enrich_finding(f)
                    except Exception:
                        pass
                    findings.append(f)
            elif isinstance(result, Exception):
                self.logger.error(f"Error during CVE lookup: {result}")
                findings.append(self._create_error_finding(f"Error during CVE lookup: {result}"))

        return findings

    async def _lookup_cves(self, tech_name: str, version: Optional[str], categories: List[str]) -> List[Dict]:
        """
        Looks up vulnerabilities for a given technology and version using the OSV.dev API.
        """
        if not version:
            return [self._create_info_finding(f"Detected technology: {tech_name} (version not identified).", f"tech:{tech_name}")]

        # Try to map Wappalyzer category to OSV ecosystem
        ecosystem = None
        for cat_name in categories:
            cat_slug = cat_name.lower().replace(' ', '-')
            if cat_slug in ECOSYSTEM_MAPPING:
                ecosystem = ECOSYSTEM_MAPPING[cat_slug]
                break

        query = {
            "version": version,
            "package": {"name": tech_name.lower()}
        }
        if ecosystem:
            query["package"]["ecosystem"] = ecosystem
        
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post("https://api.osv.dev/v1/query", json=query, timeout=10)
                resp.raise_for_status()
                data = resp.json()

            if "vulns" in data and data["vulns"]:
                return [self._create_finding_from_osv(vuln, tech_name, version) for vuln in data["vulns"]]
        except httpx.HTTPStatusError as e:
            self.logger.warning(f"OSV API request failed for {tech_name} v{version}: {e.response.status_code}")
            return [self._create_error_finding(f"OSV API request failed for {tech_name} v{version}: {e.response.status_code}")]
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during CVE lookup for {tech_name}: {e}")
            return [self._create_error_finding(f"Unexpected error during CVE lookup for {tech_name}: {e}")]
        
        return []

    def _create_finding_from_osv(self, vuln_data: Dict[str, Any], tech_name: str, version: str) -> Dict:
        """
        Creates a structured finding dictionary from an OSV vulnerability object.
        """
        severity = Severity.MEDIUM # Default
        if "database_specific" in vuln_data and "severity" in vuln_data["database_specific"]:
            sev_text = vuln_data["database_specific"]["severity"].lower()
            if sev_text == "critical":
                severity = Severity.CRITICAL
            elif sev_text == "high":
                severity = Severity.HIGH
            elif sev_text == "low":
                severity = Severity.LOW

        description = vuln_data.get('summary', vuln_data.get('details'))
        if not description:
            vuln_id = vuln_data.get('id', 'N/A')
            description = (
                f"A known vulnerability with ID {vuln_id} was found in {tech_name} "
                f"version {version}. No summary was provided, but further details "
                "may be available in the references."
            )
        
        remediation = (
            f"Upgrade {tech_name} to a version that patches {vuln_data.get('id', 'this vulnerability')}. "
            "Review the vulnerability details and references for official advisories and patched versions."
        )

        return {
            "type": "vulnerability",
            "severity": severity.value,
            "title": f"Known Vulnerability in {tech_name} v{version} ({vuln_data.get('id', 'N/A')})",
            "description": description,
            "location": f"Component: {tech_name} v{version}",
            "cwe": f"OSV: {vuln_data.get('id', 'N/A')}",
            "confidence": 100,
            "category": "technology-fingerprint", # For frontend filtering
            "remediation": remediation,
            "cvss": 0, # Should be extracted from OSV data if available
            "evidence": {
                "references": [ref["url"] for ref in vuln_data.get("references", [])],
                "aliases": vuln_data.get("aliases", []),
            },
        }

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Technology Fingerprint Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }
    
    def _create_info_finding(self, description: str, location: str) -> Dict:
        return { "type": "info", "severity": Severity.INFO.value, "title": "Technology Information", "description": description, "location": location, "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }

def register(scanner_registry):
    scanner_registry.register("technologyfingerprint", TechnologyFingerprintScanner)
