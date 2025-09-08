import logging
logger = logging.getLogger(__name__)
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity
from typing import List, Dict
from .technology_fingerprint_scanner import TechnologyFingerprintScanner
from backend.utils.enrichment import EnrichmentService

class TechnologyVulnerabilitiesScanner(BaseScanner):
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        try:
            return await self._perform_scan(scan_input.target, scan_input.options or {})
        except Exception as e:
            logger.error(f"Technology Vulnerabilities scan failed: {e}", exc_info=True)
            return [self._create_error_finding(f"Technology Vulnerabilities scan failed: {e}")]
    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        # Delegate to TechnologyFingerprintScanner to avoid duplicate logic.
        try:
            delegate = TechnologyFingerprintScanner()
            findings = await delegate._perform_scan(target, options)
            # Ensure more aggressive enrichment for tech findings
            enr = EnrichmentService()
            enriched: List[Dict] = []
            for f in findings:
                try:
                    f = await enr.enrich_finding(f)
                except Exception:
                    pass
                enriched.append(f)
            return enriched
        except Exception as e:
            logger.error(f"Failed to analyze {target}: {e}")
            return [self._create_error_finding(f"Could not fetch or analyze the target URL: {e}")]
    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Technology Vulnerabilities Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
