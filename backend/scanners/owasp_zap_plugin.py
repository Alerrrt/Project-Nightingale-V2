import logging
from typing import List, Dict

from backend.plugins.base_plugin import BasePlugin
from backend.config_types.models import ScanInput

logger = logging.getLogger(__name__)

class OwaspZapPlugin(BasePlugin):
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        try:
            return await self._perform_scan(scan_input.target, scan_input.options or {})
        except Exception as e:
            logger.error(f"OWASP ZAP Plugin scan failed: {e}", exc_info=True)
            return [self._create_error_finding(f"OWASP ZAP Plugin scan failed: {e}")]
    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        findings = []
        try:
            # ... existing scan logic ...
            pass
        except Exception as e:
            logger.error(f"Failed to analyze {target}: {e}")
            return [self._create_error_finding(f"Could not fetch or analyze the target URL: {e}")]
        return findings
    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": "INFO", "title": "OWASP ZAP Plugin Error", "description": description, "location": "Plugin", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
