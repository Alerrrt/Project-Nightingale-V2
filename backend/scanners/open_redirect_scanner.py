# -*- coding: utf-8 -*-
import re
from typing import List, Dict, Any
from datetime import datetime
import httpx
from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Severity, OwaspCategory
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger

logger = get_context_logger(__name__)

class OpenRedirectScanner(BaseScanner):
    """
    Scanner for detecting open redirect vulnerabilities.
    """
    metadata = {
        "name": "Open Redirect",
        "description": "Detects open redirect vulnerabilities by injecting common payloads into redirect parameters and analyzing responses.",
        "owasp_category": "A10:2021 - Server-Side Request Forgery (SSRF)",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="open_redirect_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        start_time = datetime.now()
        scan_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        try:
            logger.info("Scan started", extra={
                "scanner": self.__class__.__name__,
                "scan_id": scan_id,
                "target": scan_input.target,
                "options": scan_input.options
            })
            results = await self._perform_scan(scan_input.target, scan_input.options)
            self._update_metrics(True, start_time)
            logger.info("Scan completed", extra={
                "scanner": self.__class__.__name__,
                "scan_id": scan_id,
                "target": scan_input.target,
                "result_count": len(results)
            })
            return results
        except Exception as e:
            self._update_metrics(False, start_time)
            logger.error("Scan failed", extra={
                "scanner": self.__class__.__name__,
                "scan_id": scan_id,
                "target": scan_input.target,
                "error": str(e)
            }, exc_info=True)
            raise

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        findings: List[Dict] = []
        logger.info("Starting open redirect scan", extra={
            "target": target,
            "scanner": self.__class__.__name__
        })
        
        # Common redirect parameters and payloads
        redirect_params = options.get('parameters', [
            'next', 'url', 'target', 'rurl', 'dest', 'destination', 'redir', 'redirect', 'redirect_url', 'redirect_uri', 'continue', 'return', 'returnTo', 'return_to'
        ])
        payloads = options.get('payloads', [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            '///evil.com',
            'http://evil.com',
            'evil.com',
            '////evil.com',
            '\\evil.com',
        ])
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                for param in redirect_params:
                    for payload in payloads:
                        params = {param: payload}
                        try:
                            response = await client.get(target, params=params, follow_redirects=False)
                            location = response.headers.get('location', '')
                            if response.status_code in (301, 302, 303, 307, 308) and any(p in location for p in ['evil.com']):
                                logger.info("Potential open redirect detected", extra={
                                    "url": target,
                                    "parameter": param,
                                    "payload": payload,
                                    "location": location,
                                    "scanner": self.__class__.__name__
                                })
                                findings.append({
                                    "type": "open_redirect",
                                    "severity": Severity.MEDIUM,
                                    "title": "Open Redirect Vulnerability",
                                    "description": f"Potential open redirect via parameter '{param}' with payload '{payload}'.",
                                    "evidence": {
                                        "url": target,
                                        "parameter": param,
                                        "payload": payload,
                                        "location": location,
                                        "status_code": response.status_code
                                    },
                                    "owasp_category": OwaspCategory.SSRF,
                                    "recommendation": "Validate and whitelist redirect destinations. Do not allow user-controlled input to dictate redirect locations. Use relative paths for redirects where possible."
                                })
                        except Exception as e:
                            logger.warning("Error testing open redirect payload", extra={
                                "url": target,
                                "parameter": param,
                                "payload": payload,
                                "error": str(e),
                                "scanner": self.__class__.__name__
                            })
                            continue
        except Exception as e:
            logger.error("Unexpected error during open redirect scan", extra={
                "target": target,
                "error": str(e),
                "scanner": self.__class__.__name__
            }, exc_info=True)

        logger.info("Finished open redirect scan", extra={
            "target": target,
            "findings_count": len(findings),
            "scanner": self.__class__.__name__
        })
        return findings

def register(scanner_registry: ScannerRegistry) -> None:
    scanner_registry.register("open_redirect", OpenRedirectScanner) 