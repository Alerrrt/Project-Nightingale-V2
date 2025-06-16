import logging
import uuid
from typing import List, Dict, Any, Optional

import httpx
from pydantic import BaseModel

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog

logger = logging.getLogger(__name__)


class SqlInjectionScanTarget(BaseModel):
    """Model for the target of an SQL Injection scan."""
    url: str


class SqlInjectionFinding(BaseModel):
    """Model for a detected SQL Injection vulnerability finding."""
    vulnerability_type: str = "SQL Injection"
    severity: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    response_status: Optional[int] = None
    response_body_snippet: Optional[str] = None


class SqlInjectionScanner(BaseScanner):
    """
    A scanner module for detecting SQL Injection vulnerabilities.
    """

    metadata = {
        "name": "SQL Injection",
        "description": "Detects SQL injection vulnerabilities by injecting common payloads and analyzing responses.",
        "owasp_category": "A03:2021 - Injection",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously scans a target URL for SQL Injection vulnerabilities.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects representing detected vulnerabilities.
        """
        findings: List[Finding] = []
        url = target
        logger.info(f"Starting SQL Injection scan for: {url}")

        common_payloads = [
            "' OR '1'='1",
            '" OR "1"="1"\'',
            " admin'--",
            "' OR '1'='1'--",
            "' HAVING 1=1 --",
        ]

        async with httpx.AsyncClient(follow_redirects=True) as client:
            for payload in common_payloads:
                try:
                    test_url = f"{url}?id={payload}"
                    response = await client.get(test_url)
                    response.raise_for_status()

                    if "syntax error" in response.text.lower() or "mysql_fetch_array" in response.text.lower():
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="SQL Injection",
                                description=f"Potential SQL Injection detected with payload: {payload}",
                                severity=Severity.HIGH,
                                owasp_category=OwaspCategory.A03_INJECTION,
                                affected_url=url,
                                request=RequestLog(
                                    method="GET",
                                    url=test_url,
                                    headers=dict(response.request.headers),
                                    body=None
                                ),
                                response=response.text[:500],
                                proof=f"Payload: {payload}, Response Status: {response.status_code}, Response Snippet: {response.text[:100]}"
                            )
                        )
                except httpx.HTTPStatusError as e:
                    logger.warning(f"HTTP error during SQL Injection scan for {test_url}: {e}", exc_info=True)
                except httpx.RequestError as e:
                    logger.warning(f"Request error during SQL Injection scan for {test_url}: {e}", exc_info=True)
                except Exception as e:
                    logger.error(f"An unexpected error occurred during SQL Injection scan for {test_url}: {e}", exc_info=True)

        logger.info(f"Finished SQL Injection scan for: {url}")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("sql_injection", SqlInjectionScanner)