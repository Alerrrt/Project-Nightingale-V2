import asyncio
import uuid
from typing import List, Dict, Any
import httpx
from urllib.parse import urljoin

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class SsrfScanner(BaseScanner):
    """
    A scanner module for detecting Server-Side Request Forgery (SSRF) vulnerabilities.
    """

    metadata = {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Detects SSRF vulnerabilities by attempting to access internal resources via user-controlled parameters.",
        "owasp_category": "A10:2021 - Server-Side Request Forgery (SSRF)",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for SSRF vulnerabilities by attempting to access internal resources.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected SSRF vulnerabilities.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting SSRF scan for {target_url}...")

        # List of internal IPs and services to test
        internal_targets = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",  # AWS metadata service
            "http://metadata.google.internal",  # GCP metadata service
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata path
            "http://127.0.0.1:22",  # SSH
            "http://127.0.0.1:3306",  # MySQL
            "http://127.0.0.1:5432",  # PostgreSQL
            "http://127.0.0.1:6379",  # Redis
            "http://127.0.0.1:27017",  # MongoDB
        ]

        # Common parameters that might be vulnerable to SSRF
        ssrf_parameters = [
            "url",
            "path",
            "src",
            "dest",
            "redirect",
            "return",
            "next",
            "target",
            "rurl",
            "returnUrl",
            "returnTo",
            "return_to",
            "callback",
            "callback_url",
            "callbackUrl"
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            for internal_target in internal_targets:
                for param in ssrf_parameters:
                    try:
                        # Try to access the internal target through the target URL
                        test_url = urljoin(target_url, f"?{param}={internal_target}")
                        response = await client.get(test_url)
                        
                        # Check if we got a response from the internal service
                        if response.status_code != 404 and len(response.text) > 0:
                            findings.append(
                                Finding(
                                    id=str(uuid.uuid4()),
                                    vulnerability_type="Server-Side Request Forgery (SSRF)",
                                    description=f"Potential SSRF vulnerability detected through parameter '{param}'. The application appears to be accessing internal resources.",
                                    severity=Severity.HIGH,
                                    affected_url=test_url,
                                    remediation="Implement proper URL validation and whitelisting. Use a URL parser that validates against allowed domains. Consider using a proxy service for external requests.",
                                    owasp_category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
                                    proof={
                                        "parameter": param,
                                        "internal_target": internal_target,
                                        "response_status": response.status_code,
                                        "response_length": len(response.text)
                                    }
                                )
                            )

                    except httpx.RequestError as e:
                        print(f"Error testing SSRF for {internal_target}: {e}")
                    except Exception as e:
                        print(f"An unexpected error occurred during SSRF scan: {e}")

        print(f"[*] Finished SSRF scan for {target_url}.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("ssrf", SsrfScanner) 