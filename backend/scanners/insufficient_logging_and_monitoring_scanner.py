import asyncio
import uuid
from typing import List, Dict, Any
import httpx

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class InsufficientLoggingAndMonitoringScanner(BaseScanner):
    """
    A scanner module for detecting insufficient logging and monitoring vulnerabilities.
    """

    metadata = {
        "name": "Insufficient Logging and Monitoring",
        "description": "Detects missing security headers and improper error handling that may indicate insufficient logging and monitoring.",
        "owasp_category": "A09:2021 - Security Logging and Monitoring Failures",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for insufficient logging and monitoring vulnerabilities.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected insufficient logging and monitoring issues.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Insufficient Logging and Monitoring scan for {target_url}...")

        # Test cases for insufficient logging
        test_cases = [
            {
                "path": "/api/login",
                "method": "POST",
                "data": {"username": "test", "password": "test123"},
                "expected_status": 401,
                "description": "Failed login attempt"
            },
            {
                "path": "/api/users/1",
                "method": "DELETE",
                "data": None,
                "expected_status": 403,
                "description": "Unauthorized deletion attempt"
            },
            {
                "path": "/api/admin",
                "method": "GET",
                "data": None,
                "expected_status": 403,
                "description": "Unauthorized admin access attempt"
            }
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            for test_case in test_cases:
                try:
                    url = f"{target_url.rstrip('/')}/{test_case['path'].lstrip('/')}"
                    
                    if test_case['method'] == 'POST':
                        response = await client.post(url, json=test_case['data'])
                    elif test_case['method'] == 'DELETE':
                        response = await client.delete(url)
                    else:
                        response = await client.get(url)

                    # Check if the response indicates proper error handling
                    if response.status_code == test_case['expected_status']:
                        # Check for security headers that might indicate logging
                        security_headers = {
                            "x-content-type-options": "nosniff",
                            "x-frame-options": "DENY",
                            "content-security-policy": "default-src 'self'"
                        }

                        missing_headers = []
                        for header, value in security_headers.items():
                            if header not in response.headers:
                                missing_headers.append(header)

                        if missing_headers:
                            findings.append(
                                Finding(
                                    id=str(uuid.uuid4()),
                                    vulnerability_type="Insufficient Security Headers",
                                    description=f"Missing security headers for {test_case['description']}.",
                                    severity=Severity.MEDIUM,
                                    affected_url=url,
                                    remediation="Implement proper security headers and ensure all security events are logged. Consider implementing a Web Application Firewall (WAF) for additional monitoring.",
                                    owasp_category=OwaspCategory.A09_LOGGING_AND_MONITORING_FAILURES,
                                    proof={
                                        "test_case": test_case['description'],
                                        "missing_headers": missing_headers,
                                        "response_status": response.status_code
                                    }
                                )
                            )

                except httpx.RequestError as e:
                    print(f"Error testing logging for {url}: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred during logging scan: {e}")

        print(f"[*] Finished Insufficient Logging and Monitoring scan for {target_url}.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("insufficient_logging_and_monitoring", InsufficientLoggingAndMonitoringScanner) 