import asyncio
import uuid
from typing import List, Dict, Any
import httpx

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class BrokenAuthenticationScanner(BaseScanner):
    """
    A scanner module for detecting broken authentication vulnerabilities.
    """

    metadata = {
        "name": "Broken Authentication",
        "description": "Detects missing authentication and weak credentials on common authentication endpoints.",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for broken authentication vulnerabilities.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected broken authentication vulnerabilities.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Broken Authentication scan for {target_url}...")

        # Common authentication endpoints to test
        auth_endpoints = [
            "/login",
            "/auth",
            "/signin",
            "/api/auth",
            "/api/login",
            "/api/v1/auth",
            "/api/v1/login"
        ]

        # Common weak credentials to test
        weak_credentials = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "test", "password": "test"},
            {"username": "user", "password": "user"}
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            for endpoint in auth_endpoints:
                auth_url = f"{target_url.rstrip('/')}/{endpoint.lstrip('/')}"
                
                try:
                    # Test for missing authentication
                    response = await client.get(auth_url)
                    if response.status_code == 200:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="Missing Authentication",
                                description=f"Endpoint '{auth_url}' is accessible without authentication.",
                                severity=Severity.HIGH,
                                affected_url=auth_url,
                                remediation="Implement proper authentication checks for all sensitive endpoints. Ensure authentication is required before accessing protected resources.",
                                owasp_category=OwaspCategory.A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES,
                                proof={
                                    "endpoint": auth_url,
                                    "response_status": response.status_code,
                                    "response_length": len(response.text)
                                }
                            )
                        )

                    # Test for weak credentials
                    for creds in weak_credentials:
                        try:
                            response = await client.post(
                                auth_url,
                                json=creds,
                                headers={"Content-Type": "application/json"}
                            )
                            
                            # Check if login was successful
                            if response.status_code == 200 and "token" in response.text.lower():
                                findings.append(
                                    Finding(
                                        id=str(uuid.uuid4()),
                                        vulnerability_type="Weak Credentials",
                                        description=f"Endpoint '{auth_url}' accepts weak credentials.",
                                        severity=Severity.HIGH,
                                        affected_url=auth_url,
                                        remediation="Implement strong password policies and prevent the use of common or weak credentials. Consider implementing rate limiting and account lockout mechanisms.",
                                        owasp_category=OwaspCategory.A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES,
                                        proof={
                                            "endpoint": auth_url,
                                            "credentials": creds,
                                            "response_status": response.status_code
                                        }
                                    )
                                )
                        except httpx.RequestError:
                            continue

                except httpx.RequestError as e:
                    print(f"Error testing authentication for {auth_url}: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred during authentication scan: {e}")

        print(f"[*] Finished Broken Authentication scan for {target_url}.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("broken_authentication", BrokenAuthenticationScanner) 