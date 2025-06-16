import asyncio
import uuid
from typing import List, Dict, Any
import httpx

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class InsecureDesignScanner(BaseScanner):
    """
    A scanner module for detecting insecure design vulnerabilities.
    """

    metadata = {
        "name": "Insecure Design",
        "description": "Detects insecure design patterns such as missing security headers, weak password policies, and lack of rate limiting.",
        "owasp_category": "A04:2021 - Insecure Design",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for insecure design vulnerabilities.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected insecure design issues.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Insecure Design scan for {target_url}...")

        # Test cases for insecure design patterns
        test_cases = [
            {
                "path": "/api/users",
                "method": "GET",
                "description": "User enumeration through API",
                "expected_status": 200
            },
            {
                "path": "/api/register",
                "method": "POST",
                "data": {
                    "username": "test",
                    "password": "test123",
                    "email": "test@example.com"
                },
                "description": "Weak password policy",
                "expected_status": 201
            },
            {
                "path": "/api/reset-password",
                "method": "POST",
                "data": {
                    "email": "test@example.com"
                },
                "description": "Password reset without rate limiting",
                "expected_status": 200
            }
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            for test_case in test_cases:
                try:
                    url = f"{target_url.rstrip('/')}/{test_case['path'].lstrip('/')}"
                    
                    if test_case['method'] == 'POST':
                        response = await client.post(url, json=test_case['data'])
                    else:
                        response = await client.get(url)

                    # Check for insecure design patterns
                    if response.status_code == test_case['expected_status']:
                        # Check for security headers
                        security_headers = {
                            "x-content-type-options": "nosniff",
                            "x-frame-options": "DENY",
                            "content-security-policy": "default-src 'self'",
                            "strict-transport-security": "max-age=31536000; includeSubDomains"
                        }

                        missing_headers = []
                        for header, value in security_headers.items():
                            if header not in response.headers:
                                missing_headers.append(header)

                        if missing_headers:
                            findings.append(
                                Finding(
                                    id=str(uuid.uuid4()),
                                    vulnerability_type="Insecure Design",
                                    description=f"Missing security headers for {test_case['description']}.",
                                    severity=Severity.MEDIUM,
                                    affected_url=url,
                                    remediation="Implement proper security headers and follow secure design principles. Consider implementing a Web Application Firewall (WAF) for additional protection.",
                                    owasp_category=OwaspCategory.A04_INSECURE_DESIGN,
                                    proof={
                                        "test_case": test_case['description'],
                                        "missing_headers": missing_headers,
                                        "response_status": response.status_code
                                    }
                                )
                            )

                        # Check for weak password policy
                        if test_case['description'] == "Weak password policy":
                            if len(test_case['data']['password']) < 8:
                                findings.append(
                                    Finding(
                                        id=str(uuid.uuid4()),
                                        vulnerability_type="Weak Password Policy",
                                        description="Application allows weak passwords.",
                                        severity=Severity.HIGH,
                                        affected_url=url,
                                        remediation="Implement a strong password policy requiring minimum length, complexity, and preventing common passwords.",
                                        owasp_category=OwaspCategory.A04_INSECURE_DESIGN,
                                        proof={
                                            "test_case": test_case['description'],
                                            "password_length": len(test_case['data']['password'])
                                        }
                                    )
                                )

                except httpx.RequestError as e:
                    print(f"Error testing insecure design for {url}: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred during insecure design scan: {e}")

        print(f"[*] Finished Insecure Design scan for {target_url}.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("insecure_design", InsecureDesignScanner) 