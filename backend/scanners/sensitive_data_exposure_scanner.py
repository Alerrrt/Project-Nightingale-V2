import asyncio
import uuid
import re
from typing import List, Dict, Any
import httpx

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class SensitiveDataExposureScanner(BaseScanner):
    """
    A scanner module for detecting sensitive data exposure vulnerabilities.
    """

    metadata = {
        "name": "Sensitive Data Exposure",
        "description": "Detects exposure of sensitive data such as emails, API keys, and credentials in responses and headers.",
        "owasp_category": "A04:2021 - Insecure Design",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    # Regular expressions for detecting sensitive data patterns
    SENSITIVE_PATTERNS = {
        "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "ssn": r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        "api_key": r"(?i)(api[_-]?key|apikey)[_-]?[a-z0-9]{32,}",
        "password": r"(?i)(password|passwd|pwd)[_-]?[a-z0-9]{8,}",
        "jwt": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "private_key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for sensitive data exposure vulnerabilities.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected sensitive data exposures.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Sensitive Data Exposure scan for {target_url}...")

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            try:
                # Get the main page content
                response = await client.get(target_url)
                content = response.text

                # Check for sensitive data patterns
                for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Mask the sensitive data in the finding
                        sensitive_data = match.group(0)
                        masked_data = self._mask_sensitive_data(sensitive_data, pattern_name)
                        
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="Sensitive Data Exposure",
                                description=f"Potential {pattern_name.replace('_', ' ').title()} exposure detected in the response.",
                                severity=Severity.HIGH,
                                affected_url=target_url,
                                remediation="Implement proper data protection measures. Ensure sensitive data is encrypted in transit and at rest. Follow the principle of least privilege and only expose necessary data.",
                                owasp_category=OwaspCategory.A04_INSECURE_DESIGN,
                                proof={
                                    "pattern_type": pattern_name,
                                    "masked_data": masked_data,
                                    "context": content[max(0, match.start()-20):min(len(content), match.end()+20)]
                                }
                            )
                        )

                # Check response headers for sensitive information
                headers = response.headers
                sensitive_headers = {
                    "server": "Server version information",
                    "x-powered-by": "Technology stack information",
                    "x-aspnet-version": "ASP.NET version information",
                    "x-aspnetmvc-version": "ASP.NET MVC version information"
                }

                for header, description in sensitive_headers.items():
                    if header in headers:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="Information Disclosure",
                                description=f"Server is revealing {description} in response headers.",
                                severity=Severity.MEDIUM,
                                affected_url=target_url,
                                remediation="Remove or mask sensitive information from response headers. Configure the server to not expose version information or technology stack details.",
                                owasp_category=OwaspCategory.A04_INSECURE_DESIGN,
                                proof={
                                    "header": header,
                                    "value": headers[header]
                                }
                            )
                        )

            except httpx.RequestError as e:
                print(f"Error during sensitive data exposure scan: {e}")
            except Exception as e:
                print(f"An unexpected error occurred during sensitive data exposure scan: {e}")

        print(f"[*] Finished Sensitive Data Exposure scan for {target_url}.")
        return findings

    def _mask_sensitive_data(self, data: str, pattern_type: str) -> str:
        """
        Mask sensitive data while preserving format.

        Args:
            data: The sensitive data to mask
            pattern_type: The type of sensitive data

        Returns:
            Masked version of the sensitive data
        """
        if pattern_type == "credit_card":
            return f"{data[:4]}{'*' * (len(data)-8)}{data[-4:]}"
        elif pattern_type == "email":
            username, domain = data.split('@')
            return f"{username[0]}{'*' * (len(username)-2)}{username[-1]}@{domain}"
        elif pattern_type == "ssn":
            return f"***-**-{data[-4:]}"
        else:
            return f"{data[:4]}{'*' * (len(data)-8)}{data[-4:]}"


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("sensitive_data_exposure", SensitiveDataExposureScanner) 