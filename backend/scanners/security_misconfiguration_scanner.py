import asyncio
import uuid
from typing import List, Dict, Any
import httpx

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class SecurityMisconfigurationScanner(BaseScanner):
    """
    A scanner module for detecting security misconfigurations.
    """

    metadata = {
        "name": "Security Misconfiguration",
        "description": "Detects common security misconfigurations such as exposed files and missing security headers.",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for security misconfigurations.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected security misconfigurations.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Security Misconfiguration scan for {target_url}...")

        # Common sensitive files and directories to check
        sensitive_paths = [
            "/.git",
            "/.env",
            "/config",
            "/backup",
            "/admin",
            "/phpinfo.php",
            "/server-status",
            "/.htaccess",
            "/wp-config.php",
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt"
        ]

        # Common security headers to check
        security_headers = {
            "X-Frame-Options": "Missing X-Frame-Options header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing Content-Security-Policy header",
            "X-XSS-Protection": "Missing X-XSS-Protection header"
        }

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            # Check for sensitive files and directories
            for path in sensitive_paths:
                try:
                    url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="Sensitive File Exposure",
                                description=f"Sensitive file or directory '{path}' is publicly accessible.",
                                severity=Severity.HIGH,
                                affected_url=url,
                                remediation="Remove or restrict access to sensitive files and directories. Implement proper access controls and consider using robots.txt to prevent crawling of sensitive paths.",
                                owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                                proof={
                                    "path": path,
                                    "response_status": response.status_code,
                                    "response_length": len(response.text)
                                }
                            )
                        )

                except httpx.RequestError as e:
                    print(f"Error checking path {path}: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred while checking {path}: {e}")

            # Check for security headers
            try:
                response = await client.get(target_url)
                headers = response.headers
                
                for header, description in security_headers.items():
                    if header not in headers:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="Missing Security Header",
                                description=description,
                                severity=Severity.MEDIUM,
                                affected_url=target_url,
                                remediation=f"Implement the {header} header to enhance security. Configure appropriate values based on your application's security requirements.",
                                owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                                proof={
                                    "missing_header": header,
                                    "current_headers": dict(headers)
                                }
                            )
                        )

            except httpx.RequestError as e:
                print(f"Error checking security headers: {e}")
            except Exception as e:
                print(f"An unexpected error occurred while checking security headers: {e}")

        print(f"[*] Finished Security Misconfiguration scan for {target_url}.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("security_misconfiguration", SecurityMisconfigurationScanner) 