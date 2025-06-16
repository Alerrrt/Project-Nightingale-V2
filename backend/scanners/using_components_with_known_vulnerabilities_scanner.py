import asyncio
import uuid
import re
from typing import List, Dict, Any
import httpx

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class UsingComponentsWithKnownVulnerabilitiesScanner(BaseScanner):
    """
    A scanner module for detecting the use of components with known vulnerabilities.
    """

    metadata = {
        "name": "Using Components with Known Vulnerabilities",
        "description": "Detects use of outdated or vulnerable client/server components by analyzing versions in HTML and headers.",
        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    # Common JavaScript libraries and their version patterns
    JS_LIBRARIES = {
        "jquery": r"jquery[.-](\d+\.\d+\.\d+)",
        "bootstrap": r"bootstrap[.-](\d+\.\d+\.\d+)",
        "angular": r"angular[.-](\d+\.\d+\.\d+)",
        "react": r"react[.-](\d+\.\d+\.\d+)",
        "vue": r"vue[.-](\d+\.\d+\.\d+)"
    }

    # Common vulnerable versions (simplified for example)
    VULNERABLE_VERSIONS = {
        "jquery": ["1.12.4", "2.2.4", "3.0.0"],
        "bootstrap": ["3.3.7", "4.0.0"],
        "angular": ["1.5.0", "1.6.0"],
        "react": ["15.0.0", "16.0.0"],
        "vue": ["2.0.0", "2.1.0"]
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for components with known vulnerabilities.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected vulnerable components.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Components with Known Vulnerabilities scan for {target_url}...")

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            try:
                # Get the main page content
                response = await client.get(target_url)
                content = response.text

                # Check for JavaScript libraries
                for library, pattern in self.JS_LIBRARIES.items():
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        version = match.group(1)
                        if version in self.VULNERABLE_VERSIONS.get(library, []):
                            findings.append(
                                Finding(
                                    id=str(uuid.uuid4()),
                                    vulnerability_type="Vulnerable Component",
                                    description=f"Vulnerable version of {library} ({version}) detected.",
                                    severity=Severity.HIGH,
                                    affected_url=target_url,
                                    remediation=f"Upgrade {library} to the latest secure version. Remove any unused dependencies and regularly update all components.",
                                    owasp_category=OwaspCategory.A06_VULNERABLE_AND_OUTDATED_COMPONENTS,
                                    proof={
                                        "library": library,
                                        "version": version,
                                        "context": content[max(0, match.start()-20):min(len(content), match.end()+20)]
                                    }
                                )
                            )

                # Check for common server technologies
                server_headers = {
                    "server": "Server technology",
                    "x-powered-by": "Web framework",
                    "x-aspnet-version": "ASP.NET version",
                    "x-aspnetmvc-version": "ASP.NET MVC version"
                }

                headers = response.headers
                for header, description in server_headers.items():
                    if header in headers:
                        value = headers[header]
                        # Add logic here to check for known vulnerable versions of server technologies
                        # This is a simplified example
                        if "apache/2.4.49" in value.lower():
                            findings.append(
                                Finding(
                                    id=str(uuid.uuid4()),
                                    vulnerability_type="Vulnerable Server Component",
                                    description=f"Vulnerable version of {description} detected: {value}",
                                    severity=Severity.HIGH,
                                    affected_url=target_url,
                                    remediation="Upgrade the server component to the latest secure version. Regularly update all server components and apply security patches.",
                                    owasp_category=OwaspCategory.A06_VULNERABLE_AND_OUTDATED_COMPONENTS,
                                    proof={
                                        "header": header,
                                        "value": value
                                    }
                                )
                            )

            except httpx.RequestError as e:
                print(f"Error during components scan: {e}")
            except Exception as e:
                print(f"An unexpected error occurred during components scan: {e}")

        print(f"[*] Finished Components with Known Vulnerabilities scan for {target_url}.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("using_components_with_known_vulnerabilities", UsingComponentsWithKnownVulnerabilitiesScanner) 