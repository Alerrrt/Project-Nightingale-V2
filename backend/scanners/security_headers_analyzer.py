import asyncio
import uuid
from typing import List, Dict, Any

import httpx
from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class SecurityHeadersAnalyzer(BaseScanner):
    """
    A scanner module for analyzing security headers.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for the presence and proper configuration of security headers.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects representing missing or insecure headers.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Analyzing security headers for {target_url}...")

        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                response = await client.get(target_url)
                response.raise_for_status()

                headers = response.headers

                # Check Strict-Transport-Security (HSTS)
                if not headers.get("Strict-Transport-Security"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            vulnerability_type="Missing HSTS Header",
                            description="The HTTP Strict Transport Security (HSTS) header is missing, which could allow protocol downgrade attacks.",
                            severity=Severity.MEDIUM,
                            affected_url=target_url,
                            remediation="Implement the HSTS header on the web server with an appropriate max-age directive (e.g., Strict-Transport-Security: max-age=31536000; includeSubDomains; preload).",
                            owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                            proof={"details": "HSTS header not found in response."}
                        )
                    )

                # Check Content-Security-Policy (CSP)
                if not headers.get("Content-Security-Policy"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            vulnerability_type="Missing Content-Security-Policy Header",
                            description="The Content-Security-Policy (CSP) header is missing, increasing the risk of XSS and data injection attacks.",
                            severity=Severity.HIGH,
                            affected_url=target_url,
                            remediation="Implement a strong Content-Security-Policy header to mitigate various client-side attacks.",
                            owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                            proof={"details": "Content-Security-Policy header not found in response."}
                        )
                    )
                # Further CSP checks could be added here (e.g., unsafe-inline, unsafe-eval)

                # Check X-Frame-Options (Clickjacking)
                x_frame_options = headers.get("X-Frame-Options")
                if not x_frame_options:
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            vulnerability_type="Missing X-Frame-Options Header",
                            description="The X-Frame-Options header is missing, which can lead to clickjacking attacks.",
                            severity=Severity.MEDIUM,
                            affected_url=target_url,
                            remediation="Add the X-Frame-Options header with 'DENY' or 'SAMEORIGIN' to prevent framing.",
                            owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                            proof={"details": "X-Frame-Options header not found in response."}
                        )
                    )
                elif x_frame_options.lower() not in ["deny", "sameorigin"]:
                     findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            vulnerability_type="Weak X-Frame-Options Header",
                            description=f"The X-Frame-Options header is set to '{x_frame_options}', which may not fully protect against clickjacking.",
                            severity=Severity.LOW,
                            affected_url=target_url,
                            remediation="Set the X-Frame-Options header to 'DENY' or 'SAMEORIGIN'.",
                            owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                            proof={"details": f"X-Frame-Options: {x_frame_options}."}
                        )
                    )

                # Check X-Content-Type-Options
                if not headers.get("X-Content-Type-Options"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            vulnerability_type="Missing X-Content-Type-Options Header",
                            description="The X-Content-Type-Options header is missing, which could lead to MIME type sniffing vulnerabilities.",
                            severity=Severity.LOW,
                            affected_url=target_url,
                            remediation="Add the X-Content-Type-Options: nosniff header to responses.",
                            owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                            proof={"details": "X-Content-Type-Options header not found in response."}
                        )
                    )

                # Check Referrer-Policy
                if not headers.get("Referrer-Policy"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            vulnerability_type="Missing Referrer-Policy Header",
                            description="The Referrer-Policy header is missing, which may inadvertently leak sensitive URL information to third parties.",
                            severity=Severity.INFO,
                            affected_url=target_url,
                            remediation="Implement a suitable Referrer-Policy header (e.g., 'no-referrer', 'same-origin', 'strict-origin-when-cross-origin').",
                            owasp_category=OwaspCategory.UNKNOWN, # Can be A05 or A07 depending on context
                            proof={"details": "Referrer-Policy header not found in response."}
                        )
                    )

        except httpx.HTTPStatusError as e:
            print(f"HTTP error while analyzing headers for {target_url}: {e}")
        except httpx.RequestError as e:
            print(f"Request error while analyzing headers for {target_url}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred during security headers scan of {target_url}: {e}")

        print(f"[*] Finished analyzing security headers for {target_url}.")
        return findings 