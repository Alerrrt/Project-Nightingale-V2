import asyncio
import uuid # Import uuid
from typing import List, Optional, Dict, Any

import httpx # Assuming httpx is used for async http requests
from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog # Import Severity, OwaspCategory, and RequestLog


class XssScanner(BaseScanner):
    """
    A scanner module for detecting Cross-Site Scripting (XSS) vulnerabilities.
    """

    metadata = {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Detects potential XSS vulnerabilities by searching for script tags and unescaped user input.",
        "owasp_category": "A03:2021 - Injection",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously scans a target for potential XSS vulnerabilities.

        Args:
            target: The target information for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects representing potential XSS vulnerabilities found.
        """
        findings: List[Finding] = []
        target_url = target

        # Basic placeholder logic for XSS detection
        # In a real-world scenario, this would involve:
        # - Sending crafted payloads in parameters and headers
        # - Analyzing the response for reflected payloads or DOM manipulation
        # - Considering different XSS types (reflected, stored, DOM-based)
        # - Using a headless browser for DOM-based XSS detection

        print(f"[*] Scanning {target_url} for XSS vulnerabilities...")

        async with httpx.AsyncClient(follow_redirects=True) as client:
            try:
                # Example: Make an asynchronous request to the target
                response = await client.get(str(target_url))
                response.raise_for_status() # Raise an exception for bad status codes
 
                # Placeholder for checking response for XSS indicators
                # In a real scenario, you would analyze the response body, headers, etc.
                # for signs of vulnerability after injecting payloads.
                if "<script>" in response.text: # Very simplistic check
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()), # Assign a unique ID
                            vulnerability_type="Potential Stored XSS Indicator", # Renamed to vulnerability_type
                    description=(
                                "Found indicators of potential stored XSS on a page likely containing user-supplied content: " + str(target_url) + "."), # Convert HttpUrl to string
                            severity=Severity.MEDIUM, # Use Severity enum
                            owasp_category=OwaspCategory.A03_INJECTION, # Use OwaspCategory enum
                            affected_url=str(target_url), # Use affected_url and ensure it's a string
                            technical_details=f"Response snippet: {response.text[:500]}...", # Example technical details
                    proof={
                                "url": str(target_url),
                        "indicator": "Presence of unescaped user input in HTML context." # Placeholder for proof indicator
                            },
                            request=RequestLog(
                                method="GET",
                                url=str(target_url),
                                headers=dict(response.request.headers) # Capture request headers
                            ),
                            response=response.text[:500] # Store a snippet of the response body
                )
                    )
            except httpx.HTTPStatusError as e:
                print(f"HTTP error while scanning {target_url}: {e}")
            except httpx.RequestError as e:
                print(f"Request error while scanning {target_url}: {e}")
            except Exception as e:
                print(f"An unexpected error occurred during XSS scan of {target_url}: {e}")

        print(f"[*] XSS scan of {target_url} completed.")

        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("xss", XssScanner)

# Example of how this might be used (for testing purposes)
# async def main():
#     scanner = XssScanner()
#     scan_input = ScanInput(target="http://example.com/vulnerable_to_