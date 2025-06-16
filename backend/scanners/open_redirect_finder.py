import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory

class OpenRedirectFinderScanner(BaseScanner):
    """
    A scanner module for detecting open redirect vulnerabilities.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously crawls the target and injects payloads to detect unsafe redirects.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected open redirects.
        """
        findings: List[Finding] = []
        base_url = target
        print(f"[*] Starting Open Redirect scan for {base_url}...")

        # Simple example payloads and common redirect parameters
        redirect_params = ["next", "redirect", "url", "dest", "continue", "return_to"]
        evil_url = "https://evil.com/malicious_page"

        async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
            # Fetch the main page to find potential links/forms
            try:
                response = await client.get(base_url)
                response.raise_for_status()
                # A more advanced scanner would parse HTML to find all links and form actions
                # For now, we'll just test the base URL with common redirect parameters

                tasks = []
                for param in redirect_params:
                    test_url = f"{base_url}?{param}={evil_url}"
                    tasks.append(self._check_redirect(client, test_url, param, evil_url))

                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        findings.append(result)

            except httpx.RequestError as e:
                print(f"Error fetching base URL {base_url}: {e}")

        print(f"[*] Finished Open Redirect scan for {base_url}.")
        return findings

    async def _check_redirect(self, client: httpx.AsyncClient, test_url: str, param: str, evil_url: str) -> Optional[Finding]:
        try:
            response = await client.get(test_url)
            # Check for 3xx redirect status codes
            if 300 <= response.status_code < 400:
                location = response.headers.get("location")
                if location and evil_url in location: # Check if the redirect points to our evil URL
                    return Finding(
                        id=str(uuid.uuid4()),
                        vulnerability_type="Open Redirect",
                        description=f"Open redirect vulnerability detected. The URL redirects to an external malicious site: {location}",
                        severity=Severity.HIGH,
                        affected_url=test_url,
                        remediation="Ensure all redirect functionalities validate the destination URL against a whitelist of allowed domains. Do not rely on blacklisting or user-supplied input directly for redirects.",
                        owasp_category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL, # Could also be A04: Insecure Design
                        proof={
                            "test_url": test_url,
                            "parameter": param,
                            "injected_payload": evil_url,
                            "redirect_status": response.status_code,
                            "redirect_location": location
                        }
                    )
        except httpx.RequestError as e:
            print(f"Error checking redirect for {test_url}: {e}")
        return None 