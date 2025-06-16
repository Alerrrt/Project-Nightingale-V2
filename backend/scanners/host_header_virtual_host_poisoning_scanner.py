import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from urllib.parse import urlparse

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class HostHeaderVirtualHostPoisoningScanner(BaseScanner):
    """
    A scanner module for detecting Host Header and Virtual Host Poisoning vulnerabilities.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously swaps the Host: header to evil.com or 127.0.0.1 and watches for odd behavior.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected Host Header/Virtual Host Poisoning vulnerabilities.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Host Header and Virtual Host Poisoning scan for {target_url}...")

        # Common malicious Host headers to test
        evil_hosts = [
            "evil.com",
            "127.0.0.1",
            "localhost",
            "example.com:8080", # Port-specific
            "www.attacker.com",
            f"{urlparse(target_url).netloc}:8080", # Original host with different port
            "[::1]", # IPv6 localhost
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            tasks = []
            for evil_host in evil_hosts:
                tasks.append(self._check_host_header_poisoning(client, target_url, evil_host))

            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    findings.append(result)

        print(f"[*] Finished Host Header and Virtual Host Poisoning scan for {target_url}.")
        return findings

    async def _check_host_header_poisoning(self, client: httpx.AsyncClient, target_url: str, evil_host: str) -> Optional[Finding]:
        try:
            headers = {"Host": evil_host}
            response = await client.get(target_url, headers=headers)

            # This is a highly simplified check. Real detection involves:
            # - Analyzing redirects (e.g., redirecting to evil.com with correct path)
            # - Analyzing response content for reflected evil_host (e.g., in links, absolute URLs)
            # - Cache poisoning indicators (e.g., different content served based on Host header in cached response)
            # - Server-side errors or unexpected behavior

            # Check for reflection of the evil host in the response body or Location header
            if evil_host in response.text or (response.headers.get("location") and evil_host in response.headers["location"]):
                if response.status_code == 200 or 300 <= response.status_code < 400: # Check for successful responses or redirects
                    return Finding(
                        id=str(uuid.uuid4()),
                        vulnerability_type="Host Header Injection/Virtual Host Poisoning",
                        description=f"Potential Host Header Injection or Virtual Host Poisoning detected. The injected Host header '{evil_host}' was reflected in the response or caused an unexpected redirect.",
                        severity=Severity.HIGH,
                        affected_url=target_url,
                        remediation="Ensure the application explicitly validates the Host header against a whitelist of allowed domains or uses the original request's Host header only for internal routing, not for generating absolute URLs or redirects. Prevent caching mechanisms from caching responses based on arbitrary Host headers.",
                        owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION, # Can also be A01 Broken Access Control or A04 Insecure Design
                        proof={
                            "test_url": target_url,
                            "injected_host_header": evil_host,
                            "response_status": response.status_code,
                            "response_snippet": response.text[:200],
                            "location_header": response.headers.get("location"),
                            "reflection_found": True
                        }
                    )
            elif response.status_code == 400: # Sometimes a 400 Bad Request can indicate header processing issues
                print(f"Received 400 Bad Request for Host: {evil_host} on {target_url}")
                # Consider if this warrants a low severity info finding, or just debug log.

        except httpx.RequestError as e:
            print(f"Error checking Host Header poisoning for {target_url} with Host {evil_host}: {e}")
        return None 