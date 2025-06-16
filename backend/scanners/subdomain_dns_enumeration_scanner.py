import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from urllib.parse import urlparse
import dns.resolver

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory

class SubdomainDNSEnumerationScanner(BaseScanner):
    """
    A scanner module for discovering subdomains via brute-force and DNS lookups.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously uses a wordlist to discover additional subdomains and identifies them.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for discovered subdomains.
        """
        findings: List[Finding] = []
        target_url = target
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        print(f"[*] Starting Subdomain & DNS Enumeration scan for {domain}...")

        # Basic subdomain wordlist
        subdomains_wordlist = [
            "www", "mail", "api", "dev", "test", "admin", "blog",
            "shop", "cdn", "beta", "staging", "webmail", "ftp"
        ]

        tasks = []
        for sub in subdomains_wordlist:
            full_subdomain = f"{sub}.{domain}"
            tasks.append(self._check_subdomain(full_subdomain, target_url))

        results = await asyncio.gather(*tasks)
        for result in results:
            if result:
                findings.append(result)

        print(f"[*] Finished Subdomain & DNS Enumeration scan for {domain}.")
        return findings

    async def _check_subdomain(self, subdomain: str, base_url: str) -> Optional[Finding]:
        try:
            # Try to resolve the DNS record for the subdomain
            answers = dns.resolver.resolve(subdomain, 'A')
            ip_address = answers[0].address
            print(f"Found subdomain: {subdomain} -> {ip_address}")

            # Optionally, make an HTTP request to confirm it's an active web host
            try:
                async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
                    # Construct a URL for the subdomain, preserving scheme from original target
                    subdomain_url = f"{urlparse(base_url).scheme}://{subdomain}"
                    response = await client.get(subdomain_url)
                    if response.status_code < 500: # Consider 5xx as potentially active but erroring
                        return Finding(
                            id=str(uuid.uuid4()),
                            vulnerability_type="Subdomain Discovered",
                            description=f"Active subdomain '{subdomain}' resolved to IP '{ip_address}' and returned HTTP status '{response.status_code}'.",
                            severity=Severity.INFO,
                            affected_url=subdomain_url,
                            remediation="Review this subdomain for unintended exposures or vulnerabilities. Ensure it's properly configured and secured.",
                            owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION, # Or A06 if it's an outdated component
                            proof={
                                "subdomain": subdomain,
                                "resolved_ip": ip_address,
                                "http_status": response.status_code,
                                "response_snippet": response.text[:100]
                            }
                        )
            except httpx.RequestError as e:
                print(f"HTTP request failed for {subdomain_url}: {e}")
                # Still return finding if DNS resolved but HTTP failed, indicating potential internal resource
                return Finding(
                    id=str(uuid.uuid4()),
                    vulnerability_type="Subdomain Discovered (HTTP Unreachable)",
                    description=f"Active subdomain '{subdomain}' resolved to IP '{ip_address}' but was unreachable via HTTP. Could indicate internal network resource.",
                    severity=Severity.INFO,
                    affected_url=f"http://{subdomain}",
                    remediation="Investigate internal network exposure for this subdomain.",
                    owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                    proof={
                        "subdomain": subdomain,
                        "resolved_ip": ip_address,
                        "error": str(e)
                    }
                )

        except dns.resolver.NXDOMAIN: # No such domain
            pass # Subdomain does not exist
        except dns.resolver.LifetimeTimeout: # DNS query timed out
            print(f"DNS query timed out for {subdomain}")
        except Exception as e:
            print(f"Error checking subdomain {subdomain}: {e}")
        return None 