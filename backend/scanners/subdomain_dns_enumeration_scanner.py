import asyncio
import uuid
from typing import List, Optional, Dict, Any
from backend.utils import get_http_client
from urllib.parse import urlparse
import dns.resolver
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from backend.scanners.base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class SubdomainDNSEnumerationScanner(BaseScanner):
    """
    A scanner module for discovering subdomains via brute-force and DNS lookups.
    """

    metadata = {
        "name": "Subdomain DNS Enumeration",
        "description": "Discovers subdomains via brute-force and DNS lookups.",
        "owasp_category": "A06:2021 - Security Misconfiguration",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="subdomain_dns_enum_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        start_time = datetime.now()
        scan_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        try:
            logger.info("Scan started", extra={
                "scanner": self.__class__.__name__,
                "scan_id": scan_id,
                "target": scan_input.target,
                "options": scan_input.options
            })
            results = await self._perform_scan(scan_input.target, scan_input.options or {})
            self._update_metrics(True, start_time)
            logger.info("Scan completed", extra={
                "scanner": self.__class__.__name__,
                "scan_id": scan_id,
                "target": scan_input.target,
                "result_count": len(results)
            })
            return results
        except Exception as e:
            self._update_metrics(False, start_time)
            logger.error("Scan failed", extra={
                "scanner": self.__class__.__name__,
                "scan_id": scan_id,
                "target": scan_input.target,
                "error": str(e)
            }, exc_info=True)
            raise

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Asynchronously uses a wordlist to discover additional subdomains and identifies them.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for discovered subdomains.
        """
        findings: List[Dict] = []
        target_url = target
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        logger.info(f"Starting Subdomain & DNS Enumeration scan for {domain}.")

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

        logger.info(f"Finished Subdomain & DNS Enumeration scan for {domain}.")
        return findings

    async def _check_subdomain(self, subdomain: str, base_url: str) -> Optional[Dict]:
        try:
            # Try to resolve the DNS record for the subdomain
            answers = dns.resolver.resolve(subdomain, 'A')
            ip_address = answers[0].address
            logger.info(f"Found subdomain: {subdomain} -> {ip_address}")

            # Optionally, make an HTTP request to confirm it's an active web host
            try:
                async with get_http_client(follow_redirects=True, timeout=5) as client:
                    # Construct a URL for the subdomain, preserving scheme from original target
                    subdomain_url = f"{urlparse(base_url).scheme}://{subdomain}"
                    response = await client.get(subdomain_url)
                    if response.status_code < 500:
                        return {
                            "type": "subdomain_discovered",
                            "severity": Severity.INFO,
                            "title": "Subdomain Discovered",
                            "description": f"Active subdomain '{subdomain}' resolved to IP '{ip_address}' and returned HTTP status '{response.status_code}'.",
                            "evidence": {
                                "subdomain": subdomain,
                                "resolved_ip": ip_address,
                                "http_status": response.status_code,
                                "response_snippet": response.text[:100]
                            },
                            "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                            "recommendation": "Review this subdomain for unintended exposures or vulnerabilities. Ensure it's properly configured and secured.",
                            "affected_url": subdomain_url
                        }
            except Exception as e:
                logger.warning(f"HTTP request failed for {subdomain}", extra={"error": str(e)})
                return {
                    "type": "subdomain_discovered_http_unreachable",
                    "severity": Severity.INFO,
                    "title": "Subdomain Discovered (HTTP Unreachable)",
                    "description": f"Active subdomain '{subdomain}' resolved to IP '{ip_address}' but was unreachable via HTTP. Could indicate internal network resource.",
                    "evidence": {
                        "subdomain": subdomain,
                        "resolved_ip": ip_address,
                        "error": str(e)
                    },
                    "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                    "recommendation": "Investigate internal network exposure for this subdomain.",
                    "affected_url": f"http://{subdomain}"
                }

        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.LifetimeTimeout:
            logger.warning(f"DNS query timed out for {subdomain}")
        except Exception as e:
            logger.error(f"Error checking subdomain {subdomain}", extra={"error": str(e)})
        return None

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Subdomain DNS Enumeration Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
