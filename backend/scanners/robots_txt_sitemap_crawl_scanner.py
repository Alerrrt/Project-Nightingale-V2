import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from urllib.parse import urljoin, urlparse
import re # Import re for regex operations 

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory

class RobotsTxtSitemapCrawlScanner(BaseScanner):
    """
    A scanner module for fetching /robots.txt and /sitemap.xml and extracting URLs.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously fetches /robots.txt and /sitemap.xml, extracts URLs, and identifies potential issues.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for discovered URLs or misconfigurations.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Robots.txt & Sitemap crawl for {target_url}...")

        base_domain = urlparse(target_url).netloc
        robots_txt_url = urljoin(target_url, "/robots.txt")
        sitemap_xml_url = urljoin(target_url, "/sitemap.xml")

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            # Fetch robots.txt
            try:
                robots_response = await client.get(robots_txt_url)
                if robots_response.status_code == 200:
                    print(f"[*] Found robots.txt at {robots_txt_url}")
                    # Basic parsing for Disallow directives
                    for line in robots_response.text.splitlines():
                        if line.lower().startswith("disallow:"):
                            disallowed_path = line.split(':', 1)[1].strip()
                            if disallowed_path and disallowed_path != '/':
                                findings.append(
                                    Finding(
                                        id=str(uuid.uuid4()),
                                        vulnerability_type="Disallowed Path in robots.txt",
                                        description=f"A disallowed path '{disallowed_path}' was found in robots.txt. This might indicate sensitive areas that developers tried to hide from search engines but are still publicly accessible.",
                                        severity=Severity.INFO,
                                        affected_url=robots_txt_url,
                                        remediation="Ensure sensitive areas are protected by proper authentication and authorization, not just by robots.txt directives.",
                                        owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                                        proof={
                                            "robots_txt_url": robots_txt_url,
                                            "disallowed_path": disallowed_path,
                                            "details": "robots.txt is for crawler guidance, not security."
                                        }
                                    )
                                )
                else:
                    print(f"robots.txt not found or error: {robots_response.status_code}")

            except httpx.RequestError as e:
                print(f"Error fetching robots.txt: {e}")

            # Fetch sitemap.xml
            try:
                sitemap_response = await client.get(sitemap_xml_url)
                if sitemap_response.status_code == 200:
                    print(f"[*] Found sitemap.xml at {sitemap_xml_url}")
                    # Basic parsing for URLs in sitemap (very simplistic, might need XML parsing library)
                    # Example: <loc>http://www.example.com/page.html</loc>
                    url_pattern = r"<loc>(.*?)</loc>"
                    found_urls = re.findall(url_pattern, sitemap_response.text)
                    for url in found_urls:
                        # For now, just log them. In a real scenario, these would be fed to other scanners.
                        print(f"Extracted URL from sitemap: {url}")
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="URL Discovered via sitemap.xml",
                                description=f"A URL '{url}' was discovered in the sitemap.xml file.",
                                severity=Severity.INFO,
                                affected_url=sitemap_xml_url,
                                remediation="Review all URLs exposed in sitemap.xml to ensure they are intended for public access and are properly secured.",
                                owasp_category=OwaspCategory.UNKNOWN,
                                proof={
                                    "sitemap_url": sitemap_xml_url,
                                    "discovered_url": url
                                }
                            )
                        )
                else:
                    print(f"sitemap.xml not found or error: {sitemap_response.status_code}")
            except httpx.RequestError as e:
                print(f"Error fetching sitemap.xml: {e}")

        print(f"[*] Finished Robots.txt & Sitemap crawl for {target_url}.")
        return findings 