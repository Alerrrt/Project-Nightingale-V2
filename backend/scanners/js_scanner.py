import asyncio
import uuid
import httpx
from urllib.parse import urljoin, urlparse
from typing import List, Optional, Dict, Any
import logging
from bs4 import BeautifulSoup

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog
from .js_scanner_utils import run_retire_js

logger = logging.getLogger(__name__)

class JsScanner(BaseScanner):
    """
    A scanner module for identifying known JavaScript library vulnerabilities
    using retire.js.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Crawls the target URL for JavaScript files, downloads them,
        and scans them using retire.js.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for identified JS library vulnerabilities.
        """
        findings: List[Finding] = []
        target_url = target
        base_domain = urlparse(target_url).netloc
        logger.info(f"[*] Starting JavaScript Library scan for {target_url}...")

        discovered_js_urls = set()

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
                # 1. Crawl the given target URL for all <script src="…">
                logger.debug(f"Fetching HTML from {target_url}")
                try:
                    response = await client.get(target_url)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'lxml')
                    
                    for script_tag in soup.find_all('script', src=True):
                        src = script_tag['src']
                        full_js_url = urljoin(target_url, src)
                        
                        # Basic check to ensure it's a valid HTTP/S URL and same domain
                        parsed_js_url = urlparse(full_js_url)
                        if parsed_js_url.scheme in ['http', 'https'] and (parsed_js_url.netloc == base_domain or not parsed_js_url.netloc):
                            discovered_js_urls.add(full_js_url)
                            logger.debug(f"Discovered JS URL: {full_js_url}")
                except httpx.RequestError as e:
                    logger.warning(f"Could not fetch {target_url} for JS links: {e}")
                except Exception as e:
                    logger.error(f"Error parsing HTML for JS links from {target_url}: {e}", exc_info=True)

                js_download_tasks = []
                for js_url in discovered_js_urls:
                    js_download_tasks.append(self._download_js_file(client, js_url))
                
                downloaded_js_files = await asyncio.gather(*js_download_tasks)

                retire_scan_tasks = []
                for js_url, js_content in downloaded_js_files:
                    if js_content:
                        retire_scan_tasks.append(self._scan_js_content_with_retire(js_url, js_content))
                
                retire_results = await asyncio.gather(*retire_scan_tasks)

                for result_list in retire_results:
                    for retire_finding in result_list:
                        if retire_finding:
                            mapped_finding = self._map_retire_to_finding(retire_finding)
                            if mapped_finding:
                                findings.append(mapped_finding)

        except Exception as e:
            logger.error(f"An unexpected error occurred during JavaScript scan of {target_url}: {e}", exc_info=True)

        logger.info(f"[*] Finished JavaScript Library scan for {target_url}. Found {len(findings)} findings.")
        return findings

    async def _download_js_file(self, client: httpx.AsyncClient, js_url: str) -> tuple[str, Optional[str]]:
        """
        Downloads a JavaScript file, skipping if it's larger than 1MB.
        Returns the URL and content, or None if skipped/failed.
        """
        MAX_JS_FILE_SIZE = 1 * 1024 * 1024 # 1 MB
        try:
            logger.debug(f"Downloading JS file: {js_url}")
            # Use stream=True to check content-length before downloading entire file
            async with client.stream("GET", js_url, timeout=10) as response:
                response.raise_for_status()
                content_length = response.headers.get('content-length')
                if content_length and int(content_length) > MAX_JS_FILE_SIZE:
                    logger.warning(f"Skipping large JS file ({int(content_length)/1024/1024:.2f} MB): {js_url}")
                    return js_url, None
                
                js_content = await response.text()
                return js_url, js_content
        except httpx.RequestError as e:
            logger.warning(f"Could not download JS file {js_url}: {e}")
            return js_url, None
        except Exception as e:
            logger.error(f"Error downloading JS file {js_url}: {e}", exc_info=True)
            return js_url, None

    async def _scan_js_content_with_retire(self, js_url: str, js_content: str) -> List[dict]:
        """
        Runs retire.js on the JS content and returns its raw findings.
        Adds the original URL to each finding for context.
        """
        retire_findings = await run_retire_js(js_content)
        for finding in retire_findings:
            finding['affected_url_original'] = js_url # Add original URL for mapping
        return retire_findings

    def _map_retire_to_finding(self, retire_finding: Dict[str, Any]) -> Optional[Finding]:
        """
        Maps a single retire.js finding to our internal Finding model.
        """
        # Each entry in retire_output["data"] corresponds to a detected library
        # Each library can have multiple vulnerabilities
        # retire.js structure example:
        # {
        #   "file": "path/to/jquery.js",
        #   "results": [
        #     {
        #       "component": "jquery",
        #       "version": "1.11.0",
        #       "vulnerabilities": [
        #         {
        #           "severity": "low",
        #           "identifiers": {"CVE": ["CVE-2015-xxxx"]},
        #           "info": ["http://example.com/advisory"]
        #         }
        #       ]
        #     }
        #   ]
        # }

        file_path = retire_finding.get("file", "Unknown File")
        original_url = retire_finding.get("affected_url_original", file_path)

        for result in retire_finding.get("results", []):
            component = result.get("component", "Unknown Component")
            version = result.get("version", "Unknown Version")

            for vuln_data in result.get("vulnerabilities", []):
                severity_str = vuln_data.get("severity", "info").capitalize()
                mapped_severity = getattr(Severity, severity_str.upper(), Severity.INFO)
                
                cves = vuln_data.get("identifiers", {}).get("CVE", [])
                cve_id = cves[0] if cves else None

                advisories = vuln_data.get("info", [])
                advisory_link = advisories[0] if advisories else None

                summary = vuln_data.get("summary", "No summary provided.")

                # Construct description
                description = (
                    f"Vulnerable JavaScript library detected: {component} (Version: {version}). "
                    f"Details: {summary}"
                )

                # Technical details can include the full retire.js vulnerability object
                technical_details = json.dumps(vuln_data, indent=2)
                
                return Finding(
                    id=str(uuid.uuid4()),
                    vulnerability_type="Vulnerable JavaScript Library",
                    severity=mapped_severity,
                    description=description,
                    technical_details=technical_details,
                    remediation=(
                        f"Upgrade {component} to a non-vulnerable version. "
                        f"Consult advisory: {advisory_link}" if advisory_link else "Consult official documentation for {component}."
                    ),
                    owasp_category=OwaspCategory.A06_VULNERABLE_AND_OUTDATED_COMPONENTS,
                    affected_url=original_url,
                    proof={
                        "library": component,
                        "version": version,
                        "cves": cves,
                        "advisory_link": advisory_link,
                        "file_url": original_url
                    },
                    title=f"Vulnerable JS: {component} v{version}",
                    cwe_id=cve_id # Use CVE as CWE for simplicity here, though they are distinct
                )
        return None # Return None if no valid findings are mapped 