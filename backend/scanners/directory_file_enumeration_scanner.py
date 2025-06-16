import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory

class DirectoryFileEnumerationScanner(BaseScanner):
    """
    A scanner module for brute-forcing common paths to uncover hidden or forgotten resources.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously attempts to discover hidden directories and files.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for discovered resources.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Directory and File Enumeration scan for {target_url}...")

        # Common paths to brute-force
        common_paths = [
            "/admin", "/dashboard", "/login",
            "/backup.zip", "/backup.tar.gz", "/old.zip",
            "/.git/config", "/.env", "/docker-compose.yml",
            "/robots.txt", "/sitemap.xml",
            "/wp-admin", "/wp-login.php", # Common WordPress paths
            "/phpmyadmin",
            "/config.php", "/credentials.txt",
            "/test/", "/dev/", "/old/"
        ]

        async with httpx.AsyncClient(follow_redirects=True) as client:
            tasks = []
            for path in common_paths:
                full_url = f"{target_url.rstrip('/')}{path}"
                tasks.append(self._check_path(client, full_url, path))

            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    findings.append(result)

        print(f"[*] Finished Directory and File Enumeration scan for {target_url}.")
        return findings

    async def _check_path(self, client: httpx.AsyncClient, url: str, path: str) -> Optional[Finding]:
        try:
            response = await client.get(url, timeout=5)
            if response.status_code == 200:
                # Basic check for common directory listing indicators
                if "<title>Index of" in response.text or "Directory Listing For" in response.text:
                    return Finding(
                        id=str(uuid.uuid4()),
                        vulnerability_type="Directory Listing Enabled",
                        description=f"Directory listing enabled at {path}, potentially exposing sensitive files or directory structure.",
                        severity=Severity.MEDIUM,
                        affected_url=url,
                        remediation="Disable directory listing on your web server for this path.",
                        owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                        proof={"url": url, "status_code": response.status_code, "indicator": "Directory listing HTML"}
                    )
                else:
                    return Finding(
                        id=str(uuid.uuid4()),
                        vulnerability_type="Hidden Resource Found",
                        description=f"Potentially hidden resource found at {path}. Status code: {response.status_code}",
                        severity=Severity.LOW, # Could be Medium/High depending on content
                        affected_url=url,
                        remediation="Review the contents of this resource and ensure it\'s not publicly accessible if sensitive.",
                        owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                        proof={"url": url, "status_code": response.status_code, "response_length": len(response.text)}
                    )
            elif response.status_code in [401, 403]:
                return Finding(
                    id=str(uuid.uuid4()),
                    vulnerability_type="Access Controlled Resource Found",
                    description=f"Resource at {path} exists but requires authentication or is forbidden (Status: {response.status_code}).",
                    severity=Severity.INFO,
                    affected_url=url,
                    remediation="Review access controls for this resource.",
                    owasp_category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
                    proof={"url": url, "status_code": response.status_code}
                )
            # Do not return a finding for 404 or other expected errors
        except httpx.RequestError as e:
            print(f"Error checking path {url}: {e}")
        return None 