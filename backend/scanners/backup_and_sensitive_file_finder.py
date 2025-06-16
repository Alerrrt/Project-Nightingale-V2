import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from urllib.parse import urljoin

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory

class BackupAndSensitiveFileFinderScanner(BaseScanner):
    """
    A scanner module for finding exposed backup and sensitive configuration files.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously attempts to find common backup and sensitive files.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for discovered files.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Backup & Sensitive File scan for {target_url}...")

        # Common backup and sensitive file patterns
        common_files = [
            "/index.php.bak", "/index.html.bak", "/wp-config.php.bak",
            "/config.bak", "/config.old",
            "/.env", "/.env.bak",
            "/database.sql", "/backup.sql",
            "/.git/config", "/.git/HEAD",
            "/docker-compose.yml", "/Dockerfile",
            "/web.config.bak", # IIS related
            "/admin.bak", "/user.sql",
            "/config.json.bak", "/credentials.txt",
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            tasks = []
            for file_path in common_files:
                full_url = urljoin(target_url, file_path)
                tasks.append(self._check_file_existence(client, full_url, file_path))

            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    findings.append(result)

        print(f"[*] Finished Backup & Sensitive File scan for {target_url}.")
        return findings

    async def _check_file_existence(self, client: httpx.AsyncClient, url: str, file_path: str) -> Optional[Finding]:
        try:
            response = await client.get(url, timeout=5)
            if response.status_code == 200:
                return Finding(
                    id=str(uuid.uuid4()),
                    vulnerability_type="Exposed Sensitive File",
                    description=f"Potentially sensitive file '{file_path}' found publicly accessible. Status code: {response.status_code}",
                    severity=Severity.HIGH,
                    affected_url=url,
                    remediation="Remove or restrict access to sensitive files and backups. Do not store sensitive information in publicly accessible locations.",
                    owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                    proof={
                        "url": url,
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                        "file_path_attempted": file_path
                    }
                )
            # Do not return a finding for 404 or other expected errors
        except httpx.RequestError as e:
            print(f"Error checking file {url}: {e}")
        return None 