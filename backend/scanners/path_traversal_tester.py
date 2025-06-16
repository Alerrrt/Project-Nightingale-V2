import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from urllib.parse import urljoin

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory

class PathTraversalTesterScanner(BaseScanner):
    """
    A scanner module for detecting path traversal vulnerabilities.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously appends payloads to detect directory traversal flaws.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected path traversal vulnerabilities.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Path Traversal scan for {target_url}...")

        # Common path traversal payloads for various OS
        path_traversal_payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", # URL encoded
            "..%2f..%2f..%2f..%2fwindows/win.ini", # Double URL encoded
            "....//....//....//....//etc/passwd", # Unicode bypass
            "/etc/passwd%00.jpg", # Null byte bypass
            "\x00..\x00..\x00/etc/passwd", # Non-standard encoding
            # Add more variations and OS-specific paths
        ]

        # Common parameters that might be vulnerable
        common_params = ["file", "path", "page", "doc", "view", "filename"]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            tasks = []
            for param in common_params:
                for payload in path_traversal_payloads:
                    # Attempt to inject into query parameters
                    test_url_query = f"{target_url}?{param}={payload}"
                    tasks.append(self._check_path_traversal(client, test_url_query, param, payload))

                    # Attempt to inject into path segments (requires more sophisticated URL manipulation)
                    # For simplicity, we'll focus on query parameters first.

            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    findings.append(result)

        print(f"[*] Finished Path Traversal scan for {target_url}.")
        return findings

    async def _check_path_traversal(self, client: httpx.AsyncClient, test_url: str, param: str, payload: str) -> Optional[Finding]:
        try:
            response = await client.get(test_url)

            # Very basic check: look for content that suggests file exposure
            # In a real scanner, you'd verify against known file contents (e.g., "root:x:", "[fonts]")
            if "root:x:0:0:" in response.text.lower() or "for 16-bit app support" in response.text.lower():
                return Finding(
                    id=str(uuid.uuid4()),
                    vulnerability_type="Path Traversal",
                    description=f"Potential Path Traversal vulnerability detected by injecting '{payload}' into parameter '{param}'. Server responded with content that suggests file exposure.",
                    severity=Severity.HIGH,
                    affected_url=test_url,
                    remediation="Implement strict input validation and sanitization for all file and path-related inputs. Use whitelisting for allowed file types and directories. Do not concatenate user input directly into file paths.",
                    owasp_category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL, # Or A08: Software and Data Integrity Failures
                    proof={
                        "test_url": test_url,
                        "parameter": param,
                        "injected_payload": payload,
                        "response_status": response.status_code,
                        "response_snippet": response.text[:200]
                    }
                )
            # You might also look for specific status codes (e.g., 200 for successful file access, 400 for errors indicating payload was processed)
        except httpx.RequestError as e:
            print(f"Error checking path traversal for {test_url}: {e}")
        return None 