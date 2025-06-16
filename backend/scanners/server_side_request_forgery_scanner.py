import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from urllib.parse import urlparse, urlencode, parse_qs

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class ServerSideRequestForgeryScanner(BaseScanner):
    """
    A scanner module for detecting Server-Side Request Forgery (SSRF) vulnerabilities.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously sends controlled payloads to detect SSRF endpoints.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected SSRF vulnerabilities.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Server-Side Request Forgery scan for {target_url}...")

        # Example internal/local IP addresses and domains to test for SSRF
        ssrf_payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://169.254.169.254/latest/meta-data/", # AWS EC2 Metadata service
            "http://metadata.google.internal/computeMetadata/v1/instance/", # Google Cloud Metadata service
            "file:///etc/passwd",
            "file:///C:/Windows/System32/drivers/etc/hosts",
            # More complex payloads involving URL parsers, redirects, etc. would go here
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            tasks = []
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)

            # Iterate through existing query parameters and inject payloads
            for param, values in query_params.items():
                for payload in ssrf_payloads:
                    new_query = query_params.copy()
                    new_query[param] = [payload] # Replace parameter value with SSRF payload
                    test_url = parsed_url._replace(query=urlencode(new_query, doseq=True)).geturl()
                    tasks.append(self._check_ssrf(client, test_url, payload, param))

            # Also test common parameters if not present in the URL (e.g., 'url', 'image')
            common_ssrf_params = ["url", "image", "file", "path", "link"]
            for param in common_ssrf_params:
                if param not in query_params:
                    for payload in ssrf_payloads:
                        new_query = query_params.copy()
                        new_query[param] = [payload]
                        test_url = parsed_url._replace(query=urlencode(new_query, doseq=True)).geturl()
                        tasks.append(self._check_ssrf(client, test_url, payload, param))

            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    findings.append(result)

        print(f"[*] Finished Server-Side Request Forgery scan for {target_url}.")
        return findings

    async def _check_ssrf(self, client: httpx.AsyncClient, test_url: str, payload: str, param: str) -> Optional[Finding]:
        try:
            response = await client.get(test_url)
            # This is a very basic check. Real SSRF detection requires:
            # - Monitoring server-side errors indicating internal network access.
            # - Analyzing response content for internal system information (e.g., file contents, metadata).
            # - Detecting successful connections to controlled external servers (OOB interactions).
            if "root:x:0:0:" in response.text.lower() or "access denied" in response.text.lower() or "metadata" in response.text.lower():
                return Finding(
                    id=str(uuid.uuid4()),
                    vulnerability_type="Server-Side Request Forgery (SSRF)",
                    description=f"Potential SSRF vulnerability detected by injecting '{payload}' into parameter '{param}'. Server responded with content that suggests internal resource access or error.",
                    severity=Severity.CRITICAL,
                    affected_url=test_url,
                    remediation="Implement strict input validation for all URLs and paths provided by users. Whitelist allowed schemes, hosts, and protocols. Do not allow redirects to arbitrary URLs.",
                    owasp_category=OwaspCategory.A10_SERVER_SIDE_REQUEST_FORGERY_SSRF,
                    proof={
                        "test_url": test_url,
                        "parameter": param,
                        "injected_payload": payload,
                        "response_status": response.status_code,
                        "response_snippet": response.text[:200] # Provide a snippet of the response
                    }
                )
            # You might also look for specific status codes (e.g., 200 for internal files, 403 for denied access to internal resources)
        except httpx.RequestError as e:
            # Connection errors could indicate internal network access attempts that failed externally
            if isinstance(e, httpx.ConnectError) and ("127.0.0.1" in payload or "localhost" in payload):
                print(f"Possible SSRF: Connection error to internal payload {payload} for {test_url}: {e}")
                return Finding(
                    id=str(uuid.uuid4()),
                    vulnerability_type="Server-Side Request Forgery (SSRF) - Connection Error",
                    description=f"Possible SSRF vulnerability detected. An attempt to connect to internal host '{payload}' via parameter '{param}' resulted in a connection error, which could indicate the server tried to access it internally.",
                    severity=Severity.HIGH,
                    affected_url=test_url,
                    remediation="Implement strict input validation for all URLs and paths provided by users. Whitelist allowed schemes, hosts, and protocols. Do not allow redirects to arbitrary URLs.",
                    owasp_category=OwaspCategory.A10_SERVER_SIDE_REQUEST_FORGERY_SSRF,
                    proof={
                        "test_url": test_url,
                        "parameter": param,
                        "injected_payload": payload,
                        "error_message": str(e)
                    }
                )
            print(f"Error checking SSRF for {test_url}: {e}")
        return None 