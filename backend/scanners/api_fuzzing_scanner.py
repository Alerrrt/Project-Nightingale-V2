import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
import json
from urllib.parse import urljoin

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog

class ApiFuzzingScanner(BaseScanner):
    """
    A scanner module for fuzzing JSON API endpoints to detect unhandled errors.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously fuzzes JSON API endpoints with various payloads.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected API vulnerabilities.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting API Fuzzing scan for {target_url}...")

        # Simple placeholder fuzzing payloads
        fuzzing_payloads = {
            "string_overflow": "A" * 5000,
            "sql_injection": "' OR 1=1-- ",
            "xss": "<script>alert('XSS')</script>",
            "command_injection": "; ls -la;",
            "format_string": "%n%n%n%n%n%n%n%n%n%n%n%n",
            "negative_number": -1,
            "large_number": 99999999999999999999,
            "empty_value": "",
            "null_value": None,
        }

        # Discover JSON endpoints (very basic placeholder)
        # A real scanner would crawl, analyze Swagger/OpenAPI docs, or use a proxy.
        potential_json_endpoints = [
            f"{target_url}/api/v1/data",
            f"{target_url}/api/items",
            f"{target_url}/users/create",
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            tasks = []
            for endpoint in potential_json_endpoints:
                for payload_name, payload_value in fuzzing_payloads.items():
                    test_data = {"test_field": payload_value} # Simulate a generic JSON field
                    if payload_value is None:
                        # For None payload, ensure it's handled as JSON null
                        json_payload = json.dumps({"test_field": None})
                    else:
                        json_payload = json.dumps(test_data)

                    headers = {"Content-Type": "application/json"}
                    tasks.append(self._fuzz_endpoint(client, endpoint, json_payload, headers, payload_name))

            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    findings.append(result)

        print(f"[*] Finished API Fuzzing scan for {target_url}.")
        return findings

    async def _fuzz_endpoint(self, client: httpx.AsyncClient, url: str, payload: str, headers: Dict[str, str], payload_type: str) -> Optional[Finding]:
        try:
            response = await client.post(url, headers=headers, content=payload, timeout=5)
            
            # Look for indicators of unhandled errors or unexpected behavior
            if response.status_code >= 500 or "error" in response.text.lower() or "exception" in response.text.lower():
                return Finding(
                    id=str(uuid.uuid4()),
                    vulnerability_type=f"API Fuzzing: Unhandled Error ({payload_type})",
                    description=f"API endpoint '{url}' responded with an error (Status: {response.status_code}) or unusual content when fuzzed with '{payload_type}' payload. This could indicate a vulnerability or poor error handling.",
                    severity=Severity.MEDIUM, # Severity depends on the error and potential exploitability
                    affected_url=url,
                    remediation="Implement robust input validation and error handling for all API endpoints. Avoid exposing sensitive error messages or stack traces.",
                    owasp_category=OwaspCategory.A09_SECURITY_LOGGING_AND_MONITORING_FAILURES, # Or A04 Insecure Design
                    proof={
                        "test_url": url,
                        "payload_type": payload_type,
                        "sent_payload_snippet": payload[:100],
                        "response_status": response.status_code,
                        "response_snippet": response.text[:200]
                    }
                )
        except httpx.RequestError as e:
            print(f"Error fuzzing endpoint {url} with {payload_type} payload: {e}")
        return None 