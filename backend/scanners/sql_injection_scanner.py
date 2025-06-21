import re
import httpx
from typing import List, Dict
import logging
import asyncio

from backend.scanners.base_scanner import BaseScanner
from backend.types.models import ScanInput, Severity, OwaspCategory
from backend.utils.circuit_breaker import circuit_breaker

logger = logging.getLogger(__name__)


class SqlInjectionScanner(BaseScanner):
    """
    A scanner module for detecting SQL Injection vulnerabilities.
    """

    metadata = {
        "name": "SQL Injection Scanner",
        "description": "Detects SQL Injection vulnerabilities by sending common attack payloads.",
        "owasp_category": OwaspCategory.A03_INJECTION,
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    SQLI_PAYLOADS = [
        "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
        '" OR "1"="1"', '" OR "1"="1"--', '" OR 1=1--',
        "admin'--", "admin' #", "admin'/*",
        "' OR 'x'='x",
    ]
    TIME_BASED_PAYLOADS = [
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; WAITFOR DELAY '0:0:5'--",
    ]
    NORMAL_TIMEOUT = 5
    TIME_BASED_TIMEOUT = 10

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="sql_injection_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        """
        This is the entry point for the scanner. It will delegate to the
        private _perform_scan method. The boilerplate for logging, metrics,
        and broadcasting is handled by higher-level components.
        """
        return await self._perform_scan(scan_input.target, scan_input.options or {})

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        findings = []
        error_patterns = [
            r"sql syntax", r"mysql", r"unclosed quotation mark",
            r"odbc", r"oracle", r"microsoft ole db",
        ]

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=self.TIME_BASED_TIMEOUT) as client:
                response = await client.get(target)
                content = response.text

                forms = re.findall(r'<form[^>]*>.*?</form>', content, re.DOTALL)
                for form_html in forms:
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html)
                    method_match = re.search(r'method=["\']([^"\']*)["\']', form_html)
                    action = action_match.group(1) if action_match else ''
                    method = method_match.group(1).upper() if method_match else 'GET'
                    
                    form_url = str(httpx.URL(target).join(action))

                    inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', form_html)
                    
                    for param_name in inputs:
                        # Error-based checks
                        for payload in self.SQLI_PAYLOADS:
                            data = {input_name: 'test' for input_name in inputs}
                            data[param_name] = payload

                            try:
                                if method == 'POST':
                                    test_response = await client.post(form_url, data=data, timeout=self.NORMAL_TIMEOUT)
                                else:
                                    test_response = await client.get(form_url, params=data, timeout=self.NORMAL_TIMEOUT)

                                for pattern in error_patterns:
                                    if re.search(pattern, test_response.text, re.IGNORECASE):
                                        findings.append(self._create_finding(form_url, param_name, payload, "error-based", test_response.text))
                                        break
                            except httpx.RequestError as e:
                                logger.warning(f"Request failed for error-based SQLi check: {e}")
                        
                        # Time-based checks
                        for payload in self.TIME_BASED_PAYLOADS:
                            data = {input_name: 'test' for input_name in inputs}
                            data[param_name] = payload

                            try:
                                start_time = asyncio.get_event_loop().time()
                                if method == 'POST':
                                    await client.post(form_url, data=data, timeout=self.TIME_BASED_TIMEOUT)
                                else:
                                    await client.get(form_url, params=data, timeout=self.TIME_BASED_TIMEOUT)
                                end_time = asyncio.get_event_loop().time()

                                if (end_time - start_time) >= 4.5:
                                    findings.append(self._create_finding(form_url, param_name, payload, "time-based", f"Response time: {end_time - start_time:.2f}s"))
                                    break
                            except httpx.TimeoutException:
                                findings.append(self._create_finding(form_url, param_name, payload, "time-based-timeout", f"Request timed out after {self.TIME_BASED_TIMEOUT}s"))
                                break
                            except httpx.RequestError as e:
                                logger.warning(f"Request failed for time-based SQLi check: {e}")

        except httpx.RequestError as e:
            logger.error(f"Failed to fetch target URL {target}: {e}")

        return findings

    def _create_finding(self, url: str, param: str, payload: str, method: str, evidence: str) -> Dict:
        return {
            "type": "sql_injection",
            "severity": Severity.HIGH,
            "title": f"Potential SQL Injection ({method})",
            "description": f"A potential SQL injection vulnerability was found in the '{param}' parameter using a {method} check.",
            "location": url,
            "evidence": f"Payload: {payload}, Evidence: {evidence}",
            "confidence": "Medium" if "time-based" in method else "High",
            "owasp_category": OwaspCategory.A03_INJECTION,
            "remediation": "Use parameterized queries (prepared statements) to prevent user input from being interpreted as SQL commands."
        }