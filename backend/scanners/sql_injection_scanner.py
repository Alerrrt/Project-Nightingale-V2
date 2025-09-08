import re
import httpx
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
import asyncio

from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils import get_http_client
from backend.utils.crawler import seed_urls

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
    # Will be formatted with a delay integer seconds
    TIME_BASED_PAYLOAD_TEMPLATES = [
        "' AND SLEEP({d})--",
        "' AND (SELECT * FROM (SELECT(SLEEP({d})))a)--",
        "'; WAITFOR DELAY '0:0:{d}'--",
    ]
    NORMAL_TIMEOUT_DEFAULT = 5
    TIME_BASED_TIMEOUT_DEFAULT = 10

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="sql_injection_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        try:
            return await self._perform_scan(scan_input.target, scan_input.options or {})
        except Exception as e:
            logger.error(f"SQL Injection scan failed: {e}", exc_info=True)
            return [self._create_error_finding(f"SQL Injection scan failed: {e}")]

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        findings: List[Dict] = []
        # Expanded error patterns across engines
        error_patterns = [
            r"sql syntax", r"mysql", r"unclosed quotation mark",
            r"odbc", r"oracle", r"microsoft ole db", r"postgres", r"psql",
            r"sqlite", r"sql server", r"you have an error in your sql syntax", r"warning: pg_",
        ]

        normal_timeout = float(options.get('normal_timeout', self.NORMAL_TIMEOUT_DEFAULT))
        time_delay = int(options.get('time_delay', 5))
        time_based_timeout = float(options.get('time_based_timeout', max(self.TIME_BASED_TIMEOUT_DEFAULT, time_delay + 5)))
        use_seeds = bool(options.get('use_seeds', True))
        max_urls = int(options.get('max_urls', 6))

        # Build URLs to test
        urls_to_test: List[str] = [target]
        if use_seeds:
            try:
                urls_to_test.extend(await seed_urls(target, max_urls=max_urls))
            except Exception:
                pass

        try:
            async with get_http_client(verify=False, follow_redirects=True, timeout=time_based_timeout) as client:
                for page_url in urls_to_test:
                    try:
                        resp = await client.get(page_url)
                        content = resp.text
                    except Exception:
                        continue

                    # Scan forms on the page
                    forms = re.findall(r'<form[^>]*>.*?</form>', content, re.DOTALL | re.IGNORECASE)
                    for form_html in forms:
                        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                        action = action_match.group(1) if action_match else ''
                        method = (method_match.group(1).upper() if method_match else 'GET')
                        form_url = str(httpx.URL(page_url).join(action))
                        inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', form_html, re.IGNORECASE)
                        if not inputs:
                            continue

                        for param_name in inputs:
                            # Error-based checks
                            for payload in self.SQLI_PAYLOADS:
                                data = {input_name: 'test' for input_name in inputs}
                                data[param_name] = payload
                                try:
                                    if method == 'POST':
                                        test_response = await client.post(form_url, data=data, timeout=normal_timeout)
                                    else:
                                        test_response = await client.get(form_url, params=data, timeout=normal_timeout)
                                    body = test_response.text
                                    if any(re.search(pat, body, re.IGNORECASE) for pat in error_patterns):
                                        findings.append(self._create_finding(form_url, param_name, payload, "error-based", body[:500]))
                                        break
                                except httpx.RequestError as e:
                                    logger.warning(f"Request failed for error-based SQLi check: {e}")

                            # Time-based checks
                            for tpl in self.TIME_BASED_PAYLOAD_TEMPLATES:
                                payload = tpl.format(d=time_delay)
                                data = {input_name: 'test' for input_name in inputs}
                                data[param_name] = payload
                                try:
                                    start_time = asyncio.get_event_loop().time()
                                    if method == 'POST':
                                        await client.post(form_url, data=data, timeout=time_based_timeout)
                                    else:
                                        await client.get(form_url, params=data, timeout=time_based_timeout)
                                    end_time = asyncio.get_event_loop().time()
                                    if (end_time - start_time) >= (time_delay - 0.5):
                                        findings.append(self._create_finding(form_url, param_name, payload, "time-based", f"Response time: {end_time - start_time:.2f}s"))
                                        break
                                except httpx.TimeoutException:
                                    findings.append(self._create_finding(form_url, param_name, payload, "time-based-timeout", f"Request timed out after {time_based_timeout}s"))
                                    break
                                except httpx.RequestError as e:
                                    logger.warning(f"Request failed for time-based SQLi check: {e}")

                    # Also try common GET parameters directly on the URL
                    parsed = urlparse(page_url)
                    base_qs = parse_qs(parsed.query)
                    common_params = options.get('parameters', ['id', 'q', 'search', 'user', 'page'])
                    for param in common_params:
                        for payload in self.SQLI_PAYLOADS:
                            qs = base_qs.copy()
                            qs[param] = [payload]
                            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                            try:
                                r = await client.get(test_url, timeout=normal_timeout)
                                if any(re.search(pat, r.text, re.IGNORECASE) for pat in error_patterns):
                                    findings.append(self._create_finding(test_url, param, payload, "error-based", r.text[:500]))
                                    break
                            except Exception:
                                pass

        except httpx.RequestError as e:
            logger.error(f"Failed to fetch target URL {target}: {e}")
            findings.append(self._create_error_finding(f"Failed to fetch target URL {target}: {e}"))
        except Exception as e:
            logger.error(f"Unexpected error in SQL Injection scanner: {e}", exc_info=True)
            findings.append(self._create_error_finding(f"Unexpected error: {e}"))

        return findings

    def _create_finding(self, url: str, param: str, payload: str, method: str, evidence: str) -> Dict:
        return {
            "type": "sql_injection",
            "severity": Severity.HIGH,
            "title": f"Potential SQL Injection ({method})",
            "description": f"A potential SQL injection vulnerability was found in the '{param}' parameter using a {method} check.",
            "location": url,
            "evidence": {"url": url, "parameter": param, "payload": payload, "details": str(evidence)[:500]},
            "confidence": "Medium" if "time-based" in method else "High",
            "owasp_category": OwaspCategory.A03_INJECTION,
            "remediation": "Use parameterized queries (prepared statements) to prevent user input from being interpreted as SQL commands."
        }

    def _create_error_finding(self, description: str) -> Dict:
        return {
            "type": "error",
            "severity": Severity.INFO,
            "title": "SQL Injection Scanner Error",
            "description": description,
            "location": "Scanner",
            "cwe": "N/A",
            "remediation": "N/A",
            "confidence": 0,
            "cvss": 0
        }
