# -*- coding: utf-8 -*-
import asyncio
from datetime import datetime
from typing import List, Dict
import httpx
import re
from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Severity, OwaspCategory
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils import get_http_client
from backend.utils.crawler import seed_urls
from backend.utils.logging_config import get_context_logger
import logging

logger = get_context_logger(__name__)

class XssScanner(BaseScanner):
    """
    A scanner module for detecting Cross-Site Scripting (XSS) vulnerabilities.
    """

    metadata = {
        "name": "XSS Scanner",
        "description": "Detects Cross-Site Scripting (XSS) vulnerabilities.",
        "owasp_category": OwaspCategory.A03_XSS,
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="xss_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        """
        This is the entry point for the scanner. It will delegate to the
        private _perform_scan method. The boilerplate for logging, metrics,
        and broadcasting is handled by higher-level components.
        """
        try:
            return await self._perform_scan(scan_input.target, scan_input.options or {})
        except Exception as e:
            logger.error(f"XSS scan failed: {e}", exc_info=True)
            return [self._create_error_finding(f"XSS scan failed: {e}")]

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Perform the actual XSS vulnerability scan.
        """
        findings: List[Dict] = []
        logger.info("Starting XSS scan", extra={"target": target})

        # Safer, varied payload set including common contexts; avoids exfil actions by default
        test_payloads = options.get('payloads', [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "\"><svg/onload=alert(1)>",
            "'\"><svg/onload=alert(1)>",
            "</script><script>alert(1)</script>",
            "<img src=1 onerror=alert(1)>",
            "<a href=javascript:alert(1)>click</a>",
        ])

        test_params = options.get('parameters', [
            'q', 'search', 'id', 'input', 'query', 'keyword',
            'name', 'user', 'username', 'email', 'message',
            'comment', 'content', 'text', 'data'
        ])

        try:
            timeout = float(options.get('timeout', 10.0))
            use_seeds = bool(options.get('use_seeds', True))
            max_urls = int(options.get('max_urls', 6))
            async with get_http_client(verify=False, follow_redirects=True, timeout=timeout) as client:
                urls_to_test: List[str] = [target]
                if use_seeds:
                    try:
                        urls_to_test.extend(await seed_urls(target, max_urls=max_urls))
                    except Exception:
                        pass

                for page in urls_to_test:
                    try:
                        response = await client.get(page)
                        content = response.text
                    except Exception:
                        continue

                    forms = re.findall(r'<form[^>]*>.*?</form>', content, re.DOTALL | re.IGNORECASE)
                    
                    for form in forms:
                        form_action_match = re.search(r'action=["\']([^"\']*)["\']', form)
                        form_method_match = re.search(r'method=["\']([^"\']*)["\']', form)

                        if form_action_match:
                            form_url = form_action_match.group(1)
                            if not form_url.startswith(('http://', 'https://')):
                                form_url = f"{page.rstrip('/')}/{form_url.lstrip('/')}"

                            method = form_method_match.group(1).upper() if form_method_match else 'POST'

                            for payload in test_payloads:
                                try:
                                    if method == 'GET':
                                        # Assuming the first test_param is the most likely for GET forms
                                        test_url = f"{form_url}?{test_params[0]}={payload}"
                                        response = await client.get(test_url)
                                    else:
                                        data = {param: payload for param in test_params}
                                        response = await client.post(form_url, data=data)

                                    # Reflection heuristic: payload echoed raw or HTML-escaped variants
                                    body = response.text
                                    if (payload in body) or (payload.replace('<','&lt;').replace('>','&gt;') in body):
                                        logger.info("Potential XSS vulnerability detected in form", extra={
                                            "url": form_url,
                                            "method": method,
                                            "payload": payload
                                        })
                                        findings.append({
                                            "type": "reflected_xss",
                                            "severity": Severity.HIGH,
                                            "title": "Reflected XSS Vulnerability",
                                            "description": f"Found reflected XSS vulnerability in form submission to {form_url}",
                                            "evidence": {
                                                "url": form_url,
                                                "method": method,
                                                "payload": payload,
                                                "reflection": body[:200]
                                            },
                                            "owasp_category": OwaspCategory.INJECTION,
                                            "remediation": "Implement contextual output encoding, validate and sanitize inputs, avoid dangerous sinks such as innerHTML, and deploy a strict Content-Security-Policy."
                                        })
                                except Exception as e:
                                    logger.warning("Error testing XSS payload for form", extra={
                                        "url": form_url,
                                        "payload": payload,
                                        "error": str(e)
                                    })
                                    continue

                # URL parameter probes across seeds
                for page in urls_to_test:
                    for param in test_params:
                        for payload in test_payloads:
                            try:
                                test_url = f"{page}?{param}={payload}"
                                response = await client.get(test_url)
                                body = response.text
                                if (payload in body) or (payload.replace('<','&lt;').replace('>','&gt;') in body):
                                    logger.info("Potential XSS vulnerability detected in URL parameter", extra={
                                        "url": test_url,
                                        "parameter": param,
                                        "payload": payload
                                    })
                                    findings.append({
                                        "type": "reflected_xss",
                                        "severity": Severity.HIGH,
                                        "title": "Reflected XSS in URL Parameter",
                                        "description": f"Found reflected XSS in '{param}' parameter",
                                        "evidence": {
                                            "url": test_url,
                                            "parameter": param,
                                            "payload": payload,
                                            "reflection": body[:200]
                                        },
                                        "owasp_category": OwaspCategory.INJECTION,
                                        "remediation": "Implement contextual output encoding, validate and sanitize inputs, avoid dangerous sinks such as innerHTML, and deploy a strict Content-Security-Policy."
                                    })
                            except Exception as e:
                                logger.warning("Error testing XSS payload for URL parameter", extra={
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "error": str(e)
                                })
                                continue
        except Exception as e:
            logger.error("Unexpected error during XSS scan", extra={
                "target": target,
                "error": str(e)
            }, exc_info=True)

        logger.info("Finished XSS scan", extra={
            "target": target,
            "findings_count": len(findings)
        })
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "XSS Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }
