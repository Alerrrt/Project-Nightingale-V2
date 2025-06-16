import asyncio
import uuid
import json
import pickle
import base64
from typing import List, Dict, Any
import httpx

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class InsecureDeserializationScanner(BaseScanner):
    """
    A scanner module for detecting insecure deserialization vulnerabilities.
    """

    metadata = {
        "name": "Insecure Deserialization",
        "description": "Detects insecure deserialization vulnerabilities by sending crafted payloads in various formats.",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously checks for insecure deserialization vulnerabilities by sending crafted payloads.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected insecure deserialization vulnerabilities.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting Insecure Deserialization scan for {target_url}...")

        # Test payloads for different deserialization formats
        test_payloads = [
            # JSON payload with prototype pollution
            {
                "json": json.dumps({
                    "__proto__": {
                        "isAdmin": True
                    }
                })
            },
            # Python pickle payload
            {
                "pickle": base64.b64encode(pickle.dumps({"command": "ls"})).decode()
            },
            # PHP serialized object
            {
                "php": "O:8:\"stdClass\":1:{s:1:\"x\";s:4:\"test\";}"
            }
        ]

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            for payload in test_payloads:
                try:
                    # Try different content types
                    content_types = [
                        "application/json",
                        "application/x-python-serialize",
                        "application/x-php-serialized"
                    ]

                    for content_type in content_types:
                        headers = {
                            "Content-Type": content_type
                        }
                        
                        # Send the appropriate payload based on content type
                        if content_type == "application/json":
                            data = payload["json"]
                        elif content_type == "application/x-python-serialize":
                            data = payload["pickle"]
                        else:
                            data = payload["php"]

                        response = await client.post(target_url, content=data, headers=headers)
                        
                        # Check for indicators of successful deserialization
                        if response.status_code != 400 and response.status_code != 500:
                            findings.append(
                                Finding(
                                    id=str(uuid.uuid4()),
                                    vulnerability_type="Insecure Deserialization",
                                    description="Potential insecure deserialization vulnerability detected. The application appears to be processing serialized data without proper validation.",
                                    severity=Severity.HIGH,
                                    affected_url=target_url,
                                    remediation="Implement strict input validation for all deserialized data. Use safe deserialization methods and avoid using native deserialization functions when possible. Consider using a whitelist of allowed classes/types.",
                                    owasp_category=OwaspCategory.A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES,
                                    proof={
                                        "content_type": content_type,
                                        "payload": data,
                                        "response_status": response.status_code,
                                        "response_length": len(response.text)
                                    }
                                )
                            )

                except httpx.RequestError as e:
                    print(f"Error testing deserialization for {target_url}: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred during deserialization scan: {e}")

        print(f"[*] Finished Insecure Deserialization scan for {target_url}.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("insecure_deserialization", InsecureDeserializationScanner) 