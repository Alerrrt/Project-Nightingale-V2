import re
import uuid
from typing import List, Dict, Any

import httpx
from backend.scanners.base_scanner import BaseScanner
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, HttpUrl


class SensitiveDataScanner(BaseScanner):
    """
    A scanner module for detecting sensitive data exposure vulnerabilities.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously scans a target for sensitive data exposure.

        Args:
            target: An object containing target information for scanning.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects representing potential sensitive data exposure.
        """
        findings: List[Finding] = []

        target_url = target

        # Basic example: look for patterns resembling email addresses in the response body
        # This is a simplified example; real-world scenarios require more robust pattern matching
        # and consideration of false positives.
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client: # Ensure redirects are followed
                response = await client.get(str(target_url))
                response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
                content = response.text

                # Example: Simple regex for potential email addresses
                email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                found_emails = re.findall(email_pattern, content)

                for email in found_emails:
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            vulnerability_type="Potential Email Address Exposed",
                            description=f"A pattern resembling an email address ({email}) was found in the response body.",
                            severity=Severity.LOW,
                            owasp_category=OwaspCategory.A03_INJECTION, # Changed to a relevant category
                            affected_url=str(target_url), # Ensure it's a string
                            proof=f"Email found: {email}",
                            technical_details=f"Response snippet: {content[:200]}..."
                        )
                    )

                # Example: Simple regex for potential API keys (placeholder)
                # This is highly simplistic and would need to be expanded with known key patterns.
                api_key_pattern = r"(api_key|token|password)[:=\s\"']?[a-zA-Z0-9_\\-]{16,}" # Corrected regex escape
                found_api_keys = re.findall(api_key_pattern, content)

                for key_match in found_api_keys:
                    # key_match might be a tuple if regex has capturing groups
                    exposed_key = key_match if isinstance(key_match, str) else key_match[-1]
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            vulnerability_type="Potential API Key Exposed",
                            description=f"A pattern resembling an API key ({exposed_key}) was found in the response body.",
                            severity=Severity.HIGH,
                            owasp_category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                            affected_url=str(target_url), # Ensure it's a string
                            proof=f"Exposed API Key: {exposed_key}",
                            technical_details=f"Response snippet: {content[:200]}..."
                        )
                    )

        except httpx.HTTPStatusError as e:
            print(f"HTTP error while scanning {target_url}: {e}")
        except httpx.RequestError as e:
            print(f"Request error while scanning {target_url}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred during sensitive data scan of {target_url}: {e}")

        return findings