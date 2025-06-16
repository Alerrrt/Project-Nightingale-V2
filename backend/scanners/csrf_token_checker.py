import asyncio
import uuid
from typing import List, Dict, Any
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog


class CsrfTokenCheckerScanner(BaseScanner):
    """
    A scanner module for checking CSRF tokens in HTML forms.
    """

    metadata = {
        "name": "CSRF Token Checker",
        "description": "Checks for the presence of anti-CSRF tokens in HTML forms.",
        "owasp_category": "A04:2021 - Insecure Design",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously crawls the target, identifies HTML forms, and checks for CSRF tokens.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for missing or improperly handled CSRF tokens.
        """
        findings: List[Finding] = []
        target_url = target
        print(f"[*] Starting CSRF Token Check for {target_url}...")

        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            try:
                response = await client.get(target_url)
                response.raise_for_status()
                html_content = response.text
                soup = BeautifulSoup(html_content, 'html.parser')
                forms = soup.find_all('form')

                if not forms:
                    print(f"No forms found on {target_url}. Skipping CSRF token check.")
                    return findings

                for form in forms:
                    form_action = form.get('action', '')
                    full_action_url = urljoin(target_url, form_action)
                    
                    # Check for hidden input fields that might be CSRF tokens
                    csrf_token_found = False
                    for input_tag in form.find_all('input', type='hidden'):
                        if "csrf" in input_tag.get('name', '').lower() or \
                           "token" in input_tag.get('name', '').lower():
                            csrf_token_found = True
                            break
                    
                    if not csrf_token_found:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="Missing CSRF Token",
                                description=f"Form at '{full_action_url}' does not appear to have a CSRF token. This may make it vulnerable to Cross-Site Request Forgery (CSRF) attacks.",
                                severity=Severity.HIGH,
                                affected_url=full_action_url,
                                remediation="Implement anti-CSRF tokens for all state-changing operations via forms. Ensure tokens are unique per session/request and validated on the server-side.",
                                owasp_category=OwaspCategory.A04_INSECURE_DESIGN,
                                proof={
                                    "form_action": full_action_url,
                                    "details": "No hidden input field resembling a CSRF token found."
                                }
                            )
                        )

                    # TODO: For more advanced checks, we would need to:
                    # 1. Fetch the page twice in the same session to see if the token changes.
                    # 2. Attempt to submit the form without the token or with an invalid token.
                    # 3. Analyze server response to confirm token validation.

            except httpx.RequestError as e:
                print(f"Error fetching {target_url} for CSRF token check: {e}")
            except Exception as e:
                print(f"An unexpected error occurred during CSRF Token Check of {target_url}: {e}")

        print(f"[*] Finished CSRF Token Check for {target_url}.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("csrf_token_checker", CsrfTokenCheckerScanner) 