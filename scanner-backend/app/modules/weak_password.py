from typing import List
import httpx
import re
from . import Detection

COMMON_WEAK_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "monkey", "admin"
]

async def analyze_weak_password(response: httpx.Response) -> List[Detection]:
    findings = []
    # Look for password fields with weak default values
    matches = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', response.text, re.IGNORECASE)
    for match in matches:
        for weak in COMMON_WEAK_PASSWORDS:
            if f'value="{weak}"' in match or f"value='{weak}'" in match:
                findings.append(
                    Detection(
                        module_id="weak_password",
                        description="Weak password default in form",
                        details=f"Password field has weak default: {weak}"
                    )
                )
    return findings 