from typing import List
import httpx
import re
from . import Detection

async def analyze_csrf_token(response: httpx.Response) -> List[Detection]:
    # Look for forms without CSRF token fields
    forms = re.findall(r'<form[\s\S]*?>[\s\S]*?</form>', response.text, re.IGNORECASE)
    findings = []
    for form in forms:
        if not re.search(r'name=["\"]csrf(token)?["\"]', form, re.IGNORECASE):
            findings.append(
                Detection(
                    module_id="csrf_token",
                    description="Form missing CSRF token",
                    details="A form was found without a CSRF token field."
                )
            )
    return findings 