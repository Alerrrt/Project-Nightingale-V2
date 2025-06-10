from typing import List
import httpx
import re
from . import Detection

ERROR_PATTERNS = [
    r"exception in thread",
    r"traceback (most recent call last)",
    r"fatal error",
    r"stack trace",
    r"undefined variable",
    r"nullreferenceexception",
    r"system\.data\.sqlclient\.sqlexception",
    r"odbc sql server driver",
    r"mysql error"
]

async def analyze_verbose_error(response: httpx.Response) -> List[Detection]:
    findings = []
    for pattern in ERROR_PATTERNS:
        if re.search(pattern, response.text, re.IGNORECASE):
            findings.append(
                Detection(
                    module_id="verbose_error",
                    description="Verbose error message detected",
                    details=f"Found error pattern: {pattern}"
                )
            )
    return findings 