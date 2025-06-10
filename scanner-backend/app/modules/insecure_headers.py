from typing import List
import httpx
from . import Detection

def get_missing_headers(headers: dict) -> List[str]:
    required = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection"
    ]
    return [h for h in required if h not in headers]

async def analyze_insecure_headers(response: httpx.Response) -> List[Detection]:
    missing = get_missing_headers(response.headers)
    if not missing:
        return []
    return [
        Detection(
            module_id="insecure_headers",
            description="Missing security headers",
            details=f"Missing: {', '.join(missing)}"
        )
    ] 