from typing import List
import httpx
from . import Detection

async def analyze_weak_basic_auth(response: httpx.Response) -> List[Detection]:
    if response.status_code == 401 and "Basic realm" in response.headers.get("WWW-Authenticate", ""):
        return [
            Detection(
                module_id="weak_basic_auth",
                description="Weak HTTP Basic Auth Detected",
                details="The server uses HTTP Basic Auth, which is not secure over HTTP."
            )
        ]
    return [] 