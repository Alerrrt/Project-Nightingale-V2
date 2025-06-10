from typing import List
import httpx
from . import Detection

async def analyze_x_content_type(response: httpx.Response) -> List[Detection]:
    if "X-Content-Type-Options" not in response.headers:
        return [
            Detection(
                module_id="x_content_type",
                description="Missing X-Content-Type-Options header",
                details="The X-Content-Type-Options header is missing."
            )
        ]
    return [] 