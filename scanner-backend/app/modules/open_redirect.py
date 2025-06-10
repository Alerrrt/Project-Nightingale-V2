from typing import List
import httpx
from urllib.parse import urlparse, parse_qs
from . import Detection

async def analyze_open_redirect(response: httpx.Response) -> List[Detection]:
    url = str(response.url)
    params = parse_qs(urlparse(url).query)
    findings = []
    for param, values in params.items():
        for value in values:
            if value.startswith("http://") or value.startswith("https://"):
                if value not in url:
                    continue
                findings.append(
                    Detection(
                        module_id="open_redirect",
                        description="Potential Open Redirect",
                        details=f"Parameter '{param}' may allow open redirect to {value}"
                    )
                )
    return findings 