from typing import List
import httpx
from . import Detection

async def analyze_dir_listing(response: httpx.Response) -> List[Detection]:
    if "Index of /" in response.text and "Parent Directory" in response.text:
        return [
            Detection(
                module_id="dir_listing",
                description="Directory Listing Enabled",
                details="The server response indicates directory listing is enabled."
            )
        ]
    return [] 