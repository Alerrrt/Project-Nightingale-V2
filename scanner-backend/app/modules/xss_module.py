from typing import List
import httpx
from urllib.parse import parse_qs, urlparse
from . import ScanModule, Detection

class XSSModule:
    id = "xss"
    description = "Detects unescaped URL parameters that could lead to XSS"

    async def analyze(self, response: httpx.Response) -> List[Detection]:
        detections = []
        content = response.text
        
        # Get URL parameters from the request
        url = str(response.url)
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Check if any parameter value appears unescaped in the response
        for param_name, param_values in params.items():
            for value in param_values:
                # Look for the raw parameter value in the response
                if value in content:
                    # Check if it's not just part of a larger word or HTML tag
                    if not any(
                        value in tag for tag in [
                            f"<{value}>",
                            f"</{value}>",
                            f'"{value}"',
                            f"'{value}'"
                        ]
                    ):
                        detections.append(
                            Detection(
                                module_id=self.id,
                                description="Potential XSS Vulnerability",
                                details=f"Parameter '{param_name}' value appears unescaped in response"
                            )
                        )

        return detections 