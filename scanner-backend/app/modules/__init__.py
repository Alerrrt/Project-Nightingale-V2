from typing import List, Protocol
import httpx
import pkg_resources

class Detection:
    def __init__(self, module_id: str, description: str, details: str):
        self.module_id = module_id
        self.description = description
        self.details = details

class ScanModule(Protocol):
    id: str
    description: str

    async def analyze(self, response: httpx.Response) -> List[Detection]:
        ...

from .sqli_module import SQLiModule
from .xss_module import XSSModule
from .insecure_headers import analyze_insecure_headers
from .open_redirect import analyze_open_redirect
from .dir_listing import analyze_dir_listing
from .weak_basic_auth import analyze_weak_basic_auth
from .csrf_token import analyze_csrf_token
from .weak_password import analyze_weak_password
from .x_content_type import analyze_x_content_type
from .verbose_error import analyze_verbose_error

def discover_modules():
    # Return a list of (module_id, analyzer function) for functional modules
    return [
        ("sqli", SQLiModule().analyze),
        ("xss", XSSModule().analyze),
        ("insecure_headers", analyze_insecure_headers),
        ("open_redirect", analyze_open_redirect),
        ("dir_listing", analyze_dir_listing),
        ("weak_basic_auth", analyze_weak_basic_auth),
        ("csrf_token", analyze_csrf_token),
        ("weak_password", analyze_weak_password),
        ("x_content_type", analyze_x_content_type),
        ("verbose_error", analyze_verbose_error),
    ] 