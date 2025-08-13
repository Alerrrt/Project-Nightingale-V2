# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from backend.utils import get_http_client


def _ensure_scheme(url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return f"https://{url}"


def _same_origin(url: str, origin: str) -> bool:
    try:
        return urlparse(url).netloc == urlparse(origin).netloc
    except Exception:
        return False


async def seed_urls(target: str, max_urls: int = 10) -> List[str]:
    """Return a small, in-scope URL frontier for scanners.

    Strategy (fast, safe):
    - Include origin root
    - Try /robots.txt for sitemap hints; try /sitemap.xml for top URLs
    - Parse homepage anchors and keep a few in-scope paths
    """
    base = _ensure_scheme(target).rstrip("/") + "/"
    origin = base
    discovered: List[str] = [origin]
    seen: Set[str] = {origin}

    # Try sitemap via robots.txt first
    try:
        robots_url = urljoin(origin, "robots.txt")
        async with get_http_client(timeout=10) as client:
            resp = await client.get(robots_url)
            if resp.status_code == 200:
                text = resp.text
                for line in text.splitlines():
                    if line.lower().startswith("sitemap:"):
                        sm_url = line.split(":", 1)[1].strip()
                        if not sm_url:
                            continue
                        try:
                            sm = await client.get(sm_url, timeout=10)
                            if sm.status_code == 200 and "<urlset" in sm.text[:2048].lower():
                                # Extract first N loc entries
                                for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", sm.text, re.I):
                                    if len(discovered) >= max_urls:
                                        break
                                    u = loc.strip()
                                    if _same_origin(u, origin) and u not in seen:
                                        discovered.append(u)
                                        seen.add(u)
                        except Exception:
                            pass
    except Exception:
        pass

    if len(discovered) >= max_urls:
        return discovered[:max_urls]

    # Try default /sitemap.xml if not found via robots
    try:
        sm_default = urljoin(origin, "sitemap.xml")
        async with get_http_client(timeout=10) as client:
            sm = await client.get(sm_default)
            if sm.status_code == 200 and "<urlset" in sm.text[:2048].lower():
                for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", sm.text, re.I):
                    if len(discovered) >= max_urls:
                        break
                    u = loc.strip()
                    if _same_origin(u, origin) and u not in seen:
                        discovered.append(u)
                        seen.add(u)
    except Exception:
        pass

    if len(discovered) >= max_urls:
        return discovered[:max_urls]

    # Parse homepage anchors
    try:
        async with get_http_client(timeout=10) as client:
            resp = await client.get(origin)
            if resp.status_code == 200 and resp.headers.get("content-type", "").lower().startswith("text/html"):
                soup = BeautifulSoup(resp.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    if len(discovered) >= max_urls:
                        break
                    u = urljoin(origin, a["href"]).split("#", 1)[0]
                    if _same_origin(u, origin) and u not in seen:
                        discovered.append(u)
                        seen.add(u)
    except Exception:
        pass

    return discovered[:max_urls]


