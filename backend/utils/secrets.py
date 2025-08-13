# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from typing import List, Dict


_SECRET_PATTERNS: List[Dict[str, object]] = [
    {
        "name": "AWS Access Key ID",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "High",
    },
    {
        "name": "AWS Secret Access Key",
        "regex": re.compile(r"(?i)aws(.{0,20})?(secret|access).{0,20}?([A-Za-z0-9/+=]{40})"),
        "severity": "High",
    },
    {
        "name": "Google API Key",
        "regex": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": "Medium",
    },
    {
        "name": "Slack Token",
        "regex": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}"),
        "severity": "Medium",
    },
    {
        "name": "Private Key Block",
        "regex": re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC )?PRIVATE KEY-----"),
        "severity": "Critical",
    },
    {
        "name": "JWT",
        "regex": re.compile(r"eyJ[A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-]+\.[A-Za-z0-9_\-+/=]{10,}"),
        "severity": "Low",
    },
]


def scan_text_for_secrets(text: str, *, max_findings: int = 20) -> List[Dict]:
    """Scan plain text for common credential/token patterns.

    Returns a list of { name, match, severity, index } up to max_findings.
    """
    findings: List[Dict] = []
    if not text:
        return findings
    for pat in _SECRET_PATTERNS:
        for m in pat["regex"].finditer(text):
            findings.append({
                "name": str(pat["name"]),
                "match": m.group(0)[:120],
                "severity": str(pat["severity"]),
                "index": m.start(),
            })
            if len(findings) >= max_findings:
                return findings
    return findings


