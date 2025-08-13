from __future__ import annotations

import re
from typing import Dict, Any, Optional, List


_CWE_BY_KEYWORD: List[tuple[str, str]] = [
    # Injection vulnerabilities
    (r"xss|cross[- ]site scripting", "CWE-79"),
    (r"sql[\s-]*injection|sqli", "CWE-89"),
    (r"command injection|os command", "CWE-78"),
    (r"ldap injection", "CWE-90"),
    (r"xml injection|xxe", "CWE-91"),
    
    # Authentication and Authorization
    (r"broken authentication|weak authentication", "CWE-287"),
    (r"session fixation|session management", "CWE-384"),
    (r"privilege escalation", "CWE-269"),
    (r"insecure direct object reference|idor", "CWE-639"),
    
    # Cross-Site vulnerabilities
    (r"csrf|cross[- ]site request forgery", "CWE-352"),
    (r"clickjacking|frame[- ]busting", "CWE-1021"),
    
    # Server-side vulnerabilities
    (r"ssrf|server[- ]side request forgery", "CWE-918"),
    (r"directory traversal|path traversal", "CWE-22"),
    (r"open redirect", "CWE-601"),
    (r"security misconfiguration", "CWE-16"),
    
    # Data exposure
    (r"information disclosure|sensitive data|leak", "CWE-200"),
    (r"insecure deserializ(e|ation)", "CWE-502"),
    (r"weak cryptography|weak encryption", "CWE-327"),
    
    # Input validation
    (r"buffer overflow", "CWE-119"),
    (r"format string", "CWE-134"),
    (r"integer overflow", "CWE-190"),
    
    # Access control
    (r"missing access control", "CWE-862"),
    (r"insecure default", "CWE-1188"),
    
    # Logging and monitoring
    (r"insufficient logging", "CWE-778"),
    (r"missing audit log", "CWE-778"),
]


def _guess_cwe_from_text(title: str, description: str) -> Optional[str]:
    blob = f"{title}\n{description}".lower()
    for pattern, cwe in _CWE_BY_KEYWORD:
        if re.search(pattern, blob):
            return cwe
    return None


def _generic_countermeasures_for_cwe(cwe: str) -> Optional[str]:
    # Comprehensive guidance for common CWEs
    mapping = {
        # Injection vulnerabilities
        "CWE-79": "Validate and encode all untrusted input; adopt CSP; prefer templating that auto-escapes.",
        "CWE-89": "Use parameterized queries/ORM; avoid string concatenation; apply least privilege to DB accounts.",
        "CWE-78": "Avoid shell commands with user input; use APIs instead; validate and sanitize all inputs.",
        "CWE-90": "Use parameterized LDAP queries; validate and sanitize input; apply least privilege.",
        "CWE-91": "Disable external entity processing; use safe XML parsers; validate XML schemas.",
        
        # Authentication and Authorization
        "CWE-287": "Implement strong authentication; use MFA; secure session management; rate limiting.",
        "CWE-384": "Regenerate session IDs after login; use secure session storage; implement session timeout.",
        "CWE-269": "Apply principle of least privilege; implement proper access controls; audit permissions.",
        "CWE-639": "Validate user permissions for each resource; use indirect object references.",
        
        # Cross-Site vulnerabilities
        "CWE-352": "Use anti-CSRF tokens and SameSite cookies; verify intent on state-changing requests.",
        "CWE-1021": "Use frame-busting headers (X-Frame-Options/Frame-ancestors) and double-submit protection.",
        
        # Server-side vulnerabilities
        "CWE-918": "Avoid fetching untrusted URLs server-side; allowlist domains; isolate SSRF-capable services.",
        "CWE-22": "Normalize and validate file paths; enforce allowlists; avoid exposing user-controlled paths.",
        "CWE-601": "Avoid reflecting unvalidated URLs; use allowlists for redirects; prefer id-based navigation.",
        "CWE-16": "Secure default configurations; remove unnecessary features; apply security headers.",
        
        # Data exposure
        "CWE-200": "Mask sensitive data; apply access controls; avoid verbose error messages; encrypt data at rest/in transit.",
        "CWE-502": "Avoid deserializing untrusted data; use safe formats (JSON); apply type validation and sandboxing.",
        "CWE-327": "Use strong cryptographic algorithms; secure key management; avoid deprecated ciphers.",
        
        # Input validation
        "CWE-119": "Use safe string handling; implement bounds checking; avoid unsafe memory operations.",
        "CWE-134": "Use safe string formatting functions; validate format strings; avoid user-controlled format strings.",
        "CWE-190": "Use safe integer operations; implement bounds checking; validate numeric inputs.",
        
        # Access control
        "CWE-862": "Implement proper access controls; validate user permissions; apply principle of least privilege.",
        "CWE-1188": "Secure default configurations; require explicit security settings; document security requirements.",
        
        # Logging and monitoring
        "CWE-778": "Implement comprehensive logging; monitor security events; retain logs securely; alert on suspicious activity.",
    }
    return mapping.get(cwe)


def map_severity_from_cvss(cvss: Optional[float], fallback: str) -> str:
    try:
        score = float(cvss) if cvss is not None else None
    except Exception:
        score = None
    if score is None:
        return fallback or "Info"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return fallback or "Info"


def ensure_cve_extracted(finding: Dict[str, Any]) -> None:
    # Extract CVE from description/evidence text if not present
    if finding.get("cve") and isinstance(finding["cve"], str):
        return
    text_fields: List[str] = []
    for key in ("description", "evidence", "title"):
        val = finding.get(key)
        if isinstance(val, str):
            text_fields.append(val)
    blob = "\n".join(text_fields)
    m = re.search(r"CVE-\d{4}-\d{4,7}", blob, flags=re.IGNORECASE)
    if m:
        finding["cve"] = m.group(0).upper()


def map_vulnerability_fields(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort mapping for CWE/CVE and remediation/countermeasures.

    - Guess CWE from title/description if absent
    - Ensure CWE link appears in references
    - Extract CVE id from text if absent
    - Provide generic countermeasures when remediation absent
    """
    title = finding.get("title", "")
    description = finding.get("description", "")

    # CWE mapping
    cwe = finding.get("cwe")
    if not cwe:
        cwe = _guess_cwe_from_text(title, description)
        if cwe:
            finding["cwe"] = cwe

    # Add CWE reference
    if finding.get("cwe"):
        try:
            finding.setdefault("references", [])
            existing = {(r.get("type"), r.get("id")) for r in finding["references"] if isinstance(r, dict)}
            cwe_id = finding["cwe"]
            ref = {"type": "CWE", "id": cwe_id, "url": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html"}
            key = (ref["type"], ref["id"])
            if key not in existing:
                finding["references"].append(ref)
        except Exception:
            pass

    # CVE extraction
    ensure_cve_extracted(finding)

    # Countermeasures remediation fallback
    if not finding.get("remediation"):
        if finding.get("cwe"):
            cm = _generic_countermeasures_for_cwe(finding["cwe"]) or "Apply secure coding best practices and input validation."
            finding["remediation"] = cm
    finding.setdefault("countermeasures", finding.get("remediation", ""))

    return finding


