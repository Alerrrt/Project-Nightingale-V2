from typing import Dict, Any, List, Optional
import json
import os


class CheatSheet:
    def __init__(self, data: Dict[str, Any]):
        self.data = data

    def map_cwe(self, evidence: Dict[str, Any]) -> Optional[str]:
        mapping = self.data.get("mapping", {}).get("cwe", {})
        # Minimal rule-based: look for keywords in description/title
        text_parts: List[str] = []
        for k in ("title", "description"):
            v = evidence.get(k) or ""
            if isinstance(v, str):
                text_parts.append(v.lower())
        blob = "\n".join(text_parts)
        for cwe, rules in mapping.items():
            for kw in rules.get("keywords", []):
                if kw.lower() in blob:
                    return cwe
        return None

    def map_owasp(self, evidence: Dict[str, Any]) -> Optional[str]:
        mapping = self.data.get("mapping", {}).get("owasp", {})
        text = ((evidence.get("title") or "") + "\n" + (evidence.get("description") or "")).lower()
        for cat, rules in mapping.items():
            for kw in rules.get("keywords", []):
                if kw.lower() in text:
                    return cat
        return None

    def remediation(self) -> Optional[str]:
        return self.data.get("remediation")


class Classifier:
    def __init__(self, cheatsheets: Dict[str, CheatSheet]):
        self.cheatsheets = cheatsheets

    def classify(self, scanner: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        sheet = self.cheatsheets.get(scanner)
        classifier: Dict[str, Any] = {}
        references: List[Dict[str, str]] = []

        if sheet:
            cwe = sheet.map_cwe(finding)
            if cwe:
                classifier["cwe"] = cwe
                references.append({"type": "CWE", "id": cwe, "url": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html"})
            owasp = sheet.map_owasp(finding)
            if owasp:
                classifier["owasp"] = owasp
            rem = sheet.remediation()
            if rem and not finding.get("remediation"):
                finding["remediation"] = rem

        finding.setdefault("references", [])
        finding.setdefault("classifier", {})
        # Avoid duplicate references
        if references:
            existing = {(r.get("type"), r.get("id")) for r in finding["references"] if isinstance(r, dict)}
            for ref in references:
                key = (ref.get("type"), ref.get("id"))
                if key not in existing:
                    finding["references"].append(ref)
        finding["classifier"].update({k: v for k, v in classifier.items() if v is not None})
        return finding


def load_cheatsheets(base_dir: str = os.path.join("backend", "data", "cheatsheets")) -> Dict[str, CheatSheet]:
    cheats: Dict[str, CheatSheet] = {}
    if not os.path.isdir(base_dir):
        return cheats
    for fn in os.listdir(base_dir):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(base_dir, fn)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                name = data.get("name") or fn.replace(".json", "")
                cheats[name] = CheatSheet(data)
        except Exception:
            continue
    return cheats


