from __future__ import annotations
import json


def _redact(secret: str) -> str:
    """Mask a detected secret: never expose the full value."""
    secret = (secret or "").strip()
    if not secret:
        return ""
    if len(secret) <= 6:
        return "***"
    return f"{secret[:3]}***{secret[-2:]}"


def parse(raw: str) -> dict:
    """Parse gitleaks JSON report (array of finding objects)."""
    result: dict = {"secrets": [], "count": 0}
    raw = (raw or "").strip()
    if not raw:
        return result

    try:
        findings = json.loads(raw)
    except json.JSONDecodeError:
        return result
    if not isinstance(findings, list):
        return result

    for f in findings:
        if not isinstance(f, dict):
            continue
        result["secrets"].append({
            "rule": f.get("RuleID") or f.get("Rule", ""),
            "description": f.get("Description", ""),
            "file": f.get("File", ""),
            "line": f.get("StartLine"),
            "redacted": _redact(f.get("Secret") or f.get("Match", "")),
        })

    result["count"] = len(result["secrets"])
    return result
