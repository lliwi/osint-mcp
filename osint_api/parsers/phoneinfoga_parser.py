from __future__ import annotations
import json
import re


def parse(raw: str) -> dict:
    result: dict = {
        "valid": False, "country": "", "carrier": "",
        "line_type": "unknown", "formatted": "", "spam_signals": [],
    }
    # Try JSON first (phoneinfoga --format json)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            result["valid"] = data.get("valid", False)
            result["country"] = data.get("country", "")
            result["carrier"] = data.get("carrier", "")
            result["line_type"] = data.get("line_type", "unknown")
            result["formatted"] = data.get("international", "")
            return result
    except json.JSONDecodeError:
        pass

    # Plain text fallback
    for line in raw.splitlines():
        lower = line.lower()
        if "country" in lower:
            result["country"] = line.split(":", 1)[-1].strip()
        elif "carrier" in lower:
            result["carrier"] = line.split(":", 1)[-1].strip()
        elif "line type" in lower or "linetype" in lower:
            result["line_type"] = line.split(":", 1)[-1].strip()
        elif "valid" in lower:
            result["valid"] = "true" in lower

    return result
