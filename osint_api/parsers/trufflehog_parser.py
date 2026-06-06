from __future__ import annotations
import json


def _location(meta: dict) -> tuple[str, object]:
    """Extract (file/uri, line) from trufflehog SourceMetadata."""
    data = (meta or {}).get("Data", {})
    if not isinstance(data, dict):
        return "", None
    for source in data.values():
        if isinstance(source, dict):
            loc = source.get("file") or source.get("uri") or source.get("link", "")
            line = source.get("line")
            return loc, line
    return "", None


def parse(raw: str) -> dict:
    """Parse trufflehog --json output (one JSON object per line)."""
    result: dict = {"secrets": [], "count": 0, "verified_count": 0}
    raw = (raw or "").strip()
    if not raw:
        return result

    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "DetectorName" not in obj and "DetectorType" not in obj:
            continue

        loc, lineno = _location(obj.get("SourceMetadata", {}))
        verified = bool(obj.get("Verified", False))
        result["secrets"].append({
            "detector": obj.get("DetectorName", ""),
            "verified": verified,
            "file": loc,
            "line": lineno,
            "redacted": obj.get("Redacted", ""),
        })
        if verified:
            result["verified_count"] += 1

    result["count"] = len(result["secrets"])
    return result
