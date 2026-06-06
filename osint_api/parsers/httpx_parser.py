from __future__ import annotations
import json


def parse(raw: str) -> dict:
    """Parse httpx (projectdiscovery) JSONL output (one JSON object per line)."""
    result: dict = {"probes": []}
    if not raw.strip():
        return result

    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        probe = {
            "url": obj.get("url") or obj.get("input", ""),
            "status_code": obj.get("status_code"),
            "title": obj.get("title", ""),
            "webserver": obj.get("webserver", ""),
            "technologies": obj.get("tech") or obj.get("technologies") or [],
        }
        result["probes"].append(probe)

    return result
