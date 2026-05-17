from __future__ import annotations
import re


def parse(raw: str) -> dict:
    """Parse sherlock --print-found --no-color output."""
    profiles = []
    for line in raw.splitlines():
        line = line.strip()
        # Sherlock format: [+] Platform: URL
        match = re.match(r"\[\+\]\s+(.+?):\s+(https?://\S+)", line)
        if match:
            profiles.append({
                "platform": match.group(1).strip(),
                "url": match.group(2).strip(),
                "status": "found",
            })
    return {"profiles": profiles, "found_count": len(profiles)}
