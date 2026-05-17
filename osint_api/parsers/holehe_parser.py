from __future__ import annotations
import re


def parse(raw: str) -> dict:
    """Parse holehe --no-color --only-used output."""
    registered: list[str] = []
    not_found: list[str] = []
    errors: list[str] = []

    for line in raw.splitlines():
        line = line.strip()
        if re.search(r"\[✓\]|\[\+\]|used|registered", line, re.IGNORECASE):
            service = re.sub(r"[\[\]✓\+\-\*!\s]", "", line.split(":")[0]).strip()
            if service:
                registered.append(service)
        elif re.search(r"\[x\]|\[-\]|not used|not found", line, re.IGNORECASE):
            service = re.sub(r"[\[\]x\-\s]", "", line.split(":")[0]).strip()
            if service:
                not_found.append(service)
        elif re.search(r"\[!\]|error|rate limit", line, re.IGNORECASE):
            errors.append(line)

    return {
        "registered": registered,
        "registered_count": len(registered),
        "not_found_count": len(not_found),
        "errors": errors,
    }
