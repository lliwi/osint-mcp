from __future__ import annotations
import re

# Strip ANSI colour codes whatweb emits even with --log-brief
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Match "Plugin[detail]" tokens, e.g. HTTPServer[nginx], Title[Example]
_PLUGIN = re.compile(r"([A-Za-z0-9\-]+)\[([^\]]*)\]")


def parse(raw: str) -> dict:
    """Parse whatweb --log-brief text output into structured fields."""
    result: dict = {"status": "", "title": "", "server": "", "ip": "",
                    "country": "", "technologies": []}
    if not raw.strip():
        return result

    text = _ANSI.sub("", raw).strip()

    # Leading "[200 OK]" status block
    status_match = re.search(r"\[(\d{3}[^\]]*)\]", text)
    if status_match:
        result["status"] = status_match.group(1).strip()

    seen: set[str] = set()
    for match in _PLUGIN.finditer(text):
        name, detail = match.group(1), match.group(2).strip()
        lname = name.lower()
        if lname == "title":
            result["title"] = detail
        elif lname == "httpserver":
            result["server"] = detail
        elif lname == "ip":
            result["ip"] = detail
        elif lname == "country":
            result["country"] = detail
        elif name.isupper() and detail.isdigit():
            # status code echoed as bare "[200 OK]" — already captured
            continue
        else:
            label = f"{name}[{detail}]" if detail else name
            if label not in seen:
                seen.add(label)
                result["technologies"].append(label)

    return result
