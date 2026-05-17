from __future__ import annotations
import re


def parse(raw: str) -> dict:
    emails: list[str] = []
    hosts: list[str] = []
    ips: list[str] = []

    section = None
    for line in raw.splitlines():
        lower = line.strip().lower()
        if "emails found" in lower:
            section = "emails"
        elif "hosts found" in lower or "interesting urls" in lower:
            section = "hosts"
        elif "ip addresses" in lower:
            section = "ips"
        elif line.strip().startswith("-"):
            continue
        elif line.strip() and section:
            value = line.strip()
            if section == "emails" and "@" in value:
                emails.append(value)
            elif section == "hosts" and "." in value:
                hosts.append(value)
            elif section == "ips" and re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
                ips.append(value)

    return {"emails": list(set(emails)), "hosts": list(set(hosts)), "ips": list(set(ips))}
