from __future__ import annotations
import re


def parse(raw: str) -> dict:
    result: dict = {"raw": raw, "registrar": "", "creation_date": "", "expiry_date": "",
                    "name_servers": [], "registrant": "", "status": []}
    if not raw.strip():
        return result

    for line in raw.splitlines():
        lower = line.lower()
        if lower.startswith("registrar:") and not result["registrar"]:
            result["registrar"] = line.split(":", 1)[-1].strip()
        elif "creation date:" in lower and not result["creation_date"]:
            result["creation_date"] = line.split(":", 1)[-1].strip()
        elif ("expir" in lower and "date" in lower) and not result["expiry_date"]:
            result["expiry_date"] = line.split(":", 1)[-1].strip()
        elif "name server:" in lower:
            ns = line.split(":", 1)[-1].strip().lower()
            if ns and ns not in result["name_servers"]:
                result["name_servers"].append(ns)
        elif "domain status:" in lower:
            status = line.split(":", 1)[-1].strip().split(" ")[0]
            result["status"].append(status)
        elif "registrant" in lower and ":" in line and not result["registrant"]:
            result["registrant"] = line.split(":", 1)[-1].strip()

    return result
