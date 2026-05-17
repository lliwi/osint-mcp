from __future__ import annotations
import os
import httpx


async def check_email(email: str) -> dict:
    api_key = os.getenv("EMAILREP_API_KEY", "")
    headers = {"User-Agent": "mcp-osint-server/0.1"}
    if api_key:
        headers["Key"] = api_key

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(
                f"https://emailrep.io/{email}",
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    return {
        "available": True,
        "reputation": data.get("reputation", "unknown"),
        "suspicious": data.get("suspicious", False),
        "references": data.get("references", 0),
        "profiles": data.get("details", {}).get("profiles", []),
        "blacklisted": data.get("details", {}).get("blacklisted", False),
        "malicious_activity": data.get("details", {}).get("malicious_activity", False),
        "spam": data.get("details", {}).get("spam", False),
    }
