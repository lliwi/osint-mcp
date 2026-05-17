from __future__ import annotations
import os
import httpx


async def check_email(email: str) -> dict:
    api_key = os.getenv("HIBP_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "HIBP_API_KEY not configured"}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": api_key, "User-Agent": "mcp-osint-server/0.1"},
            )
            if resp.status_code == 404:
                return {"available": True, "breaches": [], "breach_count": 0}
            resp.raise_for_status()
            breaches = resp.json()
        except httpx.HTTPStatusError as exc:
            return {"available": True, "error": str(exc), "breaches": [], "breach_count": 0}

    sanitized = [
        {
            "name": b.get("Name", ""),
            "domain": b.get("Domain", ""),
            "breach_date": b.get("BreachDate", ""),
            "pwn_count": b.get("PwnCount", 0),
            "data_classes": b.get("DataClasses", []),
            # Never return full password data
        }
        for b in breaches
    ]
    return {"available": True, "breaches": sanitized, "breach_count": len(sanitized)}
