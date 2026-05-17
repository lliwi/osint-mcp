from __future__ import annotations
import os
import httpx


async def check_ip(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "ABUSEIPDB_API_KEY not configured"}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

    return {
        "available": True,
        "ip": data.get("ipAddress", ip),
        "is_public": data.get("isPublic", True),
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "country": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "usage_type": data.get("usageType", ""),
        "total_reports": data.get("totalReports", 0),
        "last_reported": data.get("lastReportedAt", ""),
        "reports": data.get("reports", [])[:5],  # limit output
    }
