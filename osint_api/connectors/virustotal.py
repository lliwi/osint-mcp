from __future__ import annotations
import os
import httpx


_BASE = "https://www.virustotal.com/api/v3"


async def check_domain(domain: str) -> dict:
    return await _vt_get(f"/domains/{domain}")


async def check_url(url: str) -> dict:
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    return await _vt_get(f"/urls/{url_id}")


async def check_ip(ip: str) -> dict:
    return await _vt_get(f"/ip_addresses/{ip}")


async def _vt_get(path: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "VIRUSTOTAL_API_KEY not configured"}

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(
                _BASE + path,
                headers={"x-apikey": api_key},
            )
            if resp.status_code == 404:
                return {"available": True, "found": False}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    stats = data.get("last_analysis_stats", {})
    return {
        "available": True,
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": data.get("reputation", 0),
        "last_analysis_date": data.get("last_analysis_date", ""),
        "categories": data.get("categories", {}),
    }
