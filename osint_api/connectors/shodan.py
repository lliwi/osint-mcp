from __future__ import annotations
import os
import httpx


async def check_ip(ip: str) -> dict:
    api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "SHODAN_API_KEY not configured"}

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
            )
            if resp.status_code == 404:
                return {"available": True, "found": False}
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    ports = data.get("ports", [])
    services = [
        {
            "port": s.get("port"),
            "transport": s.get("transport", "tcp"),
            "product": s.get("product", ""),
            "version": s.get("version", ""),
            "cpe": s.get("cpe", []),
        }
        for s in data.get("data", [])[:10]  # cap output
    ]

    return {
        "available": True,
        "found": True,
        "ip": ip,
        "org": data.get("org", ""),
        "country": data.get("country_name", ""),
        "asn": data.get("asn", ""),
        "hostnames": data.get("hostnames", []),
        "ports": ports,
        "services": services,
        "vulns": list(data.get("vulns", {}).keys())[:10],
        "last_update": data.get("last_update", ""),
    }
