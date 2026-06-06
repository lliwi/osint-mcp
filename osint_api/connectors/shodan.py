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


async def check_domain(domain: str) -> dict:
    """Passive Shodan lookup for a domain: resolve to IP, then host info."""
    api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "SHODAN_API_KEY not configured"}

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resolve = await client.get(
                "https://api.shodan.io/dns/resolve",
                params={"hostnames": domain, "key": api_key},
            )
            resolve.raise_for_status()
            ip = resolve.json().get(domain)
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    if not ip:
        return {"available": True, "found": False, "domain": domain}

    host = await check_ip(ip)
    if not host.get("available"):
        return host
    if not host.get("found"):
        return {"available": True, "found": False, "domain": domain, "resolved_ip": ip}

    host["domain"] = domain
    host["resolved_ip"] = ip
    return host
