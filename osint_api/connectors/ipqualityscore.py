"""
IPQualityScore connector — phone, email and IP fraud/reputation scoring.
API key goes in the URL path (not a header).
Docs: https://www.ipqualityscore.com/documentation/overview
"""
from __future__ import annotations

import os
import httpx

_BASE = "https://www.ipqualityscore.com/api/json"


def _key() -> str:
    return os.getenv("IPQUALITYSCORE_API_KEY", "")


async def check_phone(phone: str) -> dict:
    """
    Phone validation and fraud scoring.
    Returns carrier, line type, spam signals, fraud score, etc.
    """
    key = _key()
    if not key:
        return {"available": False, "reason": "IPQUALITYSCORE_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{_BASE}/phone/{key}/{phone}",
                params={"strictness": 1, "country[]": ""},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    if not data.get("success", False):
        return {"available": True, "error": data.get("message", "Unknown error")}

    return {
        "available": True,
        "valid": data.get("valid", False),
        "fraud_score": data.get("fraud_score", 0),        # 0-100, >75 = suspicious
        "country": data.get("country", ""),
        "city": data.get("city", ""),
        "carrier": data.get("carrier", ""),
        "line_type": data.get("line_type", "unknown"),     # mobile, landline, voip, etc.
        "prepaid": data.get("prepaid", False),
        "risky": data.get("risky", False),
        "active": data.get("active", None),
        "spammer": data.get("spammer", False),
        "leaked": data.get("leaked", False),
        "name": data.get("name", ""),                      # owner name if available
        "timezone": data.get("timezone", ""),
        "formatted": data.get("formatted", phone),
        "dialing_code": data.get("dialing_code", ""),
        "mcc": data.get("mcc", ""),
        "mnc": data.get("mnc", ""),
        "do_not_call": data.get("do_not_call", False),
    }


async def check_email(email: str) -> dict:
    """
    Email validation, fraud scoring and deliverability check.
    """
    key = _key()
    if not key:
        return {"available": False, "reason": "IPQUALITYSCORE_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{_BASE}/email/{key}/{email}",
                params={"strictness": 1, "fast": False},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    if not data.get("success", False):
        return {"available": True, "error": data.get("message", "Unknown error")}

    return {
        "available": True,
        "valid": data.get("valid", False),
        "fraud_score": data.get("fraud_score", 0),
        "disposable": data.get("disposable", False),       # throwaway address
        "temporary": data.get("temporary", False),
        "spam_trap": data.get("spam_trap_score", "none"),  # none/low/medium/high
        "catch_all": data.get("catch_all", False),
        "leaked": data.get("leaked", False),               # found in data breaches
        "suspect": data.get("suspect", False),
        "frequent_complainer": data.get("frequent_complainer", False),
        "deliverability": data.get("deliverability", "unknown"),  # high/medium/low
        "dns_valid": data.get("dns_valid", False),
        "smtp_score": data.get("smtp_score", -1),          # -1=invalid, 0=catch-all, 1-3=valid
        "overall_score": data.get("overall_score", 0),     # 0-4, higher = more trustworthy
        "first_name": data.get("first_name", ""),
        "common": data.get("common", False),               # common provider (gmail, etc.)
        "generic": data.get("generic", False),             # generic address (info@, admin@)
        "domain_age": data.get("domain_age", {}),
        "sanitized_email": data.get("sanitized_email", email),
        "suggested_domain": data.get("suggested_domain", ""),
    }


async def check_ip(ip: str) -> dict:
    """
    IP fraud scoring, VPN/proxy/Tor detection.
    """
    key = _key()
    if not key:
        return {"available": False, "reason": "IPQUALITYSCORE_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{_BASE}/ip/{key}/{ip}",
                params={"strictness": 1, "allow_public_access_points": True},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    if not data.get("success", False):
        return {"available": True, "error": data.get("message", "Unknown error")}

    return {
        "available": True,
        "fraud_score": data.get("fraud_score", 0),
        "country_code": data.get("country_code", ""),
        "region": data.get("region", ""),
        "city": data.get("city", ""),
        "isp": data.get("ISP", ""),
        "organization": data.get("organization", ""),
        "asn": data.get("ASN", 0),
        "proxy": data.get("proxy", False),
        "vpn": data.get("vpn", False),
        "tor": data.get("tor", False),
        "active_vpn": data.get("active_vpn", False),
        "active_tor": data.get("active_tor", False),
        "recent_abuse": data.get("recent_abuse", False),
        "bot_status": data.get("bot_status", False),
        "connection_type": data.get("connection_type", ""),  # Residential/Corporate/Data Center
        "abuse_velocity": data.get("abuse_velocity", "none"),  # none/low/medium/high
        "latitude": data.get("latitude", None),
        "longitude": data.get("longitude", None),
        "timezone": data.get("timezone", ""),
        "mobile": data.get("mobile", False),
        "host": data.get("host", ""),
    }
