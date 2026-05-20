"""
FullContact Person Enrich API v3.
Enriches a person from email, phone, username or social profile URL.
Docs: https://dashboard.fullcontact.com/api-ref#person-enrichment
"""
from __future__ import annotations

import os
import httpx

_BASE = "https://api.fullcontact.com/v3"


def _headers() -> dict:
    key = os.getenv("FULLCONTACT_API_KEY", "")
    if not key:
        return {}
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


def _available() -> bool:
    return bool(os.getenv("FULLCONTACT_API_KEY", ""))


async def enrich_by_email(email: str) -> dict:
    return await _enrich({"email": email})


async def enrich_by_phone(phone: str) -> dict:
    return await _enrich({"phones": [phone]})


async def enrich_by_username(username: str, platform: str = "") -> dict:
    """
    platform examples: twitter, linkedin, github, instagram, youtube
    If no platform given, tries common ones via multiple calls.
    """
    if platform:
        return await _enrich({"profiles": [{"service": platform, "username": username}]})

    # Try the most common platforms in order
    for svc in ("twitter", "github", "instagram", "linkedin"):
        result = await _enrich({"profiles": [{"service": svc, "username": username}]})
        if result.get("available") and result.get("found"):
            return result
    return {"available": True, "found": False, "reason": "No match on common platforms"}


async def _enrich(payload: dict) -> dict:
    if not _available():
        return {"available": False, "reason": "FULLCONTACT_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{_BASE}/person.enrich",
                json=payload,
                headers=_headers(),
            )
            if resp.status_code == 404:
                return {"available": True, "found": False}
            if resp.status_code == 403:
                return {"available": False, "error": "Invalid API key or quota exceeded"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    person = _parse_person(data)
    person["available"] = True
    person["found"] = True
    return person


def _parse_person(data: dict) -> dict:
    result: dict = {}

    # Basic identity
    if name := data.get("fullName"):
        result["full_name"] = name
    if age_range := data.get("ageRange"):
        result["age_range"] = age_range
    if gender := data.get("gender"):
        result["gender"] = gender

    # Location
    if location := data.get("location"):
        result["location"] = location

    # Employment
    employment = data.get("employment", [])
    if employment:
        result["employment"] = [
            {
                "name": e.get("name", ""),
                "title": e.get("title", ""),
                "current": e.get("current", False),
            }
            for e in employment[:3]
        ]

    # Education
    education = data.get("education", [])
    if education:
        result["education"] = [
            {"name": e.get("name", ""), "degree": e.get("degree", "")}
            for e in education[:3]
        ]

    # Social profiles
    profiles = data.get("details", {}).get("profiles", {})
    if profiles:
        result["social_profiles"] = [
            {"service": svc, "url": info.get("url", ""), "username": info.get("username", "")}
            for svc, info in profiles.items()
            if isinstance(info, dict)
        ]

    # Emails (masked — FullContact returns partial)
    emails = data.get("details", {}).get("emails", [])
    if emails:
        result["associated_emails"] = [e.get("value", "") for e in emails[:5]]

    # Phones (masked)
    phones = data.get("details", {}).get("phones", [])
    if phones:
        result["associated_phones"] = [p.get("value", "") for p in phones[:3]]

    # Photo
    if photo := data.get("avatar"):
        result["photo_url"] = photo

    # Bio
    if bio := data.get("bio"):
        result["bio"] = bio[:300]

    return result
