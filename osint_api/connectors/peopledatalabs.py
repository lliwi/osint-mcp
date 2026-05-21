"""
People Data Labs (PDL) Person Enrichment API.
Enriches a person profile from email, phone, username or social profile URL.
Docs: https://docs.peopledatalabs.com/docs/person-enrichment-api

Privacy note: PDL returns very rich PII data. This connector surfaces only
what is relevant for OSINT purposes and masks or omits highly sensitive fields.
"""
from __future__ import annotations

import os
import httpx

_BASE = "https://api.peopledatalabs.com/v5"
_MIN_LIKELIHOOD = 6   # 1-10 scale — only return results with high confidence


def _key() -> str:
    return os.getenv("PEOPLEDATALABS_API_KEY", "")


def _available() -> bool:
    return bool(_key())


def _headers() -> dict:
    return {"X-Api-Key": _key(), "Content-Type": "application/json"}


# ─── Public enrichment functions ──────────────────────────────────────────────

async def enrich_by_email(email: str) -> dict:
    return await _enrich({"email": email})


async def enrich_by_phone(phone: str) -> dict:
    return await _enrich({"phone": phone})


async def enrich_by_profile(platform: str, username: str) -> dict:
    """
    platform: linkedin, github, twitter, facebook, instagram
    """
    profile_map = {
        "linkedin":  f"linkedin.com/in/{username}",
        "github":    f"github.com/{username}",
        "twitter":   f"twitter.com/{username}",
        "facebook":  f"facebook.com/{username}",
        "instagram": f"instagram.com/{username}",
    }
    url = profile_map.get(platform.lower(), "")
    if not url:
        return {"available": True, "found": False, "reason": f"Platform '{platform}' not supported"}
    return await _enrich({"profile": url})


async def enrich_by_username(username: str) -> dict:
    """Try GitHub and LinkedIn profiles for a given username."""
    for platform in ("github", "linkedin", "twitter"):
        result = await enrich_by_profile(platform, username)
        if result.get("available") and result.get("found"):
            return result
    return {"available": True, "found": False, "reason": "No PDL match for username"}


# ─── Core enrichment call ─────────────────────────────────────────────────────

async def _enrich(params: dict) -> dict:
    if not _available():
        return {"available": False, "reason": "PEOPLEDATALABS_API_KEY not configured"}

    payload = {**params, "min_likelihood": _MIN_LIKELIHOOD}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                f"{_BASE}/person/enrich",
                json=payload,
                headers=_headers(),
            )
            if resp.status_code == 404:
                return {"available": True, "found": False}
            if resp.status_code == 401:
                return {"available": False, "error": "Invalid PDL API key"}
            if resp.status_code == 402:
                return {"available": False, "error": "PDL quota exceeded"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    if data.get("status") != 200 or not data.get("data"):
        return {"available": True, "found": False}

    return _parse(data["data"], likelihood=data.get("likelihood", 0))


# ─── Response parser ──────────────────────────────────────────────────────────

def _parse(data: dict, likelihood: int = 0) -> dict:
    result: dict = {
        "available": True,
        "found": True,
        "likelihood": likelihood,   # 1-10 confidence score
    }

    # Identity
    if name := data.get("full_name"):
        result["full_name"] = name
    if gender := data.get("gender"):
        result["gender"] = gender
    if birth_year := data.get("birth_year"):
        result["birth_year"] = birth_year  # year only, not full date

    # Location
    if loc := data.get("location_name"):
        result["location"] = loc
    if country := data.get("location_country"):
        result["country"] = country

    # Current job
    job: dict = {}
    if title := data.get("job_title"):
        job["title"] = title
    if company := data.get("job_company_name"):
        job["company"] = company
    if industry := data.get("job_company_industry"):
        job["industry"] = industry
    if size := data.get("job_company_size"):
        job["company_size"] = size
    if job:
        result["current_job"] = job

    # Work history (last 5 positions)
    experience = data.get("experience", [])
    if experience:
        result["experience"] = [
            {
                "title": e.get("title", {}).get("name", ""),
                "company": e.get("company", {}).get("name", ""),
                "start": e.get("start_date", ""),
                "end": e.get("end_date", ""),
                "current": e.get("is_primary", False),
            }
            for e in experience[:5]
        ]

    # Education (last 3)
    education = data.get("education", [])
    if education:
        result["education"] = [
            {
                "school": e.get("school", {}).get("name", ""),
                "degree": e.get("degrees", [""])[0] if e.get("degrees") else "",
                "end_year": e.get("end_date", ""),
            }
            for e in education[:3]
        ]

    # Social profiles
    profiles = []
    for platform, field in (
        ("linkedin",  "linkedin_url"),
        ("github",    "github_url"),
        ("twitter",   "twitter_url"),
        ("facebook",  "facebook_url"),
    ):
        url = data.get(field, "")
        if url:
            profiles.append({"platform": platform, "url": url})

    # Also from the profiles array
    for p in data.get("profiles", []):
        network = p.get("network", "")
        url = p.get("url", "")
        username = p.get("username", "")
        if url and not any(pr["url"] == url for pr in profiles):
            profiles.append({"platform": network, "url": url, "username": username})

    if profiles:
        result["social_profiles"] = profiles[:10]

    # Work email (masked for privacy)
    work_email = data.get("work_email", "")
    if work_email:
        result["work_email_domain"] = work_email.split("@")[-1] if "@" in work_email else ""
        # Show masked version only
        local = work_email.split("@")[0]
        result["work_email_hint"] = local[:2] + "***@" + result["work_email_domain"]

    # Known email domains (not full addresses)
    emails = data.get("emails", [])
    if emails:
        result["known_email_domains"] = list({
            e.get("address", "").split("@")[-1]
            for e in emails
            if "@" in e.get("address", "")
        })

    # Skills (top 15)
    skills = data.get("skills", [])
    if skills:
        result["skills"] = skills[:15]

    # Languages
    languages = data.get("languages", [])
    if languages:
        result["languages"] = [
            lg.get("name", lg) if isinstance(lg, dict) else lg
            for lg in languages[:5]
        ]

    # Industry
    if industry := data.get("industry"):
        result["industry"] = industry

    # NOTE: We intentionally omit:
    # - full personal_emails (PII)
    # - mobile_phone (PII)
    # - inferred_salary (sensitive inference)
    # - birth_date (full date — year only shown above)
    # - location_geo (precise coordinates)

    return result
