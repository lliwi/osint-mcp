"""
PeopleDataLabs (PDL) Person Enrichment API v5.
Retrieves social profiles, employment history, education and contact info.

Based on: github.com/lliwi/case-manager — PDLService + PDLPersonEnrichPlugin
"""
from __future__ import annotations

import os
from typing import Any
import httpx

_BASE = "https://api.peopledatalabs.com/v5"
_ENDPOINT = "/person/enrich"

# Network display labels
_NETWORK_LABELS = {
    "linkedin":  "LinkedIn",
    "twitter":   "X (Twitter)",
    "facebook":  "Facebook",
    "github":    "GitHub",
    "instagram": "Instagram",
    "youtube":   "YouTube",
    "angellist": "AngelList",
    "gravatar":  "Gravatar",
    "aboutme":   "About.me",
    "foursquare":"Foursquare",
    "xing":      "Xing",
    "pinterest": "Pinterest",
    "flickr":    "Flickr",
    "spotify":   "Spotify",
    "skype":     "Skype",
}


def _key() -> str:
    return os.getenv("PEOPLEDATALABS_API_KEY", "")


def _available() -> bool:
    return bool(_key())


def _headers() -> dict:
    return {"X-Api-Key": _key(), "Content-Type": "application/json"}


def _as_list(value: Any) -> list:
    """PDL returns JSON false (Python bool False) for empty array fields instead of []."""
    return value if isinstance(value, list) else []


# ─── Public enrichment functions ──────────────────────────────────────────────

async def enrich_by_email(email: str, name: str = "", company: str = "",
                          location: str = "") -> dict:
    params: dict = {"email": email}
    if name:
        params["name"] = name
    if company:
        params["company"] = company
    if location:
        params["location"] = location
    return await _enrich(params)


async def enrich_by_phone(phone: str, name: str = "", company: str = "",
                          location: str = "") -> dict:
    params: dict = {"phone": phone}
    if name:
        params["name"] = name
    if company:
        params["company"] = company
    if location:
        params["location"] = location
    return await _enrich(params)


async def enrich_by_profile(profile_url: str) -> dict:
    """Enrich by social profile URL (LinkedIn, GitHub, Twitter, etc.)."""
    return await _enrich({"profile": profile_url})


async def enrich_by_name(name: str, company: str = "", location: str = "") -> dict:
    params: dict = {"name": name}
    if company:
        params["company"] = company
    if location:
        params["location"] = location
    return await _enrich(params)


async def enrich_by_username(username: str) -> dict:
    """Try common social profile URLs for a username."""
    for platform, url_template in (
        ("github",    f"github.com/{username}"),
        ("twitter",   f"twitter.com/{username}"),
        ("linkedin",  f"linkedin.com/in/{username}"),
        ("instagram", f"instagram.com/{username}"),
    ):
        result = await enrich_by_profile(url_template)
        if result.get("available") and result.get("found"):
            return result
    return {"available": True, "found": False, "reason": "No PDL match for username"}


# ─── Core API call ────────────────────────────────────────────────────────────

async def _enrich(params: dict, min_likelihood: int = 2) -> dict:
    if not _available():
        return {"available": False, "reason": "PEOPLEDATALABS_API_KEY not configured"}

    payload = {
        **params,
        "min_likelihood": min_likelihood,
        "pretty": False,
        "include_if_matched": True,
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                f"{_BASE}{_ENDPOINT}",
                params=payload,
                headers=_headers(),
            )
            if resp.status_code == 404:
                return {"available": True, "found": False}
            if resp.status_code == 401:
                return {"available": False, "error": "Invalid PDL API key or no permissions"}
            if resp.status_code == 402:
                return {"available": False, "error": "PDL credits exhausted"}
            if resp.status_code == 429:
                return {"available": False, "error": "PDL rate limit exceeded"}
            resp.raise_for_status()
            raw = resp.json()
    except httpx.TimeoutException:
        return {"available": False, "error": "PDL request timed out"}
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    if raw.get("status") != 200 and not raw.get("data"):
        return {"available": True, "found": False}

    return _process_response(raw)


# ─── Response normaliser ──────────────────────────────────────────────────────

def _process_response(raw: dict) -> dict:
    raw_data = raw.get("data")
    data: dict = raw_data if isinstance(raw_data, dict) else {}
    likelihood: int = raw.get("likelihood", 0)
    matched: list = _as_list(raw.get("matched"))

    # ── Social profiles ───────────────────────────────────────────────────────
    profiles = []
    for p in _as_list(data.get("profiles")):
        network = (p.get("network") or "").lower()
        raw_url = p.get("url") or ""
        url = ("https://" + raw_url) if raw_url and not raw_url.startswith("http") else raw_url
        profiles.append({
            "network":     network,
            "label":       _NETWORK_LABELS.get(network, network.title()),
            "url":         url,
            "username":    p.get("username") or "",
            "id":          p.get("id") or "",
            "first_seen":  p.get("first_seen") or "",
            "last_seen":   p.get("last_seen") or "",
            "num_sources": p.get("num_sources") or 0,
        })
    # Profiles with a URL first
    profiles.sort(key=lambda p: (0 if p["url"] else 1, p["network"]))

    # ── Dedicated social links ────────────────────────────────────────────────
    social_links: dict = {}
    for field in (
        "linkedin_url", "twitter_url", "facebook_url", "github_url",
        "linkedin_username", "twitter_username", "facebook_username", "github_username",
        "facebook_id", "linkedin_id",
    ):
        if data.get(field):
            social_links[field] = data[field]

    # ── Employment (last 5) ───────────────────────────────────────────────────
    experience = []
    for exp in _as_list(data.get("experience"))[:5]:
        company_info = exp.get("company")
        company_info = company_info if isinstance(company_info, dict) else {}
        title_info = exp.get("title")
        title_info = title_info if isinstance(title_info, dict) else {}
        experience.append({
            "title":        title_info.get("name") or "",
            "company":      company_info.get("name") or "",
            "company_size": company_info.get("size") or "",
            "is_primary":   exp.get("is_primary", False),
            "start_date":   exp.get("start_date") or "",
            "end_date":     exp.get("end_date") or "",
            "current":      not exp.get("end_date"),
            "type":         exp.get("type") or "",
        })

    # ── Locations (top 3) ─────────────────────────────────────────────────────
    locations = []
    for loc in _as_list(data.get("locations"))[:3]:
        locations.append({
            "name":       loc.get("name") or "",
            "locality":   loc.get("locality") or "",
            "region":     loc.get("region") or "",
            "country":    loc.get("country") or "",
            "is_primary": loc.get("is_primary", False),
        })

    # ── Emails & phones (domain-only for privacy) ─────────────────────────────
    # Full addresses kept internally but domain only exposed in findings
    raw_emails = [
        e.get("address", "")
        for e in _as_list(data.get("emails"))
        if e.get("address")
    ]
    known_email_domains = list({
        addr.split("@")[-1] for addr in raw_emails if "@" in addr
    })
    work_email = data.get("work_email", "")
    work_email_hint = ""
    if work_email and "@" in work_email:
        local = work_email.split("@")[0]
        domain = work_email.split("@")[1]
        work_email_hint = local[:2] + "***@" + domain

    raw_phones = [
        p.get("number", "")
        for p in _as_list(data.get("phone_numbers"))
        if p.get("number")
    ]

    # ── Education (last 3) ────────────────────────────────────────────────────
    education = []
    for edu in _as_list(data.get("education"))[:3]:
        school_info = edu.get("school")
        school_info = school_info if isinstance(school_info, dict) else {}
        education.append({
            "school":     school_info.get("name") or "",
            "degrees":    _as_list(edu.get("degrees")),
            "start_date": edu.get("start_date") or "",
            "end_date":   edu.get("end_date") or "",
        })

    return {
        "available":       True,
        "found":           True,
        "likelihood":      likelihood,
        "likelihood_pct":  int((likelihood / 10) * 100),
        "matched_fields":  matched,
        # Identity
        "full_name":       data.get("full_name") or "",
        "first_name":      data.get("first_name") or "",
        "last_name":       data.get("last_name") or "",
        "gender":          data.get("gender") or "",
        "birth_year":      data.get("birth_year"),
        # Current job
        "industry":        data.get("industry") or "",
        "job_title":       data.get("job_title") or "",
        "job_company_name":data.get("job_company_name") or "",
        "job_company_website": data.get("job_company_website") or "",
        # Summary / bio
        "summary":         data.get("summary") or "",
        # Social
        "profiles":        profiles,
        "social_links":    social_links,
        # History
        "experience":      experience,
        "locations":       locations,
        "education":       education,
        # Contact (privacy-safe)
        "known_email_domains": known_email_domains,
        "work_email_hint": work_email_hint,
        "phone_count":     len(raw_phones),   # count only, not numbers
        # Skills & languages
        "skills":          (_as_list(data.get("skills")) or [])[:15],
        "languages":       [
            lg.get("name", lg) if isinstance(lg, dict) else lg
            for lg in _as_list(data.get("languages"))[:5]
        ],
    }
