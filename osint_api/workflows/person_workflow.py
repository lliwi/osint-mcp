"""
Person reconnaissance workflow.
Uses PeopleDataLabs enrichment by name + company/location/email/phone.

PDL match quality:
  - name only          → likelihood 2-5  (low)
  - name + company     → likelihood 5-7  (medium)
  - name + location    → likelihood 3-5  (low-medium)
  - name + company + location → likelihood 6-8 (good)
  - email / phone      → likelihood 7-10 (high)
"""
from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Entity, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors import intelligencex, peopledatalabs


async def run(
    name: str,
    company: str = "",
    location: str = "",
    email: str = "",
    phone: str = "",
) -> OsintResult:
    name = name.strip()
    result = OsintResult(
        workflow="person_recon",
        target=name,
        target_type=TargetType.username,
        status=TaskStatus.running,
    )

    has_extra = bool(company or location or email or phone)
    if not has_extra:
        result.status = TaskStatus.failed
        result.confidence = Confidence.low
        result.risk = Risk.low
        result.summary = (
            f"Cannot search for '{name}' without extra context. "
            "Retry with options={{\"location\":\"city\"}} or options={{\"company\":\"employer\"}}. "
            "PDL requires name + location or company to return results."
        )
        return result

    # ── People Data Labs ──────────────────────────────────────────────────────
    pdl = None

    # Priority: email/phone give the best likelihood
    if email:
        pdl = await peopledatalabs.enrich_by_email(email, name=name, company=company, location=location)
    elif phone:
        pdl = await peopledatalabs.enrich_by_phone(phone, name=name, company=company, location=location)
    else:
        pdl = await peopledatalabs.enrich_by_name(name, company=company, location=location)

    if pdl and pdl.get("available") and pdl.get("found"):
        result.sources.append(Source(name="PeopleDataLabs", url="https://www.peopledatalabs.com"))
        likelihood = pdl.get("likelihood", 0)
        likelihood_pct = pdl.get("likelihood_pct", 0)
        conf = Confidence.high if likelihood >= 7 else Confidence.medium

        for field in ("full_name", "gender", "birth_year", "industry", "summary"):
            if pdl.get(field):
                result.findings.append(Finding(
                    type=field, value=pdl[field], source="PeopleDataLabs", confidence=conf,
                ))

        if pdl.get("job_title") or pdl.get("job_company_name"):
            result.findings.append(Finding(
                type="current_job",
                value={
                    "title":   pdl.get("job_title", ""),
                    "company": pdl.get("job_company_name", ""),
                    "website": pdl.get("job_company_website", ""),
                },
                source="PeopleDataLabs", confidence=conf,
            ))

        if pdl.get("experience"):
            result.findings.append(Finding(
                type="work_history", value=pdl["experience"],
                source="PeopleDataLabs", confidence=conf,
            ))

        if pdl.get("education"):
            result.findings.append(Finding(
                type="education", value=pdl["education"],
                source="PeopleDataLabs", confidence=conf,
            ))

        if pdl.get("locations"):
            result.findings.append(Finding(
                type="locations", value=pdl["locations"],
                source="PeopleDataLabs", confidence=conf,
            ))

        if pdl.get("profiles"):
            result.findings.append(Finding(
                type="pdl_social_profiles", value=pdl["profiles"],
                source="PeopleDataLabs", confidence=conf,
                notes=f"{len(pdl['profiles'])} perfiles encontrados",
            ))
            for p in pdl["profiles"]:
                if p.get("url"):
                    result.entities.append(Entity(
                        type="social_profile",
                        value=p["url"],
                        attributes={"platform": p["network"], "username": p.get("username", "")},
                    ))

        if pdl.get("social_links"):
            result.findings.append(Finding(
                type="pdl_social_links", value=pdl["social_links"],
                source="PeopleDataLabs", confidence=Confidence.high,
            ))

        if pdl.get("skills"):
            result.findings.append(Finding(
                type="skills", value=pdl["skills"],
                source="PeopleDataLabs", confidence=Confidence.medium,
            ))

        if pdl.get("known_email_domains"):
            result.findings.append(Finding(
                type="known_email_domains", value=pdl["known_email_domains"],
                source="PeopleDataLabs", confidence=Confidence.medium,
            ))

        if pdl.get("work_email_hint"):
            result.findings.append(Finding(
                type="work_email_hint", value=pdl["work_email_hint"],
                source="PeopleDataLabs", confidence=Confidence.medium,
            ))

        result.findings.append(Finding(
            type="pdl_likelihood",
            value={"score": likelihood, "percent": likelihood_pct,
                   "matched_fields": pdl.get("matched_fields", [])},
            source="PeopleDataLabs", confidence=Confidence.high,
            notes="PDL match confidence. Score 1-10; >= 6 recommended.",
        ))

    elif pdl and not pdl.get("available"):
        result.warnings.append(f"PeopleDataLabs unavailable: {pdl.get('reason') or pdl.get('error')}")

    # ── Intelligence X ────────────────────────────────────────────────────────
    intelx = await intelligencex.search(name, max_results=10)
    if intelx.get("available") and intelx.get("found"):
        result.sources.append(Source(name="IntelligenceX", url="https://intelx.io"))
        result.findings.append(Finding(
            type="intelx_mentions", value=intelx["results"], source="IntelligenceX",
            confidence=Confidence.medium,
            notes=f"{intelx.get('total_found', 0)} mentions found",
        ))

    # ── Finalize ──────────────────────────────────────────────────────────────
    result.risk = Risk.low
    result.confidence = Confidence.high if result.sources else Confidence.low
    result.summary = (
        f"Person recon for '{name}': "
        f"{len(result.findings)} findings across {len(result.sources)} sources."
    )
    result.status = TaskStatus.completed
    return result
