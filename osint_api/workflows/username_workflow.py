from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Entity, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors import fullcontact, intelligencex, peopledatalabs
from osint_api.parsers import sherlock_parser
from osint_api.runners.cli_runner import run_cli_tool
from osint_api.security.validator import validate_username


async def run(username: str, platform_scope: str = "all") -> OsintResult:
    username = validate_username(username)
    result = OsintResult(
        workflow="username_recon",
        target=username,
        target_type=TargetType.username,
        status=TaskStatus.running,
    )

    # ── Sherlock ───────────────────────────────────────────────────────────────
    args = ["--print-found", "--no-color", "--timeout", "10", username]
    if platform_scope != "all":
        args = ["--site", platform_scope, *args]

    sherlock_run = await run_cli_tool("sherlock", args)
    if sherlock_run.stdout:
        parsed = sherlock_parser.parse(sherlock_run.stdout)
        result.sources.append(Source(name="sherlock", success=sherlock_run.returncode == 0))
        profiles = parsed.get("profiles", [])
        if profiles:
            result.findings.append(Finding(
                type="found_profiles", value=profiles, source="sherlock",
                confidence=Confidence.medium,
                notes=f"{len(profiles)} profiles found",
            ))
            for p in profiles:
                result.entities.append(Entity(
                    type="social_profile",
                    value=p["url"],
                    attributes={"platform": p["platform"], "status": p["status"]},
                ))

    # ── Maigret ───────────────────────────────────────────────────────────────
    maigret_run = await run_cli_tool(
        "maigret", ["--no-color", "--top-sites", "100", "--timeout", "10", "--json", username]
    )
    if maigret_run.stdout and not maigret_run.timed_out:
        import json
        try:
            maigret_data = json.loads(maigret_run.stdout)
            result.sources.append(Source(name="maigret", success=True))
            found = [
                {"platform": k, "url": v.get("url", ""), "status": v.get("status", "")}
                for k, v in maigret_data.items()
                if isinstance(v, dict) and v.get("status") == "Claimed"
            ]
            if found:
                result.findings.append(Finding(
                    type="maigret_profiles", value=found, source="maigret",
                    confidence=Confidence.medium,
                ))
        except (json.JSONDecodeError, AttributeError):
            pass

    # ── FullContact ───────────────────────────────────────────────────────────
    fc = await fullcontact.enrich_by_username(username, platform_scope if platform_scope != "all" else "")
    if fc.get("available") and fc.get("found"):
        result.sources.append(Source(name="FullContact", url="https://fullcontact.com"))
        for field in ("full_name", "location", "age_range", "gender", "bio", "photo_url"):
            if fc.get(field):
                result.findings.append(Finding(
                    type=field, value=fc[field], source="FullContact",
                    confidence=Confidence.medium,
                ))
        if fc.get("employment"):
            result.findings.append(Finding(
                type="employment", value=fc["employment"], source="FullContact",
                confidence=Confidence.medium,
            ))
        if fc.get("social_profiles"):
            result.findings.append(Finding(
                type="fullcontact_profiles", value=fc["social_profiles"],
                source="FullContact", confidence=Confidence.high,
            ))
        if fc.get("associated_emails"):
            result.findings.append(Finding(
                type="associated_emails", value=fc["associated_emails"],
                source="FullContact", confidence=Confidence.medium,
                notes="Partial emails from FullContact enrichment",
            ))

    # ── People Data Labs ──────────────────────────────────────────────────────
    pdl = await peopledatalabs.enrich_by_username(username)
    if pdl.get("available") and pdl.get("found"):
        result.sources.append(Source(name="PeopleDataLabs", url="https://www.peopledatalabs.com"))
        likelihood = pdl.get("likelihood", 0)
        likelihood_pct = pdl.get("likelihood_pct", 0)
        conf = Confidence.high if likelihood >= 7 else Confidence.medium

        # Identity
        for field in ("full_name", "gender", "birth_year", "industry", "summary"):
            if pdl.get(field):
                result.findings.append(Finding(
                    type=field, value=pdl[field], source="PeopleDataLabs", confidence=conf,
                ))

        # Current job
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

        # Work history
        if pdl.get("experience"):
            result.findings.append(Finding(
                type="work_history", value=pdl["experience"],
                source="PeopleDataLabs", confidence=conf,
            ))

        # Education
        if pdl.get("education"):
            result.findings.append(Finding(
                type="education", value=pdl["education"],
                source="PeopleDataLabs", confidence=conf,
            ))

        # Locations
        if pdl.get("locations"):
            result.findings.append(Finding(
                type="locations", value=pdl["locations"],
                source="PeopleDataLabs", confidence=conf,
            ))

        # Social profiles (richer than FullContact)
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

        # Social links (dedicated URL fields)
        if pdl.get("social_links"):
            result.findings.append(Finding(
                type="pdl_social_links", value=pdl["social_links"],
                source="PeopleDataLabs", confidence=Confidence.high,
            ))

        # Skills & languages
        if pdl.get("skills"):
            result.findings.append(Finding(
                type="skills", value=pdl["skills"],
                source="PeopleDataLabs", confidence=Confidence.medium,
            ))
        if pdl.get("languages"):
            result.findings.append(Finding(
                type="languages", value=pdl["languages"],
                source="PeopleDataLabs", confidence=Confidence.medium,
            ))

        # Contact hints (privacy-safe)
        if pdl.get("work_email_hint"):
            result.findings.append(Finding(
                type="work_email_hint", value=pdl["work_email_hint"],
                source="PeopleDataLabs", confidence=Confidence.medium,
                notes="Partial work email — full address not shown for privacy",
            ))
        if pdl.get("known_email_domains"):
            result.findings.append(Finding(
                type="known_email_domains", value=pdl["known_email_domains"],
                source="PeopleDataLabs", confidence=Confidence.medium,
            ))

        # Confidence score
        result.findings.append(Finding(
            type="pdl_likelihood",
            value={"score": likelihood, "percent": likelihood_pct,
                   "matched_fields": pdl.get("matched_fields", [])},
            source="PeopleDataLabs", confidence=Confidence.high,
            notes="PDL match confidence. Score 1-10, higher = more reliable.",
        ))

    # ── Intelligence X ────────────────────────────────────────────────────────
    intelx = await intelligencex.search(username, max_results=10)
    if intelx.get("available") and intelx.get("found"):
        result.sources.append(Source(name="IntelligenceX", url="https://intelx.io"))
        total = intelx.get("total_found", 0)
        result.findings.append(Finding(
            type="intelx_mentions", value=intelx["results"], source="IntelligenceX",
            confidence=Confidence.medium,
            notes=f"{total} total mentions found across leaks, pastes and web",
        ))
        # Flag if found in leaks
        leak_hits = [r for r in intelx["results"] if "Leak" in r.get("source_type", "")]
        if leak_hits:
            result.risk = Risk.medium
            result.warnings.append(
                f"Username found in {len(leak_hits)} leak/breach source(s) on IntelligenceX"
            )

    _finalize(result)
    return result



def _finalize(result: OsintResult) -> None:
    total_profiles = sum(
        len(f.value) if isinstance(f.value, list) else 1
        for f in result.findings
        if f.type in ("found_profiles", "maigret_profiles", "fullcontact_profiles")
    )
    if result.risk == Risk.unknown:
        result.risk = Risk.low
    result.confidence = Confidence.high if len(result.sources) >= 2 else Confidence.medium
    result.summary = (
        f"Username recon for '{result.target}': {total_profiles} profiles found "
        f"across {len(result.sources)} sources."
    )
    result.status = TaskStatus.completed
