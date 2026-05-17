from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Entity, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
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

    # ── sherlock ──────────────────────────────────────────────────────────────
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

    # ── maigret ──────────────────────────────────────────────────────────────
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

    _finalize(result)
    return result


def _finalize(result: OsintResult) -> None:
    total_profiles = sum(
        len(f.value) for f in result.findings if isinstance(f.value, list)
    )
    result.risk = Risk.low
    result.confidence = Confidence.high if len(result.sources) >= 2 else Confidence.medium
    result.summary = (
        f"Username recon for '{result.target}': {total_profiles} profiles found "
        f"across {len(result.sources)} tools."
    )
    result.status = TaskStatus.completed
