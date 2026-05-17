from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.parsers import phoneinfoga_parser
from osint_api.runners.cli_runner import run_cli_tool
from osint_api.security.sanitizer import mask_phone
from osint_api.security.validator import validate_phone


async def run(phone_number: str, country_hint: str = "") -> OsintResult:
    phone = validate_phone(phone_number)
    result = OsintResult(
        workflow="phone_reputation",
        target=mask_phone(phone),
        target_type=TargetType.phone,
        status=TaskStatus.running,
        warnings=["Phone data shown is for public OSINT purposes only. Respect privacy laws."],
    )

    # ── phoneinfoga ───────────────────────────────────────────────────────────
    pf_run = await run_cli_tool("phoneinfoga", ["scan", "-n", phone])
    if pf_run.stdout:
        parsed = phoneinfoga_parser.parse(pf_run.stdout)
        result.sources.append(Source(name="phoneinfoga", success=pf_run.returncode == 0))
        for field in ("country", "carrier", "line_type", "valid"):
            if parsed.get(field) is not None:
                result.findings.append(Finding(
                    type=field, value=parsed[field], source="phoneinfoga",
                    confidence=Confidence.medium,
                ))
        if parsed.get("spam_signals"):
            result.risk = Risk.medium
            result.findings.append(Finding(
                type="spam_signals", value=parsed["spam_signals"],
                source="phoneinfoga", confidence=Confidence.medium,
            ))

    _finalize(result)
    return result


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown and result.findings:
        result.risk = Risk.low
    result.confidence = Confidence.medium if result.sources else Confidence.low
    result.summary = (
        f"Phone reputation for '{result.target}': {len(result.findings)} findings. "
        f"Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
