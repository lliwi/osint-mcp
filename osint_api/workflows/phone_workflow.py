from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors import ipqualityscore
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

    # ── IPQualityScore ────────────────────────────────────────────────────────
    iqs = await ipqualityscore.check_phone(phone)
    if iqs.get("available"):
        result.sources.append(Source(name="IPQualityScore", url="https://www.ipqualityscore.com"))
        for field in ("valid", "carrier", "line_type", "country", "prepaid", "active"):
            if iqs.get(field) is not None:
                result.findings.append(Finding(
                    type=field, value=iqs[field], source="IPQualityScore",
                    confidence=Confidence.high,
                ))
        fraud_score = iqs.get("fraud_score", 0)
        result.findings.append(Finding(
            type="fraud_score", value=fraud_score, source="IPQualityScore",
            confidence=Confidence.high,
            notes="Score 0-100. >75 = suspicious, >90 = high risk",
        ))
        if fraud_score > 90:
            result.risk = Risk.high
            result.warnings.append(f"IPQualityScore fraud score very high: {fraud_score}/100")
        elif fraud_score > 75:
            result.risk = Risk.medium
            result.warnings.append(f"IPQualityScore fraud score elevated: {fraud_score}/100")

        for flag, label in (
            ("spammer", "Flagged as spammer"),
            ("leaked", "Found in known data leaks"),
            ("risky", "Flagged as risky"),
            ("do_not_call", "Registered on Do Not Call list"),
        ):
            if iqs.get(flag):
                result.warnings.append(label)
                result.findings.append(Finding(
                    type=flag, value=True, source="IPQualityScore",
                    confidence=Confidence.high,
                ))

        if iqs.get("name"):
            result.findings.append(Finding(
                type="owner_name", value=iqs["name"], source="IPQualityScore",
                confidence=Confidence.medium,
                notes="Owner name may not be accurate",
            ))

    # ── phoneinfoga (CLI) ─────────────────────────────────────────────────────
    pf_run = await run_cli_tool("phoneinfoga", ["scan", "-n", phone])
    if pf_run.stdout:
        parsed = phoneinfoga_parser.parse(pf_run.stdout)
        result.sources.append(Source(name="phoneinfoga", success=pf_run.returncode == 0))
        for field in ("country", "carrier", "line_type", "valid"):
            if parsed.get(field) is not None and not any(
                f.type == field for f in result.findings
            ):
                result.findings.append(Finding(
                    type=field, value=parsed[field], source="phoneinfoga",
                    confidence=Confidence.medium,
                ))
        if parsed.get("spam_signals"):
            result.findings.append(Finding(
                type="spam_signals", value=parsed["spam_signals"],
                source="phoneinfoga", confidence=Confidence.medium,
            ))

    _finalize(result)
    return result


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown and result.findings:
        result.risk = Risk.low
    result.confidence = Confidence.high if result.sources else Confidence.low
    result.summary = (
        f"Phone reputation for '{result.target}': {len(result.findings)} findings "
        f"from {len(result.sources)} sources. Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
