from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors import emailrep, hibp, ipqualityscore
from osint_api.parsers import holehe_parser
from osint_api.runners.cli_runner import run_cli_tool
from osint_api.security.sanitizer import mask_email
from osint_api.security.validator import validate_email


async def run(email: str) -> OsintResult:
    email = validate_email(email)
    result = OsintResult(
        workflow="email_reputation",
        target=mask_email(email),
        target_type=TargetType.email,
        status=TaskStatus.running,
    )

    domain = email.split("@")[-1]

    # ── MX records ────────────────────────────────────────────────────────────
    mx_run = await run_cli_tool("dig", ["+short", domain, "MX"])
    if mx_run.stdout.strip():
        result.sources.append(Source(name="dig_mx", success=True))
        result.findings.append(Finding(
            type="mx_records", value=mx_run.stdout.strip().splitlines(),
            source="dig", confidence=Confidence.high,
        ))

    # ── IPQualityScore ────────────────────────────────────────────────────────
    iqs = await ipqualityscore.check_email(email)
    if iqs.get("available"):
        result.sources.append(Source(name="IPQualityScore", url="https://www.ipqualityscore.com"))

        fraud_score = iqs.get("fraud_score", 0)
        result.findings.append(Finding(
            type="fraud_score", value=fraud_score, source="IPQualityScore",
            confidence=Confidence.high,
            notes="Score 0-100. >75 = suspicious, >90 = high risk",
        ))

        for field in ("valid", "deliverability", "dns_valid", "smtp_score",
                      "overall_score", "common", "generic"):
            if iqs.get(field) is not None:
                result.findings.append(Finding(
                    type=field, value=iqs[field], source="IPQualityScore",
                    confidence=Confidence.high,
                ))

        if iqs.get("disposable") or iqs.get("temporary"):
            result.risk = Risk.high
            result.warnings.append("Disposable/temporary email address detected")
            result.findings.append(Finding(
                type="disposable", value=True, source="IPQualityScore",
                confidence=Confidence.high,
            ))

        if iqs.get("spam_trap") and iqs["spam_trap"] != "none":
            result.risk = Risk.high
            result.warnings.append(f"Spam trap detected: {iqs['spam_trap']}")
            result.findings.append(Finding(
                type="spam_trap", value=iqs["spam_trap"], source="IPQualityScore",
                confidence=Confidence.high,
            ))

        if iqs.get("leaked"):
            result.risk = Risk.high
            result.warnings.append("Email found in known data breach databases (IPQualityScore)")
            result.findings.append(Finding(
                type="leaked", value=True, source="IPQualityScore",
                confidence=Confidence.high,
            ))

        if fraud_score > 90:
            result.risk = Risk.high
            result.warnings.append(f"Very high fraud score: {fraud_score}/100")
        elif fraud_score > 75:
            if result.risk == Risk.unknown:
                result.risk = Risk.medium
            result.warnings.append(f"Elevated fraud score: {fraud_score}/100")

        if iqs.get("suggested_domain"):
            result.findings.append(Finding(
                type="suggested_domain", value=iqs["suggested_domain"],
                source="IPQualityScore", confidence=Confidence.medium,
                notes="Possible typo in email domain",
            ))

    # ── holehe (service registrations) ───────────────────────────────────────
    holehe_run = await run_cli_tool("holehe", ["--no-color", "--only-used", email])
    if holehe_run.stdout:
        parsed = holehe_parser.parse(holehe_run.stdout)
        result.sources.append(Source(name="holehe", success=holehe_run.returncode == 0))
        if parsed.get("registered"):
            result.findings.append(Finding(
                type="registered_services", value=parsed["registered"],
                source="holehe", confidence=Confidence.medium,
                notes=f"{parsed['registered_count']} services found",
            ))

    # ── EmailRep ──────────────────────────────────────────────────────────────
    erep = await emailrep.check_email(email)
    if erep.get("available"):
        result.sources.append(Source(name="EmailRep", url="https://emailrep.io"))
        result.findings.append(Finding(
            type="email_reputation", value=erep.get("reputation", "unknown"),
            source="EmailRep", confidence=Confidence.high,
        ))
        if erep.get("suspicious"):
            if result.risk == Risk.unknown:
                result.risk = Risk.medium
            result.warnings.append("EmailRep flags this address as suspicious")
        if erep.get("profiles"):
            result.findings.append(Finding(
                type="linked_profiles", value=erep["profiles"],
                source="EmailRep", confidence=Confidence.medium,
            ))

    # ── HIBP (breach exposure) ────────────────────────────────────────────────
    hibp_data = await hibp.check_email(email)
    if hibp_data.get("available"):
        result.sources.append(Source(name="HaveIBeenPwned", url="https://haveibeenpwned.com"))
        breach_count = hibp_data.get("breach_count", 0)
        result.findings.append(Finding(
            type="breach_count", value=breach_count, source="HaveIBeenPwned",
            confidence=Confidence.high,
            notes="No passwords shown — only breach names and metadata",
        ))
        if breach_count > 0:
            result.risk = Risk.high
            result.warnings.append(f"Email found in {breach_count} known data breach(es)")
            result.findings.append(Finding(
                type="breaches", value=hibp_data["breaches"],
                source="HaveIBeenPwned", confidence=Confidence.high,
            ))

    _finalize(result)
    return result


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown and result.findings:
        result.risk = Risk.low
    result.confidence = Confidence.high if len(result.sources) >= 2 else Confidence.medium
    result.summary = (
        f"Email reputation for '{result.target}': {len(result.findings)} findings "
        f"from {len(result.sources)} sources. Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
