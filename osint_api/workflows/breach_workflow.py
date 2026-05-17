from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors import hibp, virustotal
from osint_api.runners.cli_runner import run_cli_tool
from osint_api.security.validator import validate_email, validate_domain, validate_url, ValidationError


async def run(indicator: str, indicator_type: str = "auto") -> OsintResult:
    if indicator_type == "auto":
        indicator_type = _detect_type(indicator)

    result = OsintResult(
        workflow="breach_exposure_check",
        target=indicator,
        target_type=_map_target_type(indicator_type),
        status=TaskStatus.running,
        warnings=["Breach data shown for defensive purposes only. No passwords displayed."],
    )

    if indicator_type == "email":
        try:
            safe = validate_email(indicator)
        except Exception:
            safe = indicator
        hibp_data = await hibp.check_email(safe)
        if hibp_data.get("available"):
            result.sources.append(Source(name="HaveIBeenPwned"))
            count = hibp_data.get("breach_count", 0)
            result.findings.append(Finding(
                type="breach_count", value=count, source="HaveIBeenPwned",
                confidence=Confidence.high,
            ))
            if count > 0:
                result.risk = Risk.high
                result.findings.append(Finding(
                    type="breaches", value=hibp_data["breaches"], source="HaveIBeenPwned",
                    confidence=Confidence.high,
                ))
                result.warnings.append(f"Found in {count} known data breach(es)")

    elif indicator_type == "domain":
        try:
            safe = validate_domain(indicator)
        except Exception:
            safe = indicator
        vt = await virustotal.check_domain(safe)
        if vt.get("available") and vt.get("found"):
            result.sources.append(Source(name="VirusTotal"))
            result.findings.append(Finding(
                type="virustotal_malicious", value=vt.get("malicious", 0),
                source="VirusTotal", confidence=Confidence.high,
            ))
            if vt.get("malicious", 0) > 0:
                result.risk = Risk.high

    elif indicator_type == "url":
        try:
            safe = validate_url(indicator)
        except Exception:
            safe = indicator
        vt = await virustotal.check_url(safe)
        if vt.get("available") and vt.get("found"):
            result.sources.append(Source(name="VirusTotal"))
            result.findings.append(Finding(
                type="url_malicious", value=vt.get("malicious", 0),
                source="VirusTotal", confidence=Confidence.high,
            ))

    _finalize(result)
    return result


def _detect_type(value: str) -> str:
    if "@" in value:
        return "email"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    return "domain"


def _map_target_type(indicator_type: str) -> TargetType:
    return {
        "email": TargetType.email,
        "domain": TargetType.domain,
        "url": TargetType.url,
        "hash": TargetType.file,
    }.get(indicator_type, TargetType.domain)


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown and result.findings:
        result.risk = Risk.low
    result.confidence = Confidence.high if result.sources else Confidence.low
    result.summary = (
        f"Breach check for '{result.target}': {len(result.findings)} findings. "
        f"Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
