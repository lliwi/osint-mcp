from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors import abuseipdb, shodan, virustotal
from osint_api.parsers import whois_parser
from osint_api.runners.cli_runner import run_cli_tool
from osint_api.security.validator import validate_ip


async def run(ip_address: str) -> OsintResult:
    ip = validate_ip(ip_address)
    result = OsintResult(
        workflow="ip_reputation",
        target=ip,
        target_type=TargetType.ip,
        status=TaskStatus.running,
    )

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    whois_run = await run_cli_tool("whois", [ip])
    if whois_run.stdout:
        parsed = whois_parser.parse(whois_run.stdout)
        result.sources.append(Source(name="whois", success=True))
        for k, v in parsed.items():
            if k != "raw" and v:
                result.findings.append(Finding(type=f"whois_{k}", value=v, source="whois",
                                                confidence=Confidence.high))

    # ── Reverse DNS ───────────────────────────────────────────────────────────
    rdns = await run_cli_tool("dig", ["+short", "-x", ip])
    if rdns.stdout.strip():
        result.sources.append(Source(name="dig_ptr", success=True))
        result.findings.append(Finding(
            type="reverse_dns", value=rdns.stdout.strip(), source="dig", confidence=Confidence.high
        ))

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    abuse = await abuseipdb.check_ip(ip)
    if abuse.get("available"):
        result.sources.append(Source(name="AbuseIPDB", url="https://www.abuseipdb.com"))
        score = abuse.get("abuse_confidence_score", 0)
        result.findings.append(Finding(
            type="abuse_confidence_score", value=score, source="AbuseIPDB",
            confidence=Confidence.high,
        ))
        if score > 50:
            result.risk = Risk.high
            result.warnings.append(f"High abuse confidence score: {score}%")
        elif score > 10:
            result.risk = Risk.medium

        for field in ("country", "isp", "usage_type", "total_reports"):
            if abuse.get(field):
                result.findings.append(Finding(type=field, value=abuse[field],
                                                source="AbuseIPDB", confidence=Confidence.high))

    # ── Shodan (passive) ──────────────────────────────────────────────────────
    shodan_data = await shodan.check_ip(ip)
    if shodan_data.get("available") and shodan_data.get("found"):
        result.sources.append(Source(name="Shodan", url="https://www.shodan.io"))
        for field in ("org", "country", "asn", "ports", "hostnames"):
            if shodan_data.get(field):
                result.findings.append(Finding(type=field, value=shodan_data[field],
                                                source="Shodan", confidence=Confidence.high))
        if shodan_data.get("vulns"):
            result.risk = Risk.high
            result.findings.append(Finding(
                type="known_vulnerabilities", value=shodan_data["vulns"],
                source="Shodan", confidence=Confidence.medium,
            ))
            result.warnings.append(f"Shodan reports {len(shodan_data['vulns'])} known vulnerabilities")

    _finalize(result)
    return result


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown and result.findings:
        result.risk = Risk.low
    source_count = len(result.sources)
    result.confidence = Confidence.high if source_count >= 2 else Confidence.medium
    result.summary = (
        f"IP reputation for '{result.target}': {len(result.findings)} findings from "
        f"{source_count} sources. Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
