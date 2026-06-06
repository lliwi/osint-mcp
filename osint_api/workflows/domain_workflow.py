from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors import shodan, virustotal
from osint_api.parsers import httpx_parser, theharvester_parser, whatweb_parser, whois_parser
from osint_api.runners.cli_runner import run_cli_tool
from osint_api.security.validator import validate_domain


async def run(domain: str, depth: str = "standard", passive_only: bool = True) -> OsintResult:
    domain = validate_domain(domain)
    result = OsintResult(
        workflow="domain_recon",
        target=domain,
        target_type=TargetType.domain,
        status=TaskStatus.running,
    )

    # ── WHOIS ────────────────────────────────────────────────────────────────
    whois_run = await run_cli_tool("whois", ["-H", domain])
    if whois_run.stdout:
        parsed = whois_parser.parse(whois_run.stdout)
        result.sources.append(Source(name="whois", success=whois_run.returncode == 0))
        for k, v in parsed.items():
            if k == "raw":
                continue
            if v:
                result.findings.append(Finding(type=f"whois_{k}", value=v, source="whois",
                                                confidence=Confidence.high))

    # ── DNS records ──────────────────────────────────────────────────────────
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        dns_run = await run_cli_tool("dig", ["+short", domain, record_type])
        if dns_run.stdout.strip():
            result.sources.append(Source(name=f"dig_{record_type}", success=True))
            result.findings.append(Finding(
                type=f"dns_{record_type.lower()}",
                value=dns_run.stdout.strip().splitlines(),
                source="dig",
                confidence=Confidence.high,
            ))

    # ── Subdomain discovery ───────────────────────────────────────────────────
    if depth in ("deep", "standard"):
        sub_run = await run_cli_tool("subfinder", ["-d", domain, "-silent"])
        if sub_run.stdout.strip():
            subdomains = [s for s in sub_run.stdout.strip().splitlines() if s]
            result.sources.append(Source(name="subfinder", success=True))
            result.findings.append(Finding(
                type="subdomains", value=subdomains, source="subfinder",
                confidence=Confidence.medium,
            ))

    # ── HTTP probing & fingerprinting (active) ────────────────────────────────
    if not passive_only:
        url = f"https://{domain}"

        httpx_run = await run_cli_tool(
            "httpx",
            ["-u", domain, "-silent", "-json", "-title", "-status-code",
             "-web-server", "-tech-detect", "-follow-redirects"],
        )
        if httpx_run.stdout:
            parsed_x = httpx_parser.parse(httpx_run.stdout)
            if parsed_x.get("probes"):
                result.sources.append(Source(name="httpx", success=httpx_run.returncode == 0))
                result.findings.append(Finding(
                    type="http_probe", value=parsed_x["probes"], source="httpx",
                    confidence=Confidence.high,
                ))

        whatweb_run = await run_cli_tool(
            "whatweb", ["--no-errors", url]
        )
        if whatweb_run.stdout:
            parsed_w = whatweb_parser.parse(whatweb_run.stdout)
            if parsed_w.get("technologies") or parsed_w.get("server"):
                result.sources.append(Source(name="whatweb", success=whatweb_run.returncode == 0))
                result.findings.append(Finding(
                    type="web_fingerprint",
                    value={k: v for k, v in parsed_w.items() if v},
                    source="whatweb", confidence=Confidence.high,
                ))

    # ── theHarvester ─────────────────────────────────────────────────────────
    harvester_run = await run_cli_tool(
        "theHarvester", ["-d", domain, "-b", "bing,duckduckgo,certspotter,crtsh,dnsdumpster", "-l", "100"]
    )
    if harvester_run.stdout:
        parsed_h = theharvester_parser.parse(harvester_run.stdout)
        result.sources.append(Source(name="theHarvester", success=harvester_run.returncode == 0))
        for key in ("emails", "hosts", "ips"):
            if parsed_h.get(key):
                result.findings.append(Finding(
                    type=key, value=parsed_h[key], source="theHarvester",
                    confidence=Confidence.medium,
                ))

    # ── Shodan (passive service discovery) ───────────────────────────────────
    shodan_data = await shodan.check_domain(domain)
    if shodan_data.get("available") and shodan_data.get("found"):
        result.sources.append(Source(name="Shodan", url="https://www.shodan.io"))
        if shodan_data.get("resolved_ip"):
            result.findings.append(Finding(
                type="shodan_resolved_ip", value=shodan_data["resolved_ip"],
                source="Shodan", confidence=Confidence.high,
            ))
        for field in ("org", "asn", "ports", "services"):
            if shodan_data.get(field):
                result.findings.append(Finding(
                    type=field, value=shodan_data[field],
                    source="Shodan", confidence=Confidence.high,
                ))
        if shodan_data.get("vulns"):
            result.risk = Risk.high
            result.findings.append(Finding(
                type="known_vulnerabilities", value=shodan_data["vulns"],
                source="Shodan", confidence=Confidence.medium,
            ))
            result.warnings.append(f"Shodan reports {len(shodan_data['vulns'])} known vulnerabilities")

    # ── VirusTotal (API) ──────────────────────────────────────────────────────
    vt = await virustotal.check_domain(domain)
    if vt.get("available") and vt.get("found"):
        result.sources.append(Source(name="VirusTotal", url="https://www.virustotal.com"))
        malicious = vt.get("malicious", 0)
        result.findings.append(Finding(
            type="virustotal_reputation",
            value={"malicious": malicious, "suspicious": vt.get("suspicious", 0)},
            source="VirusTotal",
            confidence=Confidence.high,
        ))
        if malicious > 0:
            result.risk = Risk.high
            result.warnings.append(f"Domain flagged as malicious by {malicious} VT engines")

    _finalize(result)
    return result


def _finalize(result: OsintResult) -> None:
    source_count = len(result.sources)
    finding_count = len(result.findings)

    if source_count >= 3 and finding_count >= 3:
        result.confidence = Confidence.high
    elif source_count >= 1:
        result.confidence = Confidence.medium
    else:
        result.confidence = Confidence.low

    if result.risk == Risk.unknown and finding_count > 0:
        result.risk = Risk.low

    result.summary = (
        f"Domain recon for '{result.target}': {finding_count} findings from "
        f"{source_count} sources. Confidence: {result.confidence.value}. Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
