"""
Allowlist of permitted CLI tools and their allowed arguments.
No argument outside this list may be passed to subprocess execution.
"""
from __future__ import annotations

TOOL_ALLOWLIST: dict[str, dict] = {
    "whois": {
        "binary": "whois",
        "allowed_flags": ["-H", "-r", "-a"],
        "positional_validators": ["domain_or_ip"],
        "timeout": 30,
    },
    "dig": {
        "binary": "dig",
        "allowed_flags": ["+short", "+noall", "+answer", "+nocmd", "ANY", "A", "AAAA",
                          "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "-x"],
        "positional_validators": ["domain_or_ip"],
        "timeout": 15,
    },
    "subfinder": {
        "binary": "subfinder",
        "allowed_flags": ["-d", "-silent", "-o", "-t", "-timeout", "-nW"],
        "positional_validators": [],
        "timeout": 120,
    },
    "theHarvester": {
        "binary": "theHarvester",
        "allowed_flags": ["-d", "-l", "-b", "-f", "-S", "-v"],
        "allowed_b_sources": [
            "bing", "duckduckgo", "google", "yahoo", "baidu",
            "certspotter", "crtsh", "dnsdumpster", "hackertarget",
            "rapiddns", "sublist3r", "threatcrowd", "threatminer",
            "urlscan", "virustotal",
        ],
        "positional_validators": [],
        "timeout": 120,
    },
    "httpx": {
        "binary": "httpx",
        "allowed_flags": ["-u", "-silent", "-title", "-status-code", "-tech-detect",
                          "-web-server", "-follow-redirects", "-timeout"],
        "positional_validators": [],
        "timeout": 60,
    },
    "whatweb": {
        "binary": "whatweb",
        "allowed_flags": ["--log-brief", "--no-errors", "--quiet", "-a"],
        "positional_validators": ["url"],
        "timeout": 30,
    },
    "sherlock": {
        "binary": "sherlock",
        "allowed_flags": ["--timeout", "--print-found", "--no-color", "--csv",
                          "--folderoutput", "--site"],
        "positional_validators": ["username"],
        "timeout": 180,
    },
    "maigret": {
        "binary": "maigret",
        "allowed_flags": ["--timeout", "--no-color", "-a", "--json",
                          "--folderoutput", "--site", "--top-sites"],
        "positional_validators": ["username"],
        "timeout": 180,
    },
    "holehe": {
        "binary": "holehe",
        "allowed_flags": ["--no-color", "--only-used", "--timeout"],
        "positional_validators": ["email"],
        "timeout": 120,
    },
    "phoneinfoga": {
        "binary": "phoneinfoga",
        "allowed_flags": ["scan", "-n", "--output", "--format"],
        "positional_validators": ["phone"],
        "timeout": 60,
    },
    "exiftool": {
        "binary": "exiftool",
        "allowed_flags": ["-json", "-csv", "-n", "-q", "-s", "-a",
                          "-GPS*", "-Author", "-CreateDate", "-ModifyDate",
                          "-Software", "-FileType", "-all", "-ee"],
        "positional_validators": ["filepath"],
        "timeout": 30,
    },
    "mat2": {
        "binary": "mat2",
        "allowed_flags": ["--show", "--inplace", "--no-sandbox"],
        "positional_validators": ["filepath"],
        "timeout": 30,
    },
    "pdfinfo": {
        "binary": "pdfinfo",
        "allowed_flags": ["-meta", "-enc", "-l"],
        "positional_validators": ["filepath"],
        "timeout": 15,
    },
    "file": {
        "binary": "file",
        "allowed_flags": ["-b", "-i", "--mime-type"],
        "positional_validators": ["filepath"],
        "timeout": 10,
    },
    "strings": {
        "binary": "strings",
        "allowed_flags": ["-n", "-a"],
        "positional_validators": ["filepath"],
        "timeout": 15,
    },
    "gitleaks": {
        "binary": "gitleaks",
        "allowed_flags": ["detect", "--source", "--report-format", "--report-path",
                          "--no-git", "--verbose"],
        "positional_validators": [],
        "timeout": 120,
    },
    "trufflehog": {
        "binary": "trufflehog",
        "allowed_flags": ["filesystem", "git", "--json", "--no-update",
                          "--concurrency", "--only-verified"],
        "positional_validators": [],
        "timeout": 120,
    },
}


def is_tool_allowed(tool_name: str) -> bool:
    return tool_name in TOOL_ALLOWLIST


def get_tool_config(tool_name: str) -> dict | None:
    return TOOL_ALLOWLIST.get(tool_name)


def validate_args(tool_name: str, args: list[str]) -> tuple[bool, str]:
    """Returns (ok, error_message). Checks each flag against the allowlist."""
    config = TOOL_ALLOWLIST.get(tool_name)
    if config is None:
        return False, f"Tool '{tool_name}' is not in the allowlist"

    allowed_flags = set(config.get("allowed_flags", []))
    for arg in args:
        if arg.startswith("-") and arg not in allowed_flags:
            return False, f"Flag '{arg}' is not allowed for tool '{tool_name}'"

    return True, ""
