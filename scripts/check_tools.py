#!/usr/bin/env python3
"""
check_tools.py — verifica que cada tool del catálogo está disponible.

Modos:
  python scripts/check_tools.py           # solo comprobaciones estáticas
  python scripts/check_tools.py --live    # además lanza workflows reales contra la API
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import time
from pathlib import Path

try:
    import httpx as _http
    def _get(url, **kw):  return _http.get(url, **kw)
    def _post(url, **kw): return _http.post(url, **kw)
except ImportError:
    import urllib.request, json as _json
    class _Resp:
        def __init__(self, data): self._d = data
        def raise_for_status(self): pass
        def json(self): return _json.loads(self._d)
    def _get(url, headers=None, timeout=15, **_):
        req = urllib.request.Request(url, headers=headers or {})
        return _Resp(urllib.request.urlopen(req, timeout=timeout).read())
    def _post(url, headers=None, json=None, timeout=10, **_):
        data = _json.dumps(json).encode() if json else b""
        req = urllib.request.Request(url, data=data, headers={**(headers or {}), "Content-Type": "application/json"})
        return _Resp(urllib.request.urlopen(req, timeout=timeout).read())

try:
    import yaml as _yaml
    def _load_yaml(fh): return _yaml.safe_load(fh)
except ImportError:
    def _load_yaml(fh):
        raise SystemExit("PyYAML not available. Run: pip install pyyaml")

try:
    ROOT = Path(__file__).resolve().parent.parent
except NameError:
    ROOT = Path.cwd()

# Inside container the app lives at /app
_CANDIDATES = [ROOT / "config" / "tools.yml", Path("/app/config/tools.yml")]
TOOLS_FILE = next((p for p in _CANDIDATES if p.exists()), _CANDIDATES[0])

# ── API key env-var per tool ──────────────────────────────────────────────────
_API_KEY_MAP: dict[str, str] = {
    "abuseipdb":                   "ABUSEIPDB_API_KEY",
    "shodan":                      "SHODAN_API_KEY",
    "ipqualityscore_email":        "IPQUALITYSCORE_API_KEY",
    "ipqualityscore_phone":        "IPQUALITYSCORE_API_KEY",
    "emailrep":                    "EMAILREP_API_KEY",
    "hibp":                        "HIBP_API_KEY",
    "fullcontact":                 "FULLCONTACT_API_KEY",
    "peopledatalabs":              "PEOPLEDATALABS_API_KEY",
    "intelligencex":               "INTELX_API_KEY",
    "virustotal":                  "VIRUSTOTAL_API_KEY",
    "rapidapi_license_plate_spain":"RAPIDAPI_KEY",
    "censys":                      "CENSYS_API_TOKEN",
    "tineye":                      "TINEYE_API_KEY",
    "securitytrails":              "SECURITYTRAILS_API_KEY",
    "twilio":                      "TWILIO_ACCOUNT_SID",
    "numverify":                   "NUMVERIFY_API_KEY",
}

# ── Live test fixtures — datos reales inofensivos ─────────────────────────────
_LIVE_FIXTURES: dict[str, dict] = {
    "domain_recon":     {"workflow": "domain_recon",     "target": "example.com"},
    "email_osint":      {"workflow": "email_osint",      "target": "test@example.com"},
    "ip_reputation":    {"workflow": "ip_reputation",    "target": "8.8.8.8"},
    "username_lookup":  {"workflow": "username_lookup",  "target": "johndoe"},
    "phone_lookup":     {"workflow": "phone_lookup",     "target": "+15555550100"},
}

COLORS = {
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "red":    "\033[91m",
    "cyan":   "\033[96m",
    "reset":  "\033[0m",
    "bold":   "\033[1m",
}


def c(color: str, text: str) -> str:
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def ok(msg: str)   -> str: return c("green",  f"✓  {msg}")
def warn(msg: str) -> str: return c("yellow", f"⚠  {msg}")
def err(msg: str)  -> str: return c("red",    f"✗  {msg}")
def info(msg: str) -> str: return c("cyan",   f"   {msg}")


# ─── Static checks ────────────────────────────────────────────────────────────

def check_cli_tool(tool: dict) -> tuple[str, list[str]]:
    binary = tool.get("binary", tool["name"])
    path = shutil.which(binary)
    if path:
        return "ok", [ok(f"{tool['name']} — {binary} found at {path}")]
    return "missing", [err(f"{tool['name']} — binary '{binary}' not found in PATH")]


def check_api_tool(tool: dict, env: dict[str, str]) -> tuple[str, list[str]]:
    env_var = _API_KEY_MAP.get(tool["name"])
    if not env_var:
        return "unknown", [warn(f"{tool['name']} — no env-var mapping defined (add to _API_KEY_MAP)")]
    # Prefer live process env; fall back to parsed .env file
    value = os.environ.get(env_var) or env.get(env_var, "")
    if value and value.lower() not in ("", "changeme"):
        return "ok", [ok(f"{tool['name']} — {env_var} configured ({value[:6]}…)")]
    return "missing_key", [err(f"{tool['name']} — {env_var} not set")]


def static_checks(tools: list[dict], env: dict[str, str]) -> dict[str, int]:
    counts: dict[str, int] = {"ok": 0, "missing": 0, "missing_key": 0,
                               "disabled": 0, "unknown": 0}

    categories: dict[str, list[dict]] = {}
    for t in tools:
        categories.setdefault(t["category"], []).append(t)

    for cat, cat_tools in sorted(categories.items()):
        print(f"\n{c('bold', cat.upper())}")
        for tool in cat_tools:
            if not tool.get("enabled", True):
                counts["disabled"] += 1
                print(warn(f"{tool['name']} — disabled in tools.yml"))
                continue

            tool_type = tool.get("type", "cli")
            if tool_type == "cli":
                status, lines = check_cli_tool(tool)
            elif tool_type == "api":
                status, lines = check_api_tool(tool, env)
            else:
                status, lines = "unknown", [warn(f"{tool['name']} — type '{tool_type}' unknown")]

            counts[status] = counts.get(status, 0) + 1
            for line in lines:
                print(line)

    return counts


# ─── Live checks ──────────────────────────────────────────────────────────────

def _wait_task(base_url: str, headers: dict, task_id: str, timeout: int = 60) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = _get(f"{base_url}/tasks/{task_id}?wait=10", headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "running":
            return data
        time.sleep(2)
    return {"status": "timeout", "error": "Task did not complete in time"}


def live_checks(base_url: str, api_key: str) -> None:
    headers = {"X-OSINT-API-Key": api_key, "Content-Type": "application/json"}
    print(f"\n{c('bold', 'LIVE WORKFLOW TESTS')} → {base_url}\n")

    for name, fixture in _LIVE_FIXTURES.items():
        sys.stdout.write(f"  {name:<20} ")
        sys.stdout.flush()
        try:
            r = _post(f"{base_url}/workflow/run", headers=headers, json=fixture, timeout=10)
            r.raise_for_status()
            task_id = r.json()["task_id"]
            result = _wait_task(base_url, headers, task_id)
            status = result.get("status")
            if status == "completed":
                findings = len((result.get("result") or {}).get("findings", []))
                print(ok(f"completed — {findings} findings"))
            elif status == "timeout":
                print(warn("timed out waiting for result"))
            else:
                print(err(f"{status} — {result.get('error', '')}"))
        except Exception as exc:
            print(err(str(exc)))


# ─── .env parser (stdlib fallback) ───────────────────────────────────────────

def _parse_dotenv(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
        if m:
            key, val = m.group(1), m.group(2).split("#")[0].strip().strip('"').strip("'")
            env[key] = val
    return env


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Check OSINT tool availability")
    parser.add_argument("--live", action="store_true",
                        help="Run live workflow tests against the OSINT API")
    parser.add_argument("--api-url", default="http://localhost:8001",
                        help="OSINT API base URL (default: http://localhost:8001)")
    args = parser.parse_args()

    env: dict[str, str] = {}
    env_file = ROOT / "config" / ".env"
    if env_file.exists():
        try:
            from dotenv import dotenv_values
            env = dotenv_values(env_file)
        except ImportError:
            env = _parse_dotenv(env_file)

    with open(TOOLS_FILE) as fh:
        data = _load_yaml(fh)
    tools = data.get("tools", [])

    print(c("bold", f"\n{'─'*60}"))
    print(c("bold", f" OSINT Tool Availability Check — {len(tools)} tools in catalog"))
    print(c("bold", f"{'─'*60}"))

    counts = static_checks(tools, env)

    print(f"\n{c('bold', '─'*60)}")
    print(f" {ok(str(counts['ok']))} ready   "
          f" {warn(str(counts['disabled']))} disabled   "
          f" {err(str(counts['missing'] + counts['missing_key']))} unavailable")
    if counts.get("unknown"):
        print(f" {c('yellow', str(counts['unknown']))} unknown mapping")
    print(c("bold", "─"*60))

    if args.live:
        api_key = os.environ.get("OSINT_INTERNAL_API_KEY") or env.get("OSINT_INTERNAL_API_KEY", "")
        if not api_key:
            print(err("OSINT_INTERNAL_API_KEY not set — cannot run live tests"))
            sys.exit(1)
        live_checks(args.api_url, api_key)


if __name__ == "__main__":
    main()
