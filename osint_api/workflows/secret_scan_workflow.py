"""
Secret-scanning workflow.
Scans an uploaded file/directory or a public git repository for leaked
credentials and secrets using gitleaks and trufflehog.

Defensive use only: detected secret values are redacted, never displayed in full.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import uuid

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.parsers import gitleaks_parser, trufflehog_parser
from osint_api.runners.cli_runner import run_cli_tool
from osint_api.security.validator import validate_file_path, validate_git_url

_UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/osint-uploads")


async def run(target: str, scan_type: str = "auto") -> OsintResult:
    if scan_type not in ("file", "git"):
        scan_type = "git" if target.strip().lower().startswith(("http://", "https://")) else "file"

    result = OsintResult(
        workflow="secret_scan",
        target=target,
        target_type=TargetType.url if scan_type == "git" else TargetType.file,
        status=TaskStatus.running,
        warnings=["Secret scan for defensive purposes only. Detected secrets are redacted."],
    )

    if scan_type == "git":
        await _scan_git(result, target)
    else:
        await _scan_file(result, target)

    _finalize(result)
    return result


async def _scan_file(result: OsintResult, file_path: str) -> None:
    safe_path = validate_file_path(file_path, _UPLOAD_DIR)
    if not os.path.exists(safe_path):
        raise ValueError(
            f"Path '{os.path.basename(safe_path)}' not found on the server. "
            "Upload the file first with uploadFileBase64 and use the returned 'path'."
        )
    result.target = os.path.basename(safe_path)

    # ── gitleaks (filesystem, no git history) ─────────────────────────────────
    report_path = f"/tmp/gitleaks-{uuid.uuid4().hex[:8]}.json"
    gl_run = await run_cli_tool(
        "gitleaks",
        ["detect", "--source", safe_path, "--no-git",
         "--report-format", "json", "--report-path", report_path],
    )
    # gitleaks exits 1 when leaks are found — that is not an error for us.
    if gl_run.returncode in (0, 1):
        result.sources.append(Source(name="gitleaks", success=True))
        try:
            with open(report_path) as fh:
                parsed = gitleaks_parser.parse(fh.read())
        except OSError:
            parsed = {"secrets": [], "count": 0}
        finally:
            try:
                os.remove(report_path)
            except OSError:
                pass
        _record_secrets(result, parsed, source="gitleaks")

    # ── trufflehog (filesystem) ───────────────────────────────────────────────
    th_run = await run_cli_tool(
        "trufflehog", ["filesystem", safe_path, "--json", "--no-update"]
    )
    if th_run.stdout:
        parsed = trufflehog_parser.parse(th_run.stdout)
        result.sources.append(Source(name="trufflehog", success=th_run.returncode == 0))
        _record_secrets(result, parsed, source="trufflehog")


async def _scan_git(result: OsintResult, git_url: str) -> None:
    safe_url = validate_git_url(git_url)
    result.warnings.append("Scanning a remote repository clones it on the server.")

    clone_dir = tempfile.mkdtemp(prefix="secret-scan-")
    report_path = os.path.join(clone_dir, f".gitleaks-{uuid.uuid4().hex[:8]}.json")
    try:
        # ── Clone once (default branch, full history for secret detection) ────
        clone_run = await run_cli_tool(
            "git",
            ["clone", "--quiet", "--single-branch", "--no-tags", safe_url, clone_dir],
            env={"GIT_TERMINAL_PROMPT": "0"},  # never prompt for credentials
        )
        if clone_run.returncode != 0:
            result.warnings.append(
                f"Could not clone repository: {clone_run.stderr.strip()[:200] or 'unknown error'}"
            )
            return

        # ── gitleaks (scans full git history of the clone) ────────────────────
        gl_run = await run_cli_tool(
            "gitleaks",
            ["detect", "--source", clone_dir,
             "--report-format", "json", "--report-path", report_path],
        )
        if gl_run.returncode in (0, 1):  # 1 = leaks found, not an error
            result.sources.append(Source(name="gitleaks", success=True))
            try:
                with open(report_path) as fh:
                    parsed = gitleaks_parser.parse(fh.read())
            except OSError:
                parsed = {"secrets": [], "count": 0}
            _record_secrets(result, parsed, source="gitleaks")

        # ── trufflehog (scans the local clone's git history) ──────────────────
        th_run = await run_cli_tool(
            "trufflehog", ["git", f"file://{clone_dir}", "--json", "--no-update"]
        )
        if th_run.stdout:
            parsed = trufflehog_parser.parse(th_run.stdout)
            result.sources.append(Source(name="trufflehog", success=th_run.returncode == 0))
            _record_secrets(result, parsed, source="trufflehog")
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)


def _record_secrets(result: OsintResult, parsed: dict, source: str) -> None:
    count = parsed.get("count", 0)
    result.findings.append(Finding(
        type="secret_count", value=count, source=source, confidence=Confidence.high,
    ))
    if count > 0:
        result.risk = Risk.high
        result.findings.append(Finding(
            type="secrets", value=parsed["secrets"], source=source,
            confidence=Confidence.high,
        ))
        verified = parsed.get("verified_count")
        if verified:
            result.warnings.append(f"{source}: {verified} of {count} secret(s) verified as live")
        else:
            result.warnings.append(f"{source}: {count} potential secret(s) found")


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown:
        result.risk = Risk.low if result.findings else Risk.unknown
    result.confidence = Confidence.high if result.sources else Confidence.low
    total = sum(
        f.value for f in result.findings
        if f.type == "secret_count" and isinstance(f.value, int)
    )
    result.summary = (
        f"Secret scan for '{result.target}': {total} potential secret(s) "
        f"across {len(result.sources)} scanner(s). Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
