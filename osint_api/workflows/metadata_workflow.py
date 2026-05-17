from __future__ import annotations
import hashlib
import os

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.parsers import exiftool_parser
from osint_api.runners.cli_runner import run_cli_tool
from osint_api.security.validator import validate_file_path

_UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/osint-uploads")


async def run(file_path: str) -> OsintResult:
    safe_path = validate_file_path(file_path, _UPLOAD_DIR)
    basename = os.path.basename(safe_path)

    result = OsintResult(
        workflow="metadata_analysis",
        target=basename,
        target_type=TargetType.file,
        status=TaskStatus.running,
    )

    # ── File type ─────────────────────────────────────────────────────────────
    file_run = await run_cli_tool("file", ["-b", safe_path])
    file_type = file_run.stdout.strip()
    if file_type:
        result.sources.append(Source(name="file", success=True))
        result.findings.append(Finding(type="file_type", value=file_type,
                                       source="file", confidence=Confidence.high))

    # ── SHA256 hash ───────────────────────────────────────────────────────────
    try:
        with open(safe_path, "rb") as fh:
            sha256 = hashlib.sha256(fh.read()).hexdigest()
        result.findings.append(Finding(type="sha256", value=sha256,
                                       source="local", confidence=Confidence.high))
    except OSError:
        pass

    # ── ExifTool ──────────────────────────────────────────────────────────────
    exif_run = await run_cli_tool("exiftool", ["-json", "-q", safe_path])
    if exif_run.stdout:
        parsed = exiftool_parser.parse(exif_run.stdout)
        result.sources.append(Source(name="exiftool", success=True))
        result.findings.append(Finding(
            type="exif_metadata", value=parsed.get("metadata", {}),
            source="exiftool", confidence=Confidence.high,
        ))
        if parsed.get("gps_present"):
            result.risk = Risk.high
            result.warnings.append("File contains GPS coordinates — potential privacy risk")
        result.warnings.extend(parsed.get("privacy_risks", []))

    # ── mat2 (metadata check) ─────────────────────────────────────────────────
    mat2_run = await run_cli_tool("mat2", ["--show", safe_path])
    if mat2_run.stdout.strip():
        result.sources.append(Source(name="mat2", success=True))
        result.findings.append(Finding(
            type="mat2_fields", value=mat2_run.stdout.strip().splitlines(),
            source="mat2", confidence=Confidence.high,
        ))

    _finalize(result)
    return result


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown:
        result.risk = Risk.low
    result.confidence = Confidence.high if result.sources else Confidence.low
    result.summary = (
        f"Metadata analysis for '{result.target}': {len(result.findings)} findings. "
        f"Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
