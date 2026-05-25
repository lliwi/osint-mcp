"""
Metadata analysis workflow.
Supports: images (JPEG/PNG/TIFF/RAW/HEIC), PDFs, Office documents (DOCX/XLSX/PPTX/ODT…).
"""
from __future__ import annotations

import hashlib
import json
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
    if not os.path.isfile(safe_path):
        raise ValueError(
            f"File '{os.path.basename(safe_path)}' not found on the server. "
            "Upload it first with uploadFileBase64 (or fetchFile for a URL) "
            "and use the returned 'path' as the target."
        )
    basename = os.path.basename(safe_path)

    result = OsintResult(
        workflow="metadata_analysis",
        target=basename,
        target_type=TargetType.file,
        status=TaskStatus.running,
    )

    # ── File type detection ───────────────────────────────────────────────────
    file_run = await run_cli_tool("file", ["-b", safe_path])
    file_type_str = file_run.stdout.strip()
    if file_type_str:
        result.sources.append(Source(name="file", success=True))
        result.findings.append(Finding(
            type="file_type", value=file_type_str,
            source="file", confidence=Confidence.high,
        ))

    # ── SHA256 hash ───────────────────────────────────────────────────────────
    try:
        with open(safe_path, "rb") as fh:
            file_bytes = fh.read()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        result.findings.append(Finding(
            type="sha256", value=sha256,
            source="local", confidence=Confidence.high,
        ))
    except OSError:
        file_bytes = b""

    # ── ExifTool (all file types) ─────────────────────────────────────────────
    exif_run = await run_cli_tool("exiftool", ["-json", "-q", "-n", safe_path])
    parsed = exiftool_parser.parse(exif_run.stdout) if exif_run.stdout else {}

    if parsed and parsed.get("field_count", 0) > 0:
        result.sources.append(Source(name="exiftool", success=True))
        doc_type = parsed.get("doc_type", "unknown")

        # File type + MIME from exiftool
        if parsed.get("mime_type"):
            result.findings.append(Finding(
                type="mime_type", value=parsed["mime_type"],
                source="exiftool", confidence=Confidence.high,
            ))

        # Surfaced key fields (type-aware)
        surfaced = parsed.get("surfaced", {})
        if surfaced:
            result.findings.append(Finding(
                type="key_metadata", value=surfaced,
                source="exiftool", confidence=Confidence.high,
                notes=f"{doc_type} document — {len(surfaced)} key fields extracted",
            ))

        # GPS
        if parsed.get("gps_present"):
            result.risk = Risk.high
            result.warnings.append("GPS coordinates found — physical location may be exposed")
            gps_fields = {
                k: v for k, v in parsed.get("metadata", {}).items()
                if k.startswith("GPS")
            }
            result.findings.append(Finding(
                type="gps_coordinates", value=gps_fields,
                source="exiftool", confidence=Confidence.high,
            ))

        # Privacy risks
        for risk_msg in parsed.get("privacy_risks", []):
            result.warnings.append(risk_msg)
            if result.risk == Risk.unknown:
                result.risk = Risk.medium

        # Full metadata (truncated for large files)
        full_meta = parsed.get("metadata", {})
        if full_meta:
            result.findings.append(Finding(
                type="full_metadata", value=_truncate_metadata(full_meta),
                source="exiftool", confidence=Confidence.high,
                notes=f"{parsed.get('field_count', 0)} total metadata fields",
            ))

        # Type-specific analysis
        if doc_type == "image":
            _analyse_image(result, surfaced, parsed.get("metadata", {}))
        elif doc_type == "pdf":
            _analyse_pdf(result, surfaced)
        elif doc_type == "office":
            _analyse_office(result, surfaced, file_type_str)

    # ── PDF-specific: pdfinfo ─────────────────────────────────────────────────
    ext = os.path.splitext(basename)[1].lower()
    if ext == ".pdf" or "pdf" in file_type_str.lower():
        pdf_run = await run_cli_tool("pdfinfo", [safe_path])
        if pdf_run.stdout and pdf_run.returncode == 0:
            pdf_meta = _parse_pdfinfo(pdf_run.stdout)
            result.sources.append(Source(name="pdfinfo", success=True))
            result.findings.append(Finding(
                type="pdfinfo", value=pdf_meta,
                source="pdfinfo", confidence=Confidence.high,
            ))
            if pdf_meta.get("Encrypted", "").lower() in ("yes", "true"):
                result.findings.append(Finding(
                    type="encrypted", value=True,
                    source="pdfinfo", confidence=Confidence.high,
                ))
                result.warnings.append("PDF is encrypted — content may be protected")

    # ── mat2 (metadata fields that mat2 can clean) ────────────────────────────
    mat2_run = await run_cli_tool("mat2", ["--show", safe_path])
    if mat2_run.stdout.strip() and mat2_run.returncode == 0:
        mat2_fields = [
            line.strip() for line in mat2_run.stdout.strip().splitlines()
            if line.strip() and ":" in line
        ]
        if mat2_fields:
            result.sources.append(Source(name="mat2", success=True))
            result.findings.append(Finding(
                type="sanitizable_metadata", value=mat2_fields,
                source="mat2", confidence=Confidence.high,
                notes="These metadata fields can be removed with mat2 --inplace",
            ))

    # ── strings (quick sensitive string scan for office/binary) ──────────────
    if ext in (".doc", ".xls", ".ppt") and len(file_bytes) < 5 * 1024 * 1024:
        strings_run = await run_cli_tool("strings", ["-n", "8", safe_path])
        if strings_run.stdout:
            suspicious = _find_suspicious_strings(strings_run.stdout)
            if suspicious:
                result.findings.append(Finding(
                    type="suspicious_strings", value=suspicious,
                    source="strings", confidence=Confidence.medium,
                    notes="Potentially sensitive strings found in binary content",
                ))
                result.warnings.append("Suspicious strings found in document binary content")

    _finalize(result)
    return result


# ─── Type-specific analysis helpers ──────────────────────────────────────────

def _analyse_image(result: OsintResult, surfaced: dict, metadata: dict) -> None:
    """Add image-specific findings."""
    camera = {
        k: surfaced.get(k)
        for k in ("Make", "Model", "SerialNumber", "LensModel")
        if surfaced.get(k)
    }
    if camera:
        result.findings.append(Finding(
            type="camera_info", value=camera,
            source="exiftool", confidence=Confidence.high,
        ))
    if surfaced.get("Software"):
        result.findings.append(Finding(
            type="editing_software", value=surfaced["Software"],
            source="exiftool", confidence=Confidence.high,
            notes="Image may have been processed or edited",
        ))
    if surfaced.get("DateTimeOriginal"):
        result.findings.append(Finding(
            type="capture_date", value=surfaced["DateTimeOriginal"],
            source="exiftool", confidence=Confidence.high,
        ))


def _analyse_pdf(result: OsintResult, surfaced: dict) -> None:
    """Add PDF-specific findings."""
    author_fields = {k: surfaced[k] for k in ("Author", "Creator", "Producer") if surfaced.get(k)}
    if author_fields:
        result.findings.append(Finding(
            type="document_author", value=author_fields,
            source="exiftool", confidence=Confidence.high,
        ))
        if result.risk == Risk.unknown:
            result.risk = Risk.medium
    if surfaced.get("Keywords"):
        result.findings.append(Finding(
            type="document_keywords", value=surfaced["Keywords"],
            source="exiftool", confidence=Confidence.medium,
        ))


def _analyse_office(result: OsintResult, surfaced: dict, file_type_str: str) -> None:
    """Add Office document-specific findings."""
    # Author trail
    author_trail = {
        k: surfaced[k]
        for k in ("Author", "Creator", "LastModifiedBy", "LastSavedBy", "Manager")
        if surfaced.get(k)
    }
    if author_trail:
        result.findings.append(Finding(
            type="author_trail", value=author_trail,
            source="exiftool", confidence=Confidence.high,
            notes="These fields identify who created and last modified the document",
        ))
        if result.risk == Risk.unknown:
            result.risk = Risk.medium

    # Organisation
    org_info = {k: surfaced[k] for k in ("Company", "Manager") if surfaced.get(k)}
    if org_info:
        result.findings.append(Finding(
            type="organisation_info", value=org_info,
            source="exiftool", confidence=Confidence.high,
        ))

    # Template (can leak internal paths)
    if surfaced.get("Template") and surfaced["Template"] not in ("Normal", "Normal.dotm", ""):
        result.findings.append(Finding(
            type="document_template", value=surfaced["Template"],
            source="exiftool", confidence=Confidence.medium,
            notes="Template path may reveal internal network structure",
        ))

    # Document statistics
    stats = {
        k: surfaced[k]
        for k in ("Words", "Characters", "Pages", "Slides", "Notes",
                  "RevisionNumber", "TotalEditTime")
        if surfaced.get(k) is not None
    }
    if stats:
        result.findings.append(Finding(
            type="document_stats", value=stats,
            source="exiftool", confidence=Confidence.high,
        ))


# ─── Utility helpers ──────────────────────────────────────────────────────────

def _parse_pdfinfo(raw: str) -> dict:
    result = {}
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip()] = v.strip()
    return result


_SUSPICIOUS_PATTERNS = [
    r"\\\\[a-zA-Z0-9_\-\.]+\\",   # UNC paths (\\server\share)
    r"[A-Z]:\\Users\\[^\\]+\\",    # Windows user paths
    r"/home/[a-z_][a-z0-9_\-]+/", # Linux home paths
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # emails
    r"password|passwd|secret|token|api.?key",  # credential keywords
]

import re as _re
_SUSPICIOUS_RE = [_re.compile(p, _re.IGNORECASE) for p in _SUSPICIOUS_PATTERNS]


def _find_suspicious_strings(output: str) -> list[str]:
    found = []
    for line in output.splitlines():
        line = line.strip()
        if not line or len(line) < 8:
            continue
        for pattern in _SUSPICIOUS_RE:
            if pattern.search(line):
                found.append(line[:200])
                break
    return found[:20]


def _truncate_metadata(metadata: dict, max_val_len: int = 300) -> dict:
    """Truncate long metadata values to avoid oversized findings."""
    return {
        k: (str(v)[:max_val_len] + "…" if len(str(v)) > max_val_len else v)
        for k, v in metadata.items()
    }


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown:
        result.risk = Risk.low
    result.confidence = Confidence.high if result.sources else Confidence.low
    result.summary = (
        f"Metadata analysis for '{result.target}': {len(result.findings)} findings. "
        f"Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
