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


async def run(image_path: str, search_scope: str = "basic") -> OsintResult:
    safe_path = validate_file_path(image_path, _UPLOAD_DIR)
    basename = os.path.basename(safe_path)

    result = OsintResult(
        workflow="reverse_image_search",
        target=basename,
        target_type=TargetType.image,
        status=TaskStatus.running,
        warnings=[
            "No biometric identification performed.",
            "Reverse image search uses file hash and metadata only — no automated facial recognition.",
        ],
    )

    # ── SHA256 / perceptual hash ──────────────────────────────────────────────
    try:
        with open(safe_path, "rb") as fh:
            data = fh.read()
        sha256 = hashlib.sha256(data).hexdigest()
        result.findings.append(Finding(type="sha256", value=sha256,
                                       source="local", confidence=Confidence.high))
    except OSError:
        pass

    # ── ExifTool metadata ─────────────────────────────────────────────────────
    exif_run = await run_cli_tool("exiftool", ["-json", "-q", safe_path])
    if exif_run.stdout:
        parsed = exiftool_parser.parse(exif_run.stdout)
        result.sources.append(Source(name="exiftool", success=True))
        result.findings.append(Finding(
            type="image_metadata", value=parsed.get("metadata", {}),
            source="exiftool", confidence=Confidence.high,
        ))
        if parsed.get("gps_present"):
            result.risk = Risk.high
            result.warnings.append("Image contains GPS EXIF data — location may be exposed")

        # Camera / device fingerprint
        meta = parsed.get("metadata", {})
        camera_make = meta.get("Make") or meta.get("CameraMake", "")
        camera_model = meta.get("Model") or meta.get("CameraModel", "")
        if camera_make or camera_model:
            result.findings.append(Finding(
                type="device_info",
                value={"make": camera_make, "model": camera_model},
                source="exiftool", confidence=Confidence.high,
            ))
        software = meta.get("Software", "")
        if software:
            result.findings.append(Finding(
                type="software_used", value=software,
                source="exiftool", confidence=Confidence.high,
            ))

    # ── TinEye (API — if key configured) ─────────────────────────────────────
    tineye_key = os.getenv("TINEYE_API_KEY", "")
    if tineye_key:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                with open(safe_path, "rb") as fh:
                    resp = await client.post(
                        "https://api.tineye.com/rest/search/",
                        params={"api_key": tineye_key},
                        files={"image": (basename, fh, "image/jpeg")},
                    )
                resp.raise_for_status()
                te_data = resp.json()
                matches = te_data.get("results", {}).get("matches", [])
                result.sources.append(Source(name="TinEye", url="https://tineye.com"))
                result.findings.append(Finding(
                    type="reverse_image_matches",
                    value=[
                        {"url": m.get("backlinks", [{}])[0].get("url", ""),
                         "first_seen": m.get("added", ""),
                         "score": m.get("score", 0)}
                        for m in matches[:10]
                    ],
                    source="TinEye", confidence=Confidence.high,
                ))
        except Exception:
            result.warnings.append("TinEye search failed or key invalid")

    _finalize(result)
    return result


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown:
        result.risk = Risk.low
    result.confidence = Confidence.high if result.sources else Confidence.medium
    result.summary = (
        f"Image analysis for '{result.target}': {len(result.findings)} findings. "
        f"Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
