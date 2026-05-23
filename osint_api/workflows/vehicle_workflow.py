"""
Vehicle reconnaissance workflow.
Supports Spanish license plate (matrícula) and VIN (bastidor).
"""
from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors.vehicle_spain import lookup, detect_query_type


async def run(plate: str, country: str = "ES") -> OsintResult:
    # Normalise input
    query = plate.strip().upper().replace("-", "").replace(" ", "")
    query_type = detect_query_type(query)

    result = OsintResult(
        workflow="vehicle_recon",
        target=query,
        target_type=TargetType.domain,  # closest available generic type
        status=TaskStatus.running,
        warnings=[
            "Vehicle data from public DGT records via RapidAPI (License Plate Spain).",
        ],
    )

    if query_type == "unknown":
        result.status = TaskStatus.failed
        result.warnings.append(
            "Unrecognised format. Use a Spanish plate (e.g. 1234ABC) or 17-char VIN."
        )
        return result

    # ── API call ─────────────────────────────────────────────────────────────
    data = await lookup(query, query_type=query_type)

    if not data.get("available"):
        result.status = TaskStatus.failed
        result.warnings.append(f"Vehicle lookup unavailable: {data.get('reason') or data.get('error')}")
        return result

    if not data.get("found"):
        result.status = TaskStatus.completed
        result.confidence = Confidence.high
        result.risk = Risk.low
        result.summary = (
            f"No vehicle found for {query_type} '{query}' in the DGT database."
        )
        return result

    result.sources.append(Source(
        name="RapidAPI / License Plate Spain (DGT)",
        url="https://rapidapi.com/api/api-license-plate-spain",
        success=True,
    ))

    v = data.get("vehicle_data", {})

    # ── Identity ──────────────────────────────────────────────────────────────
    identity: dict = {}
    for field in ("plate", "vin", "make", "model", "version", "color", "body_type", "country"):
        if v.get(field):
            identity[field] = v[field]

    if identity:
        result.findings.append(Finding(
            type="vehicle_identity",
            value=identity,
            source="RapidAPI/DGT",
            confidence=Confidence.high,
            notes=f"{v.get('make', '')} {v.get('model', '')} — {v.get('color', '')}".strip(),
        ))

    # ── Engine & performance ──────────────────────────────────────────────────
    engine: dict = {}
    for field in ("fuel_type", "engine_code", "power_kw", "drivetrain", "injection"):
        if v.get(field):
            engine[field] = v[field]

    if engine:
        result.findings.append(Finding(
            type="engine",
            value=engine,
            source="RapidAPI/DGT",
            confidence=Confidence.high,
        ))

    # ── Registration dates ────────────────────────────────────────────────────
    if v.get("first_registration"):
        result.findings.append(Finding(
            type="registration_dates",
            value={"first_registration": v["first_registration"]},
            source="RapidAPI/DGT",
            confidence=Confidence.high,
        ))

    _finalize(result, v)
    return result


def _finalize(result: OsintResult, v: dict) -> None:
    result.risk = Risk.low
    result.confidence = Confidence.high
    make  = v.get("make", "")
    model = v.get("model", "")
    year  = (v.get("first_registration") or "")[:4]
    color = v.get("color", "")
    desc  = " ".join(filter(None, [make, model, year, color])) or "unknown vehicle"
    result.summary = (
        f"Vehicle recon for '{result.target}': {desc}. "
        f"{len(result.findings)} findings."
    )
    result.status = TaskStatus.completed
