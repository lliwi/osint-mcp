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
            "Vehicle data from public DGT records via RapidAPI (Autoways).",
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
        name="RapidAPI / Autoways (DGT)",
        url="https://rapidapi.com/autoways/api/api-license-plate-spain-matricula-api-espana",
        success=True,
    ))

    v = data.get("vehicle_data", {})

    # ── Identity ──────────────────────────────────────────────────────────────
    identity: dict = {}
    for field in ("plate", "vin", "make", "model", "version",
                  "commercial_name", "color", "body_type"):
        if v.get(field):
            identity[field] = v[field]

    if identity:
        result.findings.append(Finding(
            type="vehicle_identity",
            value=identity,
            source="Autoways/DGT",
            confidence=Confidence.high,
            notes=f"{v.get('make', '')} {v.get('model', '')} — {v.get('color', '')}".strip(),
        ))

    # ── Engine & performance ──────────────────────────────────────────────────
    engine: dict = {}
    for field in ("fuel_type", "engine_code", "engine_cc", "engine_liters",
                  "power_kw", "power_hp", "fiscal_power",
                  "gearbox", "num_gears", "max_speed_kmh"):
        if v.get(field):
            engine[field] = v[field]

    if engine:
        result.findings.append(Finding(
            type="engine",
            value=engine,
            source="Autoways/DGT",
            confidence=Confidence.high,
        ))

    # ── Dimensions & capacity ─────────────────────────────────────────────────
    dims: dict = {}
    for field in ("num_doors", "num_seats", "length_mm", "width_mm",
                  "height_mm", "max_weight_kg", "tyres"):
        if v.get(field):
            dims[field] = v[field]

    if dims:
        result.findings.append(Finding(
            type="dimensions",
            value=dims,
            source="Autoways/DGT",
            confidence=Confidence.high,
        ))

    # ── Emissions ─────────────────────────────────────────────────────────────
    emissions: dict = {}
    for field in ("co2_g_km", "euro_standard", "consumption_l100"):
        if v.get(field):
            emissions[field] = v[field]

    if emissions:
        result.findings.append(Finding(
            type="emissions",
            value=emissions,
            source="Autoways/DGT",
            confidence=Confidence.high,
        ))

    # ── Registration dates ────────────────────────────────────────────────────
    dates: dict = {}
    for field in ("first_registration", "model_year_start", "model_year_end"):
        if v.get(field):
            dates[field] = v[field]

    if dates:
        result.findings.append(Finding(
            type="registration_dates",
            value=dates,
            source="Autoways/DGT",
            confidence=Confidence.high,
        ))

    _finalize(result, v)
    return result


def _finalize(result: OsintResult, v: dict) -> None:
    result.risk = Risk.low
    result.confidence = Confidence.high
    make  = v.get("make", "")
    model = v.get("model", "")
    year  = v.get("first_registration", v.get("model_year_start", ""))[:4]
    color = v.get("color", "")
    desc  = " ".join(filter(None, [make, model, year, color])) or "unknown vehicle"
    result.summary = (
        f"Vehicle recon for '{result.target}': {desc}. "
        f"{len(result.findings)} findings."
    )
    result.status = TaskStatus.completed
