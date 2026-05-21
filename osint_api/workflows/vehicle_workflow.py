"""
Vehicle reconnaissance workflow — Spanish license plate lookup.
Uses RapidAPI License Plate Spain to retrieve technical vehicle data.
"""
from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors import vehicle_spain
from osint_api.security.validator import validate_license_plate, ValidationError


async def run(plate: str, country: str = "ES") -> OsintResult:
    # Validate and normalise plate
    try:
        plate = validate_license_plate(plate, country=country)
    except ValidationError as exc:
        result = OsintResult(
            workflow="vehicle_recon",
            target=plate,
            target_type=TargetType.domain,  # reusing closest type; vehicles don't have a dedicated type
            status=TaskStatus.failed,
        )
        result.warnings.append(str(exc))
        result.status = TaskStatus.failed
        return result

    result = OsintResult(
        workflow="vehicle_recon",
        target=plate,
        target_type=TargetType.domain,   # closest available type
        status=TaskStatus.running,
        warnings=[
            "Vehicle data retrieved from public DGT records via RapidAPI.",
            "Owner data processing requires legal basis under RGPD Art.6.",
        ],
    )

    # ── License plate lookup ──────────────────────────────────────────────────
    data = await vehicle_spain.lookup_plate(plate)

    if not data.get("available"):
        reason = data.get("reason") or data.get("error", "API not available")
        result.status = TaskStatus.failed
        result.warnings.append(f"Vehicle lookup failed: {reason}")
        return result

    if not data.get("found"):
        result.status = TaskStatus.completed
        result.summary = f"No vehicle found for plate '{plate}' in the database."
        result.confidence = Confidence.high
        result.risk = Risk.low
        return result

    result.sources.append(Source(
        name="RapidAPI / License Plate Spain",
        url="https://rapidapi.com/search/license+plate+spain",
        success=True,
    ))

    # ── Vehicle technical data ────────────────────────────────────────────────
    vehicle = data.get("vehicle", {})
    if vehicle:
        result.findings.append(Finding(
            type="vehicle_info",
            value=vehicle,
            source="RapidAPI",
            confidence=Confidence.high,
            notes=f"{vehicle.get('brand', '')} {vehicle.get('model', '')} {vehicle.get('year', '')}".strip(),
        ))

    # Individual surfaced fields for easy reading
    for field, label in (
        ("brand",              "brand"),
        ("model",              "model"),
        ("year",               "year"),
        ("color",              "color"),
        ("fuel_type",          "fuel_type"),
        ("body_type",          "body_type"),
        ("engine_displacement_cc", "engine_cc"),
        ("engine_power",       "engine_power"),
        ("seats",              "seats"),
        ("environmental_badge","environmental_badge"),
    ):
        val = vehicle.get(field)
        if val is not None:
            result.findings.append(Finding(
                type=label, value=val,
                source="RapidAPI", confidence=Confidence.high,
            ))

    # ── ITV status ────────────────────────────────────────────────────────────
    itv = data.get("itv", {})
    if itv:
        result.findings.append(Finding(
            type="itv_status", value=itv,
            source="RapidAPI", confidence=Confidence.high,
            notes="Spanish mandatory vehicle inspection status",
        ))
        # Flag if ITV expired
        itv_result = str(itv.get("last_result", "")).lower()
        if "negativ" in itv_result or "unfavorable" in itv_result or "fail" in itv_result:
            result.risk = Risk.medium
            result.warnings.append("Vehicle has a negative ITV (failed inspection)")

    # ── Insurance ─────────────────────────────────────────────────────────────
    insurance = data.get("insurance", {})
    if insurance:
        result.findings.append(Finding(
            type="insurance", value=insurance,
            source="RapidAPI", confidence=Confidence.high,
        ))
        insured_val = str(insurance.get("insured", "")).lower()
        if insured_val in ("no", "false", "0", "sin seguro"):
            result.risk = Risk.high
            result.warnings.append("Vehicle appears to have no active insurance")

    # ── Theft flag ────────────────────────────────────────────────────────────
    stolen = data.get("stolen_flag", "")
    if str(stolen).lower() in ("yes", "si", "sí", "true", "1", "robado"):
        result.risk = Risk.high
        result.findings.append(Finding(
            type="stolen", value=True,
            source="RapidAPI", confidence=Confidence.high,
        ))
        result.warnings.append("⚠️ Vehicle has been reported as STOLEN")

    # ── Owner (if unlocked via env) ───────────────────────────────────────────
    if data.get("owner"):
        result.findings.append(Finding(
            type="owner_data", value=data["owner"],
            source="RapidAPI", confidence=Confidence.high,
            notes="Owner PII — handle with care under RGPD",
        ))
    if data.get("owner_data_suppressed"):
        result.findings.append(Finding(
            type="owner_data_suppressed", value=True,
            source="RapidAPI", confidence=Confidence.high,
            notes="Set VEHICLE_INCLUDE_OWNER_DATA=true with legal basis to unlock",
        ))

    # Propagate any warnings from connector
    for w in data.get("warnings", []):
        if w not in result.warnings:
            result.warnings.append(w)

    _finalize(result)
    return result


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown:
        result.risk = Risk.low
    result.confidence = Confidence.high if result.sources else Confidence.low
    vehicle = next((f.value for f in result.findings if f.type == "vehicle_info"), {})
    brand  = vehicle.get("brand", "")
    model  = vehicle.get("model", "")
    year   = vehicle.get("year", "")
    desc   = f"{brand} {model} {year}".strip() or "unknown vehicle"
    result.summary = (
        f"Vehicle recon for plate '{result.target}': {desc}. "
        f"{len(result.findings)} findings. Risk: {result.risk.value}."
    )
    result.status = TaskStatus.completed
