"""
Spanish vehicle lookup via RapidAPI — License Plate Spain API.
Returns technical vehicle data from DGT records.

RapidAPI subscription required: search "License plate Spain" on rapidapi.com
The host varies by provider — configure via RAPIDAPI_VEHICLE_HOST.

Privacy note: owner name and address data requires legal basis under RGPD.
This connector surfaces only technical/public vehicle data by default.
"""
from __future__ import annotations

import os
import httpx

# RapidAPI credentials
_RAPIDAPI_KEY  = lambda: os.getenv("RAPIDAPI_KEY", "")
_VEHICLE_HOST  = lambda: os.getenv("RAPIDAPI_VEHICLE_HOST",
                                   "license-plate-spain2.p.rapidapi.com")

# Whether to include owner data if returned (requires legal basis)
_INCLUDE_OWNER = os.getenv("VEHICLE_INCLUDE_OWNER_DATA", "false").lower() == "true"


def _available() -> bool:
    return bool(_RAPIDAPI_KEY()) and bool(_VEHICLE_HOST())


def _headers() -> dict:
    return {
        "x-rapidapi-key":  _RAPIDAPI_KEY(),
        "x-rapidapi-host": _VEHICLE_HOST(),
    }


async def lookup_plate(plate: str) -> dict:
    """
    Look up a Spanish license plate.
    Returns technical vehicle data: brand, model, year, fuel, colour, ITV status.
    Owner data omitted unless VEHICLE_INCLUDE_OWNER_DATA=true and legally authorised.
    """
    if not _available():
        return {
            "available": False,
            "reason": "RAPIDAPI_KEY or RAPIDAPI_VEHICLE_HOST not configured",
        }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                f"https://{_VEHICLE_HOST()}/",
                params={"plate": plate},
                headers=_headers(),
            )
            if resp.status_code == 404:
                return {"available": True, "found": False, "plate": plate}
            if resp.status_code == 401:
                return {"available": False, "error": "Invalid RapidAPI key"}
            if resp.status_code == 429:
                return {"available": False, "error": "RapidAPI rate limit exceeded"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    if not data:
        return {"available": True, "found": False, "plate": plate}

    return _parse(plate, data)


def _parse(plate: str, data: dict) -> dict:
    """
    Normalise the API response. Field names vary by RapidAPI provider.
    Handles both snake_case and camelCase responses.
    """
    def _get(*keys: str, default="") -> str:
        for k in keys:
            v = data.get(k) or data.get(k.lower()) or data.get(_camel(k))
            if v:
                return str(v).strip()
        return default

    result: dict = {
        "available": True,
        "found": True,
        "plate": plate,
    }

    # ── Technical data (public) ───────────────────────────────────────────────
    vehicle: dict = {}

    brand = _get("brand", "marca", "make", "fabricante")
    model = _get("model", "modelo")
    version = _get("version", "variante", "variant")
    if brand:
        vehicle["brand"] = brand
    if model:
        vehicle["model"] = model
    if version:
        vehicle["version"] = version

    year = _get("year", "año", "anio", "firstRegistrationYear",
                "fechaMatriculacion", "matriculationYear")
    if year:
        vehicle["year"] = year

    color = _get("color", "colour", "colorVehiculo")
    if color:
        vehicle["color"] = color

    fuel = _get("fuel", "combustible", "fuelType", "tipoCombustible")
    if fuel:
        vehicle["fuel_type"] = fuel

    body = _get("bodyType", "carroceria", "tipoVehiculo", "vehicleType")
    if body:
        vehicle["body_type"] = body

    doors = _get("doors", "puertas", "numeroPuertas")
    if doors:
        vehicle["doors"] = doors

    displacement = _get("displacement", "cilindrada", "engineDisplacement")
    power_cv = _get("power", "potencia", "powerCV", "cv", "kw", "powerKW")
    if displacement:
        vehicle["engine_displacement_cc"] = displacement
    if power_cv:
        vehicle["engine_power"] = power_cv

    seats = _get("seats", "plazas", "numeroplazas")
    if seats:
        vehicle["seats"] = seats

    tara = _get("tara", "weight", "pesoKg")
    if tara:
        vehicle["weight_kg"] = tara

    if vehicle:
        result["vehicle"] = vehicle

    # ── ITV / Technical inspection ────────────────────────────────────────────
    itv: dict = {}
    itv_date = _get("itvDate", "fechaItv", "itv", "nextITV", "proximaItv",
                    "fechaCaducidadItv")
    itv_result = _get("itvResult", "resultadoItv", "itvStatus")
    if itv_date:
        itv["next_itv_date"] = itv_date
    if itv_result:
        itv["last_result"] = itv_result
    if itv:
        result["itv"] = itv

    # ── Insurance ─────────────────────────────────────────────────────────────
    insurance: dict = {}
    insured = _get("insured", "asegurado", "tieneSeguro", "hasInsurance")
    ins_company = _get("insuranceCompany", "aseguradora", "compania")
    ins_expiry = _get("insuranceExpiry", "fechaVencimientoSeguro", "polizaVigencia")
    if insured:
        insurance["insured"] = insured
    if ins_company:
        insurance["company"] = ins_company
    if ins_expiry:
        insurance["expiry_date"] = ins_expiry
    if insurance:
        result["insurance"] = insurance

    # ── Environmental badge (etiqueta DGT) ───────────────────────────────────
    badge = _get("environmentalBadge", "etiquetaDgt", "etiqueta", "label")
    if badge:
        result["environmental_badge"] = badge

    # ── Theft / reports ───────────────────────────────────────────────────────
    stolen = _get("stolen", "robado", "reportedStolen")
    if stolen:
        result["stolen_flag"] = stolen

    # ── Owner data (only if explicitly enabled + legal basis confirmed) ───────
    if _INCLUDE_OWNER:
        owner: dict = {}
        owner_name = _get("ownerName", "titular", "nombre", "propietario")
        owner_nif  = _get("ownerNif", "nif", "dni", "cif")
        owner_addr = _get("ownerAddress", "domicilio", "direccion")
        if owner_name:
            owner["name"] = owner_name
        if owner_nif:
            owner["nif"] = owner_nif[:3] + "****" + owner_nif[-1] if len(owner_nif) > 4 else "***"
        if owner_addr:
            owner["address"] = owner_addr
        if owner:
            result["owner"] = owner
            result["warnings"] = [
                "Owner data shown — ensure legal basis under RGPD Art.6 before processing"
            ]
    else:
        # Signal owner data was suppressed
        has_owner = any(
            k in data for k in ("ownerName", "titular", "nombre", "propietario")
        )
        if has_owner:
            result["owner_data_suppressed"] = True
            result.setdefault("warnings", [])
            result["warnings"].append(
                "Owner PII suppressed. Set VEHICLE_INCLUDE_OWNER_DATA=true only with legal basis."
            )

    # ── Raw data passthrough (for fields not mapped above) ────────────────────
    result["raw"] = data

    return result


def _camel(snake: str) -> str:
    """Convert snake_case to camelCase for field lookups."""
    parts = snake.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])
