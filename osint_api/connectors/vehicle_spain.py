"""
Spanish vehicle lookup via RapidAPI — License Plate Spain API.
Supports Spanish license plate (matrícula) and VIN (bastidor).

API: api-license-plate-spain (RapidAPI)
Host: api-license-plate-spain.p.rapidapi.com
Endpoint: GET /es?plate=1234BCD
"""
from __future__ import annotations

import re
import os
import httpx

_HOST = "api-license-plate-spain.p.rapidapi.com"
_URL  = f"https://{_HOST}/es"

_PLATE_MODERN = re.compile(r"^[0-9]{4}[A-Z]{3}$")
_PLATE_OLD    = re.compile(r"^[A-Z]{1,2}[0-9]{4}[A-Z]{2}$")
_VIN_PATTERN  = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$", re.IGNORECASE)


def _key() -> str:
    return os.getenv("RAPIDAPI_KEY", "")


def _available() -> bool:
    return bool(_key())


def _headers() -> dict:
    return {
        "X-RapidAPI-Key":  _key(),
        "X-RapidAPI-Host": _HOST,
    }


def detect_query_type(query: str) -> str:
    """Return 'plate', 'vin', or 'unknown'."""
    q = query.strip().upper().replace("-", "").replace(" ", "")
    if _VIN_PATTERN.match(q):
        return "vin"
    if _PLATE_MODERN.match(q) or _PLATE_OLD.match(q):
        return "plate"
    return "unknown"


async def lookup(query: str, query_type: str = "auto") -> dict:
    """
    Look up a vehicle by Spanish plate or VIN.

    Args:
        query:      Matrícula (e.g. '1234ABC') or VIN (17 chars).
        query_type: 'plate', 'vin', or 'auto' (default).
    """
    query = query.strip().upper().replace("-", "").replace(" ", "")

    if query_type == "auto":
        query_type = detect_query_type(query)

    if query_type == "unknown":
        return {
            "available": True,
            "found": False,
            "error": (
                "Formato no reconocido. Usa una matrícula española (ej. 1234ABC) "
                "o un VIN de 17 caracteres."
            ),
        }

    if not _available():
        return {"available": False, "reason": "RAPIDAPI_KEY not configured"}

    params = {}
    if query_type == "plate":
        params["plate"] = query
    else:
        params["vin"] = query

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(_URL, params=params, headers=_headers())

            if resp.status_code in (401, 403):
                return {"available": False, "error": "Invalid RapidAPI key or no active subscription"}
            if resp.status_code == 429:
                return {"available": False, "error": "RapidAPI rate limit exceeded"}
            if resp.status_code == 404:
                return {"available": True, "found": False, "query": query}

            resp.raise_for_status()
            payload = resp.json()

    except httpx.TimeoutException:
        return {"available": False, "error": "Request timed out"}
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    # API returns a list; empty list means not found
    if not payload or (isinstance(payload, list) and len(payload) == 0):
        return {"available": True, "found": False, "query": query}

    data = payload[0] if isinstance(payload, list) else payload

    return {
        "available": True,
        "found": True,
        "query": query,
        "query_type": query_type,
        "source": "RapidAPI / DGT (api-license-plate-spain)",
        "vehicle_data": _normalize(data),
        "raw": payload,
    }


def _normalize(data: dict) -> dict:
    """Map DGT/RapidAPI Spanish fields to internal schema."""
    return {
        # ── Identification ────────────────────────────────────────────────
        "plate":              data.get("MATRICULA", ""),
        "vin":                data.get("VIN", ""),
        "make":               data.get("MARCA", ""),
        "model":              data.get("MODELO", ""),
        "version":            data.get("TPMOTOR", ""),
        "color":              data.get("COLOR", ""),
        "body_type":          data.get("CARROCERIA", ""),
        "country":            data.get("PAIS", ""),

        # ── Engine & Performance ──────────────────────────────────────────
        "fuel_type":          data.get("TYMOTOR", ""),
        "engine_code":        data.get("MOTOR", ""),
        "power_kw":           data.get("KWs", ""),
        "drivetrain":         data.get("TRACCION", ""),
        "injection":          data.get("INYECCION", ""),

        # ── Dates ─────────────────────────────────────────────────────────
        "first_registration": data.get("FECHA_MATRICULACION", ""),

        # ── TecDoc IDs ────────────────────────────────────────────────────
        "tecdoc_ktype":       data.get("ID_KTYPE", ""),
        "brand_id":           data.get("IDMARCA", ""),
        "model_id":           data.get("IDMODELO", ""),
        "tecdoc_brand_id":    data.get("ID_MARCA_TECDOC", ""),
        "tecdoc_model_id":    data.get("ID_MODELO_TECDOC", ""),
    }
