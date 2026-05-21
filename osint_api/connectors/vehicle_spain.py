"""
Spanish vehicle lookup via RapidAPI — Autoways / DGT API.
Supports Spanish license plate (matrícula) and VIN (bastidor).

API: api-license-plate-spain-matricula-api-espana (RapidAPI / Autoways)
Host: api-license-plate-spain-matricula-api-espana.p.rapidapi.com
Docs: https://rapidapi.com/autoways/api/api-license-plate-spain-matricula-api-espana
"""
from __future__ import annotations

import re
import os
import httpx

_HOST = "api-license-plate-spain-matricula-api-espana.p.rapidapi.com"
_URL  = f"https://{_HOST}/"

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

    params = {"country": "es"}
    if query_type == "plate":
        params["plaque"] = query
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

    # API-level errors
    if payload.get("error"):
        return {
            "available": True,
            "found": False,
            "error": payload.get("message", "API error"),
        }

    data = payload.get("data", {})
    if not data:
        return {"available": True, "found": False, "query": query}

    return {
        "available": True,
        "found": True,
        "query": query,
        "query_type": query_type,
        "source": "RapidAPI / Autoways (DGT)",
        "vehicle_data": _normalize(data),
        "raw": data,
    }


def _normalize(data: dict) -> dict:
    """Map Autoways AWN_ prefixed fields to a clean schema."""
    return {
        # ── Identification ────────────────────────────────────────────────
        "plate":           data.get("AWN_immat", ""),
        "vin":             data.get("AWN_VIN", ""),
        "make":            data.get("AWN_marque", ""),
        "model":           data.get("AWN_modele", ""),
        "version":         data.get("AWN_version", ""),
        "commercial_name": data.get("AWN_nom_commercial", ""),
        "label":           data.get("AWN_label", ""),
        "color":           data.get("AWN_couleur", ""),
        "body_type":       data.get("AWN_style_carrosserie", ""),
        "platform_code":   data.get("AWN_code_platform", ""),

        # ── Engine & Performance ──────────────────────────────────────────
        "fuel_type":       data.get("AWN_energie", ""),
        "engine_code":     data.get("AWN_code_moteur", ""),
        "engine_cc":       data.get("AWN_cylindre_capacite", ""),
        "engine_liters":   data.get("AWN_cylindree_liters", ""),
        "power_kw":        data.get("AWN_puissance_KW", ""),
        "power_hp":        data.get("AWN_puissance_chevaux", ""),
        "fiscal_power":    data.get("AWN_puissance_fiscale", ""),
        "gearbox":         data.get("AWN_type_boite_vites", ""),
        "num_gears":       data.get("AWN_nbr_vitesses", ""),
        "max_speed_kmh":   data.get("AWN_max_speed", ""),

        # ── Dimensions & Capacity ─────────────────────────────────────────
        "num_doors":       data.get("AWN_nbr_portes", ""),
        "num_seats":       data.get("AWN_nbr_places", ""),
        "length_mm":       data.get("AWN_longueur", ""),
        "width_mm":        data.get("AWN_largeur", ""),
        "height_mm":       data.get("AWN_hauteur", ""),
        "max_weight_kg":   data.get("AWN_PTAC", ""),

        # ── Emissions ─────────────────────────────────────────────────────
        "co2_g_km":        data.get("AWN_emission_co_2", ""),
        "euro_standard":   data.get("AWN_norme_euro_standardise", ""),
        "consumption_l100":data.get("AWN_consommation_mixte", ""),

        # ── Tyres ─────────────────────────────────────────────────────────
        "tyres":           data.get("AWN_pneus", ""),

        # ── Dates ─────────────────────────────────────────────────────────
        "first_registration": data.get("AWN_date_mise_en_circulation", ""),
        "model_year_start":   data.get("AWN_annee_de_debut_modele", ""),
        "model_year_end":     data.get("AWN_annee_de_fin_modele", ""),
    }
