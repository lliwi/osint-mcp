"""
Cala.ai — verified knowledge / entity intelligence API.
Docs: https://docs.cala.ai  ·  Base: https://api.cala.ai  ·  Auth: X-API-KEY header.

Used for entity due-diligence: resolve a name to a verified entity (company,
person, product, law, place), pull its sourced facts and a sourced summary.
"""
from __future__ import annotations

import os
import httpx

_BASE = "https://api.cala.ai"

# Entity types accepted by /v1/entities (see Cala docs).
ENTITY_TYPES = ("Company", "Person", "Product", "ResearchPaper", "Law", "Place")


def _available() -> bool:
    return bool(os.getenv("CALA_API_KEY", ""))


def _headers() -> dict:
    return {"X-API-KEY": os.getenv("CALA_API_KEY", ""), "Content-Type": "application/json"}


async def search_entities(name: str, entity_types: list[str] | None = None,
                          limit: int = 10) -> dict:
    """GET /v1/entities — resolve a name to candidate entities."""
    if not _available():
        return {"available": False, "reason": "CALA_API_KEY not configured"}

    params: dict = {"name": name, "limit": max(1, min(limit, 100))}
    if entity_types:
        params["entity_types"] = entity_types

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(f"{_BASE}/v1/entities", params=params, headers=_headers())
            if resp.status_code == 429:
                return {"available": True, "error": "rate_limited"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    entities = data.get("entities", []) or []
    return {"available": True, "found": bool(entities), "entities": entities}


async def get_entity(entity_id: str) -> dict:
    """POST /v1/entities/{id} — full sourced detail for a resolved entity."""
    if not _available():
        return {"available": False, "reason": "CALA_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=25) as client:
            resp = await client.post(
                f"{_BASE}/v1/entities/{entity_id}", json={}, headers=_headers()
            )
            if resp.status_code == 404:
                return {"available": True, "found": False}
            if resp.status_code == 429:
                return {"available": True, "error": "rate_limited"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    return {"available": True, "found": True, "entity": data}


async def knowledge_query(question: str) -> dict:
    """POST /v1/knowledge/query — structured, tabular answer (typed JSON rows).

    `question` is either a Cala QL dot-notation expression (e.g.
    'Italdesign Barcelona.employees') or a natural-language question.
    """
    if not _available():
        return {"available": False, "reason": "CALA_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{_BASE}/v1/knowledge/query",
                json={"input": question, "return_entities": True},
                headers=_headers(),
            )
            if resp.status_code == 429:
                return {"available": True, "error": "rate_limited"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    results = data.get("results", []) or []
    return {
        "available": True,
        "found": bool(results),
        "results": results,
        "entities": data.get("entities", []) or [],
    }


async def knowledge_search(question: str) -> dict:
    """POST /v1/knowledge/search — sourced natural-language answer (markdown)."""
    if not _available():
        return {"available": False, "reason": "CALA_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{_BASE}/v1/knowledge/search",
                json={"input": question, "return_entities": True},
                headers=_headers(),
            )
            if resp.status_code == 429:
                return {"available": True, "error": "rate_limited"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    return {
        "available": True,
        "found": bool(data.get("content")),
        "content": data.get("content", ""),
        "context": data.get("context", []) or [],
        "entities": data.get("entities", []) or [],
    }
