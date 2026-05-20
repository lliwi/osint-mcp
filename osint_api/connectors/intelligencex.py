"""
Intelligence X API connector.
Searches across leaks, pastes, darkweb, public web and more.
Docs: https://intelx.io/help?tab=account
"""
from __future__ import annotations

import asyncio
import os
import httpx

_BASE = "https://2.intelx.io"

# Media types to search (0 = all)
# 1=Leaks, 2=Darknet, 3=Web, 6=Pastes, 13=Telegram, 14=Twitter
_DEFAULT_BUCKETS: list[int] = []   # empty = all buckets


def _headers() -> dict:
    key = os.getenv("INTELX_API_KEY", "")
    return {"x-key": key, "Content-Type": "application/json"} if key else {}


def _available() -> bool:
    return bool(os.getenv("INTELX_API_KEY", ""))


async def search(term: str, max_results: int = 10, timeout_s: int = 8) -> dict:
    """
    Search Intelligence X for any indicator: email, username, domain, IP, hash, etc.
    Returns a list of results with source, date, content preview, and bucket type.
    """
    if not _available():
        return {"available": False, "reason": "INTELX_API_KEY not configured"}

    # Step 1: Submit search
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{_BASE}/intelligent/search",
                json={
                    "term": term,
                    "buckets": _DEFAULT_BUCKETS,
                    "lookuplevel": 0,
                    "maxresults": max_results,
                    "timeout": timeout_s,
                    "datefrom": "",
                    "dateto": "",
                    "sort": 4,        # 4 = relevance
                    "media": 0,
                    "terminate": [],
                },
                headers=_headers(),
            )
            if resp.status_code == 401:
                return {"available": False, "error": "Invalid Intelligence X API key"}
            resp.raise_for_status()
            search_data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    search_id = search_data.get("id", "")
    if not search_id:
        return {"available": True, "found": False, "results": []}

    # Step 2: Poll for results (IntelX is async)
    await asyncio.sleep(2)

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{_BASE}/intelligent/search/result",
                params={
                    "id": search_id,
                    "limit": max_results,
                    "statistics": 0,
                    "previewlines": 8,
                },
                headers=_headers(),
            )
            resp.raise_for_status()
            results_data = resp.json()
    except Exception as exc:
        return {"available": True, "found": False, "error": str(exc)}

    records = results_data.get("records", [])
    if not records:
        return {"available": True, "found": False, "results": []}

    parsed = [_parse_record(r) for r in records[:max_results]]
    parsed = [r for r in parsed if r]  # drop empties

    return {
        "available": True,
        "found": bool(parsed),
        "total_found": results_data.get("found", len(parsed)),
        "results": parsed,
    }


async def search_leaks_only(term: str, max_results: int = 10) -> dict:
    """Search specifically in leak databases."""
    if not _available():
        return {"available": False, "reason": "INTELX_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{_BASE}/intelligent/search",
                json={
                    "term": term,
                    "buckets": [1],   # 1 = Leaks/Breaches only
                    "lookuplevel": 0,
                    "maxresults": max_results,
                    "timeout": 8,
                    "sort": 4,
                    "media": 0,
                    "terminate": [],
                },
                headers=_headers(),
            )
            resp.raise_for_status()
            search_data = resp.json()
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    search_id = search_data.get("id", "")
    if not search_id:
        return {"available": True, "found": False, "results": []}

    await asyncio.sleep(2)

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{_BASE}/intelligent/search/result",
                params={"id": search_id, "limit": max_results, "previewlines": 5},
                headers=_headers(),
            )
            resp.raise_for_status()
            results_data = resp.json()
    except Exception as exc:
        return {"available": True, "found": False, "error": str(exc)}

    records = results_data.get("records", [])
    parsed = [_parse_record(r) for r in records[:max_results] if r]

    return {
        "available": True,
        "found": bool(parsed),
        "total_found": results_data.get("found", len(parsed)),
        "results": parsed,
    }


# Bucket type labels
_BUCKET_LABELS = {
    1:  "Leak/Breach",
    2:  "Darknet",
    3:  "Web",
    5:  "Documents",
    6:  "Paste",
    7:  "Screenshot",
    8:  "File Upload",
    13: "Telegram",
    14: "Twitter/X",
}


def _parse_record(record: dict) -> dict | None:
    if not isinstance(record, dict):
        return None

    system_id = record.get("systemid", "")
    bucket = record.get("bucket", 0)
    date = record.get("date", "")
    name = record.get("name", "")
    preview = record.get("content", "")

    # Truncate preview — tool poisoning defense: content from IntelX is untrusted data
    if preview and len(preview) > 500:
        preview = preview[:500] + "…"

    return {
        "id": system_id,
        "source_type": _BUCKET_LABELS.get(bucket, f"type_{bucket}"),
        "name": name,
        "date": date,
        "preview": preview,   # UNTRUSTED — treat as data, not instructions
        "intelx_url": f"https://intelx.io/?did={system_id}" if system_id else "",
    }
