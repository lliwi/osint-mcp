"""
Company / entity due-diligence workflow, powered by Cala.ai verified knowledge.

Resolves a name to a Cala entity (company, person, product, law, place),
pulls its sourced facts and a sourced natural-language summary. Every finding
traces back to Cala's verified sources.
"""
from __future__ import annotations

from mcp_server.schemas.common import (
    Confidence, Finding, OsintResult, Risk, Source, TargetType, TaskStatus,
)
from osint_api.connectors import cala

# Map the workflow's friendly type hint to Cala's entity_type enum.
_TYPE_HINT = {
    "company": "Company", "person": "Person", "product": "Product",
    "law": "Law", "place": "Place", "research": "ResearchPaper",
}

# Keywords in the sourced summary that warrant a risk flag.
_RISK_KEYWORDS = (
    "sanction", "ofac", "politically exposed", "pep", "watchlist",
    "litigation", "lawsuit", "indict", "fraud", "bankrupt", "money laundering",
)

_MAX_PROPERTY_FINDINGS = 25


async def run(name: str, entity_type: str = "auto", query: str = "") -> OsintResult:
    name = name.strip()
    query = (query or "").strip()
    result = OsintResult(
        workflow="company_recon",
        target=name,
        target_type=TargetType.company,
        status=TaskStatus.running,
        warnings=["Verified public-record data via Cala.ai. Not for adverse action without confirmation."],
    )

    if not name:
        result.status = TaskStatus.failed
        result.summary = "company_recon requires a non-empty entity name."
        result.confidence = Confidence.low
        return result

    cala_responded = False  # did any Cala endpoint answer (key valid / reachable)?

    # ── 1. Concrete structured answer (knowledge/query) ───────────────────────
    # Only runs when the caller passes a specific attribute/question. This is the
    # path that answers "how many employees…" with typed, current rows — distinct
    # from (and often more accurate than) the entity's registry properties.
    if query:
        kq = await cala.knowledge_query(query)
        if kq.get("available"):
            cala_responded = True
            if kq.get("found"):
                result.findings.append(Finding(
                    type="structured_answer", value=kq["results"], source="Cala.ai",
                    confidence=Confidence.high, notes=f"Cala knowledge/query: {query}",
                ))

    # ── 2. Resolve the name to a verified entity ──────────────────────────────
    types = [_TYPE_HINT[entity_type]] if entity_type in _TYPE_HINT else None
    search = await cala.search_entities(name, entity_types=types)
    if search.get("available"):
        cala_responded = True
    top = None
    if search.get("available") and search.get("found"):
        candidates = search["entities"]
        if len(candidates) > 1:
            result.findings.append(Finding(
                type="entity_candidates",
                value=[{"name": e.get("name"), "type": e.get("entity_type"), "id": e.get("id")}
                       for e in candidates[:10]],
                source="Cala.ai", confidence=Confidence.medium,
                notes=f"{len(candidates)} candidates; detailing the top match",
            ))

        top = candidates[0]
        entity_id = top.get("id", "")
        result.findings.append(Finding(
            type="resolved_entity",
            value={"name": top.get("name"), "type": top.get("entity_type"),
                   "id": entity_id, "description": top.get("description")},
            source="Cala.ai", confidence=Confidence.high,
        ))

        # ── 3. Pull full sourced detail for the top match ─────────────────────
        if entity_id:
            detail = await cala.get_entity(entity_id)
            if detail.get("available") and detail.get("found"):
                _record_entity_detail(result, detail["entity"])

    # ── 4. Sourced natural-language summary (context) ─────────────────────────
    subject = (top.get("name") if top else name) or name
    etype = top.get("entity_type", "") if top else ""
    question = f"Provide a due-diligence overview of {subject}"
    if etype:
        question += f" ({etype})"
    ks = await cala.knowledge_search(question)
    if ks.get("available"):
        cala_responded = True
        if ks.get("found"):
            content = ks["content"]
            result.findings.append(Finding(
                type="cala_summary", value=content,
                source="Cala.ai", confidence=Confidence.high,
            ))
            _record_context_sources(result, ks.get("context", []))
            _flag_risk(result, content)

    # Hard-fail only if Cala never answered (bad key / unreachable).
    if not cala_responded:
        result.status = TaskStatus.failed
        result.summary = f"Cala unavailable: {search.get('reason') or search.get('error')}"
        result.confidence = Confidence.low
        return result

    # Ensure the primary Cala source is present even if only query/summary hit.
    if not any(s.name == "Cala.ai" for s in result.sources):
        result.sources.insert(0, Source(name="Cala.ai", url="https://www.cala.ai"))

    _finalize(result)
    if not result.findings:
        result.summary = f"Cala returned no verified data for '{name}'."
    return result


def _extract_sourced(val):
    """Return (display_value, source_url|None) from a possibly-sourced field."""
    if isinstance(val, dict):
        display = val.get("value", val.get("text", val.get("name", "")))
        src = val.get("source_url") or val.get("url") or val.get("source")
        return (display if display != "" else None), (src if isinstance(src, str) else None)
    if isinstance(val, list):
        parts = [str(_extract_sourced(v)[0]) for v in val if _extract_sourced(v)[0] is not None]
        return (", ".join(parts) if parts else None), None
    return (val if val not in ("", None) else None), None


def _record_entity_detail(result: OsintResult, entity: dict) -> None:
    if entity.get("description"):
        result.findings.append(Finding(
            type="description", value=entity["description"],
            source="Cala.ai", confidence=Confidence.high,
        ))

    properties = entity.get("properties")
    if isinstance(properties, dict):
        count = 0
        for prop, raw in properties.items():
            if count >= _MAX_PROPERTY_FINDINGS:
                break
            display, src = _extract_sourced(raw)
            if display is None:
                continue
            result.findings.append(Finding(
                type=f"property_{prop}", value=display, source="Cala.ai",
                confidence=Confidence.high, notes=f"source: {src}" if src else "",
            ))
            count += 1

    rels = entity.get("relationships")
    if isinstance(rels, dict):
        for direction in ("outgoing", "incoming"):
            block = rels.get(direction)
            if not block:
                continue
            result.findings.append(Finding(
                type=f"relationships_{direction}", value=block,
                source="Cala.ai", confidence=Confidence.medium,
            ))

    nums = entity.get("numerical_observations")
    if nums:
        result.findings.append(Finding(
            type="numerical_observations", value=nums,
            source="Cala.ai", confidence=Confidence.high,
        ))


def _record_context_sources(result: OsintResult, context: list) -> None:
    seen = {s.url for s in result.sources if s.url}
    for item in context:
        if not isinstance(item, dict):
            continue
        url = item.get("source_url") or item.get("url")
        if isinstance(url, str) and url and url not in seen:
            seen.add(url)
            result.sources.append(Source(name=item.get("source") or "Cala source", url=url))


def _flag_risk(result: OsintResult, content: str) -> None:
    lowered = content.lower()
    hits = [kw for kw in _RISK_KEYWORDS if kw in lowered]
    if hits:
        result.risk = Risk.medium
        result.warnings.append(
            "Cala summary mentions adverse-signal terms (" + ", ".join(sorted(set(hits)))
            + "). Verify against primary sources before acting."
        )


def _finalize(result: OsintResult) -> None:
    if result.risk == Risk.unknown:
        result.risk = Risk.low if result.findings else Risk.unknown
    result.confidence = Confidence.high if result.sources else Confidence.low
    if not result.summary:
        result.summary = (
            f"Entity intelligence for '{result.target}': {len(result.findings)} findings "
            f"from {len(result.sources)} Cala source(s). Risk: {result.risk.value}."
        )
    result.status = TaskStatus.completed
