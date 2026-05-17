"""
Loads the tool catalog from tools.yml.
Can optionally merge in tools from an external osintToolsData.json source.
"""
from __future__ import annotations

import logging
from pathlib import Path

import httpx
import yaml

from osint_api.catalog.schema import ToolEntry

logger = logging.getLogger(__name__)

_CATALOG_PATH = Path(__file__).parent.parent.parent / "config" / "tools.yml"

# Categories we want to pull from the external source if merging
_WANTED_CATEGORIES = {"domain", "ip", "email", "phone", "username", "image", "metadata", "breach"}

_catalog: list[ToolEntry] = []


def load_catalog() -> list[ToolEntry]:
    global _catalog
    if _catalog:
        return _catalog

    with open(_CATALOG_PATH, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    _catalog = [ToolEntry(**t) for t in data.get("tools", [])]
    logger.info("Loaded %d tools from catalog", len(_catalog))
    return _catalog


def get_tools(category: str | None = None, enabled_only: bool = True) -> list[ToolEntry]:
    tools = load_catalog()
    if enabled_only:
        tools = [t for t in tools if t.enabled]
    if category and category != "all":
        tools = [t for t in tools if t.category == category]
    return tools


def get_tool(name: str) -> ToolEntry | None:
    return next((t for t in load_catalog() if t.name == name), None)


async def import_from_osint_resources(url: str) -> list[ToolEntry]:
    """
    Fetches osintToolsData.json and imports representative tools not already in catalog.
    Returns list of newly imported tools.
    """
    existing_names = {t.name.lower() for t in load_catalog()}
    new_tools: list[ToolEntry] = []

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        raw = resp.json()

    # osintToolsData.json is typically a list of tool objects
    items = raw if isinstance(raw, list) else raw.get("tools", [])

    for item in items:
        name = item.get("name", "").strip()
        category = (item.get("category") or item.get("tags", [""])[0]).lower()

        if not name or name.lower() in existing_names:
            continue
        if category not in _WANTED_CATEGORIES:
            continue

        entry = ToolEntry(
            name=name,
            category=category,
            type=item.get("type", "web"),
            description=item.get("description", ""),
            enabled=False,  # imported tools start disabled until reviewed
            requires_api_key=bool(item.get("requires_api_key", False)),
            risk_level=item.get("risk_level", "low"),
            inputs=item.get("inputs", []),
            outputs=item.get("outputs", []),
            timeout=item.get("timeout", 60),
            source="osintToolsData.json",
        )
        _catalog.append(entry)
        existing_names.add(name.lower())
        new_tools.append(entry)
        logger.info("Imported tool from external source: %s (%s)", name, category)

    logger.info("Imported %d new tools from external source", len(new_tools))
    return new_tools
