"""
OSINT API — FastAPI backend. Called by the MCP server via HTTP.
All endpoints require the X-OSINT-API-Key header.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

from mcp_server.schemas.common import OsintResult, ReportRequest, WorkflowRequest
from osint_api.catalog.loader import get_tools, import_from_osint_resources
from osint_api.catalog.schema import ToolEntry
from osint_api.reports.json_report import build_json_report
from osint_api.reports.markdown_report import build_markdown_report
from osint_api.reports.html_report import build_html_report
from osint_api.security.rate_limiter import RateLimitExceeded, workflow_limiter
from osint_api.task_store import task_store
from osint_api.workflows.orchestrator import dispatch_workflow

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

_API_KEY = os.getenv("OSINT_INTERNAL_API_KEY", "changeme")
_api_key_header = APIKeyHeader(name="X-OSINT-API-Key", auto_error=True)


async def require_api_key(key: str = Security(_api_key_header)) -> str:
    if key != _API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return key


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("OSINT API starting — mode=%s", os.getenv("OSINT_MODE", "safe"))
    yield
    logger.info("OSINT API shutting down")


app = FastAPI(
    title="OSINT API",
    description="Backend API for the MCP OSINT Server",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — needed for GPT Actions and browser-based clients
_cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["X-OSINT-API-Key", "Content-Type", "Accept"],
)


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "mode": os.getenv("OSINT_MODE", "safe")}


# ─── Catalog ──────────────────────────────────────────────────────────────────

@app.get("/tools", dependencies=[Depends(require_api_key)])
async def list_tools(category: str = "all", enabled_only: bool = True) -> list[ToolEntry]:
    return get_tools(category=category if category != "all" else None, enabled_only=enabled_only)


class ImportRequest(BaseModel):
    url: str = "https://raw.githubusercontent.com/lliwi/osint-resources/refs/heads/main/data/osintToolsData.json"


@app.post("/tools/import", dependencies=[Depends(require_api_key)])
async def import_tools(req: ImportRequest):
    from osint_api.security.validator import validate_url
    try:
        safe_url = validate_url(req.url)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    imported = await import_from_osint_resources(safe_url)
    return {"imported": len(imported), "tools": [t.name for t in imported]}


# ─── Workflows ────────────────────────────────────────────────────────────────

@app.post("/workflow/run", dependencies=[Depends(require_api_key)])
async def run_workflow(req: WorkflowRequest, request: Request):
    client_id = request.client.host if request.client else "unknown"
    try:
        await workflow_limiter.check_or_raise(client_id)
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    record = await task_store.create(workflow=req.workflow, target=req.target)

    import asyncio
    asyncio.create_task(_run_workflow_bg(record.task_id, req))

    return {"task_id": record.task_id, "status": "running"}


async def _run_workflow_bg(task_id: str, req: WorkflowRequest) -> None:
    try:
        result = await dispatch_workflow(req)
        result.task_id = task_id
        await task_store.complete(task_id, result)
    except Exception as exc:
        logger.exception("Workflow '%s' failed for task %s", req.workflow, task_id)
        await task_store.fail(task_id, str(exc))


# ─── Tasks ────────────────────────────────────────────────────────────────────

@app.get("/tasks/{task_id}", dependencies=[Depends(require_api_key)])
async def get_task(task_id: str):
    record = await task_store.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
    return {
        "task_id": record.task_id,
        "workflow": record.workflow,
        "target": record.target,
        "status": record.status,
        "started_at": record.started_at.isoformat(),
        "finished_at": record.finished_at.isoformat() if record.finished_at else None,
        "error": record.error,
        "result": record.result.model_dump() if record.result else None,
    }


# ─── Reports ──────────────────────────────────────────────────────────────────

@app.post("/reports/{task_id}", dependencies=[Depends(require_api_key)])
async def generate_report(task_id: str, req: ReportRequest):
    record = await task_store.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
    if record.result is None:
        raise HTTPException(status_code=409, detail="Task result not yet available")

    fmt = req.format.lower()
    if fmt == "markdown":
        content = build_markdown_report(record.result)
        media_type = "text/markdown"
    elif fmt == "json":
        content = build_json_report(record.result)
        media_type = "application/json"
    elif fmt == "html":
        content = build_html_report(record.result)
        media_type = "text/html"
    else:
        raise HTTPException(status_code=422, detail=f"Unsupported format: '{fmt}'")

    from fastapi.responses import Response
    return Response(content=content, media_type=media_type)
