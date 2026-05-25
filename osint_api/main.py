"""
OSINT API — FastAPI backend. Called by the MCP server via HTTP.
All endpoints require the X-OSINT-API-Key header.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from uuid import uuid4

import magic
from fastapi import Depends, FastAPI, File, HTTPException, Request, Security, UploadFile
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

_UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/osint-uploads")
_MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))  # 20 MB

_ALLOWED_MIME_TYPES: dict[str, str] = {
    "image/jpeg":    ".jpg",
    "image/png":     ".png",
    "image/webp":    ".webp",
    "image/gif":     ".gif",
    "image/tiff":    ".tiff",
    "image/bmp":     ".bmp",
    "image/heic":    ".heic",
    "image/heif":    ".heif",
    "application/pdf": ".pdf",
    "application/msword": ".doc",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document":   ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/vnd.oasis.opendocument.text":         ".odt",
    "application/vnd.oasis.opendocument.spreadsheet":  ".ods",
    "application/vnd.oasis.opendocument.presentation": ".odp",
}


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


# ─── File upload ─────────────────────────────────────────────────────────────

@app.post("/files/upload", dependencies=[Depends(require_api_key)])
async def upload_file(file: UploadFile = File(...)):
    data = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed: {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )

    # Validate MIME from magic bytes — never trust the client-supplied Content-Type
    try:
        mime = magic.from_buffer(data, mime=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"MIME detection failed: {exc}")

    if mime not in _ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"File type '{mime}' is not allowed. Accepted: images, PDF, Office, ODF.",
        )

    ext = _ALLOWED_MIME_TYPES[mime]
    file_id = f"{uuid4()}{ext}"
    dest = os.path.join(_UPLOAD_DIR, file_id)

    try:
        os.makedirs(_UPLOAD_DIR, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {exc}")

    logger.info("File uploaded: %s (%s, %d bytes)", file_id, mime, len(data))
    return {
        "file_id": file_id,
        "path": dest,
        "mime_type": mime,
        "size_bytes": len(data),
    }


class UploadBase64Request(BaseModel):
    data: str
    filename: str = "file"


@app.post("/files/upload-base64", dependencies=[Depends(require_api_key)])
async def upload_base64(req: UploadBase64Request):
    """
    Decode a base64-encoded file and stage it for analysis.
    Use when you have the file as base64 (e.g., from a user attachment).
    """
    import base64 as _b64

    try:
        # Strip data-URI prefix if present (e.g. "data:image/png;base64,...")
        raw_b64 = req.data.split(",", 1)[-1] if "," in req.data else req.data
        data = _b64.b64decode(raw_b64)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid base64 data: {exc}")

    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed: {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )

    try:
        mime = magic.from_buffer(data, mime=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"MIME detection failed: {exc}")

    if mime not in _ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"File type '{mime}' is not allowed. Accepted: images, PDF, Office, ODF.",
        )

    ext = _ALLOWED_MIME_TYPES[mime]
    file_id = f"{uuid4()}{ext}"
    dest = os.path.join(_UPLOAD_DIR, file_id)

    try:
        os.makedirs(_UPLOAD_DIR, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {exc}")

    logger.info("File uploaded (base64): %s (%s, %d bytes)", file_id, mime, len(data))
    return {
        "file_id": file_id,
        "path": dest,
        "mime_type": mime,
        "size_bytes": len(data),
    }


class FetchRequest(BaseModel):
    url: str


@app.post("/files/fetch", dependencies=[Depends(require_api_key)])
async def fetch_file(req: FetchRequest):
    """
    Download a file from a public URL and stage it for analysis.
    Use this when the file is accessible via a URL (e.g. shared drive, CDN, paste site).
    ChatGPT Actions must use this endpoint — direct binary upload is not supported by that platform.
    """
    import httpx
    from osint_api.security.validator import validate_url, ValidationError as VErr

    try:
        safe_url = validate_url(req.url)
    except VErr as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True,
                                      max_redirects=5) as client:
            # Stream so we can enforce the size limit without loading it all into RAM first
            async with client.stream("GET", safe_url) as resp:
                if resp.status_code not in (200, 206):
                    raise HTTPException(status_code=502,
                                        detail=f"Remote server returned {resp.status_code}")
                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                    total += len(chunk)
                    if total > _MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail=f"Remote file exceeds {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
                        )
                    chunks.append(chunk)
                data = b"".join(chunks)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch URL: {exc}")

    try:
        mime = magic.from_buffer(data, mime=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"MIME detection failed: {exc}")

    if mime not in _ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"File type '{mime}' is not allowed. Accepted: images, PDF, Office, ODF.",
        )

    ext = _ALLOWED_MIME_TYPES[mime]
    file_id = f"{uuid4()}{ext}"
    dest = os.path.join(_UPLOAD_DIR, file_id)

    try:
        os.makedirs(_UPLOAD_DIR, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {exc}")

    logger.info("File fetched from URL: %s → %s (%s, %d bytes)", safe_url, file_id, mime, len(data))
    return {
        "file_id": file_id,
        "path": dest,
        "mime_type": mime,
        "size_bytes": len(data),
    }


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
    finally:
        _delete_upload(req.target)


def _delete_upload(path: str) -> None:
    """Delete file if it was placed in UPLOAD_DIR by the upload endpoint."""
    if not path:
        return
    upload_dir = os.path.abspath(_UPLOAD_DIR)
    try:
        abs_path = os.path.abspath(path)
        if abs_path.startswith(upload_dir + os.sep) and os.path.isfile(abs_path):
            os.remove(abs_path)
            logger.info("Deleted uploaded file after analysis: %s", abs_path)
    except OSError as exc:
        logger.warning("Could not delete uploaded file '%s': %s", path, exc)


# ─── Tasks ────────────────────────────────────────────────────────────────────

@app.get("/tasks/{task_id}", dependencies=[Depends(require_api_key)])
async def get_task(task_id: str, wait: int = 0):
    """
    Returns task status and result.
    If wait>0, blocks up to that many seconds (max 25) until the task completes.
    Use wait=20 to avoid repeated polling — ideal for GPT Actions.
    """
    import asyncio as _asyncio

    record = await task_store.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")

    if wait > 0 and record.status == "running":
        deadline = _asyncio.get_event_loop().time() + min(wait, 25)
        while _asyncio.get_event_loop().time() < deadline:
            await _asyncio.sleep(0.5)
            record = await task_store.get(task_id)
            if record is None or record.status != "running":
                break

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

class ReportFormatRequest(BaseModel):
    format: str = "markdown"


@app.post("/reports/{task_id}", dependencies=[Depends(require_api_key)])
async def generate_report(task_id: str, req: ReportFormatRequest):
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
