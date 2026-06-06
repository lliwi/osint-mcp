"""
MCP OSINT Server — exposes 13 OSINT tools to AI clients via stdio or HTTP/SSE.

Usage:
    python -m mcp_server.server --transport stdio         # for Claude Code / Gemini CLI
    python -m mcp_server.server --transport sse --port 3000  # for remote HTTP clients
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    TextContent,
    Tool,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), stream=sys.stderr)
logger = logging.getLogger(__name__)

_API_URL = os.getenv("OSINT_API_URL", "http://localhost:8001")
_API_KEY = os.getenv("OSINT_INTERNAL_API_KEY", "changeme")
_HEADERS = {"X-OSINT-API-Key": _API_KEY, "Content-Type": "application/json"}

server = Server("mcp-osint-server")


# ─── Tool definitions ─────────────────────────────────────────────────────────

_TOOLS = [
    Tool(
        name="domain_recon",
        description="Passive OSINT reconnaissance for a domain: WHOIS, DNS, subdomains, "
                    "web technologies, certificates and historical URLs.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain (e.g. example.com)"},
                "depth": {"type": "string", "enum": ["quick", "standard", "deep"],
                          "default": "standard"},
                "passive_only": {"type": "boolean", "default": True},
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="ip_reputation",
        description="Analyze a public IP address: ASN, organization, country, abuse reports, "
                    "passive service discovery via Shodan.",
        inputSchema={
            "type": "object",
            "properties": {
                "ip_address": {"type": "string", "description": "Target IP address (IPv4 or IPv6)"},
            },
            "required": ["ip_address"],
        },
    ),
    Tool(
        name="email_reputation",
        description="Analyze an email address: MX records, service registrations (holehe), "
                    "reputation (EmailRep), and breach exposure (HIBP). No login or emails sent.",
        inputSchema={
            "type": "object",
            "properties": {
                "email": {"type": "string", "description": "Target email address"},
            },
            "required": ["email"],
        },
    ),
    Tool(
        name="phone_reputation",
        description="Lookup a phone number: carrier, country, line type, spam signals. "
                    "Public sources only. No calls made.",
        inputSchema={
            "type": "object",
            "properties": {
                "phone_number": {"type": "string",
                                 "description": "Phone number in E.164 format (e.g. +34123456789)"},
                "country_hint": {"type": "string", "description": "ISO-3166 country code hint",
                                 "default": ""},
            },
            "required": ["phone_number"],
        },
    ),
    Tool(
        name="username_recon",
        description="Search for public profiles linked to a username across social networks "
                    "and online services using Sherlock and Maigret.",
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Target username / alias"},
                "platform_scope": {"type": "string", "default": "all",
                                   "description": "Limit to specific platform or 'all'"},
            },
            "required": ["username"],
        },
    ),
    Tool(
        name="reverse_image_search",
        description="Analyze an uploaded image: extract EXIF metadata, compute hash, "
                    "and optionally search TinEye for reverse matches. No facial recognition.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string",
                               "description": "Filename of image already uploaded to the server"},
                "search_scope": {"type": "string", "enum": ["basic", "extended"],
                                 "default": "basic"},
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="metadata_analysis",
        description="Extract and analyze metadata from files (images, PDFs, Office docs): "
                    "hash, file type, EXIF, author, GPS, creation dates, privacy risks.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string",
                              "description": "Filename of file already uploaded to the server"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="breach_exposure_check",
        description="Check if an email, domain, or URL appears in known data breaches or "
                    "malicious intelligence feeds. No passwords are shown.",
        inputSchema={
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "Email, domain, or URL to check"},
                "indicator_type": {"type": "string",
                                   "enum": ["auto", "email", "domain", "url", "hash"],
                                   "default": "auto"},
            },
            "required": ["indicator"],
        },
    ),
    Tool(
        name="vehicle_recon",
        description="Look up a Spanish license plate via RapidAPI. Returns brand, model, year, "
                    "color, fuel type, ITV status, insurance and environmental badge. "
                    "Owner data suppressed by default (requires RGPD legal basis).",
        inputSchema={
            "type": "object",
            "properties": {
                "plate": {
                    "type": "string",
                    "description": "Spanish license plate, e.g. 1234BCD or M1234AB",
                },
                "country": {
                    "type": "string",
                    "default": "ES",
                    "description": "Country code (currently only ES supported)",
                },
            },
            "required": ["plate"],
        },
    ),
    Tool(
        name="secret_scan",
        description="Scan an uploaded file/directory or a public git repository "
                    "(github.com, gitlab.com, bitbucket.org, codeberg.org) for leaked "
                    "credentials and secrets using gitleaks and trufflehog. "
                    "Defensive use only — detected secrets are redacted, never shown in full.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Filename already uploaded to the server, or an https git URL",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["auto", "file", "git"],
                    "default": "auto",
                    "description": "Force a scan mode, or 'auto' to detect from the target",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="list_osint_tools",
        description="List available OSINT tools in the catalog, optionally filtered by category.",
        inputSchema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["all", "domain", "ip", "email", "phone", "username",
                             "image", "metadata", "breach"],
                    "default": "all",
                },
                "enabled_only": {"type": "boolean", "default": True},
            },
        },
    ),
    Tool(
        name="recommend_osint_workflow",
        description="Auto-detect the type of an indicator and recommend which workflows to run.",
        inputSchema={
            "type": "object",
            "properties": {
                "indicator": {"type": "string",
                              "description": "Any OSINT indicator: email, IP, domain, phone, username, URL"},
            },
            "required": ["indicator"],
        },
    ),
    Tool(
        name="run_osint_workflow",
        description="Run any OSINT workflow by name with a target and optional parameters.",
        inputSchema={
            "type": "object",
            "properties": {
                "workflow": {"type": "string", "description": "Workflow name (e.g. domain_recon)"},
                "target": {"type": "string", "description": "Target value for the workflow"},
                "mode": {"type": "string", "enum": ["safe", "analyst"], "default": "safe"},
                "output_format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
                "options": {"type": "object", "description": "Extra workflow-specific parameters",
                            "default": {}},
            },
            "required": ["workflow", "target"],
        },
    ),
    Tool(
        name="get_task_result",
        description="Poll the status and result of a previously submitted OSINT task.",
        inputSchema={
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task ID returned by run_osint_workflow"},
            },
            "required": ["task_id"],
        },
    ),
    Tool(
        name="export_report",
        description="Generate and return an OSINT report for a completed task.",
        inputSchema={
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task ID of a completed task"},
                "format": {"type": "string", "enum": ["markdown", "json", "html"],
                           "default": "markdown"},
            },
            "required": ["task_id"],
        },
    ),
]


@server.list_tools()
async def handle_list_tools(_: ListToolsRequest) -> ListToolsResult:
    return ListToolsResult(tools=_TOOLS)


@server.call_tool()
async def handle_call_tool(request: CallToolRequest) -> CallToolResult:
    name = request.params.name
    args: dict[str, Any] = request.params.arguments or {}

    try:
        result = await _dispatch(name, args)
        return CallToolResult(content=[TextContent(type="text", text=result)])
    except Exception as exc:
        logger.exception("Tool '%s' error", name)
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {exc}")],
            isError=True,
        )


async def _dispatch(name: str, args: dict) -> str:
    async with httpx.AsyncClient(base_url=_API_URL, headers=_HEADERS, timeout=320) as client:

        if name == "list_osint_tools":
            resp = await client.get(
                "/tools",
                params={"category": args.get("category", "all"),
                        "enabled_only": str(args.get("enabled_only", True)).lower()},
            )
            resp.raise_for_status()
            tools = resp.json()
            lines = [f"## Available OSINT Tools ({len(tools)})\n"]
            for t in tools:
                lines.append(f"- **{t['name']}** [{t['category']}] — {t['description']}")
            return "\n".join(lines)

        if name == "recommend_osint_workflow":
            from osint_api.workflows.orchestrator import recommend
            rec = recommend(args["indicator"])
            return (
                f"**Detected type:** {rec['detected_type']}\n\n"
                f"**Recommended workflows:**\n" +
                "\n".join(f"- `{w}`" for w in rec["recommended_workflows"]) +
                ("\n\n**Safety notes:**\n" + "\n".join(f"- {n}" for n in rec["safety_notes"])
                 if rec["safety_notes"] else "")
            )

        if name == "get_task_result":
            resp = await client.get(f"/tasks/{args['task_id']}")
            resp.raise_for_status()
            return json.dumps(resp.json(), indent=2, ensure_ascii=False)

        if name == "export_report":
            resp = await client.post(
                f"/reports/{args['task_id']}",
                json={"task_id": args["task_id"], "format": args.get("format", "markdown")},
            )
            resp.raise_for_status()
            return resp.text

        # ── Workflow tools ────────────────────────────────────────────────────
        workflow_map = {
            "domain_recon": "domain_recon",
            "ip_reputation": "ip_reputation",
            "email_reputation": "email_reputation",
            "phone_reputation": "phone_reputation",
            "username_recon": "username_recon",
            "reverse_image_search": "reverse_image_search",
            "metadata_analysis": "metadata_analysis",
            "breach_exposure_check": "breach_exposure_check",
            "vehicle_recon": "vehicle_recon",
            "secret_scan": "secret_scan",
            "run_osint_workflow": args.get("workflow", ""),
        }

        workflow = workflow_map.get(name, name)
        target_key_map = {
            "domain_recon": "domain",
            "ip_reputation": "ip_address",
            "email_reputation": "email",
            "phone_reputation": "phone_number",
            "username_recon": "username",
            "reverse_image_search": "image_path",
            "metadata_analysis": "file_path",
            "breach_exposure_check": "indicator",
            "vehicle_recon": "plate",
        }
        target_key = target_key_map.get(name, "target")
        target = args.get(target_key) or args.get("target", "")

        # Submit workflow
        payload = {
            "workflow": workflow,
            "target": target,
            "mode": args.get("mode", "safe"),
            "output_format": args.get("output_format", "json"),
            "options": {k: v for k, v in args.items() if k not in (target_key, "target")},
        }
        resp = await client.post("/workflow/run", json=payload)
        resp.raise_for_status()
        task_id = resp.json()["task_id"]

        # Poll until done (max 300s)
        import asyncio
        for _ in range(60):
            await asyncio.sleep(5)
            poll = await client.get(f"/tasks/{task_id}")
            poll.raise_for_status()
            task_data = poll.json()
            status = task_data.get("status")
            if status in ("completed", "failed", "partial"):
                break

        if task_data.get("status") == "failed":
            return f"Workflow failed: {task_data.get('error', 'unknown error')}"

        result_data = task_data.get("result", {})
        out_format = args.get("output_format", "json")
        if out_format == "markdown":
            # Request markdown report
            rpt = await client.post(
                f"/reports/{task_id}",
                json={"task_id": task_id, "format": "markdown"},
            )
            return rpt.text
        return json.dumps(result_data, indent=2, ensure_ascii=False)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="MCP OSINT Server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    parser.add_argument("--port", type=int, default=3000,
                        help="Port for SSE transport (default: 3000)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Host for SSE transport (default: 0.0.0.0)")
    args = parser.parse_args()

    if args.transport == "stdio":
        import asyncio
        from mcp.server.stdio import stdio_server

        async def _run_stdio():
            async with stdio_server() as (read, write):
                await server.run(
                    read, write,
                    InitializationOptions(
                        server_name="mcp-osint-server",
                        server_version="0.1.0",
                        capabilities=server.get_capabilities(
                            notification_options=None,
                            experimental_capabilities={},
                        ),
                    ),
                )

        asyncio.run(_run_stdio())

    elif args.transport == "sse":
        import uvicorn
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route

        sse_transport = SseServerTransport("/messages")

        async def handle_sse(request):
            async with sse_transport.connect_sse(
                request.scope, request.receive, request._send
            ) as (read, write):
                await server.run(
                    read, write,
                    InitializationOptions(
                        server_name="mcp-osint-server",
                        server_version="0.1.0",
                        capabilities=server.get_capabilities(
                            notification_options=None,
                            experimental_capabilities={},
                        ),
                    ),
                )

        async def handle_health(request):
            from starlette.responses import JSONResponse
            return JSONResponse({"status": "ok", "transport": "sse"})

        starlette_app = Starlette(
            routes=[
                Route("/health", endpoint=handle_health),
                Route("/sse", endpoint=handle_sse),
                Mount("/messages", app=sse_transport.handle_post_message),
            ]
        )

        # Suppress /health spam from SSE keep-alive polling in access logs
        import logging as _logging
        class _HealthFilter(_logging.Filter):
            def filter(self, record: _logging.LogRecord) -> bool:
                return "GET /health" not in record.getMessage()
        _logging.getLogger("uvicorn.access").addFilter(_HealthFilter())

        logger.info("MCP OSINT Server (SSE) starting on %s:%s", args.host, args.port)
        uvicorn.run(starlette_app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
