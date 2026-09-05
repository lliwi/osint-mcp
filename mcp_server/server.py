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
import jsonschema
from mcp.server import Server, ServerRequestContext
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), stream=sys.stderr)
logger = logging.getLogger(__name__)

_API_URL = os.getenv("OSINT_API_URL", "http://localhost:8001")
_API_KEY = os.getenv("OSINT_INTERNAL_API_KEY", "changeme")
_HEADERS = {"X-OSINT-API-Key": _API_KEY, "Content-Type": "application/json"}


# ─── Tool definitions ─────────────────────────────────────────────────────────

_TOOLS = [
    Tool(
        name="domain_recon",
        description="Passive OSINT reconnaissance for a domain: WHOIS, DNS, subdomains, "
                    "web technologies, certificates and historical URLs.",
        input_schema={
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
        input_schema={
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
        input_schema={
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
        input_schema={
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
        input_schema={
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
        input_schema={
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
        input_schema={
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
        input_schema={
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
        input_schema={
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
        name="company_recon",
        description="Entity due-diligence via Cala.ai verified knowledge. Resolves a company, "
                    "person, product, law or place name to a verified entity and returns its "
                    "sourced facts (sector, funding, registry, relationships, metrics) plus a "
                    "sourced summary. Flags sanctions/PEP/litigation terms. Every fact is traceable.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Entity name to look up, e.g. 'Amenitiz' or 'OpenAI'",
                },
                "entity_type": {
                    "type": "string",
                    "enum": ["auto", "company", "person", "product", "law", "place", "research"],
                    "default": "auto",
                    "description": "Restrict resolution to an entity type, or 'auto' to search all",
                },
                "query": {
                    "type": "string",
                    "default": "",
                    "description": "Optional concrete question about the entity, answered with "
                                   "structured typed rows via Cala knowledge/query. Pass a Cala QL "
                                   "dot-notation expression (e.g. 'Italdesign Barcelona.employees') "
                                   "or a natural-language question. Use this whenever the user asks "
                                   "for a specific attribute (employees, revenue, founders, address) "
                                   "— it is more accurate than the entity's registry properties.",
                },
            },
            "required": ["name"],
        },
    ),
    Tool(
        name="secret_scan",
        description="Scan an uploaded file/directory or a public git repository "
                    "(github.com, gitlab.com, bitbucket.org, codeberg.org) for leaked "
                    "credentials and secrets using gitleaks and trufflehog. "
                    "Defensive use only — detected secrets are redacted, never shown in full.",
        input_schema={
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
        input_schema={
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
        input_schema={
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
        input_schema={
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
        input_schema={
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
        input_schema={
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


_TOOLS_BY_NAME = {t.name: t for t in _TOOLS}


# ─── Request handlers ─────────────────────────────────────────────────────────

def _error(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)


async def handle_list_tools(
    ctx: ServerRequestContext,
    params: PaginatedRequestParams | None,
) -> ListToolsResult:
    return ListToolsResult(tools=_TOOLS)


async def handle_call_tool(
    ctx: ServerRequestContext,
    params: CallToolRequestParams,
) -> CallToolResult:
    name = params.name
    args: dict[str, Any] = params.arguments or {}

    tool = _TOOLS_BY_NAME.get(name)
    if tool is None:
        return _error(f"Error: unknown tool '{name}'")

    # The low-level server validates the JSON-RPC envelope, not the tool
    # arguments against inputSchema — that is on us.
    try:
        jsonschema.validate(instance=args, schema=tool.input_schema)
    except jsonschema.ValidationError as exc:
        return _error(f"Input validation error: {exc.message}")

    try:
        result = await _dispatch(name, args)
        return CallToolResult(content=[TextContent(type="text", text=result)])
    except Exception as exc:
        logger.exception("Tool '%s' error", name)
        return _error(f"Error: {exc}")


server = Server(
    "mcp-osint-server",
    version="0.1.0",
    on_list_tools=handle_list_tools,
    on_call_tool=handle_call_tool,
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
            "company_recon": "company_recon",
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
            "company_recon": "name",
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

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")


def _transport_security(extra_hosts: list[str]):
    """DNS-rebinding protection for the HTTP transports — always on.

    The SDK only enables this by itself when the app is bound to a loopback
    address, so binding 0.0.0.0 (what the container does) would silently leave it
    off. We build the settings explicitly instead. Loopback is always accepted;
    any other name the server is reached under — a domain, a LAN IP — has to be
    declared, or the request is rejected with 421.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    hosts: list[str] = []
    for host in (*_LOOPBACK_HOSTS, *extra_hosts):
        if host and host not in hosts:
            hosts.append(host)

    allowed_hosts: list[str] = []
    allowed_origins: list[str] = []
    for host in hosts:
        # Bare entry matches a portless Host header, ":*" matches any port.
        allowed_hosts += [host, f"{host}:*"]
        allowed_origins += [f"{scheme}://{host}{port}"
                            for scheme in ("http", "https") for port in ("", ":*")]

    logger.info("DNS-rebinding protection enabled; accepted Host values: %s",
                ", ".join(allowed_hosts))
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def _health_route(transport: str):
    """/health route for the HTTP transports — used by the container healthcheck."""
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def handle_health(request):
        return JSONResponse({"status": "ok", "transport": transport})

    return Route("/health", endpoint=handle_health)


def _silence_health_access_logs() -> None:
    """Keep the access log readable — /health is polled every few seconds."""

    class _HealthFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return "GET /health" not in record.getMessage()

    logging.getLogger("uvicorn.access").addFilter(_HealthFilter())


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP OSINT Server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"],
                        default="stdio",
                        help="stdio for local clients; streamable-http for remote clients "
                             "(sse is deprecated by the MCP spec, kept for compatibility)")
    parser.add_argument("--port", type=int, default=3000,
                        help="Port for the HTTP transports (default: 3000)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Bind host for the HTTP transports (default: 0.0.0.0)")
    parser.add_argument("--allowed-host", action="append", metavar="HOST",
                        help="Extra Host header value the HTTP transports accept, e.g. "
                             "osint.example.com (repeatable). Loopback is always accepted. "
                             "Defaults to $MCP_ALLOWED_HOSTS (comma-separated).")
    args = parser.parse_args()

    extra_hosts = args.allowed_host or [
        h.strip() for h in os.getenv("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()
    ]

    if args.transport == "stdio":
        import asyncio
        from mcp.server.stdio import stdio_server

        async def _run_stdio():
            async with stdio_server() as (read, write):
                await server.run(
                    read, write,
                    server.create_initialization_options(),
                )

        asyncio.run(_run_stdio())

    elif args.transport == "sse":
        import uvicorn
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.responses import Response
        from starlette.routing import Mount, Route

        sse_transport = SseServerTransport(
            "/messages/", security_settings=_transport_security(extra_hosts)
        )

        async def handle_sse(request):
            async with sse_transport.connect_sse(
                request.scope, request.receive, request._send
            ) as (read, write):
                await server.run(
                    read, write,
                    server.create_initialization_options(),
                )
            # Starlette requires an ASGI response from a Route endpoint; the SSE
            # stream is already finished at this point.
            return Response()

        starlette_app = Starlette(
            routes=[
                _health_route("sse"),
                Route("/sse", endpoint=handle_sse),
                Mount("/messages/", app=sse_transport.handle_post_message),
            ]
        )

        _silence_health_access_logs()

        logger.warning("The SSE transport is deprecated by the MCP spec; "
                       "prefer --transport streamable-http for new clients.")
        logger.info("MCP OSINT Server (SSE) starting on %s:%s", args.host, args.port)
        uvicorn.run(starlette_app, host=args.host, port=args.port)

    elif args.transport == "streamable-http":
        import uvicorn

        # streamable_http_app() wires the session manager into the app lifespan.
        starlette_app = server.streamable_http_app(
            streamable_http_path="/mcp",
            transport_security=_transport_security(extra_hosts),
            custom_starlette_routes=[_health_route("streamable-http")],
        )

        _silence_health_access_logs()

        logger.info("MCP OSINT Server (streamable-http) starting on %s:%s/mcp",
                    args.host, args.port)
        uvicorn.run(starlette_app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
