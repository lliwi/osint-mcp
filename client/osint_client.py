#!/usr/bin/env python3
"""
OSINT Client — multi-proveedor LLM
====================================
Soporta Ollama (local), DeepSeek y OpenAI como backends de modelo.
Las herramientas OSINT se ejecutan siempre contra la OSINT API local.

Uso:
    python osint_client.py                             # Ollama, modelo por defecto
    python osint_client.py -p deepseek                 # DeepSeek API
    python osint_client.py -p openai -m gpt-4o-mini    # OpenAI API
    python osint_client.py -m qwen3.5:2b               # Ollama, modelo específico
    python osint_client.py --check                     # verificar servicios
    python osint_client.py --report <task_id>          # descargar informe
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any

import httpx
from openai import OpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

# ─── Configuración global ─────────────────────────────────────────────────────

OSINT_API = os.getenv("OSINT_API_URL",           "http://localhost:8001")
OSINT_KEY = os.getenv("OSINT_INTERNAL_API_KEY",   "changeme")

console = Console()

# ─── Proveedores ──────────────────────────────────────────────────────────────

@dataclass
class Provider:
    name: str           # identificador CLI
    label: str          # nombre de display
    base_url: str
    api_key: str        # vacío → aviso en check
    default_model: str
    models_hint: list[str]  # sugerencias de modelos disponibles


def _load_providers() -> dict[str, Provider]:
    return {
        "ollama": Provider(
            name="ollama",
            label="Ollama (local)",
            base_url=os.getenv("OLLAMA_URL", "http://localhost:11434/v1"),
            api_key="ollama",           # Ollama no requiere key real
            default_model=os.getenv("OLLAMA_MODEL", "qwen3.5:2b"),
            models_hint=["qwen3.5:2b", "qwen2.5:7b", "llama3.1:8b",
                         "llama3.2:3b", "mistral-nemo", "phi4"],
        ),
        "deepseek": Provider(
            name="deepseek",
            label="DeepSeek API",
            base_url="https://api.deepseek.com/v1",
            api_key=os.getenv("DEEPSEEK_API_KEY", ""),
            default_model="deepseek-chat",
            models_hint=["deepseek-chat", "deepseek-reasoner"],
        ),
        "openai": Provider(
            name="openai",
            label="OpenAI API",
            base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            api_key=os.getenv("OPENAI_API_KEY", ""),
            default_model="gpt-4o-mini",
            models_hint=["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
        ),
    }


PROVIDERS = _load_providers()

# ─── Quirks por proveedor / modelo ────────────────────────────────────────────

# Modelos con thinking emitido en <think> dentro del content (Ollama Qwen3)
_OLLAMA_THINKING_PREFIXES = ("qwen3", "qwen3.5")

# Modelos con razonamiento en reasoning_content separado (DeepSeek-R1)
_DEEPSEEK_REASONER = "deepseek-reasoner"


def _needs_think_off(provider: Provider, model: str) -> bool:
    """True si hay que pasar think=False vía extra_body (Ollama Qwen3)."""
    return provider.name == "ollama" and any(
        model.startswith(p) for p in _OLLAMA_THINKING_PREFIXES
    )


def _is_deepseek_reasoner(provider: Provider, model: str) -> bool:
    return provider.name == "deepseek" and model == _DEEPSEEK_REASONER


def _strip_think_tags(text: str) -> str:
    """Elimina bloques <think>…</think> del contenido (Qwen3 sin think=False)."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _clean_content(provider: Provider, model: str, content: str | None) -> str:
    """Limpia el content según el proveedor."""
    text = content or ""
    # Ollama Qwen3 sin think=False puede filtrar igual
    if provider.name == "ollama":
        text = _strip_think_tags(text)
    return text.strip() or "_(Sin respuesta)_"


# ─── System prompt ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
Eres un analista OSINT experto con acceso a herramientas especializadas de \
inteligencia de fuentes abiertas.

Cuando el usuario te pida investigar un dominio, IP, email, teléfono, username \
o comprobar brechas de datos, usa la herramienta OSINT más adecuada.

Directrices:
- Usa las herramientas proactivamente cuando el usuario proporcione un indicador
- Presenta los hallazgos de forma clara y estructurada en español
- Destaca riesgos, advertencias y datos relevantes
- Sugiere análisis complementarios cuando sea útil
- NUNCA reveles contraseñas ni credenciales encontradas en brechas
- Recuerda al usuario que el OSINT es para fines defensivos y legales

Si no sabes qué herramienta usar, ejecuta recommend_osint_workflow primero.\
"""

# ─── Definición de herramientas ───────────────────────────────────────────────

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "domain_recon",
            "description": (
                "Reconocimiento OSINT pasivo de un dominio: WHOIS, registros DNS "
                "(A, AAAA, MX, NS, TXT), subdominios, tecnologías web y certificados."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Dominio objetivo, p.ej. example.com"},
                    "depth": {"type": "string", "enum": ["quick", "standard", "deep"],
                              "description": "Profundidad del análisis"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ip_reputation",
            "description": "Analiza una IP pública: ASN, organización, país, reportes de abuso.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "Dirección IP (IPv4 o IPv6)"},
                },
                "required": ["ip_address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "email_reputation",
            "description": (
                "Analiza un email: registros MX, servicios registrados, reputación "
                "y exposición en brechas. Sin login ni envío de emails."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "email": {"type": "string", "description": "Email objetivo"},
                },
                "required": ["email"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "phone_reputation",
            "description": "Consulta un teléfono: carrier, país, tipo de línea, spam. Solo fuentes públicas.",
            "parameters": {
                "type": "object",
                "properties": {
                    "phone_number": {"type": "string",
                                     "description": "Teléfono en E.164, p.ej. +34123456789"},
                    "country_hint": {"type": "string", "description": "Código ISO del país (opcional)"},
                },
                "required": ["phone_number"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "username_recon",
            "description": "Busca perfiles públicos de un username en redes sociales (Sherlock + Maigret).",
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username o alias objetivo"},
                    "platform_scope": {"type": "string",
                                       "description": "Plataforma específica o 'all'"},
                },
                "required": ["username"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "breach_exposure_check",
            "description": "Comprueba exposición en brechas de datos. No muestra contraseñas.",
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "Email, dominio o URL"},
                    "indicator_type": {"type": "string", "enum": ["auto", "email", "domain", "url"]},
                },
                "required": ["indicator"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "recommend_osint_workflow",
            "description": "Detecta el tipo de un indicador y recomienda qué workflows ejecutar.",
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "Indicador OSINT a clasificar"},
                },
                "required": ["indicator"],
            },
        },
    },
]

_TARGET_FIELD = {
    "domain_recon":             "domain",
    "ip_reputation":            "ip_address",
    "email_reputation":         "email",
    "phone_reputation":         "phone_number",
    "username_recon":           "username",
    "breach_exposure_check":    "indicator",
    "recommend_osint_workflow": "indicator",
}

# ─── Ejecución de herramientas ─────────────────────────────────────────────────

def call_tool(tool_name: str, arguments: dict[str, Any]) -> str:
    if tool_name == "recommend_osint_workflow":
        return _recommend(arguments.get("indicator", ""))

    target_field = _TARGET_FIELD.get(tool_name, "target")
    target = arguments.get(target_field) or arguments.get("target", "")

    with console.status(f"[cyan]Ejecutando [bold]{tool_name}[/bold] → {target}[/]"):
        try:
            resp = httpx.post(
                f"{OSINT_API}/workflow/run",
                json={"workflow": tool_name, "target": target,
                      "mode": "safe", "output_format": "json", "options": arguments},
                headers={"X-OSINT-API-Key": OSINT_KEY},
                timeout=30,
            )
            resp.raise_for_status()
            task_id = resp.json()["task_id"]
        except httpx.ConnectError:
            return "❌ OSINT API no disponible. ¿Están los contenedores arrancados?"
        except Exception as exc:
            return f"❌ Error al lanzar workflow: {exc}"

    console.print(f"  [dim]task_id: {task_id}[/dim]")

    data: dict = {}
    with console.status("[cyan]Esperando resultados...[/]"):
        for _ in range(100):
            time.sleep(3)
            try:
                poll = httpx.get(f"{OSINT_API}/tasks/{task_id}",
                                 headers={"X-OSINT-API-Key": OSINT_KEY}, timeout=15)
                poll.raise_for_status()
                data = poll.json()
                if data.get("status") in ("completed", "failed", "partial"):
                    break
            except Exception:
                continue

    if data.get("status") == "failed":
        return f"❌ Workflow fallido: {data.get('error', 'error desconocido')}"

    result = data.get("result", {})
    lines = [
        f"**Task ID:** `{task_id}`",
        f"**Estado:** {data.get('status')}",
        f"**Resumen:** {result.get('summary', 'Sin resumen')}",
        f"**Confianza:** {result.get('confidence', '?')}",
        f"**Riesgo:** {result.get('risk', '?')}",
    ]
    findings = result.get("findings", [])
    if findings:
        lines.append("\n**Hallazgos:**")
        for f in findings[:20]:
            val = f.get("value")
            val_str = json.dumps(val, ensure_ascii=False) if not isinstance(val, str) else val
            if len(val_str) > 400:
                val_str = val_str[:400] + "…"
            lines.append(f"- `{f['type']}` [{f.get('source','?')}]: {val_str}")

    sources = [s["name"] for s in result.get("sources", [])]
    if sources:
        lines.append(f"\n**Fuentes:** {', '.join(sources)}")

    warnings = result.get("warnings", [])
    if warnings:
        lines.append("\n**⚠️ Advertencias:**")
        lines.extend(f"- {w}" for w in warnings)

    _save_last_task(task_id, tool_name, target)
    return "\n".join(lines)


def _recommend(indicator: str) -> str:
    indicator = indicator.strip()
    if "@" in indicator:
        detected, workflows = "email", ["email_reputation", "breach_exposure_check"]
    elif indicator.startswith("http"):
        detected, workflows = "url", ["breach_exposure_check"]
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        detected, workflows = "ip", ["ip_reputation"]
    elif re.match(r"^\+?[0-9()\s\-]{7,16}$", indicator):
        detected, workflows = "phone", ["phone_reputation"]
    elif "." in indicator:
        detected, workflows = "domain", ["domain_recon", "breach_exposure_check"]
    else:
        detected, workflows = "username", ["username_recon"]
    return json.dumps({"tipo_detectado": detected, "workflows_recomendados": workflows,
                       "nota": "Ejecuta los workflows recomendados."}, ensure_ascii=False, indent=2)


def _save_last_task(task_id: str, workflow: str, target: str) -> None:
    try:
        path = os.path.join(os.path.dirname(__file__), ".last_tasks.json")
        try:
            with open(path) as fh:
                tasks = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            tasks = []
        tasks.insert(0, {"task_id": task_id, "workflow": workflow, "target": target})
        with open(path, "w") as fh:
            json.dump(tasks[:20], fh, indent=2)
    except Exception:
        pass


# ─── Verificación de servicios ─────────────────────────────────────────────────

def check_services(provider: Provider, model: str) -> bool:
    all_ok = True
    table = Table(show_header=False, box=None, padding=(0, 1))

    # OSINT API
    try:
        r = httpx.get(f"{OSINT_API}/health", timeout=5)
        mode = r.json().get("mode", "?")
        table.add_row("[green]✓[/]", "OSINT API",
                      f"[dim]{OSINT_API}[/dim]  modo: [cyan]{mode}[/cyan]")
    except Exception as exc:
        table.add_row("[red]✗[/]", "OSINT API", f"[red]No disponible — {exc}[/red]")
        all_ok = False

    # MCP Server
    try:
        httpx.get("http://localhost:3000/health", timeout=5)
        table.add_row("[green]✓[/]", "MCP Server (SSE)", "[dim]localhost:3000[/dim]")
    except Exception:
        table.add_row("[yellow]~[/]", "MCP Server (SSE)",
                      "[dim]No responde (opcional para este cliente)[/dim]")

    # Proveedor LLM
    if provider.name == "ollama":
        all_ok = _check_ollama(table, provider, model) and all_ok
    elif provider.name == "deepseek":
        all_ok = _check_api_key(table, provider, model) and all_ok
    elif provider.name == "openai":
        all_ok = _check_api_key(table, provider, model) and all_ok

    console.print(Panel(table, title="[bold]Estado de servicios[/bold]", border_style="blue"))
    return all_ok


def _check_ollama(table: Table, provider: Provider, model: str) -> bool:
    ollama_base = provider.base_url.rstrip("/v1").rstrip("/")
    try:
        r = httpx.get(f"{ollama_base}/api/tags", timeout=5)
        available = [m["name"] for m in r.json().get("models", [])]
        match = next((m for m in available if m == model or m.startswith(model)), None)
        if match:
            table.add_row("[green]✓[/]", "Ollama",
                          f"[dim]{ollama_base}[/dim]  modelo: [cyan]{match}[/cyan]")
            return True
        else:
            table.add_row("[yellow]⚠[/]", "Ollama",
                f"[yellow]Modelo '{model}' no encontrado.[/yellow]\n"
                f"  Disponibles: {', '.join(available[:5]) or 'ninguno'}\n"
                f"  Ejecuta: [bold]ollama pull {model}[/bold]")
            return False
    except Exception as exc:
        table.add_row("[red]✗[/]", "Ollama",
            f"[red]No disponible — {exc}[/red]\n"
            f"  Instala: [bold]curl -fsSL https://ollama.com/install.sh | sh[/bold]\n"
            f"  Luego:   [bold]ollama pull {model}[/bold]")
        return False


def _check_api_key(table: Table, provider: Provider, model: str) -> bool:
    if not provider.api_key:
        env_var = f"{provider.name.upper()}_API_KEY"
        table.add_row("[red]✗[/]", provider.label,
            f"[red]API key no configurada.[/red]\n"
            f"  Añade [bold]{env_var}=sk-...[/bold] a config/.env")
        return False

    # Verificar con una llamada ligera a la API
    try:
        client = OpenAI(base_url=provider.base_url, api_key=provider.api_key)
        # Llamada mínima para verificar auth
        client.models.list()
        table.add_row("[green]✓[/]", provider.label,
                      f"[dim]{provider.base_url}[/dim]  modelo: [cyan]{model}[/cyan]")
        return True
    except Exception as exc:
        err = str(exc)
        # 401 = key inválida, 404 = endpoint no tiene /models (DeepSeek) → OK de todas formas
        if "404" in err or "models" in err.lower():
            table.add_row("[green]✓[/]", provider.label,
                          f"[dim]{provider.base_url}[/dim]  modelo: [cyan]{model}[/cyan]")
            return True
        table.add_row("[red]✗[/]", provider.label, f"[red]{err[:120]}[/red]")
        return False


# ─── Descarga de informes / tareas recientes ──────────────────────────────────

def download_report(task_id: str, fmt: str = "markdown") -> None:
    try:
        resp = httpx.post(
            f"{OSINT_API}/reports/{task_id}",
            json={"task_id": task_id, "format": fmt},
            headers={"X-OSINT-API-Key": OSINT_KEY},
            timeout=30,
        )
        resp.raise_for_status()
    except Exception as exc:
        console.print(f"[red]Error descargando informe:[/red] {exc}")
        return
    console.print(Markdown(resp.text) if fmt == "markdown" else resp.text)


def show_recent_tasks() -> None:
    path = os.path.join(os.path.dirname(__file__), ".last_tasks.json")
    try:
        with open(path) as fh:
            tasks = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        console.print("[dim]No hay tareas recientes.[/dim]")
        return
    t = Table(title="Tareas recientes", show_lines=True)
    t.add_column("Task ID", style="cyan", no_wrap=True)
    t.add_column("Workflow")
    t.add_column("Target")
    for task in tasks[:10]:
        t.add_row(task["task_id"][:8] + "…", task["workflow"], task["target"])
    console.print(t)


# ─── Bucle principal de chat ───────────────────────────────────────────────────

def chat(provider: Provider, model: str) -> None:
    llm = OpenAI(base_url=provider.base_url, api_key=provider.api_key)
    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]

    # Quirks por proveedor
    think_off = _needs_think_off(provider, model)
    extra_body: dict = {"think": False} if think_off else {}
    is_reasoner = _is_deepseek_reasoner(provider, model)

    # Info panel
    hints: list[str] = []
    if think_off:
        hints.append(f"[dim]Modo thinking desactivado ({model})[/dim]")
    if is_reasoner:
        hints.append("[dim]Modo razonamiento DeepSeek-R1 activo[/dim]")

    console.print(Panel.fit(
        f"[bold cyan]MCP OSINT Client[/bold cyan]\n"
        f"Proveedor : [yellow]{provider.label}[/yellow]\n"
        f"Modelo    : [yellow]{model}[/yellow]\n"
        f"OSINT API : [dim]{OSINT_API}[/dim]\n"
        + ("\n" + "\n".join(hints) if hints else "") +
        "\n\n[dim]exit/salir · clear/nuevo · tareas · informe <id>[/dim]",
        border_style="cyan",
        padding=(1, 2),
    ))

    while True:
        try:
            user_input = Prompt.ask("\n[bold green]Tú[/bold green]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Hasta luego.[/dim]")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "salir", "bye"):
            console.print("[dim]Hasta luego.[/dim]")
            break
        if user_input.lower() in ("clear", "nuevo", "reset"):
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            console.print("[dim]── Conversación reiniciada ──[/dim]")
            continue
        if user_input.lower() == "tareas":
            show_recent_tasks()
            continue
        if user_input.lower().startswith("informe "):
            parts = user_input.split()
            download_report(parts[1], parts[2] if len(parts) > 2 else "markdown")
            continue

        messages.append({"role": "user", "content": user_input})

        # Bucle agéntico
        while True:
            with console.status("[cyan]Pensando...[/]"):
                try:
                    response = llm.chat.completions.create(
                        model=model,
                        messages=messages,
                        tools=TOOLS,
                        tool_choice="auto",
                        temperature=0.1,
                        extra_body=extra_body or None,
                    )
                except Exception as exc:
                    console.print(f"[red]Error {provider.label}:[/red] {exc}")
                    break

            msg = response.choices[0].message

            # Mostrar razonamiento de DeepSeek-R1 si está disponible
            if is_reasoner:
                reasoning = getattr(msg, "reasoning_content", None)
                if reasoning:
                    console.print(f"[dim]💭 Razonamiento ({len(reasoning)} chars)[/dim]")

            messages.append(msg)

            if not msg.tool_calls:
                content = _clean_content(provider, model, msg.content)
                console.print()
                console.rule("[dim]Respuesta[/dim]", style="dim")
                console.print(Markdown(content))
                console.rule(style="dim")
                break

            # Ejecutar tool calls
            for tc in msg.tool_calls:
                tool_name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                console.print(
                    f"\n  [yellow]⚙[/yellow] [bold]{tool_name}[/bold]"
                    f"  [dim]{json.dumps(args, ensure_ascii=False)}[/dim]"
                )
                result_text = call_tool(tool_name, args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_text,
                })


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="OSINT Client — Ollama / DeepSeek / OpenAI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Proveedores y modelos:
  ollama    qwen3.5:2b  qwen2.5:7b  llama3.1:8b  mistral-nemo  phi4
  deepseek  deepseek-chat  deepseek-reasoner
  openai    gpt-4o-mini  gpt-4o  gpt-4-turbo

Variables de entorno necesarias:
  OSINT_INTERNAL_API_KEY   clave interna de la OSINT API
  DEEPSEEK_API_KEY         para -p deepseek
  OPENAI_API_KEY           para -p openai
  OLLAMA_URL               URL de Ollama (default: http://localhost:11434/v1)

Ejemplos:
  python osint_client.py                            # Ollama, modelo por defecto
  python osint_client.py -p deepseek               # DeepSeek-V3
  python osint_client.py -p deepseek -m deepseek-reasoner  # DeepSeek-R1
  python osint_client.py -p openai -m gpt-4o-mini  # OpenAI
  python osint_client.py --check                    # verificar servicios
  python osint_client.py --report <task_id>         # descargar informe
        """,
    )
    parser.add_argument("-p", "--provider",
                        choices=list(PROVIDERS.keys()), default="ollama",
                        help="Proveedor LLM (default: ollama)")
    parser.add_argument("-m", "--model", default=None,
                        help="Modelo a usar (default según proveedor)")
    parser.add_argument("--check", action="store_true",
                        help="Solo verificar conectividad")
    parser.add_argument("--report", metavar="TASK_ID",
                        help="Descargar informe de una tarea")
    parser.add_argument("--report-format", choices=["markdown", "json", "html"],
                        default="markdown")
    args = parser.parse_args()

    provider = PROVIDERS[args.provider]

    # Recargar providers para que las env vars del .env estén en vigor
    # (el usuario puede haberlas puesto en config/.env y run.sh las carga)
    provider = _load_providers()[args.provider]

    model = args.model or provider.default_model

    console.print()
    services_ok = check_services(provider, model)

    if args.report:
        download_report(args.report, args.report_format)
        return

    if args.check:
        status = "[green]Todos los servicios listos.[/green]" if services_ok \
            else "[yellow]Algunos servicios no disponibles — revisa arriba.[/yellow]"
        console.print(f"\n{status}")
        return

    if not services_ok:
        console.print("\n[red]Servicios no disponibles. Revisa la configuración.[/red]\n")
        sys.exit(1)

    console.print()
    chat(provider, model)


if __name__ == "__main__":
    main()
