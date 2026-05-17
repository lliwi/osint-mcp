from __future__ import annotations

import html
import json
from datetime import datetime

from mcp_server.schemas.common import OsintResult


def build_html_report(result: OsintResult) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def h(s: str) -> str:
        return html.escape(str(s))

    findings_html = ""
    for f in result.findings:
        val = json.dumps(f.value, ensure_ascii=False) if not isinstance(f.value, str) else f.value
        findings_html += f"""
        <div class="finding">
          <h3>{h(f.type)}</h3>
          <p><strong>Source:</strong> {h(f.source)} &nbsp;|&nbsp;
             <strong>Confidence:</strong> {h(f.confidence)}</p>
          <pre>{h(val)}</pre>
          {"<p><em>" + h(f.notes) + "</em></p>" if f.notes else ""}
        </div>"""

    sources_html = "".join(
        f'<li><strong>{h(s.name)}</strong> {"✓" if s.success else "✗"}'
        f'{" — <a href=" + h(s.url) + ">" + h(s.url) + "</a>" if s.url else ""}</li>'
        for s in result.sources
    )

    warnings_html = "".join(f"<li>{h(w)}</li>" for w in result.warnings)

    risk_color = {"high": "#dc2626", "medium": "#d97706", "low": "#16a34a", "unknown": "#6b7280"}
    risk_c = risk_color.get(result.risk.value, "#6b7280")

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>OSINT Report — {h(result.target)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 1rem; color: #111; }}
    h1 {{ border-bottom: 2px solid #3b82f6; padding-bottom: .5rem; }}
    h2 {{ color: #1d4ed8; margin-top: 2rem; }}
    h3 {{ color: #374151; }}
    .badge {{ display: inline-block; padding: .25rem .75rem; border-radius: 999px; font-weight: bold; color: white; }}
    .risk {{ background: {risk_c}; }}
    .finding {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; margin: .75rem 0; }}
    pre {{ background: #f3f4f6; padding: .75rem; border-radius: 4px; overflow-x: auto; font-size: .85em; }}
    ul {{ margin: .5rem 0; padding-left: 1.5rem; }}
    footer {{ margin-top: 3rem; color: #9ca3af; font-size: .8em; border-top: 1px solid #e5e7eb; padding-top: 1rem; }}
  </style>
</head>
<body>
  <h1>OSINT Report — {h(result.target)}</h1>
  <p><em>Generated: {h(now)}</em></p>

  <h2>1. Resumen ejecutivo</h2>
  <p>{h(result.summary)}</p>

  <h2>2. Objetivo</h2>
  <ul>
    <li><strong>Target:</strong> <code>{h(result.target)}</code></li>
    <li><strong>Type:</strong> {h(result.target_type)}</li>
    <li><strong>Workflow:</strong> {h(result.workflow)}</li>
    <li><strong>Task ID:</strong> <code>{h(result.task_id)}</code></li>
  </ul>

  <h2>3. Riesgo &amp; Confianza</h2>
  <p>
    Riesgo: <span class="badge risk">{h(result.risk.upper())}</span>
    &nbsp;&nbsp;
    Confianza: <span class="badge" style="background:#1d4ed8">{h(result.confidence.upper())}</span>
  </p>

  <h2>4. Herramientas usadas</h2>
  <ul>{sources_html}</ul>

  <h2>5. Hallazgos</h2>
  {findings_html or "<p><em>Sin hallazgos.</em></p>"}

  {"<h2>Advertencias</h2><ul>" + warnings_html + "</ul>" if result.warnings else ""}

  <footer>
    <p>MCP OSINT Server — uso exclusivo para OSINT defensivo y autorizado.</p>
    <p>Inicio: {h(result.started_at.isoformat())} | Fin: {h(result.finished_at.isoformat() if result.finished_at else "N/A")}</p>
  </footer>
</body>
</html>"""
