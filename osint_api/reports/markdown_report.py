from __future__ import annotations

import json
from datetime import datetime

from mcp_server.schemas.common import OsintResult


def build_markdown_report(result: OsintResult) -> str:
    lines: list[str] = []
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines += [
        f"# OSINT Report — {result.target}",
        f"_Generated: {now}_",
        "",
        "---",
        "",
        "## 1. Resumen ejecutivo",
        "",
        result.summary or "_No summary available._",
        "",
        "---",
        "",
        "## 2. Objetivo analizado",
        "",
        f"- **Target:** `{result.target}`",
        f"- **Type:** {result.target_type.value}",
        f"- **Workflow:** {result.workflow}",
        f"- **Task ID:** `{result.task_id}`",
        "",
        "---",
        "",
        "## 3. Metodología",
        "",
        "OSINT pasivo. Fuentes públicas únicamente. Sin interacción activa con el objetivo.",
        "",
        "---",
        "",
        "## 4. Herramientas usadas",
        "",
    ]

    for src in result.sources:
        status = "OK" if src.success else "FAIL"
        url_part = f" — {src.url}" if src.url else ""
        lines.append(f"- **{src.name}** [{status}]{url_part}")

    lines += [
        "",
        "---",
        "",
        "## 5. Hallazgos",
        "",
    ]

    if result.findings:
        for f in result.findings:
            value_str = json.dumps(f.value, ensure_ascii=False) if not isinstance(f.value, str) else f.value
            lines += [
                f"### {f.type}",
                f"- **Source:** {f.source}",
                f"- **Confidence:** {f.confidence.value}",
                f"- **Value:** {value_str}",
            ]
            if f.notes:
                lines.append(f"- **Notes:** {f.notes}")
            lines.append("")
    else:
        lines.append("_No findings._")
        lines.append("")

    lines += [
        "---",
        "",
        "## 6. Evidencias",
        "",
    ]
    for ev in result.evidence:
        lines.append(f"- `{ev.filename}` — {ev.description}")
    if not result.evidence:
        lines.append("_No evidence files._")

    lines += [
        "",
        "---",
        "",
        "## 7. Nivel de confianza",
        "",
        f"**{result.confidence.upper()}**",
        "",
        "---",
        "",
        "## 8. Riesgo",
        "",
        f"**{result.risk.upper()}**",
        "",
        "---",
        "",
        "## 9. Limitaciones",
        "",
        "- Solo fuentes públicas disponibles en el momento de la consulta.",
        "- Resultados pueden ser incompletos si las APIs externas no están configuradas.",
        "- Datos pueden estar desactualizados según la fuente.",
        "",
        "---",
        "",
        "## 10. Recomendaciones",
        "",
    ]

    if result.risk.value in ("high", "medium"):
        lines.append("- **Acción recomendada:** Revisar hallazgos de riesgo alto/medio con un analista.")
    else:
        lines.append("- No se identificaron riesgos significativos en esta consulta.")

    if result.warnings:
        lines += ["", "**Advertencias:**"]
        for w in result.warnings:
            lines.append(f"- {w}")

    lines += [
        "",
        "---",
        "",
        "## 11. Anexos técnicos",
        "",
        f"- **Started:** {result.started_at.isoformat()}",
        f"- **Finished:** {result.finished_at.isoformat() if result.finished_at else 'N/A'}",
        f"- **Status:** {result.status.value}",
        "",
    ]

    return "\n".join(lines)
