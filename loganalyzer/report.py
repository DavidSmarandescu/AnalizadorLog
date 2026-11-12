from __future__ import annotations

import json
from collections import Counter

from .models import SEVERITIES, Finding

_COLORS = {"critical": "\033[1;31m", "high": "\033[31m",
           "medium": "\033[33m", "low": "\033[36m"}
_LABELS = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO"}
_RESET = "\033[0m"


def render_json(findings: list[Finding], stats: dict) -> str:
    return json.dumps(
        {"stats": stats, "findings": [f.to_dict() for f in findings]},
        indent=2, ensure_ascii=False,
    )


def render_text(findings: list[Finding], stats: dict, color: bool = False) -> str:
    def paint(severity: str, text: str) -> str:
        return f"{_COLORS[severity]}{text}{_RESET}" if color else text

    out = ["=== Análisis de logs ===",
           f"Líneas leídas: {stats['lines']}   "
           f"Eventos reconocidos: {stats['events']} "
           f"(ssh: {stats['ssh_events']}, web: {stats['web_events']})"]

    if not findings:
        out.append("\nSin hallazgos.")
        return "\n".join(out)

    by_severity = Counter(f.severity for f in findings)
    summary = ", ".join(f"{by_severity[s]} {_LABELS[s].lower()}"
                        for s in reversed(SEVERITIES) if by_severity[s])
    out.append(f"Hallazgos: {len(findings)} ({summary})")

    for f in findings:
        out.append("")
        out.append(f"{paint(f.severity, f'[{_LABELS[f.severity]}]')} {f.title} — {f.ip}")
        out.append(f"  {f.detail}")
        out.append(f"  Regla: {f.rule}   Periodo: {f.first_seen:%Y-%m-%d %H:%M:%S}"
                   f" → {f.last_seen:%Y-%m-%d %H:%M:%S}")
        for line in f.evidence:
            out.append(f"    | {line[:160]}")

    out.append("\n=== IPs con más hallazgos ===")
    per_ip: dict[str, list[Finding]] = {}
    for f in findings:
        per_ip.setdefault(f.ip, []).append(f)
    ranked = sorted(per_ip.items(), key=lambda kv: -len(kv[1]))
    for ip, items in ranked[:10]:
        worst = items[0].severity  # ya vienen ordenados por gravedad
        rules = ", ".join(sorted({f.rule for f in items}))
        out.append(f"  {ip:<16} {len(items)} hallazgos (máx. {_LABELS[worst]}): {rules}")
    return "\n".join(out)
