"""Reglas de detección. Cada una recibe eventos y devuelve hallazgos."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable
from urllib.parse import unquote_plus

from .models import Event, Finding

MAX_EVIDENCE = 3


@dataclass
class Config:
    ssh_fail_threshold: int = 5      # fallos de login para considerar fuerza bruta
    ssh_window: int = 300            # ...dentro de estos segundos
    ssh_enum_threshold: int = 5      # usuarios inexistentes distintos probados
    web_404_threshold: int = 20      # respuestas 404 para considerar enumeración
    web_404_window: int = 60
    web_login_threshold: int = 10    # logins web fallidos (401/403)
    web_login_window: int = 300


def densest_window(times: list[datetime], seconds: int) -> tuple[int, int, int]:
    """Máximo número de eventos dentro de una ventana deslizante.

    `times` debe estar ordenada. Devuelve (cantidad, índice inicial, índice final).
    """
    window = timedelta(seconds=seconds)
    best = (0, 0, 0)
    start = 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        if end - start + 1 > best[0]:
            best = (end - start + 1, start, end)
    return best


def _by_ip(events: Iterable[Event]) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        groups[e.ip].append(e)
    for group in groups.values():
        group.sort(key=lambda e: e.ts)
    return groups


def _evidence(events: list[Event]) -> list[str]:
    return [e.raw for e in events[:MAX_EVIDENCE]]


# --------------------------------------------------------------------- SSH

def detect_ssh_brute_force(events: list[Event], cfg: Config) -> list[Finding]:
    findings = []
    failed = [e for e in events if e.source == "ssh" and e.kind == "failed"]
    for ip, group in _by_ip(failed).items():
        count, i, j = densest_window([e.ts for e in group], cfg.ssh_window)
        if count < cfg.ssh_fail_threshold:
            continue
        users = sorted({e.user for e in group if e.user})
        findings.append(Finding(
            rule="ssh_brute_force", severity="high", ip=ip,
            title="Fuerza bruta contra SSH",
            detail=(f"{len(group)} logins fallidos en total; pico de {count} en "
                    f"{cfg.ssh_window}s. Usuarios probados: {', '.join(users[:8])}"
                    + (" ..." if len(users) > 8 else "")),
            count=len(group), first_seen=group[0].ts, last_seen=group[-1].ts,
            evidence=_evidence(group[i:j + 1]),
        ))
    return findings


def detect_ssh_compromise(events: list[Event], cfg: Config) -> list[Finding]:
    """Login correcto desde una IP que antes acumuló muchos fallos."""
    findings = []
    ssh = [e for e in events if e.source == "ssh" and e.kind in ("failed", "accepted")]
    for ip, group in _by_ip(ssh).items():
        failures = 0
        for e in group:
            if e.kind == "failed":
                failures += 1
            elif failures >= cfg.ssh_fail_threshold:
                findings.append(Finding(
                    rule="ssh_login_after_failures", severity="critical", ip=ip,
                    title="Login SSH exitoso tras fuerza bruta",
                    detail=(f"Acceso concedido al usuario '{e.user}' "
                            f"({e.auth_method}) después de {failures} intentos "
                            f"fallidos. Posible cuenta comprometida."),
                    count=failures + 1, first_seen=group[0].ts, last_seen=e.ts,
                    evidence=[e.raw],
                ))
                break
    return findings


def detect_ssh_user_enum(events: list[Event], cfg: Config) -> list[Finding]:
    findings = []
    invalid = [e for e in events if e.source == "ssh" and e.kind == "invalid"]
    for ip, group in _by_ip(invalid).items():
        users = sorted({e.user for e in group if e.user})
        if len(users) < cfg.ssh_enum_threshold:
            continue
        findings.append(Finding(
            rule="ssh_user_enumeration", severity="medium", ip=ip,
            title="Enumeración de usuarios SSH",
            detail=(f"{len(users)} usuarios inexistentes probados: "
                    f"{', '.join(users[:8])}" + (" ..." if len(users) > 8 else "")),
            count=len(group), first_seen=group[0].ts, last_seen=group[-1].ts,
            evidence=_evidence(group),
        ))
    return findings


# --------------------------------------------------------------------- Web

_PAYLOADS: dict[str, list[re.Pattern]] = {
    "inyección SQL": [re.compile(p) for p in (
        r"union\s+(all\s+)?select", r"'\s*or\s+'?\d+'?\s*=\s*'?\d+",
        r"\bsleep\(\d+\)", r"information_schema", r";\s*drop\s+table", r"'\s*--",
    )],
    "XSS": [re.compile(p) for p in (
        r"<script", r"javascript:", r"\bon(error|load|mouseover)\s*=",
    )],
    "path traversal": [re.compile(p) for p in (
        r"\.\./", r"\.\.\\", r"/etc/(passwd|shadow)", r"boot\.ini",
    )],
    "inyección de comandos": [re.compile(p) for p in (
        r"[;|`]\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b", r"\$\(",
    )],
    "Log4Shell": [re.compile(r"\$\{jndi:")],
}

_SCANNERS = re.compile(
    r"sqlmap|nikto|nmap|gobuster|dirbuster|dirb\b|wpscan|nuclei|masscan|zgrab|"
    r"feroxbuster|ffuf|wfuzz|acunetix|nessus|openvas"
)

_SENSITIVE = re.compile(
    r"/(\.env|\.git/|\.aws/|\.ssh/|\.htpasswd|wp-config\.php|phpmyadmin|id_rsa|"
    r"backup\.(sql|zip|tar\.gz)|dump\.sql|server-status|actuator/(env|heapdump))"
)

_LOGIN_PATH = re.compile(r"/(login|signin|wp-login\.php|auth|session|oauth/token)\b")


def _decode(text: str | None) -> str:
    # Doble decodificación: los atacantes suelen codificar dos veces (%252e).
    return unquote_plus(unquote_plus(text or "")).lower()


def detect_web_payloads(events: list[Event], cfg: Config) -> list[Finding]:
    hits: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.source != "web":
            continue
        # Log4Shell suele venir en cabeceras, no solo en la URL.
        haystack = " ".join(_decode(x) for x in (e.path, e.user_agent, e.referer))
        for category, patterns in _PAYLOADS.items():
            if any(p.search(haystack) for p in patterns):
                hits[(e.ip, category)].append(e)
    findings = []
    for (ip, category), group in hits.items():
        group.sort(key=lambda e: e.ts)
        ok = sum(1 for e in group if e.status is not None and 200 <= e.status < 300)
        detail = f"{len(group)} peticiones con patrones de {category}."
        if ok:
            detail += (f" {ok} recibieron respuesta 2xx: revisar si el "
                       f"ataque tuvo éxito.")
        findings.append(Finding(
            rule="web_attack_payload", severity="high", ip=ip,
            title=f"Intento de {category}", detail=detail, count=len(group),
            first_seen=group[0].ts, last_seen=group[-1].ts,
            evidence=_evidence(group),
        ))
    return findings


def detect_web_scanners(events: list[Event], cfg: Config) -> list[Finding]:
    findings = []
    flagged = [e for e in events
               if e.source == "web" and _SCANNERS.search((e.user_agent or "").lower())]
    for ip, group in _by_ip(flagged).items():
        tools = sorted({_SCANNERS.search(e.user_agent.lower())[0] for e in group})
        findings.append(Finding(
            rule="web_scanner_user_agent", severity="medium", ip=ip,
            title="Herramienta de escaneo detectada",
            detail=(f"{len(group)} peticiones con User-Agent de: "
                    f"{', '.join(tools)}."),
            count=len(group), first_seen=group[0].ts, last_seen=group[-1].ts,
            evidence=_evidence(group),
        ))
    return findings


def detect_web_enumeration(events: list[Event], cfg: Config) -> list[Finding]:
    findings = []
    not_found = [e for e in events if e.source == "web" and e.status == 404]
    for ip, group in _by_ip(not_found).items():
        count, i, j = densest_window([e.ts for e in group], cfg.web_404_window)
        if count < cfg.web_404_threshold:
            continue
        findings.append(Finding(
            rule="web_enumeration", severity="medium", ip=ip,
            title="Enumeración de rutas web",
            detail=(f"{len(group)} respuestas 404 en total; pico de {count} en "
                    f"{cfg.web_404_window}s. Típico de fuzzing de directorios."),
            count=len(group), first_seen=group[0].ts, last_seen=group[-1].ts,
            evidence=_evidence(group[i:j + 1]),
        ))
    return findings


def detect_web_sensitive_files(events: list[Event], cfg: Config) -> list[Finding]:
    findings = []
    probes = [e for e in events
              if e.source == "web" and _SENSITIVE.search(_decode(e.path))]
    for ip, group in _by_ip(probes).items():
        served = [e for e in group if e.status == 200]
        if served:
            paths = sorted({e.path for e in served})
            findings.append(Finding(
                rule="web_sensitive_file_exposed", severity="critical", ip=ip,
                title="Archivo sensible servido",
                detail=(f"El servidor respondió 200 a: {', '.join(paths[:5])}. "
                        f"Puede haber filtrado secretos."),
                count=len(served), first_seen=served[0].ts, last_seen=served[-1].ts,
                evidence=_evidence(served),
            ))
        else:
            findings.append(Finding(
                rule="web_sensitive_file_probe", severity="low", ip=ip,
                title="Búsqueda de archivos sensibles",
                detail=(f"{len(group)} peticiones a rutas como .env, .git o "
                        f"copias de seguridad; ninguna tuvo éxito."),
                count=len(group), first_seen=group[0].ts, last_seen=group[-1].ts,
                evidence=_evidence(group),
            ))
    return findings


def detect_web_login_brute_force(events: list[Event], cfg: Config) -> list[Finding]:
    findings = []
    failed = [e for e in events
              if e.source == "web" and e.http_method == "POST"
              and e.status in (401, 403) and _LOGIN_PATH.search(_decode(e.path))]
    for ip, group in _by_ip(failed).items():
        count, i, j = densest_window([e.ts for e in group], cfg.web_login_window)
        if count < cfg.web_login_threshold:
            continue
        findings.append(Finding(
            rule="web_login_brute_force", severity="high", ip=ip,
            title="Fuerza bruta contra login web",
            detail=(f"{len(group)} logins rechazados en total; pico de {count} "
                    f"en {cfg.web_login_window}s."),
            count=len(group), first_seen=group[0].ts, last_seen=group[-1].ts,
            evidence=_evidence(group[i:j + 1]),
        ))
    return findings


DETECTORS = (
    detect_ssh_brute_force,
    detect_ssh_compromise,
    detect_ssh_user_enum,
    detect_web_payloads,
    detect_web_scanners,
    detect_web_enumeration,
    detect_web_sensitive_files,
    detect_web_login_brute_force,
)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def analyze(events: Iterable[Event], cfg: Config | None = None) -> list[Finding]:
    """Ejecuta todas las reglas; devuelve hallazgos ordenados por gravedad."""
    cfg = cfg or Config()
    events = list(events)
    findings = [f for detector in DETECTORS for f in detector(events, cfg)]
    findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.first_seen, f.ip))
    return findings
