"""Convierte líneas de log en eventos.

Formatos soportados:
  - sshd vía syslog clásico   ("Nov 10 03:14:07 host sshd[123]: ...")
  - sshd vía syslog ISO 8601  ("2026-11-10T03:14:07+00:00 host sshd[123]: ...")
  - acceso web en formato "combined" de nginx/Apache

Todas las fechas se devuelven sin zona horaria. Las que traen zona (web, ISO)
se convierten a UTC; las de syslog clásico se dejan tal cual vienen.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, Iterator

from .models import Event

_SYSLOG = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d\d:\d\d:\d\d)\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\S+)\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) "
    r"from (?P<ip>\S+) port \d+"
)
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)")

_WEB = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) \S+'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def _to_naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _parse_ssh_message(ts: datetime, msg: str, raw: str) -> Event | None:
    if m := _SSH_FAILED.match(msg):
        return Event(ts, "ssh", m["ip"], "failed", raw,
                     user=m["user"], auth_method=m["method"])
    if m := _SSH_ACCEPTED.match(msg):
        return Event(ts, "ssh", m["ip"], "accepted", raw,
                     user=m["user"], auth_method=m["method"])
    if m := _SSH_INVALID.match(msg):
        return Event(ts, "ssh", m["ip"], "invalid", raw, user=m["user"])
    return None


def parse_line(line: str, year: int) -> Event | None:
    """Devuelve un Event, o None si la línea no es relevante o no se reconoce."""
    line = line.rstrip("\n")
    try:
        if m := _SYSLOG.match(line):
            # El syslog clásico no incluye el año; se antepone para evitar
            # ambigüedades con el 29 de febrero.
            ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
            return _parse_ssh_message(ts, m["msg"], line)
        if m := _SYSLOG_ISO.match(line):
            ts = _to_naive_utc(datetime.fromisoformat(m["ts"]))
            return _parse_ssh_message(ts, m["msg"], line)
        if m := _WEB.match(line):
            ts = _to_naive_utc(datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z"))
            parts = m["request"].split()
            method = parts[0] if parts else None
            path = parts[1] if len(parts) > 1 else m["request"]
            return Event(ts, "web", m["ip"], "request", line,
                         http_method=method, path=path, status=int(m["status"]),
                         user_agent=m["ua"], referer=m["referer"])
    except ValueError:
        return None
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[Event]:
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event
