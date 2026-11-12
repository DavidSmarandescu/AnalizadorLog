from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class Event:
    """Una línea de log ya interpretada."""

    ts: datetime
    source: str  # "ssh" | "web"
    ip: str
    kind: str  # ssh: failed | accepted | invalid ; web: request
    raw: str
    user: str | None = None
    auth_method: str | None = None
    http_method: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    referer: str | None = None


@dataclass
class Finding:
    """Un comportamiento sospechoso detectado."""

    rule: str
    severity: str
    ip: str
    title: str
    detail: str
    count: int
    first_seen: datetime
    last_seen: datetime
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "title": self.title,
            "detail": self.detail,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "evidence": self.evidence,
        }
