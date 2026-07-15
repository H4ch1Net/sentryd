"""Alert model shared by the engine, storage, and every interface."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class AlertStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    DISMISSED = "dismissed"


@dataclass
class Alert:
    rule_id: str
    severity: Severity
    confidence: float  # 0.0 - 1.0
    title: str
    ts: float
    src: str | None
    dst: str | None
    evidence: dict
    count: int = 1  # occurrences merged into this alert by dedup
    status: AlertStatus = AlertStatus.NEW
    ai_summary: str | None = None
    id: int | None = None  # assigned by storage
    # Extra dedup discriminator for rules that can raise distinct findings
    # for the same src/dst pair (e.g. suspicious_port sets the port here so
    # a Telnet hit and a Metasploit hit never merge into one alert).
    key: str = ""

    @property
    def dedup_key(self) -> tuple[str, str | None, str | None, str]:
        return (self.rule_id, self.src, self.dst, self.key)

    def evidence_json(self) -> str:
        return json.dumps(self.evidence, default=str, sort_keys=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "src": self.src,
            "dst": self.dst,
            "evidence": self.evidence,
            "count": self.count,
            "status": self.status.value,
            "ai_summary": self.ai_summary,
        }
