"""Case model: one replay/capture run and everything it produced.

A case is the workspace unit. Every alert belongs to the case whose run
produced it, so alerts from different pcaps never blur together, old runs
can be archived or cleared, and the overall AI review has a natural scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CaseStatus(StrEnum):
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    ARCHIVED = "archived"


@dataclass
class Case:
    id: int | None
    name: str
    source_kind: str  # pcap | live | log
    source: str  # file path or interface name
    status: CaseStatus = CaseStatus.RUNNING
    created_at: str = ""
    pcap_sha256: str | None = None
    pcap_size: int | None = None
    packet_count: int | None = None  # normalized events parsed from the source
    events_processed: int = 0
    alert_count: int = 0
    start_ts: float | None = None  # event-time span of the processed traffic
    end_ts: float | None = None
    error: str | None = None
    notes: str = ""
    ai_report: str | None = None
    ai_report_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "source_kind": self.source_kind,
            "source": self.source,
            "status": self.status.value,
            "created_at": self.created_at,
            "pcap_sha256": self.pcap_sha256,
            "pcap_size": self.pcap_size,
            "packet_count": self.packet_count,
            "events_processed": self.events_processed,
            "alert_count": self.alert_count,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "error": self.error,
            "notes": self.notes,
            "ai_report": self.ai_report,
            "ai_report_at": self.ai_report_at,
        }
