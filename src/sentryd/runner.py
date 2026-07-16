"""Case runner: one detection run = one case.

Shared by the CLI and the web upload/replay endpoints so both produce
identical cases: a case row is created up front (status running), alerts are
stamped with the case id as they are stored, progress is written back
periodically, and the row is finalized with status, event counts, and the
event-time span. The web API runs this in a worker thread and reads status
from the case row.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from sentryd.config import load_config
from sentryd.core.alerts import Alert
from sentryd.core.cases import Case, CaseStatus
from sentryd.core.engine import AlertSink, EngineStats, RuleEngine
from sentryd.rules.base import build_rules
from sentryd.storage.store import AlertStore

PROGRESS_EVERY = 500  # events between progress writes to the case row


class CaseStoreSink:
    """Stamps each alert with the case id, then persists it."""

    def __init__(self, store: AlertStore, case_id: int) -> None:
        self.store = store
        self.case_id = case_id

    def emit(self, alert: Alert) -> None:
        alert.case_id = self.case_id
        self.store.emit(alert)

    def update(self, alert: Alert) -> None:
        self.store.update(alert)


@dataclass
class CaseRunResult:
    case: Case
    stats: EngineStats
    interrupted: bool = False


def pcap_metadata(path: Path) -> tuple[str, int]:
    """(sha256, size in bytes) of a capture file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest(), path.stat().st_size


def _build_case(source_kind: str, source_label: str, name: str | None) -> Case:
    case = Case(
        id=None,
        name=name or Path(source_label).name or source_label,
        source_kind=source_kind,
        source=str(source_label),
    )
    if source_kind == "pcap":
        path = Path(source_label)
        if path.is_file():
            case.pcap_sha256, case.pcap_size = pcap_metadata(path)
    return case


def create_pending_case(
    db: Path, *, source_kind: str, source_label: str, name: str | None = None
) -> Case:
    """Create a case row (status running) ahead of a background run, so the
    caller can hand its id to the client before processing starts."""
    with AlertStore(db) as store:
        return store.create_case(_build_case(source_kind, source_label, name))


def run_case(
    db: Path,
    source,
    *,
    source_kind: str,
    source_label: str,
    name: str | None = None,
    config_path: Path | None = None,
    extra_sinks: Iterable[AlertSink] = (),
    case_id: int | None = None,
) -> CaseRunResult:
    """Run a PacketSource through the engine inside a case.

    A fresh case is created unless case_id names one prepared earlier via
    create_pending_case. Raises SourceError (after marking the case failed)
    for user-facing source problems; KeyboardInterrupt finalizes the case as
    complete with whatever was processed and is reported via
    CaseRunResult.interrupted.
    """
    config = load_config(config_path)
    with AlertStore(db) as store:
        if case_id is not None:
            case = store.get_case(case_id)
            if case is None:
                raise ValueError(f"no case with id {case_id}")
        else:
            case = store.create_case(_build_case(source_kind, source_label, name))

        engine = RuleEngine(
            rules=build_rules(config),
            sinks=[CaseStoreSink(store, case.id), *extra_sinks],
            cooldown_seconds=config.get("engine", {}).get("cooldown_seconds", 60),
        )

        interrupted = False
        first_ts: float | None = None
        last_ts: float | None = None
        error: str | None = None
        try:
            for event in source.events():
                engine.process(event)
                if first_ts is None:
                    first_ts = event.ts
                last_ts = event.ts
                if engine.stats.events_processed % PROGRESS_EVERY == 0:
                    store.update_case_progress(case.id, engine.stats.events_processed)
            engine.flush()
        except KeyboardInterrupt:
            engine.flush()
            interrupted = True
        except Exception as exc:
            engine.flush()
            error = str(exc)
            store.finalize_case(
                case.id,
                CaseStatus.FAILED,
                events_processed=engine.stats.events_processed,
                packet_count=engine.stats.events_processed,
                start_ts=first_ts,
                end_ts=last_ts,
                error=error,
            )
            raise

        store.finalize_case(
            case.id,
            CaseStatus.COMPLETE,
            events_processed=engine.stats.events_processed,
            packet_count=engine.stats.events_processed,
            start_ts=first_ts,
            end_ts=last_ts,
        )
        finished = store.get_case(case.id)
        return CaseRunResult(case=finished, stats=engine.stats, interrupted=interrupted)
