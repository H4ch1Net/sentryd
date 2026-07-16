"""SQLite persistence: alerts and cases. Thin repository over stdlib
sqlite3, no ORM. Existing databases are migrated in place by adding any
missing columns (idempotent, checked against PRAGMA table_info)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from sentryd.core.alerts import Alert, AlertStatus, Severity
from sentryd.core.cases import Case, CaseStatus

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    rule_id     TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    confidence  REAL    NOT NULL,
    title       TEXT    NOT NULL,
    src         TEXT,
    dst         TEXT,
    evidence    TEXT    NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    status      TEXT    NOT NULL DEFAULT 'new',
    ai_summary  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    case_id     INTEGER REFERENCES cases (id) ON DELETE CASCADE,
    last_ts     REAL,
    protocol    TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    reason      TEXT    NOT NULL DEFAULT '',
    packet_count INTEGER,
    byte_count  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL,
    source_kind      TEXT    NOT NULL,
    source           TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'running',
    created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    pcap_sha256      TEXT,
    pcap_size        INTEGER,
    packet_count     INTEGER,
    events_processed INTEGER NOT NULL DEFAULT 0,
    start_ts         REAL,
    end_ts           REAL,
    error            TEXT,
    notes            TEXT    NOT NULL DEFAULT '',
    ai_report        TEXT,
    ai_report_at     TEXT
);
"""

# Columns added after the first release; applied to pre-existing databases.
_ALERT_MIGRATIONS = {
    "case_id": "INTEGER REFERENCES cases (id) ON DELETE CASCADE",
    "last_ts": "REAL",
    "protocol": "TEXT",
    "src_port": "INTEGER",
    "dst_port": "INTEGER",
    "reason": "TEXT NOT NULL DEFAULT ''",
    "packet_count": "INTEGER",
    "byte_count": "INTEGER",
}

DEFAULT_DB_PATH = Path("sentryd.db")


class AlertStore:
    """Alert/case repository. Also usable as an engine sink (emit/update)."""

    def __init__(self, path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        existing = {
            row["name"] for row in self._conn.execute("PRAGMA table_info(alerts)")
        }
        for column, decl in _ALERT_MIGRATIONS.items():
            if column not in existing:
                self._conn.execute(f"ALTER TABLE alerts ADD COLUMN {column} {decl}")
        # Created here, not in SCHEMA: on a pre-case database the column only
        # exists after the ALTERs above have run.
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_case ON alerts (case_id)")
        self._conn.commit()

    def __enter__(self) -> "AlertStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- engine sink interface ------------------------------------------------

    def emit(self, alert: Alert) -> None:
        self.insert(alert)

    def update(self, alert: Alert) -> None:
        # Dedup merges bump count/severity/confidence/last_ts and the running
        # packet/byte totals; evidence is rule-owned and immutable after emit.
        if alert.id is None:
            return
        self._conn.execute(
            "UPDATE alerts SET count = ?, severity = ?, confidence = ?, last_ts = ?, "
            "packet_count = ?, byte_count = ? WHERE id = ?",
            (
                alert.count,
                alert.severity.value,
                alert.confidence,
                alert.last_ts,
                alert.packet_count,
                alert.byte_count,
                alert.id,
            ),
        )
        self._conn.commit()

    # -- alert repository -------------------------------------------------------

    def insert(self, alert: Alert) -> Alert:
        cur = self._conn.execute(
            """
            INSERT INTO alerts (ts, rule_id, severity, confidence, title, src, dst,
                                evidence, count, status, ai_summary, case_id, last_ts,
                                protocol, src_port, dst_port, reason,
                                packet_count, byte_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.ts,
                alert.rule_id,
                alert.severity.value,
                alert.confidence,
                alert.title,
                alert.src,
                alert.dst,
                alert.evidence_json(),
                alert.count,
                alert.status.value,
                alert.ai_summary,
                alert.case_id,
                alert.last_ts,
                alert.protocol,
                alert.src_port,
                alert.dst_port,
                alert.reason,
                alert.packet_count,
                alert.byte_count,
            ),
        )
        self._conn.commit()
        alert.id = cur.lastrowid
        return alert

    def get(self, alert_id: int) -> Alert | None:
        row = self._conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._row_to_alert(row) if row else None

    def list(
        self,
        severity: str | None = None,
        rule_id: str | None = None,
        status: str | None = None,
        case_id: int | None = None,
        host: str | None = None,
        limit: int = 50,
    ) -> list[Alert]:
        query = "SELECT * FROM alerts"
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if case_id is not None:
            clauses.append("case_id = ?")
            params.append(case_id)
        if host:
            clauses.append("(src = ? OR dst = ?)")
            params.extend([host, host])
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_alert(row) for row in rows]

    def set_ai_summary(self, alert_id: int, summary: str) -> None:
        # Does not change the analyst verdict; AI presence is tracked by
        # ai_summary itself, not by the status column.
        self._conn.execute(
            "UPDATE alerts SET ai_summary = ? WHERE id = ?", (summary, alert_id)
        )
        self._conn.commit()

    def set_status(self, alert_id: int, status: AlertStatus) -> None:
        self._conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?", (status.value, alert_id)
        )
        self._conn.commit()

    def stats(self, case_id: int | None = None) -> dict:
        where, params = ("WHERE case_id = ?", [case_id]) if case_id is not None else ("", [])
        total = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts {where}", params
        ).fetchone()["n"]
        by_severity = {
            row["severity"]: row["n"]
            for row in self._conn.execute(
                f"SELECT severity, COUNT(*) AS n FROM alerts {where} GROUP BY severity", params
            )
        }
        by_rule = {
            row["rule_id"]: row["n"]
            for row in self._conn.execute(
                f"SELECT rule_id, COUNT(*) AS n FROM alerts {where} GROUP BY rule_id", params
            )
        }
        sources = self._conn.execute(
            f"SELECT COUNT(DISTINCT src) AS n FROM alerts "
            f"{where + ' AND' if where else 'WHERE'} src IS NOT NULL",
            params,
        ).fetchone()["n"]
        triaged = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts "
            f"{where + ' AND' if where else 'WHERE'} ai_summary IS NOT NULL",
            params,
        ).fetchone()["n"]
        return {
            "total": total,
            "by_severity": by_severity,
            "by_rule": by_rule,
            "sources": sources,
            "triaged": triaged,
            "top_hosts": self._top_hosts(case_id),
            "top_ports": self._top_ports(case_id),
        }

    def _top_hosts(self, case_id: int | None, limit: int = 8) -> list[dict]:
        """Hosts ranked by involvement: a source hit weighs more than a target
        hit and scales with severity, matching the AI digest scoring."""
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4, "triaged": 1}
        scores: dict[str, dict] = {}
        clause = "WHERE case_id = ?" if case_id is not None else ""
        params = [case_id] if case_id is not None else []
        for row in self._conn.execute(
            f"SELECT src, dst, severity FROM alerts {clause}", params
        ):
            weight = rank.get(row["severity"], 1)
            if row["src"]:
                entry = scores.setdefault(row["src"], {"host": row["src"], "score": 0, "alerts": 0})
                entry["score"] += 1 + weight
                entry["alerts"] += 1
            if row["dst"]:
                entry = scores.setdefault(row["dst"], {"host": row["dst"], "score": 0, "alerts": 0})
                entry["score"] += 1
        ranked = sorted(scores.values(), key=lambda e: e["score"], reverse=True)
        return ranked[:limit]

    def _top_ports(self, case_id: int | None, limit: int = 8) -> list[dict]:
        clause = "WHERE dst_port IS NOT NULL"
        params: list = []
        if case_id is not None:
            clause += " AND case_id = ?"
            params.append(case_id)
        rows = self._conn.execute(
            f"SELECT dst_port AS port, COUNT(*) AS alerts FROM alerts {clause} "
            f"GROUP BY dst_port ORDER BY alerts DESC, dst_port LIMIT ?",
            [*params, limit],
        ).fetchall()
        return [{"port": r["port"], "alerts": r["alerts"]} for r in rows]

    # -- settings (key/value) ----------------------------------------------------

    def get_setting(self, key: str, default=None):
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return json.loads(row["value"]) if row else default

    def set_setting(self, key: str, value) -> None:
        self._conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )
        self._conn.commit()

    def disabled_rules(self) -> set[str]:
        return set(self.get_setting("disabled_rules", []))

    def set_rule_disabled(self, rule_id: str, disabled: bool) -> set[str]:
        current = self.disabled_rules()
        current.add(rule_id) if disabled else current.discard(rule_id)
        self.set_setting("disabled_rules", sorted(current))
        return current

    def timeline(self, buckets: int = 30, case_id: int | None = None) -> dict:
        """Alert counts bucketed over the stored alerts' event-time span."""
        where, params = ("WHERE case_id = ?", [case_id]) if case_id is not None else ("", [])
        row = self._conn.execute(
            f"SELECT MIN(ts) AS lo, MAX(ts) AS hi, COUNT(*) AS n FROM alerts {where}", params
        ).fetchone()
        if not row["n"]:
            return {"start": None, "end": None, "buckets": []}
        lo, hi = row["lo"], row["hi"]
        width = max((hi - lo) / buckets, 1e-9)
        out = [
            {"start": lo + i * width, "end": lo + (i + 1) * width, "count": 0, "by_severity": {}}
            for i in range(buckets)
        ]
        for alert in self._conn.execute(f"SELECT ts, severity FROM alerts {where}", params):
            bucket = out[min(int((alert["ts"] - lo) / width), buckets - 1)]
            bucket["count"] += 1
            bucket["by_severity"][alert["severity"]] = (
                bucket["by_severity"].get(alert["severity"], 0) + 1
            )
        return {"start": lo, "end": hi, "buckets": out}

    def host_summary(self, ip: str, case_id: int | None = None) -> dict:
        """Everything stored about one host, for the host drawer/CLI."""
        alerts = self.list(host=ip, case_id=case_id, limit=200)
        as_src = [a for a in alerts if a.src == ip]
        as_dst = [a for a in alerts if a.dst == ip]
        return {
            "ip": ip,
            "alerts_as_source": len(as_src),
            "alerts_as_target": len(as_dst),
            "rules": sorted({a.rule_id for a in alerts}),
            "first_seen": min((a.ts for a in alerts), default=None),
            "last_seen": max((a.last_seen for a in alerts), default=None),
            "alerts": [a.to_dict() for a in alerts[:50]],
        }

    # -- case repository ----------------------------------------------------------

    def create_case(self, case: Case) -> Case:
        cur = self._conn.execute(
            """
            INSERT INTO cases (name, source_kind, source, status, pcap_sha256,
                               pcap_size, packet_count, events_processed,
                               start_ts, end_ts, error, notes, ai_report, ai_report_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case.name,
                case.source_kind,
                case.source,
                case.status.value,
                case.pcap_sha256,
                case.pcap_size,
                case.packet_count,
                case.events_processed,
                case.start_ts,
                case.end_ts,
                case.error,
                case.notes,
                case.ai_report,
                case.ai_report_at,
            ),
        )
        self._conn.commit()
        case.id = cur.lastrowid
        created = self.get_case(case.id)
        case.created_at = created.created_at if created else ""
        return case

    def get_case(self, case_id: int) -> Case | None:
        row = self._conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        return self._row_to_case(row) if row else None

    def latest_case(self) -> Case | None:
        row = self._conn.execute("SELECT * FROM cases ORDER BY id DESC LIMIT 1").fetchone()
        return self._row_to_case(row) if row else None

    def list_cases(self, include_archived: bool = True, limit: int = 100) -> list[Case]:
        query = "SELECT * FROM cases"
        if not include_archived:
            query += " WHERE status != 'archived'"
        query += " ORDER BY id DESC LIMIT ?"
        rows = self._conn.execute(query, (limit,)).fetchall()
        return [self._row_to_case(row) for row in rows]

    def update_case_progress(self, case_id: int, events_processed: int) -> None:
        self._conn.execute(
            "UPDATE cases SET events_processed = ? WHERE id = ?", (events_processed, case_id)
        )
        self._conn.commit()

    def finalize_case(
        self,
        case_id: int,
        status: CaseStatus,
        events_processed: int,
        packet_count: int | None = None,
        start_ts: float | None = None,
        end_ts: float | None = None,
        error: str | None = None,
    ) -> None:
        self._conn.execute(
            """
            UPDATE cases SET status = ?, events_processed = ?, packet_count = ?,
                             start_ts = ?, end_ts = ?, error = ?
            WHERE id = ?
            """,
            (status.value, events_processed, packet_count, start_ts, end_ts, error, case_id),
        )
        self._conn.commit()

    def set_case_status(self, case_id: int, status: CaseStatus) -> None:
        self._conn.execute(
            "UPDATE cases SET status = ? WHERE id = ?", (status.value, case_id)
        )
        self._conn.commit()

    def set_case_notes(self, case_id: int, notes: str) -> None:
        self._conn.execute("UPDATE cases SET notes = ? WHERE id = ?", (notes, case_id))
        self._conn.commit()

    def set_case_report(self, case_id: int, report: str) -> None:
        self._conn.execute(
            "UPDATE cases SET ai_report = ?, ai_report_at = datetime('now') WHERE id = ?",
            (report, case_id),
        )
        self._conn.commit()

    def delete_case(self, case_id: int) -> int:
        """Delete a case and its alerts; returns deleted alert count."""
        n = self._conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE case_id = ?", (case_id,)
        ).fetchone()["n"]
        self._conn.execute("DELETE FROM alerts WHERE case_id = ?", (case_id,))
        self._conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        self._conn.commit()
        return n

    def clear(self) -> None:
        """Wipe all alerts and cases (fresh workspace)."""
        self._conn.execute("DELETE FROM alerts")
        self._conn.execute("DELETE FROM cases")
        self._conn.commit()

    def case_alert_count(self, case_id: int) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE case_id = ?", (case_id,)
        ).fetchone()["n"]

    def close(self) -> None:
        self._conn.close()

    # -- row mapping ----------------------------------------------------------------

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            ts=row["ts"],
            rule_id=row["rule_id"],
            severity=Severity(row["severity"]),
            confidence=row["confidence"],
            title=row["title"],
            src=row["src"],
            dst=row["dst"],
            evidence=json.loads(row["evidence"]),
            count=row["count"],
            status=AlertStatus(row["status"]),
            ai_summary=row["ai_summary"],
            case_id=row["case_id"],
            last_ts=row["last_ts"],
            protocol=row["protocol"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            reason=row["reason"] or "",
            packet_count=row["packet_count"],
            byte_count=row["byte_count"],
        )

    def _row_to_case(self, row: sqlite3.Row) -> Case:
        return Case(
            id=row["id"],
            name=row["name"],
            source_kind=row["source_kind"],
            source=row["source"],
            status=CaseStatus(row["status"]),
            created_at=row["created_at"],
            pcap_sha256=row["pcap_sha256"],
            pcap_size=row["pcap_size"],
            packet_count=row["packet_count"],
            events_processed=row["events_processed"],
            alert_count=self.case_alert_count(row["id"]),
            start_ts=row["start_ts"],
            end_ts=row["end_ts"],
            error=row["error"],
            notes=row["notes"],
            ai_report=row["ai_report"],
            ai_report_at=row["ai_report_at"],
        )
