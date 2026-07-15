"""SQLite alert persistence — thin repository over stdlib sqlite3, no ORM."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from sentryd.core.alerts import Alert, AlertStatus, Severity

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
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
"""

DEFAULT_DB_PATH = Path("sentryd.db")


class AlertStore:
    """Alert repository. Also usable as an engine sink (emit/update)."""

    def __init__(self, path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    # -- engine sink interface ------------------------------------------------

    def emit(self, alert: Alert) -> None:
        self.insert(alert)

    def update(self, alert: Alert) -> None:
        if alert.id is None:
            return
        self._conn.execute(
            "UPDATE alerts SET count = ?, severity = ?, confidence = ?, evidence = ? WHERE id = ?",
            (alert.count, alert.severity.value, alert.confidence, alert.evidence_json(), alert.id),
        )
        self._conn.commit()

    # -- repository -----------------------------------------------------------

    def insert(self, alert: Alert) -> Alert:
        cur = self._conn.execute(
            """
            INSERT INTO alerts (ts, rule_id, severity, confidence, title, src, dst,
                                evidence, count, status, ai_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_alert(row) for row in rows]

    def set_ai_summary(self, alert_id: int, summary: str) -> None:
        self._conn.execute(
            "UPDATE alerts SET ai_summary = ?, status = ? WHERE id = ?",
            (summary, AlertStatus.TRIAGED.value, alert_id),
        )
        self._conn.commit()

    def set_status(self, alert_id: int, status: AlertStatus) -> None:
        self._conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?", (status.value, alert_id)
        )
        self._conn.commit()

    def stats(self) -> dict:
        total = self._conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        by_severity = {
            row["severity"]: row["n"]
            for row in self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
            )
        }
        by_rule = {
            row["rule_id"]: row["n"]
            for row in self._conn.execute(
                "SELECT rule_id, COUNT(*) AS n FROM alerts GROUP BY rule_id"
            )
        }
        return {"total": total, "by_severity": by_severity, "by_rule": by_rule}

    def close(self) -> None:
        self._conn.close()

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
        )
