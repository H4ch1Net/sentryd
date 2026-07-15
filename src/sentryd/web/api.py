"""FastAPI backend for the web UI.

JSON API over the same AlertStore the CLI and dashboard use, plus the static
single-page frontend. A fresh store connection is opened per request —
sqlite connections are cheap and thread-bound, and uvicorn serves requests
from a thread pool.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles

from sentryd import __version__
from sentryd.storage.store import AlertStore

STATIC_DIR = Path(__file__).parent / "static"


def create_app(db_path: Path) -> FastAPI:
    app = FastAPI(title="sentryd", version=__version__)

    def with_store(fn):
        with AlertStore(db_path) as store:
            return fn(store)

    @app.get("/api/alerts")
    def list_alerts(
        severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
        rule: str | None = None,
        status: str | None = Query(None, pattern="^(new|triaged|dismissed)$"),
        limit: int = Query(100, ge=1, le=1000),
    ) -> dict:
        alerts = with_store(
            lambda s: s.list(severity=severity, rule_id=rule, status=status, limit=limit)
        )
        return {"alerts": [a.to_dict() for a in alerts]}

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: int) -> dict:
        alert = with_store(lambda s: s.get(alert_id))
        if alert is None:
            raise HTTPException(status_code=404, detail=f"no alert with id {alert_id}")
        return alert.to_dict()

    @app.get("/api/stats")
    def stats() -> dict:
        return with_store(lambda s: s.stats())

    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
    return app
