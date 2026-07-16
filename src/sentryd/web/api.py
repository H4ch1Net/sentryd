"""FastAPI backend: REST API plus the static single-page frontend.

Interactive OpenAPI docs are served at /docs. A fresh store connection is
opened per request (sqlite handles are thread-bound and cheap); PCAP replay
runs in a daemon thread and publishes progress through the case row, so
status polling is just a case read.
"""

from __future__ import annotations

import re
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sentryd import __version__
from sentryd.config import load_config
from sentryd.core.cases import CaseStatus
from sentryd.core.correlate import correlate, investigation_hint, related_alerts
from sentryd.export import alerts_to_csv, alerts_to_json, case_report_markdown, case_to_json
from sentryd.runner import create_pending_case, run_case
from sentryd.rules.base import RULE_REGISTRY
from sentryd.sources.pcap import PcapFileSource
from sentryd.storage.store import AlertStore
from sentryd.triage.base import create_provider
from sentryd.triage.review import generate_case_review

STATIC_DIR = Path(__file__).parent / "static"
ALLOWED_PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
MAX_UPLOAD_BYTES = 200 * 1024 * 1024

NO_AI_DETAIL = (
    "AI triage is not configured. Set OPENROUTER_API_KEY in the server's "
    "environment or .env file. Detection and evidence work without it."
)


class ReplayRequest(BaseModel):
    path: str
    name: str | None = None


class NotesRequest(BaseModel):
    notes: str


class StatusRequest(BaseModel):
    status: str


_STATUS_PATTERN = "^(new|confirmed|false_positive|expected|ignored|dismissed|triaged)$"


def _safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name) or "upload.pcap"


def create_app(db_path: Path, uploads_dir: Path | None = None) -> FastAPI:
    app = FastAPI(
        title="sentryd",
        version=__version__,
        description="Rule-based network anomaly detection with optional AI triage.",
    )
    uploads = uploads_dir or Path(db_path).parent / "uploads"

    def with_store(fn):
        with AlertStore(db_path) as store:
            return fn(store)

    def _get_case_or_404(store: AlertStore, case_id: int):
        case = store.get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"no case with id {case_id}")
        return case

    def _start_background_replay(pcap_path: Path, name: str | None) -> dict:
        case = create_pending_case(
            db_path, source_kind="pcap", source_label=str(pcap_path), name=name
        )

        def worker() -> None:
            try:
                run_case(
                    db_path,
                    PcapFileSource(pcap_path),
                    source_kind="pcap",
                    source_label=str(pcap_path),
                    case_id=case.id,
                )
            except Exception:
                pass  # run_case already recorded the failure on the case row

        threading.Thread(target=worker, daemon=True, name=f"replay-case-{case.id}").start()
        return case.to_dict()

    # -- alerts ---------------------------------------------------------------

    @app.get("/api/alerts")
    def list_alerts(
        severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
        rule: str | None = None,
        status: str | None = Query(None, pattern=_STATUS_PATTERN),
        case: int | None = None,
        host: str | None = None,
        limit: int = Query(100, ge=1, le=1000),
    ) -> dict:
        alerts = with_store(
            lambda s: s.list(
                severity=severity, rule_id=rule, status=status,
                case_id=case, host=host, limit=limit,
            )
        )
        return {"alerts": [a.to_dict() for a in alerts]}

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: int) -> dict:
        def fetch(store: AlertStore) -> dict:
            alert = store.get(alert_id)
            if alert is None:
                raise HTTPException(status_code=404, detail=f"no alert with id {alert_id}")
            return {
                **alert.to_dict(),
                "related": [r.to_dict() for r in related_alerts(store, alert)],
                "investigation_hint": investigation_hint(alert),
            }

        return with_store(fetch)

    @app.post("/api/alerts/{alert_id}/status")
    def set_alert_status(alert_id: int, request: StatusRequest) -> dict:
        import re

        from sentryd.core.alerts import AlertStatus

        if not re.match(_STATUS_PATTERN, request.status):
            raise HTTPException(status_code=422, detail=f"invalid status {request.status!r}")

        def apply(store: AlertStore) -> dict:
            if store.get(alert_id) is None:
                raise HTTPException(status_code=404, detail=f"no alert with id {alert_id}")
            store.set_status(alert_id, AlertStatus(request.status))
            return store.get(alert_id).to_dict()

        return with_store(apply)

    @app.post("/api/alerts/{alert_id}/explain")
    def explain_alert(alert_id: int, force: bool = False) -> dict:
        def explain(store: AlertStore) -> dict:
            alert = store.get(alert_id)
            if alert is None:
                raise HTTPException(status_code=404, detail=f"no alert with id {alert_id}")
            if alert.ai_summary and not force:
                return alert.to_dict()
            provider = create_provider()
            if not provider.available:
                raise HTTPException(status_code=503, detail=NO_AI_DETAIL)
            result = provider.triage(alert)
            if result is None:
                raise HTTPException(status_code=502, detail="AI request failed; try again")
            store.set_ai_summary(alert_id, result.summary)
            return store.get(alert_id).to_dict()

        return with_store(explain)

    # -- stats ----------------------------------------------------------------

    @app.get("/api/stats")
    def stats(case: int | None = None) -> dict:
        return with_store(lambda s: s.stats(case_id=case))

    @app.get("/api/timeline")
    def timeline(buckets: int = Query(30, ge=4, le=120), case: int | None = None) -> dict:
        return with_store(lambda s: s.timeline(buckets, case_id=case))

    @app.get("/api/hosts/{ip}")
    def host(ip: str, case: int | None = None) -> dict:
        return with_store(lambda s: s.host_summary(ip, case_id=case))

    @app.get("/api/rules")
    def rules() -> dict:
        config = load_config(None)
        out = []
        for rule_id in sorted(RULE_REGISTRY):
            section = dict(config.get("rules", {}).get(rule_id) or {})
            enabled = section.pop("enabled", True)
            out.append({"rule_id": rule_id, "enabled": enabled, "config": section})
        return {"rules": out, "signatures": config.get("signatures", [])}

    # -- pcap intake -------------------------------------------------------------

    @app.post("/api/pcaps/upload", status_code=202)
    async def upload_pcap(file: UploadFile = File(...), name: str | None = None) -> dict:
        suffix = Path(file.filename or "").suffix.lower()
        if suffix not in ALLOWED_PCAP_SUFFIXES:
            raise HTTPException(
                status_code=422,
                detail=f"unsupported file type {suffix or '(none)'}; "
                f"expected one of: {', '.join(sorted(ALLOWED_PCAP_SUFFIXES))}",
            )
        uploads.mkdir(parents=True, exist_ok=True)
        safe = _safe_filename(file.filename or "upload.pcap")
        dest = uploads / f"{uuid.uuid4().hex[:8]}_{safe}"
        written = 0
        with dest.open("wb") as out:
            while chunk := await file.read(1 << 20):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    out.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit",
                    )
                out.write(chunk)
        if written == 0:
            dest.unlink(missing_ok=True)
            raise HTTPException(status_code=422, detail="uploaded file is empty")
        return {"case": _start_background_replay(dest, name or safe)}

    @app.post("/api/replay", status_code=202)
    def replay(request: ReplayRequest) -> dict:
        path = Path(request.path)
        if not path.is_file():
            raise HTTPException(status_code=404, detail=f"no such file on server: {path}")
        return {"case": _start_background_replay(path, request.name)}

    # -- cases ---------------------------------------------------------------------

    @app.get("/api/cases")
    def list_cases(include_archived: bool = True) -> dict:
        cases = with_store(lambda s: s.list_cases(include_archived=include_archived))
        return {"cases": [c.to_dict() for c in cases]}

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: int) -> dict:
        def fetch(store: AlertStore) -> dict:
            case = _get_case_or_404(store, case_id)
            alerts = store.list(case_id=case_id, limit=500)
            return {
                "case": case.to_dict(),
                "clusters": [c.to_dict() for c in correlate(alerts)],
                "stats": store.stats(case_id=case_id),
            }

        return with_store(fetch)

    @app.get("/api/cases/{case_id}/status")
    def case_status(case_id: int) -> dict:
        def fetch(store: AlertStore) -> dict:
            case = _get_case_or_404(store, case_id)
            return {
                "id": case.id,
                "status": case.status.value,
                "events_processed": case.events_processed,
                "alert_count": case.alert_count,
                "error": case.error,
            }

        return with_store(fetch)

    @app.post("/api/cases/{case_id}/archive")
    def archive_case(case_id: int) -> dict:
        def archive(store: AlertStore) -> dict:
            _get_case_or_404(store, case_id)
            store.set_case_status(case_id, CaseStatus.ARCHIVED)
            return store.get_case(case_id).to_dict()

        return with_store(archive)

    @app.delete("/api/cases/{case_id}")
    def delete_case(case_id: int) -> dict:
        def delete(store: AlertStore) -> dict:
            _get_case_or_404(store, case_id)
            deleted = store.delete_case(case_id)
            return {"deleted_case": case_id, "deleted_alerts": deleted}

        return with_store(delete)

    @app.post("/api/cases/{case_id}/notes")
    def set_notes(case_id: int, request: NotesRequest) -> dict:
        def save(store: AlertStore) -> dict:
            _get_case_or_404(store, case_id)
            store.set_case_notes(case_id, request.notes)
            return store.get_case(case_id).to_dict()

        return with_store(save)

    @app.post("/api/cases/{case_id}/triage")
    def triage_case(case_id: int, force: bool = False) -> dict:
        def review(store: AlertStore) -> dict:
            case = _get_case_or_404(store, case_id)
            if case.ai_report and not force:
                return case.to_dict()
            provider = create_provider()
            if not provider.available:
                raise HTTPException(status_code=503, detail=NO_AI_DETAIL)
            report = generate_case_review(store, case, provider, force=force)
            if report is None:
                raise HTTPException(status_code=502, detail="AI request failed; try again")
            return store.get_case(case_id).to_dict()

        return with_store(review)

    @app.get("/api/cases/{case_id}/report")
    def case_report(case_id: int, format: str = Query("md", pattern="^(md|json)$")):
        def build(store: AlertStore):
            case = _get_case_or_404(store, case_id)
            alerts = store.list(case_id=case_id, limit=1000)
            clusters = correlate(alerts)
            if format == "json":
                return Response(
                    case_to_json(case, alerts, clusters),
                    media_type="application/json",
                    headers={
                        "Content-Disposition": f'attachment; filename="case-{case_id}.json"'
                    },
                )
            return PlainTextResponse(
                case_report_markdown(case, alerts, clusters),
                media_type="text/markdown",
                headers={
                    "Content-Disposition": f'attachment; filename="case-{case_id}-report.md"'
                },
            )

        return with_store(build)

    # -- exports ------------------------------------------------------------------

    @app.get("/api/export/alerts")
    def export_alerts(
        format: str = Query("json", pattern="^(json|csv)$"),
        case: int | None = None,
        severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
        rule: str | None = None,
        limit: int = Query(1000, ge=1, le=10000),
    ):
        alerts = with_store(
            lambda s: s.list(severity=severity, rule_id=rule, case_id=case, limit=limit)
        )
        if format == "csv":
            return PlainTextResponse(
                alerts_to_csv(alerts),
                media_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="alerts.csv"'},
            )
        return Response(
            alerts_to_json(alerts),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="alerts.json"'},
        )

    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
    return app
