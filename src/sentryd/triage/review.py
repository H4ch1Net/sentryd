"""Overall case review orchestration: digest -> prompt -> stored report."""

from __future__ import annotations

import logging

from sentryd.core.cases import Case
from sentryd.core.correlate import correlate
from sentryd.storage.store import AlertStore
from sentryd.triage.base import TriageProvider
from sentryd.triage.digest import build_case_digest
from sentryd.triage.prompts import build_case_messages

log = logging.getLogger(__name__)


def generate_case_review(
    store: AlertStore,
    case: Case,
    provider: TriageProvider,
    force: bool = False,
) -> str | None:
    """Produce and persist the overall AI review for a case.

    Returns the report markdown, the cached one when present (unless force),
    or None when the provider is unavailable or the completion failed.
    Detection data is never touched; failure leaves the case unannotated.
    """
    if case.ai_report and not force:
        return case.ai_report
    if not provider.available:
        return None

    alerts = store.list(case_id=case.id, limit=500)
    digest = build_case_digest(case, alerts, correlate(alerts))
    report = provider.generate(build_case_messages(digest))
    if report is None:
        log.warning("case review failed for case %s", case.id)
        return None
    store.set_case_report(case.id, report)
    return report
