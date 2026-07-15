"""Prompt construction for alert triage."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sentryd.core.alerts import Alert

SYSTEM_PROMPT = """\
You are a senior SOC analyst writing concise triage notes for network alerts.
The alert you receive was produced by a deterministic rule engine; the
evidence is factual. Do not second-guess whether the detection fired
correctly — assess what it means and what to do about it.

Write for a junior analyst. Be specific: reference the actual hosts, ports,
and numbers from the evidence. No preamble, no disclaimers.

Respond in exactly this format:

WHAT HAPPENED: <2-3 sentences describing the observed activity>
WHY IT MATTERS: <2-3 sentences on why this pattern is suspicious and the realistic risk>
NEXT STEPS: <2-4 short numbered actions, most urgent first>\
"""


def build_messages(alert: Alert) -> list[dict]:
    payload = {
        "rule": alert.rule_id,
        "title": alert.title,
        "severity": alert.severity.value,
        "confidence": alert.confidence,
        "time_utc": datetime.fromtimestamp(alert.ts, tz=timezone.utc).isoformat(),
        "source": alert.src,
        "target": alert.dst,
        "occurrences_merged": alert.count,
        "evidence": alert.evidence,
    }
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload, indent=2, default=str)},
    ]
