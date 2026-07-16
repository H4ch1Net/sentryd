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


CASE_SYSTEM_PROMPT = """\
You are a senior SOC analyst writing an overall incident review of one
analysis case. You receive a structured digest produced by a deterministic
rule engine: alert metadata, correlated activity clusters, top hosts/ports,
and a timeline. The digest is factual; ground every statement in it and
reference alert ids like [#12] where relevant. Do not invent hosts, ports,
or events that are not in the digest. If the evidence is thin or looks
benign, say so plainly.

Write for an analyst who has not looked at this capture yet. Respond in
markdown with EXACTLY these level-2 headings, in this order:

## Executive summary
2-4 sentences: what happened, how bad, how confident.

## Likely attack chain
The sequence of activity as a short numbered list, mapped to the clusters.
If there is no coherent chain, say so.

## Top suspicious hosts
Bullet per host: role (attacker/victim/unclear), what it did, alert refs.

## Top suspicious ports and services
Bullet per port/service worth attention and why.

## Timeline
Short chronological narrative of the notable activity windows.

## Confidence
One of: high / medium / low, with the single biggest factor.

## What to investigate next
3-6 concrete, prioritized actions.

## Possible false positives
Which alerts could be benign and what would confirm that. If none, say none.\
"""


def build_case_messages(digest: dict) -> list[dict]:
    return [
        {"role": "system", "content": CASE_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(digest, indent=1, default=str)},
    ]


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
