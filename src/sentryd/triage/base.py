"""AI triage provider interface.

The triage layer annotates alerts that already exist — it is optional by
design. Detection never waits on it, and every failure mode (no API key,
network down, provider error) degrades to "no writeup", never to a broken
alert. ``create_provider()`` encodes that: no key means NullTriage.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from sentryd.core.alerts import Alert

API_KEY_ENV = "OPENROUTER_API_KEY"
MODEL_ENV = "SENTRYD_TRIAGE_MODEL"
DEFAULT_MODEL = "openai/gpt-4o-mini"


@dataclass(frozen=True)
class TriageResult:
    summary: str
    model: str


@runtime_checkable
class TriageProvider(Protocol):
    name: str
    available: bool  # False = triage is a guaranteed no-op (no key, disabled)

    def triage(self, alert: Alert) -> TriageResult | None:
        """Produce an analyst writeup for the alert, or None on any failure."""
        ...

    def generate(self, messages: list[dict]) -> str | None:
        """Run one chat completion; None on any failure. Used for case-level
        reviews and any future prompt without changing the provider."""
        ...


class NullTriage:
    """The no-op provider used when AI triage is unavailable or disabled."""

    name = "none"
    available = False

    def triage(self, alert: Alert) -> TriageResult | None:
        return None

    def generate(self, messages: list[dict]) -> str | None:
        return None


def create_provider() -> TriageProvider:
    """Build the configured provider from the environment (.env is honored).

    Missing API key is not an error — it selects NullTriage, keeping the
    whole detection pipeline fully functional without any AI dependency.
    """
    from dotenv import load_dotenv

    load_dotenv()
    api_key = os.environ.get(API_KEY_ENV, "").strip()
    if not api_key:
        return NullTriage()

    from sentryd.triage.openrouter import OpenRouterTriage

    return OpenRouterTriage(
        api_key=api_key,
        model=os.environ.get(MODEL_ENV, "").strip() or DEFAULT_MODEL,
    )
