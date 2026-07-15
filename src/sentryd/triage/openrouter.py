"""OpenRouter-backed triage provider (OpenAI-compatible chat completions)."""

from __future__ import annotations

import logging

import httpx

from sentryd.core.alerts import Alert
from sentryd.triage.base import TriageResult
from sentryd.triage.prompts import build_messages

log = logging.getLogger(__name__)

API_URL = "https://openrouter.ai/api/v1/chat/completions"


class OpenRouterTriage:
    name = "openrouter"
    available = True

    def __init__(
        self,
        api_key: str,
        model: str,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.model = model
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "X-Title": "sentryd",
        }
        self._client = client or httpx.Client(timeout=timeout)

    def triage(self, alert: Alert) -> TriageResult | None:
        try:
            response = self._client.post(
                API_URL,
                headers=self._headers,
                json={
                    "model": self.model,
                    "messages": build_messages(alert),
                    "max_tokens": 500,
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"].strip()
            if not content:
                raise ValueError("empty completion")
            return TriageResult(summary=content, model=data.get("model", self.model))
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            # Triage is best-effort by contract: log and leave the alert bare.
            log.warning("AI triage failed for alert %s: %s", alert.id, exc)
            return None
