"""Triage layer tests. The OpenRouter provider is exercised against a mock
HTTP transport — no network, no real key — and the graceful-degradation
paths (no key, provider errors) are pinned down explicitly.
"""

import httpx
import pytest

from sentryd.core.alerts import Alert, Severity
from sentryd.triage.base import API_KEY_ENV, MODEL_ENV, NullTriage, create_provider
from sentryd.triage.openrouter import OpenRouterTriage
from sentryd.triage.prompts import SYSTEM_PROMPT, build_messages


def sample_alert() -> Alert:
    return Alert(
        id=7,
        rule_id="port_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        title="Port scan: 192.168.1.66 probed 22 ports on 192.168.1.10",
        ts=1700000000.0,
        src="192.168.1.66",
        dst="192.168.1.10",
        evidence={"distinct_targets": 22, "sample_ports": [21, 22, 23]},
    )


def mock_provider(handler) -> OpenRouterTriage:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return OpenRouterTriage(api_key="test-key", model="test/model", client=client)


# -- provider selection --------------------------------------------------------


def test_no_api_key_selects_null_provider(monkeypatch):
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    assert isinstance(create_provider(), NullTriage)


def test_api_key_selects_openrouter(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV, "sk-test")
    monkeypatch.setenv(MODEL_ENV, "some/model")
    provider = create_provider()
    assert isinstance(provider, OpenRouterTriage)
    assert provider.model == "some/model"


def test_null_provider_returns_none():
    assert NullTriage().triage(sample_alert()) is None


# -- prompt construction -------------------------------------------------------


def test_messages_carry_alert_facts():
    messages = build_messages(sample_alert())
    assert messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
    user = messages[1]["content"]
    assert "port_scan" in user
    assert "192.168.1.66" in user
    assert '"distinct_targets": 22' in user


# -- OpenRouter provider -------------------------------------------------------


def test_successful_completion_returns_result():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer test-key"
        return httpx.Response(
            200,
            json={
                "model": "test/model-v2",
                "choices": [{"message": {"content": "WHAT HAPPENED: a scan.\n"}}],
            },
        )

    result = mock_provider(handler).triage(sample_alert())
    assert result is not None
    assert result.summary.startswith("WHAT HAPPENED")
    assert result.model == "test/model-v2"


def test_http_error_degrades_to_none():
    handler = lambda request: httpx.Response(500, json={"error": "boom"})
    assert mock_provider(handler).triage(sample_alert()) is None


def test_malformed_response_degrades_to_none():
    handler = lambda request: httpx.Response(200, json={"unexpected": True})
    assert mock_provider(handler).triage(sample_alert()) is None


def test_empty_completion_degrades_to_none():
    handler = lambda request: httpx.Response(
        200, json={"choices": [{"message": {"content": "   "}}]}
    )
    assert mock_provider(handler).triage(sample_alert()) is None


def test_network_failure_degrades_to_none():
    def handler(request):
        raise httpx.ConnectError("no route to host")

    assert mock_provider(handler).triage(sample_alert()) is None
