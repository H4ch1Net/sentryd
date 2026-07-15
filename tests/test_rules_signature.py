import pytest
from conftest import make_event

from sentryd.core.alerts import Severity
from sentryd.rules.base import build_rules
from sentryd.rules.signature import Signature, SignatureRule


def sig_rule(**spec_overrides):
    spec = {
        "id": "sig-test",
        "title": "test signature",
        **spec_overrides,
    }
    return SignatureRule([Signature.from_dict(spec)])


def test_port_and_flags_match():
    rule = sig_rule(
        severity="high",
        match={"protocol": "tcp", "dst_ports": [3389], "tcp_flags": "S", "tcp_flags_not": "A"},
    )
    alerts = rule.process(make_event(dst_port=3389, tcp_flags="S"))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].evidence["signature_id"] == "sig-test"
    assert alerts[0].key == "sig-test"

    assert rule.process(make_event(dst_port=3389, tcp_flags="SA")) == []  # flags_not
    assert rule.process(make_event(dst_port=443, tcp_flags="S")) == []  # port


def test_port_ranges_expand():
    rule = sig_rule(match={"dst_ports": ["5900-5910"]})
    assert len(rule.process(make_event(dst_port=5905))) == 1
    assert rule.process(make_event(dst_port=5911)) == []


def test_cidr_match():
    rule = sig_rule(match={"src_cidr": "10.20.0.0/16"})
    assert len(rule.process(make_event(src_ip="10.20.5.9"))) == 1
    assert rule.process(make_event(src_ip="10.21.0.1")) == []
    assert rule.process(make_event(src_ip=None)) == []


def test_protocol_match():
    rule = sig_rule(match={"protocol": "udp"})
    assert len(rule.process(make_event(protocol="udp"))) == 1
    assert rule.process(make_event(protocol="tcp")) == []


def test_empty_match_matches_everything():
    rule = sig_rule()
    assert len(rule.process(make_event())) == 1


def test_multiple_signatures_evaluated_independently():
    rule = SignatureRule(
        [
            Signature.from_dict({"id": "a", "title": "syn", "match": {"tcp_flags": "S", "tcp_flags_not": "A"}}),
            Signature.from_dict({"id": "b", "title": "to 443", "match": {"dst_ports": [443]}}),
        ]
    )
    alerts = rule.process(make_event(dst_port=443, tcp_flags="S"))
    assert {a.key for a in alerts} == {"a", "b"}


def test_invalid_signature_rejected():
    with pytest.raises(ValueError, match="'id' and 'title'"):
        Signature.from_dict({"title": "missing id"})
    with pytest.raises(ValueError, match="duplicate"):
        SignatureRule(
            [
                Signature.from_dict({"id": "x", "title": "one"}),
                Signature.from_dict({"id": "x", "title": "two"}),
            ]
        )


def test_build_rules_appends_signature_rule_from_config():
    config = {
        "rules": {"port_scan": {"enabled": True}},
        "signatures": [{"id": "s1", "title": "custom", "match": {"dst_ports": [1234]}}],
    }
    rules = build_rules(config)
    assert {r.rule_id for r in rules} == {"port_scan", "signature"}


def test_build_rules_skips_signature_rule_when_none_configured():
    rules = build_rules({"rules": {"port_scan": {}}, "signatures": []})
    assert {r.rule_id for r in rules} == {"port_scan"}
