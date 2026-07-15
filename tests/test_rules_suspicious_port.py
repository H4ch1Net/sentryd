from conftest import make_event

from sentryd.core.alerts import Severity
from sentryd.rules.suspicious_port import PortWatch, SuspiciousPortRule

WATCHLIST = [
    PortWatch(port=4444, label="Metasploit default handler", severity=Severity.HIGH, confidence=0.8),
    PortWatch(port=23, label="Telnet", severity=Severity.MEDIUM),
]


def test_syn_to_watched_port_alerts():
    rule = SuspiciousPortRule(WATCHLIST)
    alerts = rule.process(make_event(dst_port=4444, tcp_flags="S"))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "suspicious_port"
    assert alert.severity == Severity.HIGH
    assert alert.confidence == 0.8
    assert alert.evidence["label"] == "Metasploit default handler"
    assert alert.src == "10.0.0.5"
    assert alert.dst == "10.0.0.9"


def test_udp_to_watched_port_alerts():
    rule = SuspiciousPortRule(WATCHLIST)
    alerts = rule.process(make_event(protocol="udp", dst_port=4444))
    assert len(alerts) == 1
    assert alerts[0].evidence["protocol"] == "udp"


def test_midstream_tcp_packet_ignored():
    rule = SuspiciousPortRule(WATCHLIST)
    assert rule.process(make_event(dst_port=4444, tcp_flags="PA")) == []
    assert rule.process(make_event(dst_port=4444, tcp_flags="SA")) == []


def test_unwatched_port_silent():
    rule = SuspiciousPortRule(WATCHLIST)
    assert rule.process(make_event(dst_port=443, tcp_flags="S")) == []


def test_from_config():
    rule = SuspiciousPortRule.from_config(
        {
            "ports": [
                {"port": 31337, "label": "Back Orifice", "severity": "high", "note": "historic backdoor"},
                {"port": 9001, "label": "Tor"},  # defaults apply
            ]
        }
    )
    alerts = rule.process(make_event(dst_port=31337, tcp_flags="S"))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].evidence["note"] == "historic backdoor"

    alerts = rule.process(make_event(dst_port=9001, tcp_flags="S"))
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].confidence == 0.6
