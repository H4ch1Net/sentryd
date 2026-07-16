from conftest import make_event

from sentryd.core.alerts import Severity
from sentryd.rules.port_scan import PortScanRule


def run_events(rule, events):
    alerts = []
    for event in events:
        alerts += rule.process(event)
    return alerts


def scan_events(n_ports, src="10.0.0.66", target="10.0.0.9", start=100.0, interval=0.1):
    return [
        make_event(ts=start + i * interval, src_ip=src, dst_ip=target, dst_port=1000 + i)
        for i in range(n_ports)
    ]


def test_vertical_scan_fires_one_alert():
    rule = PortScanRule(window_seconds=10, min_distinct_targets=15)
    alerts = run_events(rule, scan_events(30))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "port_scan"
    assert alert.severity == Severity.HIGH
    assert alert.src == "10.0.0.66"
    assert alert.dst == "10.0.0.9"
    assert alert.evidence["scan_type"] == "vertical"
    assert alert.evidence["distinct_targets"] == 15  # fires the moment threshold hits
    assert 0 < alert.confidence <= 0.95


def test_below_threshold_is_silent():
    rule = PortScanRule(window_seconds=10, min_distinct_targets=15)
    assert run_events(rule, scan_events(14)) == []


def test_slow_scan_outside_window_is_silent():
    rule = PortScanRule(window_seconds=10, min_distinct_targets=15)
    # 30 ports but spread over 10 minutes, never 15 within any 10s window.
    assert run_events(rule, scan_events(30, interval=20.0)) == []


def test_established_traffic_does_not_count():
    rule = PortScanRule(window_seconds=10, min_distinct_targets=15)
    events = [
        make_event(ts=100 + i * 0.1, dst_port=1000 + i, tcp_flags=flags)
        for i in range(30)
        for flags in ("SA", "A", "PA", "FA")
    ]
    assert run_events(rule, events) == []


def test_horizontal_sweep_detected():
    rule = PortScanRule(window_seconds=10, min_distinct_targets=15)
    events = [
        make_event(ts=100 + i * 0.1, src_ip="10.0.0.66", dst_ip=f"10.0.1.{i}", dst_port=445)
        for i in range(20)
    ]
    alerts = run_events(rule, events)
    assert len(alerts) == 1
    assert alerts[0].evidence["scan_type"] == "horizontal"
    assert alerts[0].dst is None  # many targets, no single victim host
    assert alerts[0].evidence["sample_ports"] == [445]


def test_sustained_scan_refires_at_most_once_per_window():
    rule = PortScanRule(window_seconds=10, min_distinct_targets=15)
    # 300 ports over 30 seconds: threshold stays tripped the whole time.
    alerts = run_events(rule, scan_events(300, interval=0.1))
    assert 1 <= len(alerts) <= 3


def test_second_host_scan_not_swallowed_by_suppression():
    # Regression: refire suppression is keyed to the alert identity, so a
    # scan that moves to a NEW victim inside the window still alerts.
    rule = PortScanRule(window_seconds=10, min_distinct_targets=15)
    first = scan_events(20, target="10.0.0.9", start=100.0)
    second = scan_events(20, target="10.0.0.10", start=103.0)

    alerts = run_events(rule, first + second)

    assert len(alerts) == 2
    assert alerts[0].dst == "10.0.0.9"
    assert alerts[1].dst is None  # window now spans both hosts


def test_idle_sources_are_swept():
    # Spoofed-source floods must not grow per-source state forever.
    rule = PortScanRule(window_seconds=10, min_distinct_targets=15)
    for i in range(50):
        rule.process(make_event(ts=100.0, src_ip=f"10.1.{i}.1", dst_port=80))
    assert len(rule._windows) == 50

    rule.process(make_event(ts=200.0, src_ip="10.9.9.9", dst_port=80))

    assert len(rule._windows) == 1  # everything idle past the window is gone


def test_sources_tracked_independently():
    rule = PortScanRule(window_seconds=10, min_distinct_targets=15)
    # Two sources each probe 10 ports, 20 total, but neither crosses 15.
    events = scan_events(10, src="10.0.0.1") + scan_events(10, src="10.0.0.2")
    assert run_events(rule, events) == []
