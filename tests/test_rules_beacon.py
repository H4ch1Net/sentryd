import random

from conftest import make_event, tcp_packet

from sentryd.core.alerts import Severity
from sentryd.core.engine import RuleEngine
from sentryd.rules.beacon import BeaconRule
from sentryd.sources.pcap import PcapFileSource


def run_events(rule, events):
    alerts = []
    for event in events:
        alerts += rule.process(event)
    return alerts


def checkins(n, interval=60.0, start=1000.0, jitter=0.0, seed=7, **kwargs):
    """Bare-SYN connection attempts on a clock, each from a fresh source
    port (a new connection per check-in, like most implants)."""
    rng = random.Random(seed)
    defaults = {"src_ip": "10.0.0.5", "dst_ip": "198.51.100.7", "dst_port": 8443}
    events, ts = [], start
    for i in range(n):
        events.append(make_event(ts=ts, src_port=50000 + i, **{**defaults, **kwargs}))
        ts += interval * (1 + rng.uniform(-jitter, jitter))
    return events


# -- fires on machine-timed check-ins -------------------------------------------


def test_regular_tcp_beacon_fires_once():
    rule = BeaconRule()
    alerts = run_events(rule, checkins(20))

    assert len(alerts) == 1  # one alert per established rhythm, not per check-in
    alert = alerts[0]
    assert alert.rule_id == "beacon"
    assert alert.severity == Severity.MEDIUM
    assert (alert.src, alert.dst, alert.dst_port) == ("10.0.0.5", "198.51.100.7", 8443)
    assert alert.ts == 1000.0 + 5 * 60.0  # fires on the 6th contact
    assert alert.evidence["contacts"] == 6
    assert alert.evidence["mean_interval_seconds"] == 60.0
    assert alert.evidence["jitter_cv"] == 0.0
    assert alert.key == "tcp/8443"
    assert "every ~60s" in alert.title
    assert alert.reason


def test_jittered_beacon_within_threshold_fires():
    # +/-20% uniform jitter (a common implant setting) has CV ~0.12.
    alerts = run_events(BeaconRule(), checkins(20, jitter=0.20))
    assert len(alerts) == 1
    assert alerts[0].evidence["jitter_cv"] <= 0.15


def test_udp_beacon_fires():
    events = [
        make_event(ts=1000.0 + i * 30, protocol="udp", src_ip="10.0.0.5",
                   dst_ip="203.0.113.9", src_port=40000, dst_port=9999)
        for i in range(8)
    ]
    alerts = run_events(BeaconRule(), events)
    assert len(alerts) == 1
    assert alerts[0].protocol == "udp"


def test_multi_datagram_checkins_fold_into_one_contact():
    events = []
    for i in range(8):
        base = 1000.0 + i * 30
        events += [
            make_event(ts=base + offset, protocol="udp", src_ip="10.0.0.5",
                       dst_ip="203.0.113.9", src_port=40000, dst_port=9999)
            for offset in (0.0, 0.05, 0.1)
        ]
    alerts = run_events(BeaconRule(), events)
    assert len(alerts) == 1
    assert alerts[0].evidence["mean_interval_seconds"] == 30.0


def test_syn_retransmissions_do_not_break_the_rhythm():
    events = []
    for event in checkins(8):
        events.append(event)
        # the same connection attempt retried 1s and 3s later
        events.append(make_event(ts=event.ts + 1.0, src_ip=event.src_ip, dst_ip=event.dst_ip,
                                 src_port=event.src_port, dst_port=event.dst_port))
        events.append(make_event(ts=event.ts + 3.0, src_ip=event.src_ip, dst_ip=event.dst_ip,
                                 src_port=event.src_port, dst_port=event.dst_port))
    alerts = run_events(BeaconRule(), events)
    assert len(alerts) == 1
    assert alerts[0].evidence["jitter_cv"] == 0.0


def test_jitter_hovering_at_threshold_does_not_flap():
    # CV wanders around 0.15 as the window slides; hysteresis keeps it to one alert.
    alerts = run_events(BeaconRule(history=6), checkins(200, jitter=0.26, seed=3))
    assert len(alerts) <= 1


def test_rearms_after_the_rhythm_breaks():
    rule = BeaconRule(history=6)
    first = checkins(8, interval=60.0)
    # an irregular stretch, then a new steady rhythm
    broken = checkins(4, interval=7.0, start=first[-1].ts + 200.0, seed=1, jitter=0.9)
    second = checkins(10, interval=45.0, start=broken[-1].ts + 45.0)
    alerts = run_events(rule, first + broken + second)
    assert len(alerts) == 2


# -- stays quiet on everything else ---------------------------------------------


def test_human_paced_traffic_is_silent():
    rng = random.Random(42)
    ts, events = 1000.0, []
    for i in range(40):
        events.append(make_event(ts=ts, src_port=50000 + i, dst_ip="198.51.100.7", dst_port=443))
        ts += rng.expovariate(1 / 40)  # bursty, memoryless browsing
    assert run_events(BeaconRule(), events) == []


def test_too_few_contacts_is_silent():
    assert run_events(BeaconRule(), checkins(5)) == []


def test_streaming_cadence_is_not_beaconing():
    # RTP: one datagram every 20 ms is perfectly regular but far too fast.
    events = [
        make_event(ts=1000.0 + i * 0.02, protocol="udp", src_ip="10.0.0.5",
                   dst_ip="10.0.0.9", src_port=16384, dst_port=16386)
        for i in range(2000)
    ]
    assert run_events(BeaconRule(), events) == []


def test_infrastructure_ports_are_ignored():
    ntp = [
        make_event(ts=1000.0 + i * 64, protocol="udp", src_ip="10.0.0.5",
                   dst_ip="10.0.0.1", src_port=123, dst_port=123)
        for i in range(20)
    ]
    dns_replies = [
        make_event(ts=1000.0 + i * 30, protocol="udp", src_ip="10.0.0.1",
                   dst_ip="10.0.0.5", src_port=53, dst_port=40000)
        for i in range(20)
    ]
    assert run_events(BeaconRule(), ntp + dns_replies) == []


def test_established_tcp_segments_are_not_contacts():
    events = [
        make_event(ts=1000.0 + i * 60, tcp_flags="PA", src_port=50000, dst_port=8443)
        for i in range(20)
    ]
    assert run_events(BeaconRule(), events) == []


def test_long_silence_restarts_the_rhythm():
    rule = BeaconRule(max_interval_seconds=600)
    first = checkins(4, interval=60.0)
    later = checkins(4, interval=60.0, start=first[-1].ts + 5000.0)
    assert run_events(rule, first + later) == []


def test_tracked_flow_state_is_bounded():
    rule = BeaconRule(max_tracked_flows=100)
    events = [
        make_event(ts=1000.0 + i * 0.001, src_ip=f"10.{i // 65536}.{i // 256 % 256}.{i % 256}")
        for i in range(5000)
    ]
    run_events(rule, events)
    assert len(rule._flows) <= 100


def test_idle_flows_are_swept():
    rule = BeaconRule(max_interval_seconds=600)
    run_events(rule, checkins(3, src_ip="10.0.0.1"))
    run_events(rule, [make_event(ts=10_000.0, src_ip="10.0.0.2", dst_port=8443)])
    run_events(rule, [make_event(ts=10_400.0, src_ip="10.0.0.3", dst_port=8443)])
    assert ("10.0.0.1", "198.51.100.7", 8443, "tcp") not in rule._flows


# -- integration: real packets through PcapFileSource ---------------------------


def test_beacon_in_pcap_fires_through_the_engine(write_pcap):
    packets = []
    for i in range(10):
        ts = 1000.0 + i * 30.0
        packets.append(tcp_packet("192.168.1.50", "198.51.100.7", 443, ts, sport=51000 + i))
        packets.append(
            tcp_packet("198.51.100.7", "192.168.1.50", 51000 + i, ts + 0.02, sport=443, flags="SA")
        )
    path = write_pcap(packets)

    engine = RuleEngine([BeaconRule()])
    alerts = [a for e in PcapFileSource(path).events() for a in engine.process(e)]

    assert len(alerts) == 1
    assert alerts[0].src == "192.168.1.50"
    assert alerts[0].evidence["mean_interval_seconds"] == 30.0
