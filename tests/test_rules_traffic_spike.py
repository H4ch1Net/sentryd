from conftest import make_event

from sentryd.core.alerts import Severity
from sentryd.rules.traffic_spike import TrafficSpikeRule


def make_rule(**overrides):
    defaults = dict(
        bucket_seconds=5.0,
        spike_ratio=5.0,
        min_bucket_bytes=10_000,
        ewma_alpha=0.3,
        warmup_buckets=3,
    )
    return TrafficSpikeRule(**{**defaults, **overrides})


def feed(rule, host, ts, total_bytes, packets=10):
    """Spread total_bytes over `packets` events inside one bucket."""
    alerts = []
    for i in range(packets):
        alerts += rule.process(
            make_event(
                ts=ts + i * 0.01,
                src_ip=host,
                length=total_bytes // packets,
                dst_port=443,
                tcp_flags="PA",
            )
        )
    return alerts


def test_spike_after_steady_baseline_alerts():
    rule = make_rule()
    alerts = []
    for i in range(5):  # ~1000 B per 5s bucket: a quiet baseline
        alerts += feed(rule, "10.0.0.5", ts=i * 5.0, total_bytes=1000)
    assert alerts == []

    alerts += feed(rule, "10.0.0.5", ts=25.0, total_bytes=200_000)  # the flood
    alerts += feed(rule, "10.0.0.5", ts=30.0, total_bytes=1000)  # closes the bucket

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "traffic_spike"
    assert alert.src == "10.0.0.5"
    assert alert.severity == Severity.HIGH  # 200x baseline >> 2x ratio
    assert alert.evidence["bucket_bytes"] == 200_000
    assert alert.evidence["observed_ratio"] > 5


def test_steady_high_volume_is_normal():
    rule = make_rule()
    alerts = []
    for i in range(20):  # consistently chatty host — that's its baseline
        alerts += feed(rule, "10.0.0.5", ts=i * 5.0, total_bytes=100_000)
    assert alerts == []


def test_small_spike_below_floor_is_ignored():
    rule = make_rule(min_bucket_bytes=10_000)
    alerts = []
    for i in range(5):
        alerts += feed(rule, "10.0.0.5", ts=i * 5.0, total_bytes=100)
    # 50x the baseline, but only 5 KB in absolute terms — below the floor.
    alerts += feed(rule, "10.0.0.5", ts=25.0, total_bytes=5_000)
    alerts += feed(rule, "10.0.0.5", ts=30.0, total_bytes=100)
    assert alerts == []


def test_no_alert_during_warmup():
    rule = make_rule(warmup_buckets=3)
    alerts = feed(rule, "10.0.0.5", ts=0.0, total_bytes=1000)
    # A flood in the very second bucket: no established baseline yet.
    alerts += feed(rule, "10.0.0.5", ts=5.0, total_bytes=500_000)
    alerts += feed(rule, "10.0.0.5", ts=10.0, total_bytes=1000)
    assert alerts == []


def test_hosts_have_independent_baselines():
    rule = make_rule()
    alerts = []
    for i in range(5):
        alerts += feed(rule, "10.0.0.5", ts=i * 5.0, total_bytes=1000)  # quiet
        alerts += feed(rule, "10.0.0.9", ts=i * 5.0, total_bytes=200_000)  # busy
    # The busy host's normal volume would be a huge spike for the quiet one —
    # but baselines are per-host, so neither alerts.
    alerts += feed(rule, "10.0.0.9", ts=25.0, total_bytes=210_000)
    alerts += feed(rule, "10.0.0.9", ts=30.0, total_bytes=200_000)
    assert alerts == []


def test_moderate_spike_is_medium_severity():
    rule = make_rule()
    alerts = []
    for i in range(5):
        alerts += feed(rule, "10.0.0.5", ts=i * 5.0, total_bytes=5_000)
    # ~6x baseline: over the 5x threshold but under the 10x HIGH bar.
    alerts += feed(rule, "10.0.0.5", ts=25.0, total_bytes=30_000)
    alerts += feed(rule, "10.0.0.5", ts=30.0, total_bytes=5_000)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM
