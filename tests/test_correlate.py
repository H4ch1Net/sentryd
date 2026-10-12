from conftest import make_event  # noqa: F401 (fixture import side effects)

from sentryd.core.alerts import Alert, AlertStatus, Severity
from sentryd.core.correlate import (
    case_risk,
    correlate,
    investigation_hint,
    related_alerts,
)
from sentryd.storage.store import AlertStore


def alert(**overrides) -> Alert:
    defaults = dict(
        rule_id="port_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        title="scan",
        ts=100.0,
        src="10.0.0.66",
        dst="10.0.0.9",
        evidence={},
    )
    return Alert(**{**defaults, **overrides})


def test_clusters_group_by_source_and_order_rules_by_first_seen():
    alerts = [
        alert(ts=100.0, rule_id="port_scan"),
        alert(ts=105.0, rule_id="suspicious_port", severity=Severity.MEDIUM, dst_port=23),
        alert(ts=90.0, rule_id="traffic_spike", src="10.0.0.7", dst=None, severity=Severity.MEDIUM),
    ]

    clusters = correlate(alerts)

    assert len(clusters) == 2
    scanner = clusters[0]  # highest severity first
    assert scanner.source == "10.0.0.66"
    assert scanner.rules == ["port_scan", "suspicious_port"]
    assert scanner.chain == "reconnaissance -> suspicious service access"
    assert scanner.max_severity == "high"
    assert scanner.targets == ["10.0.0.9"]
    assert (scanner.first_seen, scanner.last_seen) == (100.0, 105.0)


def test_last_seen_uses_dedup_window():
    a = alert(ts=100.0, last_ts=250.0)
    cluster = correlate([a])[0]
    assert cluster.last_seen == 250.0


def test_sourceless_alerts_are_not_dropped():
    a = alert(src=None, title="odd traffic")
    clusters = correlate([a])
    assert len(clusters) == 1
    assert clusters[0].alerts == [a]


def test_cluster_dict_is_json_friendly():
    d = correlate([alert(id=7)])[0].to_dict()
    assert d["alert_ids"] == [7]
    assert d["chain"] == "reconnaissance"
    assert d["max_severity"] == "high"


def test_related_alerts_share_hosts_same_case(tmp_path):
    from sentryd.core.cases import Case

    with AlertStore(tmp_path / "t.db") as store:
        c1 = store.create_case(Case(id=None, name="one", source_kind="pcap", source="a"))
        c2 = store.create_case(Case(id=None, name="two", source_kind="pcap", source="b"))
        subject = store.insert(alert(case_id=c1.id))
        same_src = store.insert(alert(case_id=c1.id, rule_id="suspicious_port", dst="10.9.9.9"))
        same_dst = store.insert(alert(case_id=c1.id, src="172.16.0.1", dst="10.0.0.9"))
        store.insert(alert(case_id=c2.id))  # other case: excluded
        store.insert(alert(case_id=c1.id, src="1.1.1.1", dst="8.8.8.8"))  # unrelated hosts

        related = related_alerts(store, subject)

        ids = {a.id for a in related}
        assert ids == {same_src.id, same_dst.id}


def test_investigation_hints_are_specific():
    hint = investigation_hint(alert(rule_id="suspicious_port", dst_port=4444, case_id=3))
    assert "4444" in hint
    assert "--case 3" in hint
    assert "tshark" in hint

    for rule in ("port_scan", "traffic_spike", "arp_spoof", "signature", "beacon"):
        assert investigation_hint(alert(rule_id=rule))  # every rule has one


# -- kill-chain phases -----------------------------------------------------------


def scan_with_probe_and_followup():
    scan = alert(
        id=2, ts=101.7, rule_id="port_scan", dst="10.0.0.9",
        evidence={"sample_ports": [21, 22, 23, 25], "sample_hosts": ["10.0.0.9"],
                  "window_seconds": 10.0},
    )
    telnet_probe = alert(id=1, ts=100.2, rule_id="suspicious_port", severity=Severity.MEDIUM,
                         dst_port=23, confidence=0.6)
    handler = alert(id=3, ts=110.0, rule_id="suspicious_port", dst_port=4444, confidence=0.6)
    return [telnet_probe, scan, handler]


def test_probe_hit_inside_a_scan_counts_as_reconnaissance():
    cluster = correlate(scan_with_probe_and_followup())[0]

    # Without absorption this would read "suspicious service access ->
    # reconnaissance -> ..." because the Telnet probe precedes the scan alert.
    assert cluster.chain == "reconnaissance -> suspicious service access"
    recon, access = cluster.phases
    assert recon["alert_ids"] == [1, 2]
    assert recon["first_seen"] == 100.2
    assert access["alert_ids"] == [3]
    assert cluster.rules == ["suspicious_port", "port_scan"]  # raw first-seen order kept


def test_hit_on_a_port_the_scan_never_sampled_is_not_absorbed():
    alerts = scan_with_probe_and_followup()
    alerts[0].dst_port = 31337  # not in the scan's sample
    cluster = correlate(alerts)[0]
    assert cluster.chain == "suspicious service access -> reconnaissance"


def test_simultaneous_phases_follow_kill_chain_order():
    alerts = [
        alert(ts=100.0, rule_id="traffic_spike", dst=None),
        alert(ts=100.0, rule_id="port_scan"),
    ]
    assert correlate(alerts)[0].chain == "reconnaissance -> unusual data volume"


# -- risk score --------------------------------------------------------------------


def test_risk_score_is_explained_by_its_factors():
    risk = correlate(scan_with_probe_and_followup())[0].risk

    assert risk["score"] == sum(f["points"] for f in risk["factors"])
    names = [f["factor"] for f in risk["factors"]]
    assert names[0] == "peak severity high"
    assert "multi-stage activity (2 phases)" in names
    assert risk["level"] == "high"


def test_analyst_verdicts_move_the_score():
    alerts = scan_with_probe_and_followup()
    baseline = correlate(alerts)[0].risk["score"]

    alerts[2].status = AlertStatus.CONFIRMED
    assert correlate(alerts)[0].risk["score"] > baseline

    for a in alerts:
        a.status = AlertStatus.FALSE_POSITIVE
    closed = correlate(alerts)[0].risk
    assert (closed["score"], closed["level"]) == (0, "none")


def test_case_risk_takes_the_riskiest_cluster():
    clusters = correlate([
        alert(src="10.0.0.1", severity=Severity.LOW, confidence=0.5),
        alert(src="10.0.0.2", severity=Severity.HIGH, confidence=0.9),
    ])
    risk = case_risk(clusters)
    assert risk["source"] == "10.0.0.2"
    assert risk["score"] == 60 + 9
    assert case_risk([]) == {"score": 0, "level": "none", "source": None, "factors": []}
