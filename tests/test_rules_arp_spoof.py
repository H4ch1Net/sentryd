from conftest import make_event

from sentryd.core.alerts import Severity
from sentryd.core.events import ArpInfo
from sentryd.rules.arp_spoof import ArpSpoofRule

MAC_A = "aa:aa:aa:aa:aa:aa"
MAC_B = "bb:bb:bb:bb:bb:bb"
GATEWAY = "192.168.1.1"


def arp_event(ts, sender_ip, sender_mac, target_ip="192.168.1.50", op=2):
    return make_event(
        ts=ts,
        protocol="arp",
        src_ip=sender_ip,
        dst_ip=target_ip,
        src_port=None,
        dst_port=None,
        arp=ArpInfo(op=op, sender_mac=sender_mac, sender_ip=sender_ip, target_ip=target_ip),
    )


def test_consistent_mapping_is_silent():
    rule = ArpSpoofRule()
    alerts = []
    for i in range(10):
        alerts += rule.process(arp_event(ts=100.0 + i, sender_ip=GATEWAY, sender_mac=MAC_A))
    assert alerts == []


def test_mac_conflict_fires_high_alert():
    rule = ArpSpoofRule()
    rule.process(arp_event(ts=100.0, sender_ip=GATEWAY, sender_mac=MAC_A))

    alerts = rule.process(arp_event(ts=105.0, sender_ip=GATEWAY, sender_mac=MAC_B))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "arp_spoof"
    assert alert.severity == Severity.HIGH
    assert alert.evidence["previous_mac"] == MAC_A
    assert alert.evidence["new_mac"] == MAC_B
    assert alert.evidence["ip"] == GATEWAY


def test_flip_flop_alerts_again():
    rule = ArpSpoofRule()
    rule.process(arp_event(ts=100.0, sender_ip=GATEWAY, sender_mac=MAC_A))
    first = rule.process(arp_event(ts=105.0, sender_ip=GATEWAY, sender_mac=MAC_B))
    second = rule.process(arp_event(ts=110.0, sender_ip=GATEWAY, sender_mac=MAC_A))

    assert len(first) == len(second) == 1
    assert second[0].evidence["previous_mac"] == MAC_B


def test_arp_requests_do_not_establish_mappings():
    rule = ArpSpoofRule()
    # Plain who-has requests (op=1, not gratuitous) say nothing authoritative.
    rule.process(arp_event(ts=100.0, sender_ip=GATEWAY, sender_mac=MAC_A, op=1))
    alerts = rule.process(arp_event(ts=105.0, sender_ip=GATEWAY, sender_mac=MAC_B))
    assert alerts == []  # MAC_B is the first *announcement* for this IP


def test_gratuitous_arp_establishes_and_conflicts():
    rule = ArpSpoofRule()
    # Gratuitous ARP: request where sender == target. Counts as authoritative.
    rule.process(arp_event(ts=100.0, sender_ip=GATEWAY, sender_mac=MAC_A, target_ip=GATEWAY, op=1))
    alerts = rule.process(arp_event(ts=105.0, sender_ip=GATEWAY, sender_mac=MAC_B))
    assert len(alerts) == 1


def test_gratuitous_burst_fires_flood_alert():
    rule = ArpSpoofRule(gratuitous_window_seconds=10, gratuitous_threshold=8)
    alerts = []
    for i in range(12):
        alerts += rule.process(
            arp_event(ts=100.0 + i * 0.5, sender_ip=GATEWAY, sender_mac=MAC_A,
                      target_ip=GATEWAY, op=1)
        )
    flood = [a for a in alerts if "flood" in a.title]
    assert len(flood) == 1
    assert flood[0].severity == Severity.MEDIUM
    assert flood[0].evidence["mac"] == MAC_A


def test_slow_gratuitous_announcements_are_fine():
    rule = ArpSpoofRule(gratuitous_window_seconds=10, gratuitous_threshold=8)
    alerts = []
    for i in range(20):  # one announcement per minute — routine
        alerts += rule.process(
            arp_event(ts=100.0 + i * 60, sender_ip=GATEWAY, sender_mac=MAC_A,
                      target_ip=GATEWAY, op=1)
        )
    assert alerts == []


def test_stale_mapping_expires_like_an_arp_cache():
    # A MAC change hours after the last sighting is a fresh observation
    # (DHCP churn, replaced NIC), not a conflict.
    rule = ArpSpoofRule(mapping_ttl_seconds=3600)
    rule.process(arp_event(ts=100.0, sender_ip=GATEWAY, sender_mac=MAC_A))

    alerts = rule.process(arp_event(ts=100.0 + 4000, sender_ip=GATEWAY, sender_mac=MAC_B))

    assert alerts == []


def test_mac_change_within_ttl_still_conflicts():
    rule = ArpSpoofRule(mapping_ttl_seconds=3600)
    rule.process(arp_event(ts=100.0, sender_ip=GATEWAY, sender_mac=MAC_A))
    alerts = rule.process(arp_event(ts=100.0 + 3000, sender_ip=GATEWAY, sender_mac=MAC_B))
    assert len(alerts) == 1


def test_broadcast_and_zero_addresses_ignored():
    rule = ArpSpoofRule()
    rule.process(arp_event(ts=100.0, sender_ip=GATEWAY, sender_mac=MAC_A))
    assert rule.process(arp_event(ts=101.0, sender_ip=GATEWAY, sender_mac="ff:ff:ff:ff:ff:ff")) == []
    assert rule.process(arp_event(ts=102.0, sender_ip="0.0.0.0", sender_mac=MAC_B)) == []
