"""End-to-end: synthetic pcaps through PcapFileSource into the engine."""

import pytest
from conftest import benign_packets, syn_scan_packets, tcp_packet

from sentryd.core.engine import RuleEngine
from sentryd.rules.port_scan import PortScanRule
from sentryd.rules.suspicious_port import SuspiciousPortRule
from sentryd.rules.base import build_rules
from sentryd.config import load_default_config
from sentryd.sources.base import SourceError
from sentryd.sources.pcap import PcapFileSource


def default_engine(sinks=()):
    return RuleEngine(build_rules(load_default_config()), sinks=sinks)


def test_missing_file_raises_source_error(tmp_path):
    source = PcapFileSource(tmp_path / "nope.pcap")
    with pytest.raises(SourceError, match="not found"):
        next(source.events())


def test_pcap_yields_normalized_events(write_pcap):
    path = write_pcap(benign_packets())
    events = list(PcapFileSource(path).events())

    assert len(events) == 25  # 4 handshake flows x5 + 5 DNS
    tcp = [e for e in events if e.protocol == "tcp"]
    udp = [e for e in events if e.protocol == "udp"]
    assert len(tcp) == 20 and len(udp) == 5
    assert tcp[0].tcp_flags == "S"
    assert tcp[0].src_ip == "192.168.1.20"
    assert udp[0].dst_port == 53


def test_syn_scan_pcap_triggers_port_scan_alert(write_pcap):
    path = write_pcap(syn_scan_packets())
    engine = default_engine()

    stats = engine.run(PcapFileSource(path).events())

    assert stats.alerts_emitted >= 1
    assert "high" in stats.by_severity


def test_benign_pcap_triggers_nothing(write_pcap):
    path = write_pcap(benign_packets())
    engine = default_engine()

    stats = engine.run(PcapFileSource(path).events())

    assert stats.alerts_emitted == 0


def test_suspicious_port_hit_from_pcap(write_pcap):
    packets = benign_packets() + [
        tcp_packet("192.168.1.30", "10.9.9.9", 4444, ts=2000.0, flags="S")
    ]
    path = write_pcap(packets)
    engine = default_engine()

    stats = engine.run(PcapFileSource(path).events())

    assert stats.alerts_emitted == 1
    assert stats.by_severity == {"high": 1}
