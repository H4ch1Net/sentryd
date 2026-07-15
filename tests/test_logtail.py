import json

from sentryd.config import load_default_config
from sentryd.core.engine import RuleEngine
from sentryd.rules.base import build_rules
from sentryd.sources.logtail import LogTailSource, parse_line


def log_line(**fields) -> str:
    return json.dumps(fields)


def test_parse_full_record():
    event = parse_line(
        log_line(
            ts=1700000000.5,
            protocol="tcp",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.9",
            src_port=40123,
            dst_port=443,
            tcp_flags="S",
            length=60,
        )
    )
    assert event is not None
    assert event.ts == 1700000000.5
    assert event.protocol == "tcp"
    assert event.dst_port == 443
    assert event.is_syn_only


def test_parse_iso_timestamp():
    event = parse_line(log_line(ts="2023-11-14T22:13:20+00:00", protocol="udp"))
    assert event is not None
    assert event.ts == 1700000000.0


def test_missing_ts_defaults_to_now():
    event = parse_line(log_line(protocol="tcp"))
    assert event is not None
    assert event.ts > 0


def test_garbage_lines_return_none():
    assert parse_line("not json at all") is None
    assert parse_line('["a", "list"]') is None
    assert parse_line("") is None
    assert parse_line(log_line(ts="not-a-date")) is None


def test_reads_file_and_counts_skipped(tmp_path):
    logfile = tmp_path / "traffic.log"
    lines = [
        log_line(ts=1.0, protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, tcp_flags="S"),
        "some unrelated log noise",
        log_line(ts=2.0, protocol="udp", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=53),
    ]
    logfile.write_text("\n".join(lines) + "\n")

    source = LogTailSource(logfile, follow=False)
    events = list(source.events())

    assert len(events) == 2
    assert source.skipped_lines == 1
    assert events[0].dst_port == 80


def test_new_only_skips_existing_content(tmp_path):
    logfile = tmp_path / "traffic.log"
    logfile.write_text(log_line(ts=1.0, protocol="tcp") + "\n")

    source = LogTailSource(logfile, follow=False, from_start=False)
    assert list(source.events()) == []


def test_syn_scan_in_log_triggers_port_scan(tmp_path):
    logfile = tmp_path / "traffic.log"
    lines = [
        log_line(
            ts=100.0 + i * 0.1,
            protocol="tcp",
            src_ip="10.0.0.66",
            dst_ip="10.0.0.9",
            src_port=54321,
            dst_port=1000 + i,
            tcp_flags="S",
            length=60,
        )
        for i in range(30)
    ]
    logfile.write_text("\n".join(lines) + "\n")

    engine = RuleEngine(build_rules(load_default_config()))
    stats = engine.run(LogTailSource(logfile, follow=False).events())

    assert stats.alerts_emitted == 1
    assert stats.by_severity == {"high": 1}
