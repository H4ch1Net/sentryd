import pytest
import yaml

from sentryd.config import load_config, load_default_config
from sentryd.rules.base import build_rules


def test_default_config_loads_and_builds_rules():
    config = load_default_config()
    rules = build_rules(config)
    rule_ids = {r.rule_id for r in rules}
    assert {"port_scan", "suspicious_port"} <= rule_ids


def test_user_config_overrides_single_value(tmp_path):
    path = tmp_path / "override.yaml"
    path.write_text(yaml.safe_dump({"rules": {"port_scan": {"min_distinct_targets": 5}}}))

    config = load_config(path)

    assert config["rules"]["port_scan"]["min_distinct_targets"] == 5
    # untouched defaults survive the merge
    assert config["rules"]["port_scan"]["window_seconds"] == 10
    assert config["engine"]["cooldown_seconds"] == 60


def test_rule_can_be_disabled(tmp_path):
    path = tmp_path / "override.yaml"
    path.write_text(yaml.safe_dump({"rules": {"suspicious_port": {"enabled": False}}}))

    rules = build_rules(load_config(path))

    assert "suspicious_port" not in {r.rule_id for r in rules}


def test_empty_yaml_section_keeps_defaults(tmp_path):
    # "rules:" with nothing under it parses as None, that must mean
    # "no override", not "delete every rule".
    path = tmp_path / "override.yaml"
    path.write_text("rules:\n")

    config = load_config(path)

    assert {"port_scan", "suspicious_port"} <= set(config["rules"])


def test_malformed_rules_section_rejected_clearly(tmp_path):
    path = tmp_path / "override.yaml"
    path.write_text(yaml.safe_dump({"rules": ["port_scan"]}))

    with pytest.raises(ValueError, match="'rules:' must be a mapping"):
        load_config(path)


def test_unknown_rule_rejected():
    with pytest.raises(ValueError, match="unknown rule"):
        build_rules({"rules": {"made_up": {}}})
