"""Rule ABC and the registry that builds enabled rules from config."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from sentryd.core.alerts import Alert
from sentryd.core.events import Event

# rule_id -> Rule class (instantiate via cls.from_config(section))
RULE_REGISTRY: dict[str, type["Rule"]] = {}


def register(cls: type["Rule"]) -> type["Rule"]:
    """Class decorator adding a rule to the registry under its rule_id."""
    RULE_REGISTRY[cls.rule_id] = cls
    return cls


class Rule(ABC):
    """A detection rule.

    Rules may keep internal state (sliding windows, seen-maps) but must be
    pure functions of the event stream: same events in, same alerts out.
    They consume normalized Events only, never raw packets, and return
    fully-formed Alerts with severity, confidence, and evidence attached.
    """

    rule_id: ClassVar[str]

    @classmethod
    def from_config(cls, config: dict) -> "Rule":
        """Build an instance from this rule's section of the config file.

        Default: pass config keys as keyword arguments. Override for rules
        whose config needs preprocessing.
        """
        return cls(**config)

    @abstractmethod
    def process(self, event: Event) -> list[Alert]:
        """Inspect one event; return zero or more alerts."""


def build_rules(config: dict, disabled: set[str] = frozenset()) -> list[Rule]:
    """Instantiate enabled rules from ``rules:`` plus the signature matcher.

    Custom signatures live under the top-level ``signatures:`` key; when any
    are configured, a SignatureRule is appended to evaluate them.

    ``disabled`` is a runtime toggle set (from the settings store) applied on
    top of the config's own per-rule ``enabled`` flag, so the web UI and CLI
    can turn rules off without editing the config file.
    """
    from sentryd.rules.signature import SignatureRule

    rules: list[Rule] = []
    for rule_id, rule_cfg in config.get("rules", {}).items():
        if rule_id not in RULE_REGISTRY:
            raise ValueError(f"unknown rule in config: {rule_id!r}")
        rule_cfg = dict(rule_cfg or {})
        if not rule_cfg.pop("enabled", True) or rule_id in disabled:
            continue
        rules.append(RULE_REGISTRY[rule_id].from_config(rule_cfg))
    if config.get("signatures") and "signature" not in disabled:
        rules.append(SignatureRule.from_config(config))
    return rules
