"""Rule ABC and the registry that builds enabled rules from config."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, ClassVar

from sentryd.core.alerts import Alert
from sentryd.core.events import Event

# rule_id -> factory(rule_config: dict) -> Rule
RULE_REGISTRY: dict[str, Callable[[dict], "Rule"]] = {}


def register(cls: type["Rule"]) -> type["Rule"]:
    """Class decorator adding a rule to the registry under its rule_id."""
    RULE_REGISTRY[cls.rule_id] = cls.from_config
    return cls


class Rule(ABC):
    """A detection rule.

    Rules may keep internal state (sliding windows, seen-maps) but must be
    pure functions of the event stream: same events in, same alerts out.
    They consume normalized Events only — never raw packets — and return
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


def build_rules(config: dict) -> list[Rule]:
    """Instantiate every enabled rule from the ``rules:`` config section."""
    rules: list[Rule] = []
    for rule_id, rule_cfg in config.get("rules", {}).items():
        if rule_id not in RULE_REGISTRY:
            raise ValueError(f"unknown rule in config: {rule_id!r}")
        rule_cfg = dict(rule_cfg or {})
        if not rule_cfg.pop("enabled", True):
            continue
        rules.append(RULE_REGISTRY[rule_id](rule_cfg))
    return rules
