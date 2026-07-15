# sentryd

Network anomaly detection tool: deterministic rule-based detection with an
optional AI triage layer that explains alerts. Portfolio project — code
quality, clear architecture, and genuinely solid detection logic are the
priorities.

## The one invariant that matters

**Rules detect; AI only explains.** Detection must be deterministic,
explainable, and fully functional with no API key and no network access.
The AI triage layer (`triage/`) annotates alerts after they exist — it must
never be load-bearing for correctness, never sit in the packet path, and
always degrade gracefully to a no-op.

## Commands

```bash
uv sync                     # install deps (dev group included by default)
uv run pytest               # run the test suite
uv run sentryd replay tests/fixtures/portscan.pcap   # end-to-end smoke test
uv run sentryd alerts list                            # inspect stored alerts
uv run python tests/fixtures/generate.py              # regenerate demo pcaps
```

## Architecture

Pipeline: **source → Event → RuleEngine → Alert → sinks (store/console/UI)**,
with AI triage as an optional post-hoc annotator.

- `core/events.py` — `Event`, the normalized record every source produces and
  every rule consumes. `packet_to_event()` is the scapy→Event adapter.
- `core/alerts.py` — `Alert`, `Severity`, `AlertStatus`.
- `core/engine.py` — `RuleEngine`: runs rules over events, dedups alerts by
  `(rule_id, src, dst, key)` within a cooldown (event time, not wall clock),
  dispatches to `AlertSink`s (protocol: `emit(alert)` / `update(alert)`).
- `sources/` — `PacketSource` protocol (`events() -> Iterator[Event]`);
  pcap replay, live sniff, log tail. User-facing failures raise `SourceError`.
- `rules/` — one module per rule; `base.py` has the `Rule` ABC and the
  `@register` registry that `build_rules(config)` uses.
- `storage/store.py` — SQLite via stdlib `sqlite3`, no ORM. `AlertStore` is
  both the repository and an engine sink.
- `config.py` — packaged defaults (`data/default_config.yaml`) deep-merged
  with the user file (`./config/signatures.yaml` or `--config`).
- `cli.py` — Typer entrypoint (`sentryd`).

## Conventions

- **No scapy outside** `sources/`, `core/events.py`, and test fixtures. Rules
  consume `Event` only — that's what keeps them unit-testable and identical
  across live/pcap/log input.
- **Thresholds and watchlists live in config**, not in rule code. Defaults go
  in `src/sentryd/data/default_config.yaml`; `config/signatures.yaml` is the
  user-editable override.
- Every rule needs **positive and negative tests** (attack fires, benign
  traffic doesn't) in `tests/test_rules_<rule_id>.py`. Rule unit tests build
  `Event`s directly via `conftest.make_event`; integration tests craft real
  packets and go through `PcapFileSource`.
- Alerts must carry concrete `evidence` (a JSON-serializable dict) — enough
  for an analyst to verify the finding without the AI writeup.
- Rules that can raise distinct findings for the same src/dst pair must set
  `Alert.key` (see `suspicious_port`) so dedup never merges different
  findings.
- Use event timestamps (`event.ts`), never wall clock, in detection logic —
  pcap replay must behave identically to live capture.
- Committed pcaps are synthetic only (scapy-crafted, RFC1918/documentation
  addresses) — never commit real captures.
