# sentryd

Network anomaly detection with deterministic, rule-based detection and an
optional AI-powered triage layer that explains alerts in analyst-style prose.

**Design principle:** detection is pure rules and signatures — explainable,
testable, and fully functional offline. The AI layer only annotates alerts
after the fact; it is never load-bearing for correctness.

> Full setup and quickstart demo instructions land with the first release —
> the project is under active development.

## Quickstart

```bash
uv sync
uv run sentryd replay tests/fixtures/portscan.pcap
uv run sentryd alerts list
```
