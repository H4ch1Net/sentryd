# sentryd

Network anomaly detection with deterministic, rule-based detection and an
optional AI triage layer that writes analyst-style explanations of alerts.

**Design principle: rules detect, AI explains.** Every detection is made by
explainable, testable rule logic that runs entirely offline. The AI layer
annotates alerts after they exist — it never influences whether something is
detected, and the whole tool works with no API key configured.

```
 input sources                 core                       consumers
┌─────────────────┐   ┌─────────────────────┐   ┌─────────────────────────┐
│ pcap replay     │   │ normalized Events   │   │ SQLite alert store      │
│ live capture    │──▶│        ↓            │──▶│ terminal dashboard      │
│ log tailing     │   │ rule engine + dedup │   │ web UI (FastAPI)        │
└─────────────────┘   └─────────────────────┘   └─────────────────────────┘
                                                            ↑
                                     AI triage (optional) ──┘
                                     OpenRouter, or a no-op without a key
```

## Detection rules

| rule | what it catches | technique |
|---|---|---|
| `port_scan` | vertical scans, horizontal sweeps | sliding window of SYN-only attempts; distinct (host, port) targets per source |
| `traffic_spike` | floods, exfil bursts | per-host EWMA baseline per time bucket; ratio threshold + absolute floor |
| `arp_spoof` | ARP cache poisoning / MITM | IP→MAC conflict tracking over ARP announcements; gratuitous-ARP flood detection |
| `suspicious_port` | known-bad ports (4444, 31337, telnet, …) | config-driven watchlist with per-port severity and analyst notes |
| `signature` | anything stateless you can describe | YAML signatures: protocol, CIDRs, port ranges, TCP flags |

Every alert carries a rule id, severity, confidence, and concrete evidence
(the ports probed, both MACs, the byte counts) — enough for an analyst to
verify the finding without any AI. Thresholds and watchlists live in
[`config/signatures.yaml`](config/signatures.yaml), not in code.

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/) (or plain pip).

```bash
git clone https://github.com/H4ch1Net/sentryd && cd sentryd
uv sync
uv run pytest        # 91 tests, all offline
```

## Quickstart demo (~2 minutes, no root, no API key)

Replay the committed synthetic capture — background browsing with a port
scan and a Metasploit-handler connection hidden in it:

```bash
uv run sentryd replay tests/fixtures/portscan.pcap
```

Three alerts fire: a Telnet probe (medium), the port scan itself (high), and
a connection to 4444 (high). Inspect them:

```bash
uv run sentryd alerts list
uv run sentryd alerts show 2     # full evidence for the scan
```

Watch it live in the terminal dashboard (timed playback of the same pcap —
alerts appear as they "happened"; Enter drills into any alert, q quits):

```bash
uv run sentryd dash --pcap tests/fixtures/arpspoof.pcap --speed 4
```

Or in the browser:

```bash
uv run sentryd web            # then open http://127.0.0.1:8000
```

### Adding the AI layer

```bash
cp .env.example .env          # put your OpenRouter key in it
uv run sentryd triage 2      # analyst writeup for the port scan alert
```

The writeup (what happened / why it matters / next steps) is stored with the
alert and shows up in both UIs. Without a key, everything above still works —
alerts simply have no prose attached.

## Input sources

```bash
uv run sentryd replay capture.pcap        # offline pcap/pcapng replay
sudo uv run sentryd sniff -i eth0         # live capture (root required)
uv run sentryd tail traffic.log           # follow a JSON-lines traffic log
```

Live capture without root fails with advice, not a traceback. The log format
is one JSON object per line (`ts`, `protocol`, `src_ip`, `dst_ip`,
`src_port`, `dst_port`, `tcp_flags`, `length`); unparseable lines are
skipped and counted.

All three sources normalize into the same `Event` stream, so every rule
behaves identically regardless of input — and pcap replay in tests exercises
the exact code that runs on live traffic.

## Configuration

`config/signatures.yaml` overrides the packaged defaults (deep-merged, so
override only what you need): rule thresholds, the suspicious-port
watchlist, engine dedup cooldown, and custom signatures:

```yaml
rules:
  port_scan:
    min_distinct_targets: 10   # more sensitive than the default 15

signatures:
  - id: sig-rdp-inbound
    title: Inbound RDP connection attempt
    severity: high
    match:
      protocol: tcp
      dst_ports: [3389, "5900-5910"]
      tcp_flags: S
      tcp_flags_not: A
```

## Project layout

```
src/sentryd/
├── core/        Event model, Alert model, rule engine with dedup
├── sources/     pcap replay, live capture, log tailing → Events
├── rules/       one module per detection rule + config-driven signatures
├── triage/      TriageProvider protocol, OpenRouter impl, no-op fallback
├── storage/     SQLite alert store (stdlib sqlite3)
├── dashboard/   Textual terminal UI
└── web/         FastAPI JSON API + static frontend
tests/           per-rule positive/negative tests, synthetic pcap fixtures
```

Architecture notes for contributors are in [CLAUDE.md](CLAUDE.md).

## Testing

```bash
uv run pytest
```

The suite is fully offline: rules are tested against hand-built events and
scapy-crafted synthetic pcaps (both attack and benign traffic — every rule
has "must not fire" cases), the AI provider against a mock HTTP transport
including every failure mode, and both UIs headlessly. Committed demo pcaps
are synthetic and regenerable with `uv run python tests/fixtures/generate.py`.
