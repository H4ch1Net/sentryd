# Changelog

## 0.4.0

Detection depth, correlation you can rank by, and a rebuilt console.

- **Stealth scans.** `port_scan` counts FIN and XMAS probes (segments
  without ACK that can't belong to any connection) alongside bare SYNs,
  names the technique in the title, and records a per-technique breakdown.
- **Beaconing rule.** New `beacon` rule flags command-and-control
  check-ins: per-flow contact rhythm judged by the coefficient of variation
  of the intervals, with burst and SYN-retransmit folding, a streaming
  floor, infrastructure ports ignored, LRU-bounded state, and hysteresis
  so it can't flap. Thresholds live in config.
- **Kill-chain correlation.** Clusters list their phases in order; a
  watchlisted-port hit that is one of a scan's own probes counts as
  reconnaissance (the demo case used to read "service access ->
  reconnaissance"). Simultaneous phases follow kill-chain stage.
- **Risk score.** Every cluster and case gets a 0-100 score built from
  named factors (peak severity, confidence, multi-stage escalation,
  verdicts), shown in the web UI, `cases show`, and the markdown report.
- **Console rewrite.** New design system and sidebar shell, switches and
  segmented controls, a risk gauge, kill-chain steppers, an interactive
  attack graph, an activity chart that filters the table by time window,
  a command palette, keyboard-driven triage (J/K, 1-5 verdicts, X to
  select), bulk verdicts with undo, autosaving notes, real upload
  progress, density and reduce-motion preferences, and phone layouts.
- **Live updates that cost nothing when idle.** The console polls a
  trigger-maintained store revision (`GET /api/revision`) and refetches
  only when it moves; data GETs answer `304` via revision ETags;
  `GET /api/dashboard` loads every panel in one round trip. Idle traffic
  drops from 24 requests and ~129 KB per 30 s to 12 requests and 180 B.
- **Store efficiency.** WAL mode with a busy timeout (reads no longer
  contend with a running replay), schema work skipped unless
  `user_version` is behind, no per-case COUNT when listing cases, SQL-side
  aggregation for top hosts and the timeline, and new indexes.
- **API.** `POST /api/alerts/bulk-status`; `since`/`until` filters on
  alert listing and export; verdict counts and target involvement in
  stats; rule summaries on `/api/rules`; constant-time token comparison.
- **Token-gated servers work in the browser.** With `SENTRYD_API_TOKEN`
  set, the console prompts once, retries, and authenticates downloads.

## 0.3.0

Analyst workflow, settings, hardening, and packaging.

- **Alert verdicts.** Mark alerts confirmed, false positive, expected,
  ignored, or dismissed from the CLI (`sentryd alerts status`), the API
  (`POST /api/alerts/{id}/status`), or the web drawer. AI triage no longer
  changes the verdict.
- **Packet and byte counts.** Alerts carry per-finding packet/byte counts
  where the rule can attribute them; shown in the drawer and CLI, exported
  in CSV.
- **Rule enable/disable.** Toggle rules per workspace without editing config:
  `sentryd rules enable/disable`, the Settings view, or
  `POST /api/rules/{id}/toggle`. Stored in a new settings table.
- **Web Settings view and graphs.** Instance status (version, AI
  availability, counts), rule toggles, a theme switch, plus Top suspicious
  hosts and Top ports/services panels on the dashboard.
- **Security hardening.** Optional bearer-token gate on `/api/*`
  (`SENTRYD_API_TOKEN`, off by default), server-side replay sandboxed to the
  uploads dir or `SENTRYD_PCAP_DIR`, localhost-bind default with a warning
  when exposing without a token.
- **Docker and Makefile.** `docker compose up` serves the console with a
  persistent volume; `make demo/web/test/docker-up` for common tasks.
- `GET /api/status` endpoint; `SENTRYD_DB` honored by `--db`.

## 0.2.0

Case-based PCAP triage.

- **Cases.** Every replay or capture becomes a case; alerts belong to the
  case that produced them. Case metadata records source, PCAP sha256/size,
  event counts, event-time span, notes, and status.
- **Correlation.** Alerts are grouped into activity clusters by offending
  source with attack-chain labels (reconnaissance -> suspicious service
  access -> ...).
- **Overall AI review.** A size-capped digest of alert metadata (never raw
  packets) drives a structured case report: executive summary, likely attack
  chain, top hosts/ports, timeline, confidence, next steps, false positives.
- **Richer alerts.** First/last seen, protocol and ports, the exact reason a
  rule fired, related alerts, and a suggested next investigation command.
- **REST API + web upload.** Drag-and-drop PCAP upload with background replay
  and progress, full REST API (OpenAPI at `/docs`), host summaries.
- **Exports.** Alerts to JSON/CSV, case reports to markdown or JSON bundles,
  from both CLI and web.
- **Rules tooling.** `sentryd rules list/explain/lint/test`.

## 0.1.0

Initial release: deterministic rule engine (port scan, traffic spike, ARP
spoofing, suspicious ports, config-driven signatures), pcap replay, live
capture and log tailing, SQLite storage, Typer CLI, a Textual dashboard, a
FastAPI web UI, and an optional OpenRouter AI triage layer.
