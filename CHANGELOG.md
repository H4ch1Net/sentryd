# Changelog

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
