/* Overview: KPIs, activity, breakdowns, and the alert table.

   One refresh = two requests (GET /api/dashboard for every panel, GET
   /api/alerts for the table), and a superseded refresh is aborted rather
   than raced. Filters live in the URL so a reload or a shared link lands on
   the same slice. */

import { api, download } from "../api.js";
import { columnsChart, rankBars, sparkline } from "../charts.js";
import { ctx } from "../context.js";
import {
  $, animateNumber, debounce, emptyState, esc, fmtNum, fmtTime, icon, plural,
} from "../dom.js";
import { noteRevision } from "../live.js";
import { AlertTable } from "../table.js";
import { segmented, toastError } from "../ui.js";

const PORT_LABELS = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
  445: "SMB", 1337: "backdoor", 2323: "Telnet alt", 3306: "MySQL", 3389: "RDP",
  4444: "Metasploit", 5555: "ADB", 5900: "VNC", 6667: "IRC", 8080: "HTTP alt",
  8443: "HTTPS alt", 9001: "Tor", 31337: "Back Orifice",
};

const filters = { case: "", sev: "", rule: "", status: "", q: "", since: null, until: null };
let table;
let timeline;
let severity;
let controller = null;
let loaded = false;
let lastStats = null;

function scopeParam(prefix = "&") {
  return filters.case ? `${prefix}case=${filters.case}` : "";
}

function alertQuery() {
  const p = new URLSearchParams({ limit: "500" });
  if (filters.case) p.set("case", filters.case);
  if (filters.sev) p.set("severity", filters.sev);
  if (filters.rule) p.set("rule", filters.rule);
  if (filters.status) p.set("status", filters.status);
  if (filters.since != null) p.set("since", String(filters.since));
  if (filters.until != null) p.set("until", String(filters.until));
  return p;
}

/** Mirror filters into the hash (#/?case=1&sev=high...) without navigating. */
function syncHash() {
  const p = new URLSearchParams();
  for (const k of ["case", "sev", "rule", "status", "q"]) if (filters[k]) p.set(k, filters[k]);
  const hash = `#/${p.toString() ? `?${p}` : ""}`;
  if (location.hash !== hash) history.replaceState(null, "", hash);
  $('.nav a[data-tab="dashboard"]').setAttribute("href", hash); // coming back keeps the slice
}

export function readHash(query) {
  const p = new URLSearchParams(query);
  for (const k of ["case", "sev", "rule", "status", "q"]) filters[k] = p.get(k) || "";
  filters.since = filters.until = null;
}

export function scopeCase() { return filters.case; }

export function initDashboard() {
  table = new AlertTable($("#alert-table"), {
    onOpen: (id, t) => ctx.openAlert(id, t),
    onHost: (ip) => ctx.openHost(ip),
    onBulk: (ids, status, t) => ctx.bulkVerdict(ids, status, t),
    emptyHtml: () => (lastStats?.total
      ? emptyState("filter", "No alerts match these filters", 'Loosen a filter, or <a href="#/" data-clear-filters>clear them all</a>.')
      : emptyState("shield", "No alerts yet", 'Upload a capture on the <a href="#/cases">Cases</a> page, or run <code>sentryd replay tests/fixtures/portscan.pcap</code>')),
  });
  $("#alert-table").addEventListener("click", (ev) => {
    if (ev.target.closest("[data-clear-filters]")) { ev.preventDefault(); clearFilters(); }
  });

  timeline = columnsChart($("#timeline"), {
    onSelect(window) {
      filters.since = window?.start ?? null;
      filters.until = window?.end ?? null;
      renderChips();
      refreshAlerts();
    },
  });

  severity = segmented($("#filter-severity"), {
    value: filters.sev,
    onChange(v) { filters.sev = v; syncHash(); refreshAlerts(); },
  });
  $("#filter-rule").addEventListener("change", (ev) => { filters.rule = ev.target.value; syncHash(); refreshAlerts(); renderRules(); });
  $("#filter-status").addEventListener("change", (ev) => { filters.status = ev.target.value; syncHash(); refreshAlerts(); });
  const search = $("#filter-search");
  const applySearch = debounce(() => { filters.q = search.value; table.setFilter(filters.q); syncHash(); renderChips(); }, 120);
  search.addEventListener("input", applySearch);
  search.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && search.value) { ev.stopPropagation(); search.value = ""; applySearch.flush(); } });
  $("#case-filter").addEventListener("change", (ev) => {
    filters.case = ev.target.value;
    filters.since = filters.until = null;
    timeline.clear();
    syncHash();
    renderChips();
    load();
  });
  $("#export-alerts-csv").addEventListener("click", () => {
    const p = alertQuery();
    p.set("format", "csv");
    p.set("limit", "10000");
    download(`/api/export/alerts?${p}`, "alerts.csv").catch(toastError);
  });
}

/** Apply externally requested filters (palette, host drawer). */
export function applyFilters(next) {
  Object.assign(filters, { since: null, until: null }, next);
  if (next.q !== undefined) $("#filter-search").value = next.q;
  syncHash();
  enter();
}

export function clearFilters() {
  Object.assign(filters, { sev: "", rule: "", status: "", q: "", since: null, until: null });
  $("#filter-search").value = "";
  timeline.clear();
  syncHash();
  enter();
}

/** Called when the route lands here: reflect filters in controls, load. */
export function enter() {
  ctx.activeTable = table;
  $("#filter-search").value = filters.q;
  severity.set(filters.sev);
  $("#filter-status").value = filters.status;
  table.setFilter(filters.q);
  renderChips();
  return load();
}

function renderChips() {
  const chips = [];
  if (filters.since != null) chips.push(["window", `${icon("pulse")}${fmtTime(filters.since, false)} to ${fmtTime(filters.until, false)} UTC`]);
  if (filters.q) chips.push(["q", `${icon("search")}“${esc(filters.q)}”`]);
  $("#filter-chips").innerHTML = chips.map(([k, label]) =>
    `<span class="chip">${label}<button type="button" data-chip="${k}" aria-label="Remove filter">${icon("x")}</button></span>`).join("");
  $("#filter-chips").onclick = (ev) => {
    const b = ev.target.closest("[data-chip]");
    if (!b) return;
    if (b.dataset.chip === "window") { filters.since = filters.until = null; timeline.clear(); refreshAlerts(); }
    if (b.dataset.chip === "q") { filters.q = ""; $("#filter-search").value = ""; table.setFilter(""); syncHash(); }
    renderChips();
  };
}

function abortable() {
  controller?.abort();
  controller = new AbortController();
  return controller.signal;
}

/** Full refresh. `quiet` = live update: keep the frame, flash new rows. */
export async function load({ quiet = false } = {}) {
  const signal = abortable();
  const frames = document.querySelectorAll("#view-dashboard .chart-card, #view-dashboard .kpis");
  if (loaded && !quiet) frames.forEach((f) => f.classList.add("loading-frame", "refetching"));
  try {
    const [dash, alerts] = await Promise.all([
      api(`/api/dashboard?buckets=40${scopeParam()}`, { signal }),
      api(`/api/alerts?${alertQuery()}`, { signal }),
    ]);
    noteRevision(dash.revision);
    ctx.cases = dash.cases;
    lastStats = dash.stats;
    renderCaseFilter(dash.cases);
    renderKpis(dash.stats, dash.timeline);
    timeline.update(dash.timeline);
    renderRules();
    renderHosts(dash.stats.top_hosts);
    renderPorts(dash.stats.top_ports);
    table.setAlerts(alerts.alerts, { highlightNew: quiet && loaded });
    $("#alert-count").textContent = `${plural(dash.stats.total, "alert")} in scope`;
    updateNav(dash);
    loaded = true;
  } catch (err) {
    if (err.name !== "AbortError") toastError(err);
  } finally {
    if (!signal.aborted) frames.forEach((f) => f.classList.remove("refetching"));
  }
}

async function refreshAlerts() {
  const signal = abortable();
  try {
    const { alerts } = await api(`/api/alerts?${alertQuery()}`, { signal });
    table.setAlerts(alerts);
  } catch (err) {
    if (err.name !== "AbortError") toastError(err);
  }
}

function updateNav(dash) {
  const open = $("#nav-open");
  open.hidden = !dash.stats.open || filters.case !== "";
  open.textContent = fmtNum(dash.stats.open);
  open.classList.toggle("attention", dash.stats.open > 0);
  open.title = `${dash.stats.open} alerts need review`;
  const cases = $("#nav-cases");
  cases.hidden = !dash.cases.length;
  cases.textContent = fmtNum(dash.cases.length);
}

function renderCaseFilter(cases) {
  const select = $("#case-filter");
  const sig = cases.map((c) => `${c.id}:${c.name}`).join("|");
  if (select.dataset.sig === sig) return;
  select.dataset.sig = sig;
  select.innerHTML = '<option value="">All cases</option>' + cases.map((c) =>
    `<option value="${c.id}">#${c.id} ${esc(c.name)}</option>`).join("");
  select.value = filters.case;
}

function renderKpis(stats, tl) {
  const sev = stats.by_severity;
  const severe = (sev.high || 0) + (sev.critical || 0);
  const rules = Object.keys(stats.by_rule).length;
  const buckets = tl.buckets || [];

  animateNumber($("#kpi-total .tile-value"), stats.total);
  $("#kpi-total .tile-hint").textContent = stats.total
    ? `across ${plural(rules, "rule")} · ${stats.triaged} with AI writeups`
    : "nothing recorded yet";
  sparkline($("#kpi-total .spark"), buckets.map((b) => b.count));

  animateNumber($("#kpi-open .tile-value"), stats.open);
  const reviewed = stats.total ? (stats.total - stats.open) / stats.total : 0;
  $("#kpi-open .tile-hint").textContent = stats.total ? `${Math.round(reviewed * 100)}% have a verdict` : "verdicts appear here";
  $("#kpi-open .meter-fill").style.width = `${reviewed * 100}%`;

  animateNumber($("#kpi-severe .tile-value"), severe);
  $("#kpi-severe .tile-hint").textContent = stats.total ? `${Math.round((severe / stats.total) * 100)}% of alerts` : "";
  sparkline($("#kpi-severe .spark"), buckets.map((b) => (b.by_severity.high || 0) + (b.by_severity.critical || 0)));

  animateNumber($("#kpi-sources .tile-value"), stats.sources);
  const dots = $("#kpi-sources .host-dots");
  const n = Math.min(stats.sources, 24);
  if (dots.childElementCount !== n) {
    dots.innerHTML = Array.from({ length: n }, (_, i) => `<span style="--sev:var(--accent);animation-delay:${i * 25}ms"></span>`).join("");
  }

  // Grow the rule filter's options as new rules appear.
  const select = $("#filter-rule");
  const known = new Set([...select.options].map((o) => o.value));
  for (const rule of Object.keys(stats.by_rule).sort()) {
    if (!known.has(rule)) select.add(new Option(rule, rule));
  }
  select.value = filters.rule;
}

function renderRules() {
  const entries = Object.entries(lastStats?.by_rule || {}).sort((a, b) => b[1] - a[1]);
  rankBars($("#by-rule"), entries, {
    key: ([rule]) => rule,
    label: ([rule]) => esc(rule),
    value: ([, n]) => n,
    active: ([rule]) => rule === filters.rule,
    empty: "No alerts yet",
    onClick: ([rule]) => {
      filters.rule = filters.rule === rule ? "" : rule;
      $("#filter-rule").value = filters.rule;
      syncHash();
      renderRules();
      refreshAlerts();
    },
  });
}

function renderHosts(hosts) {
  rankBars($("#top-hosts"), hosts, {
    key: (h) => h.host,
    label: (h) => esc(h.host),
    value: (h) => h.score,
    meta: (h) => `${h.alerts} src · ${h.targeted} dst`,
    empty: "No hosts implicated yet",
    onClick: (h) => ctx.openHost(h.host),
  });
}

function renderPorts(ports) {
  rankBars($("#top-ports"), ports, {
    key: (p) => p.port,
    label: (p) => `${p.port}${PORT_LABELS[p.port] ? `<span class="sub">${PORT_LABELS[p.port]}</span>` : ""}`,
    value: (p) => p.alerts,
    meta: (p) => (p.alerts === 1 ? "alert" : "alerts"),
    empty: "No ports named in alerts",
    onClick: (p) => { filters.q = String(p.port); $("#filter-search").value = filters.q; table.setFilter(filters.q); syncHash(); renderChips(); },
  });
}

export function focusSearch() {
  $("#filter-search").focus();
  $("#filter-search").select();
}
