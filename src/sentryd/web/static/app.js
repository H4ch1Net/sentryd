"use strict";

const state = {
  selectedId: null,
  knownRules: new Set(),
  alerts: [],
};

const $ = (sel) => document.querySelector(sel);
const SEVERITIES = ["critical", "high", "medium", "low"];

/* ---------- helpers ---------- */

function fmtTime(ts, withDate = true) {
  const iso = new Date(ts * 1000).toISOString();
  return withDate ? iso.replace("T", " ").slice(0, 19) : iso.slice(11, 19);
}

function esc(value) {
  const div = document.createElement("div");
  div.textContent = String(value);
  return div.innerHTML;
}

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function badge(severity) {
  return `<span class="badge ${esc(severity)}"><span class="dot"></span>${esc(severity)}</span>`;
}

/* ---------- theme ---------- */

$("#theme-toggle").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme
    ? root.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  localStorage.setItem("sentryd-theme", root.dataset.theme);
});

/* ---------- tooltip ---------- */

const tooltip = $("#tooltip");

function showTooltip(html, x, y) {
  tooltip.innerHTML = html;
  tooltip.hidden = false;
  const rect = tooltip.getBoundingClientRect();
  const left = Math.min(x + 12, window.innerWidth - rect.width - 8);
  const top = Math.max(y - rect.height - 10, 8);
  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${top}px`;
}

function hideTooltip() {
  tooltip.hidden = true;
}

/* ---------- KPIs + stats ---------- */

async function refreshStats() {
  const stats = await fetchJSON("/api/stats");
  const sev = stats.by_severity;
  const severe = (sev.high || 0) + (sev.critical || 0);

  $("#kpi-total").textContent = stats.total;
  $("#kpi-total-hint").textContent = stats.total
    ? `across ${Object.keys(stats.by_rule).length} rule${Object.keys(stats.by_rule).length === 1 ? "" : "s"}`
    : "nothing recorded yet";
  $("#kpi-severe").textContent = severe;
  $("#kpi-severe-hint").textContent = stats.total
    ? `${Math.round((severe / stats.total) * 100)}% of all alerts`
    : "";
  $("#kpi-sources").textContent = stats.sources;
  $("#kpi-triaged").textContent = stats.triaged;
  $("#kpi-triaged-hint").textContent =
    stats.total && !stats.triaged ? "run: sentryd triage <id>" : "AI writeups stored";

  // keep the rule filter options in sync with rules that have fired
  const select = $("#filter-rule");
  for (const rule of Object.keys(stats.by_rule).sort()) {
    if (!state.knownRules.has(rule)) {
      state.knownRules.add(rule);
      const opt = document.createElement("option");
      opt.value = rule;
      opt.textContent = rule;
      select.appendChild(opt);
    }
  }

  renderRuleBars(stats.by_rule);
}

function renderRuleBars(byRule) {
  const container = $("#by-rule");
  const entries = Object.entries(byRule).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    container.innerHTML = `<div class="chart-empty">No alerts yet</div>`;
    return;
  }
  const max = entries[0][1];
  container.innerHTML = entries
    .map(
      ([rule, count]) => `
      <div class="rule-row">
        <span class="rule-name mono" title="${esc(rule)}">${esc(rule)}</span>
        <span class="rule-track"><span class="rule-fill" style="width:${(count / max) * 100}%"></span></span>
        <span class="rule-count">${count}</span>
      </div>`
    )
    .join("");
}

/* ---------- timeline chart ---------- */

async function refreshTimeline() {
  const data = await fetchJSON("/api/timeline?buckets=40");
  const container = $("#timeline");
  const axis = $("#timeline-axis");

  if (!data.buckets.length) {
    container.innerHTML = `<div class="chart-empty">No alerts yet</div>`;
    axis.innerHTML = "";
    return;
  }

  const max = Math.max(...data.buckets.map((b) => b.count), 1);
  container.innerHTML = "";
  for (const bucket of data.buckets) {
    const bar = document.createElement("div");
    bar.className = "bar" + (bucket.count === 0 ? " zero" : "");
    bar.style.height = `${(bucket.count / max) * 100}%`;
    if (bucket.count > 0) {
      bar.addEventListener("mousemove", (ev) => {
        const rows = SEVERITIES.filter((s) => bucket.by_severity[s])
          .map(
            (s) =>
              `<div class="tt-row"><span>${s}</span><span>${bucket.by_severity[s]}</span></div>`
          )
          .join("");
        showTooltip(
          `<div class="tt-title">${bucket.count} alert${bucket.count === 1 ? "" : "s"}</div>
           <div class="tt-row"><span>${fmtTime(bucket.start, false)}</span><span>–</span><span>${fmtTime(bucket.end, false)}</span></div>${rows}`,
          ev.clientX,
          ev.clientY
        );
      });
      bar.addEventListener("mouseleave", hideTooltip);
    }
    container.appendChild(bar);
  }
  axis.innerHTML = `<span>${fmtTime(data.start)}</span><span>${fmtTime(data.end)}</span>`;
}

/* ---------- alert table ---------- */

function currentFilters() {
  const params = new URLSearchParams();
  const severity = $("#filter-severity").value;
  const rule = $("#filter-rule").value;
  const status = $("#filter-status").value;
  if (severity) params.set("severity", severity);
  if (rule) params.set("rule", rule);
  if (status) params.set("status", status);
  params.set("limit", "500");
  return params;
}

function textMatch(alert, needle) {
  if (!needle) return true;
  const haystack = `${alert.title} ${alert.src ?? ""} ${alert.dst ?? ""} ${alert.rule_id}`.toLowerCase();
  return haystack.includes(needle.toLowerCase());
}

async function refreshAlerts() {
  const data = await fetchJSON(`/api/alerts?${currentFilters()}`);
  state.alerts = data.alerts;
  renderTable();
}

function renderTable() {
  const needle = $("#filter-search").value.trim();
  const rows = state.alerts.filter((a) => textMatch(a, needle));
  const tbody = $("#alert-table tbody");
  $("#empty").hidden = rows.length > 0;

  tbody.innerHTML = rows
    .map(
      (a) => `
      <tr data-id="${a.id}" tabindex="0" ${a.id === state.selectedId ? 'class="selected"' : ""}>
        <td class="num">${a.id}</td>
        <td class="mono">${fmtTime(a.ts)}</td>
        <td>${badge(a.severity)}</td>
        <td class="mono">${esc(a.rule_id)}</td>
        <td class="mono addr">${esc(a.src ?? "—")}</td>
        <td class="mono addr">${esc(a.dst ?? "—")}</td>
        <td class="num"><span class="count-pill">${a.count}</span></td>
        <td class="title-cell" title="${esc(a.title)}">${esc(a.title)}</td>
        <td class="ai-cell">${a.ai_summary ? "✓" : "—"}</td>
      </tr>`
    )
    .join("");

  for (const tr of tbody.querySelectorAll("tr")) {
    const open = () => openDetail(Number(tr.dataset.id));
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") open();
    });
  }
}

/* ---------- detail drawer ---------- */

async function openDetail(id) {
  state.selectedId = id;
  renderTable();

  const a = await fetchJSON(`/api/alerts/${id}`);
  $("#drawer-title").innerHTML = `
    <div class="alert-id">ALERT #${a.id} · ${esc(a.rule_id)}</div>
    <div class="alert-title">${esc(a.title)}</div>
    ${badge(a.severity)} <span class="status-chip">· ${esc(a.status)}</span>`;

  const ai = a.ai_summary
    ? `<div class="ai-writeup">${esc(a.ai_summary)}</div>`
    : `<div class="ai-missing">No AI writeup yet — run <code>sentryd triage ${a.id}</code>.
       The evidence above is complete without it.</div>`;

  $("#drawer-body").innerHTML = `
    <dl class="meta-grid">
      <dt>Time</dt><dd class="mono">${fmtTime(a.ts)} UTC</dd>
      <dt>Source</dt><dd class="mono">${esc(a.src ?? "—")}</dd>
      <dt>Target</dt><dd class="mono">${esc(a.dst ?? "—")}</dd>
      <dt>Confidence</dt><dd>${a.confidence.toFixed(2)}</dd>
      <dt>Occurrences</dt><dd>${a.count}</dd>
    </dl>
    <h3>Evidence</h3>
    <pre class="mono">${esc(JSON.stringify(a.evidence, null, 2))}</pre>
    <h3>AI triage</h3>
    ${ai}`;

  $("#drawer").hidden = false;
  $("#scrim").hidden = false;
  $("#drawer-close").focus();
}

function closeDetail() {
  state.selectedId = null;
  $("#drawer").hidden = true;
  $("#scrim").hidden = true;
  renderTable();
}

$("#drawer-close").addEventListener("click", closeDetail);
$("#scrim").addEventListener("click", closeDetail);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && !$("#drawer").hidden) closeDetail();
});

/* ---------- refresh loop ---------- */

async function refresh() {
  try {
    await Promise.all([refreshStats(), refreshTimeline(), refreshAlerts()]);
    $("#updated").textContent = `updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    $("#updated").textContent = "connection lost — retrying";
    console.error("refresh failed:", err);
  }
}

for (const sel of ["#filter-severity", "#filter-rule", "#filter-status"]) {
  $(sel).addEventListener("change", refresh);
}
$("#filter-search").addEventListener("input", renderTable);

setInterval(() => {
  if ($("#auto-refresh").checked && $("#drawer").hidden) refresh();
}, 5000);

refresh();
