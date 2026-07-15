"use strict";

const state = { selectedId: null, knownRules: new Set() };

const $ = (sel) => document.querySelector(sel);

function fmtTime(ts) {
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19);
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

async function refreshStats() {
  const stats = await fetchJSON("/api/stats");
  const chips = [`<span class="stat">total <b>${stats.total}</b></span>`];
  for (const sev of ["critical", "high", "medium", "low"]) {
    if (stats.by_severity[sev]) {
      chips.push(
        `<span class="stat severity-${sev}">${sev} <b>${stats.by_severity[sev]}</b></span>`
      );
    }
  }
  $("#stats").innerHTML = chips.join("");

  const select = $("#filter-rule");
  for (const rule of Object.keys(stats.by_rule)) {
    if (!state.knownRules.has(rule)) {
      state.knownRules.add(rule);
      const opt = document.createElement("option");
      opt.value = rule;
      opt.textContent = rule;
      select.appendChild(opt);
    }
  }
}

async function refreshAlerts() {
  const data = await fetchJSON(`/api/alerts?${currentFilters()}`);
  const tbody = $("#alert-table tbody");
  tbody.innerHTML = "";
  $("#empty").hidden = data.alerts.length > 0;

  for (const alert of data.alerts) {
    const tr = document.createElement("tr");
    tr.dataset.id = alert.id;
    if (alert.id === state.selectedId) tr.classList.add("selected");
    tr.innerHTML = `
      <td>${alert.id}</td>
      <td>${fmtTime(alert.ts)}</td>
      <td><span class="sev ${esc(alert.severity)}">${esc(alert.severity)}</span></td>
      <td>${esc(alert.rule_id)}</td>
      <td>${esc(alert.src ?? "-")}</td>
      <td>${esc(alert.dst ?? "-")}</td>
      <td>${alert.count}</td>
      <td title="${esc(alert.title)}">${esc(alert.title)}</td>`;
    tr.addEventListener("click", () => openDetail(alert.id));
    tbody.appendChild(tr);
  }
}

async function openDetail(id) {
  state.selectedId = id;
  document.querySelectorAll("#alert-table tbody tr").forEach((tr) =>
    tr.classList.toggle("selected", Number(tr.dataset.id) === id)
  );

  const a = await fetchJSON(`/api/alerts/${id}`);
  const ai = a.ai_summary
    ? `<div class="ai-summary">${esc(a.ai_summary)}</div>`
    : `<div class="ai-missing">no AI writeup yet — run: sentryd triage ${a.id}</div>`;

  $("#detail-body").innerHTML = `
    <h2><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span> ${esc(a.title)}</h2>
    <dl>
      <dt>rule</dt><dd>${esc(a.rule_id)}</dd>
      <dt>time</dt><dd>${fmtTime(a.ts)} UTC</dd>
      <dt>source</dt><dd>${esc(a.src ?? "-")}</dd>
      <dt>target</dt><dd>${esc(a.dst ?? "-")}</dd>
      <dt>confidence</dt><dd>${a.confidence.toFixed(2)}</dd>
      <dt>occurrences</dt><dd>${a.count}</dd>
      <dt>status</dt><dd>${esc(a.status)}</dd>
    </dl>
    <h3>evidence</h3>
    <pre>${esc(JSON.stringify(a.evidence, null, 2))}</pre>
    <h3>AI triage</h3>
    ${ai}`;
  $("#detail").hidden = false;
}

function closeDetail() {
  state.selectedId = null;
  $("#detail").hidden = true;
  document
    .querySelectorAll("#alert-table tbody tr.selected")
    .forEach((tr) => tr.classList.remove("selected"));
}

async function refresh() {
  try {
    await Promise.all([refreshStats(), refreshAlerts()]);
  } catch (err) {
    console.error("refresh failed:", err);
  }
}

for (const sel of ["#filter-severity", "#filter-rule", "#filter-status"]) {
  $(sel).addEventListener("change", refresh);
}
$("#detail-close").addEventListener("click", closeDetail);

setInterval(() => {
  if ($("#auto-refresh").checked) refresh();
}, 5000);

refresh();
