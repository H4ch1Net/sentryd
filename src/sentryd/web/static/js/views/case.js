/* Case detail: risk, summary and notes, AI review, correlated activity with
   kill-chain phases, the attack graph, activity, and the case's alerts.

   The skeleton is built once per case; live refreshes update each section
   in place (and skip ones whose data didn't change), so notes being typed,
   scroll position, and table selection all survive an update. */

import { api, download } from "../api.js";
import { animateGauges, attackGraph, columnsChart, gauge, killChain } from "../charts.js";
import { ctx } from "../context.js";
import {
  $, SEVERITIES, badge, debounce, emptyState, esc, fmtBytes, fmtDuration, fmtNum, fmtTime,
  hostLink, icon, plural, renderMarkdown, skeletonRows, statusChip,
} from "../dom.js";
import { AlertTable } from "../table.js";
import { attachMenu, busy, confirmDialog, toast, toastError } from "../ui.js";

let caseId = null;
let table = null;
let timeline = null;
let sigs = {};
let alertsCache = [];
let window_ = null;
let seq = 0;

export function currentCase() { return caseId; }

function skeleton(id) {
  $("#case-body").innerHTML = `
    <div class="case-top">
      <section class="card risk-card" id="case-risk">${'<span class="skeleton" style="width:200px;height:120px;border-radius:120px 120px 12px 12px"></span>'}</section>
      <section class="card summary-card">
        <header class="card-head"><div><h2>Summary</h2><p class="card-sub" id="case-sub"></p></div></header>
        <dl class="facts" id="case-facts">${skeletonRows(4)}</dl>
        <div class="notes">
          <textarea id="case-notes" rows="2" placeholder="Analyst notes: saved automatically as you type" aria-label="Analyst notes"></textarea>
          <div class="notes-state" id="notes-state"></div>
        </div>
      </section>
    </div>
    <section class="card ai-card">
      <header class="card-head">
        <div><h2>Overall AI review</h2><p class="card-sub">a size-capped digest of alert metadata, never raw packets, sent only when you ask</p></div>
        <button class="btn primary" type="button" id="run-triage">${icon("sparkles")}Run AI review</button>
      </header>
      <div id="triage-body" class="triage-body"></div>
    </section>
    <section class="card">
      <header class="card-head"><div><h2>Correlated activity</h2><p class="card-sub">alerts grouped by offending source, phases in kill-chain order</p></div></header>
      <div class="clusters" id="case-clusters">${skeletonRows(3)}</div>
    </section>
    <section class="card">
      <header class="card-head">
        <div><h2>Attack graph</h2><p class="card-sub">who touched whom &middot; edge color is the pair's highest severity, weight its alert count</p></div>
        <div class="legend">${SEVERITIES.map((s) => `<span class="legend-item"><span class="legend-line" style="--sev:var(--sev-${s})"></span>${s}</span>`).join("")}</div>
      </header>
      <div class="graph-wrap" id="case-graph"></div>
    </section>
    <section class="card chart-card">
      <header class="card-head">
        <div><h2>Alert activity</h2><p class="card-sub">event time &middot; click a bar to filter the alerts below</p></div>
        <div class="legend"><span class="legend-item"><span class="swatch severe"></span>High &amp; critical</span><span class="legend-item"><span class="swatch other"></span>Low &amp; medium</span></div>
      </header>
      <div class="columns-chart" id="case-timeline" role="group" aria-label="Case alert counts over event time"></div>
    </section>
    <section class="card table-card">
      <header class="card-head table-head"><div><h2>Alerts</h2><p class="card-sub" id="case-alert-count"></p></div>
        <div class="chips" id="case-chips"></div></header>
      <div id="case-alerts"></div>
    </section>`;

  table = new AlertTable($("#case-alerts"), {
    onOpen: (aid, t) => ctx.openAlert(aid, t),
    onHost: (ip) => ctx.openHost(ip),
    onBulk: (ids, status, t) => ctx.bulkVerdict(ids, status, t),
    emptyHtml: () => (alertsCache.length
      ? emptyState("filter", "No alerts in this window", "Click the selected bar again to clear the time filter.")
      : emptyState("shield", "This case produced no alerts", "Every enabled rule ran over the capture and nothing crossed a threshold.")),
  });
  ctx.activeTable = table;
  timeline = columnsChart($("#case-timeline"), {
    onSelect(w) {
      window_ = w;
      applyWindow();
    },
  });

  const notes = $("#case-notes");
  const state = $("#notes-state");
  const save = debounce(async () => {
    state.className = "notes-state";
    state.textContent = "Saving…";
    try {
      await api(`/api/cases/${id}/notes`, { method: "POST", json: { notes: notes.value } });
      notes.dataset.saved = notes.value;
      state.className = "notes-state saved";
      state.innerHTML = `${icon("check")} Saved`;
    } catch (err) {
      state.textContent = "";
      toastError(err);
    }
  }, 700);
  notes.addEventListener("input", () => { state.className = "notes-state"; state.textContent = "Editing…"; save(); });
  notes.addEventListener("blur", () => { if (notes.value !== notes.dataset.saved) save.flush(); });

  $("#triage-body").addEventListener("click", (ev) => {
    const ref = ev.target.closest(".alert-ref");
    if (ref) { ev.preventDefault(); ctx.openAlert(Number(ref.dataset.alert), table); }
  });
  $("#case-clusters").addEventListener("click", (ev) => {
    const host = ev.target.closest(".host-link");
    if (host) { ev.preventDefault(); ctx.openHost(host.dataset.host); }
  });
  $("#run-triage").addEventListener("click", (ev) => runTriage(ev.currentTarget));
}

function applyWindow() {
  const rows = window_ ? alertsCache.filter((a) => a.ts >= window_.start && a.ts <= window_.end) : alertsCache;
  table.setAlerts(rows);
  $("#case-chips").innerHTML = window_
    ? `<span class="chip">${icon("pulse")}${fmtTime(window_.start, false)} to ${fmtTime(window_.end, false)} UTC<button type="button" aria-label="Clear time filter">${icon("x")}</button></span>` : "";
  $("#case-chips").onclick = (ev) => { if (ev.target.closest("button")) { window_ = null; timeline.clear(); applyWindow(); } };
}

function headerActions(c) {
  const actions = $("#case-actions");
  actions.innerHTML = `
    <div class="menu"><button class="btn" type="button" id="case-export">${icon("download")}Export${icon("chevron-down")}</button></div>
    <button class="btn" type="button" id="case-archive" ${c.status === "archived" || c.status === "running" ? "disabled" : ""}>${icon("archive")}${c.status === "archived" ? "Archived" : "Archive"}</button>
    <button class="btn danger" type="button" id="case-delete" ${c.status === "running" ? "disabled" : ""}>${icon("trash")}Delete</button>`;
  const save = (path, name) => () => download(path, name).catch(toastError);
  attachMenu($("#case-export"), [
    { label: "Analyst report", sub: ".md", icon: "file", run: save(`/api/cases/${c.id}/report?format=md`, `case-${c.id}-report.md`) },
    { label: "Full bundle", sub: ".json", icon: "file", run: save(`/api/cases/${c.id}/report?format=json`, `case-${c.id}.json`) },
    { label: "Alerts", sub: ".csv", icon: "download", run: save(`/api/export/alerts?format=csv&case=${c.id}`, "alerts.csv") },
  ]);
  $("#case-archive").addEventListener("click", (ev) => busy(ev.currentTarget, async () => {
    try {
      await api(`/api/cases/${c.id}/archive`, { method: "POST" });
      toast(`Case #${c.id} archived`, { kind: "ok" });
      await ctx.sync();
    } catch (err) { toastError(err); }
  }));
  $("#case-delete").addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: `Delete case #${c.id}?`,
      body: `<b>${esc(c.name)}</b> and its ${plural(c.alert_count, "alert")}, notes and AI review will be removed. This can't be undone.`,
      confirmLabel: "Delete case",
      danger: true,
    });
    if (!ok) return;
    try {
      await api(`/api/cases/${c.id}`, { method: "DELETE" });
      toast(`Case #${c.id} deleted`, { kind: "ok" });
      ctx.navigate("#/cases");
    } catch (err) { toastError(err); }
  });
}

function renderRisk(risk) {
  const el = $("#case-risk");
  el.dataset.level = risk.level;
  el.innerHTML = `${gauge(risk.score)}
    <span class="risk-level"><span class="dot"></span>${risk.level === "none" ? "no open risk" : `${esc(risk.level)} risk`}</span>
    ${risk.source ? `<span class="risk-source">driven by ${hostLink(risk.source)}</span>` : '<span class="risk-source">no alerts to score</span>'}
    ${risk.factors.length ? `<ul class="factors">${risk.factors.map((f) => `<li><span>${esc(f.factor)}</span><b>+${f.points}</b></li>`).join("")}</ul>` : ""}`;
  el.onclick = (ev) => { const h = ev.target.closest(".host-link"); if (h) { ev.preventDefault(); ctx.openHost(h.dataset.host); } };
  animateGauges(el);
}

function renderFacts(c, stats) {
  const span = c.start_ts != null ? `${fmtTime(c.start_ts)} to ${fmtTime(c.end_ts, false)} UTC <span class="dim">(${fmtDuration(c.end_ts - c.start_ts)})</span>` : "-";
  const sev = SEVERITIES.filter((s) => stats.by_severity[s]).map((s) => badge(s, stats.by_severity[s])).join(" ");
  $("#case-sub").textContent = `${c.source_kind} case · created ${c.created_at} UTC`;
  $("#case-facts").innerHTML = `
    <dt>Source</dt><dd class="mono">${esc(c.source)}</dd>
    <dt>Traffic</dt><dd>${plural(c.events_processed, "event")} &middot; ${span}</dd>
    ${c.pcap_sha256 ? `<dt>Capture</dt><dd class="mono" title="${esc(c.pcap_sha256)}">sha256 ${esc(c.pcap_sha256.slice(0, 16))}&hellip; &middot; ${fmtBytes(c.pcap_size)}</dd>` : ""}
    <dt>Alerts</dt><dd>${fmtNum(stats.total)} ${sev}</dd>
    <dt>Reviewed</dt><dd>${stats.total ? `${stats.total - stats.open} of ${stats.total} have a verdict` : "-"}</dd>
    ${c.error ? `<dt>Error</dt><dd class="err">${esc(c.error)}</dd>` : ""}`;
}

function renderNotes(c) {
  const notes = $("#case-notes");
  // Never clobber what the analyst is typing.
  if (document.activeElement === notes || (notes.dataset.saved !== undefined && notes.value !== notes.dataset.saved)) return;
  notes.value = c.notes || "";
  notes.dataset.saved = notes.value;
}

function renderTriage(c) {
  const body = $("#triage-body");
  if (body.dataset.busy) return;
  const button = $("#run-triage");
  button.innerHTML = `${icon("sparkles")}${c.ai_report ? "Regenerate" : "Run AI review"}`;
  button.dataset.force = c.ai_report ? "true" : "false";
  body.innerHTML = c.ai_report
    ? `<div class="report">${renderMarkdown(c.ai_report)}</div><p class="card-sub">generated ${esc(c.ai_report_at)} UTC from a bounded evidence digest</p>`
    : `<p class="empty-inline" style="padding:0.4rem 0 0">No AI review yet. Detection, correlation and evidence on this page never depend on it.</p>`;
}

async function runTriage(button) {
  const body = $("#triage-body");
  body.dataset.busy = "1";
  body.innerHTML = `<div class="ai-thinking"><span class="bars3"><span></span><span></span><span></span></span>Building the evidence digest and asking for an overall review. This can take up to a minute.</div>`;
  try {
    await busy(button, () => api(`/api/cases/${caseId}/triage?force=${button.dataset.force}`, { method: "POST" }));
    delete body.dataset.busy;
    await ctx.sync();
  } catch (err) {
    delete body.dataset.busy;
    body.innerHTML = `<p class="err">${esc(err.message)}</p>`;
  }
}

function renderClusters(clusters) {
  const el = $("#case-clusters");
  if (!clusters.length) {
    el.innerHTML = '<p class="empty-inline">No alerts to correlate.</p>';
    return;
  }
  el.innerHTML = clusters.map((cl, i) => `
    <article class="cluster" style="animation-delay:${i * 50}ms">
      <div class="cluster-head">
        ${badge(cl.max_severity)}
        <span class="cluster-src">${hostLink(cl.source)}</span>
        <span class="cluster-targets">${icon("arrow-right")}${cl.targets.length ? cl.targets.slice(0, 4).map(hostLink).join(" ") + (cl.targets.length > 4 ? ` +${cl.targets.length - 4}` : "") : "no single target"}</span>
        <span class="risk-pill lvl-${esc(cl.risk.level)}" title="${esc(cl.risk.factors.map((f) => `${f.factor} +${f.points}`).join("\n"))}">
          risk <span class="mini-meter"><span style="width:${cl.risk.score}%"></span></span><b>${cl.risk.score}</b></span>
      </div>
      ${killChain(cl.phases)}
    </article>`).join("");
}

function renderGraph(alerts) {
  const el = $("#case-graph");
  const drawn = attackGraph(el, alerts, { onHost: (ip) => ctx.openHost(ip) });
  if (!drawn) {
    el.innerHTML = emptyState("graph", "No host-to-host activity", "Alerts here name a single host (volume spikes, ARP conflicts), so there are no edges to draw.");
  }
}

/** Load (or live-refresh) a case. */
export async function load(id, { quiet = false } = {}) {
  const mine = ++seq;
  if (id !== caseId) {
    caseId = id;
    sigs = {};
    window_ = null;
    $("#case-title").textContent = `Case #${id}`;
    $("#case-crumb").textContent = `#${id}`;
    $("#case-status-chip").innerHTML = "";
    $("#case-actions").innerHTML = "";
    skeleton(id);
  }
  ctx.activeTable = table;
  let detail;
  let alerts;
  let tl;
  try {
    [detail, { alerts }, tl] = await Promise.all([
      api(`/api/cases/${id}`),
      api(`/api/alerts?case=${id}&limit=500`),
      api(`/api/timeline?buckets=40&case=${id}`),
    ]);
  } catch (err) {
    if (err.status === 404) {
      $("#case-body").innerHTML = `<section class="card">${emptyState("cases", `Case #${id} doesn't exist`, 'It may have been deleted. <a href="#/cases">Back to cases</a>')}</section>`;
      caseId = null;
      return;
    }
    return toastError(err);
  }
  if (mine !== seq || id !== caseId) return;

  const c = detail.case;
  $("#case-title").textContent = c.name;
  $("#case-crumb").textContent = `#${c.id} ${c.name}`;
  $("#case-status-chip").innerHTML = statusChip(c.status);
  document.title = `#${c.id} ${c.name} · sentryd`;

  const changed = (key, value) => {
    const sig = JSON.stringify(value);
    if (sigs[key] === sig) return false;
    sigs[key] = sig;
    return true;
  };
  if (changed("actions", [c.status, c.name, c.alert_count])) headerActions(c);
  if (changed("risk", detail.risk)) renderRisk(detail.risk);
  if (changed("facts", [c, detail.stats])) renderFacts(c, detail.stats);
  renderNotes(c);
  if (changed("triage", [c.ai_report, c.ai_report_at])) renderTriage(c);
  if (changed("clusters", detail.clusters)) renderClusters(detail.clusters);
  if (changed("graph", alerts.map((a) => [a.id, a.severity, a.src, a.dst]))) renderGraph(alerts);
  timeline.update(tl);
  $("#case-alert-count").textContent = plural(detail.stats.total, "alert");
  alertsCache = alerts;
  if (window_) applyWindow();
  else table.setAlerts(alerts, { highlightNew: quiet });
}
