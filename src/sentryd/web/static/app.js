"use strict";

/* ============ shared helpers ============ */

const $ = (sel) => document.querySelector(sel);
const SEVERITIES = ["critical", "high", "medium", "low"];

const state = {
  route: "dashboard",
  caseId: null, // dashboard scope filter ("" = all)
  detailCaseId: null, // case detail view
  selectedId: null,
  knownRules: new Set(),
  alerts: [],
};

function fmtTime(ts, withDate = true) {
  const iso = new Date(ts * 1000).toISOString();
  return withDate ? iso.replace("T", " ").slice(0, 19) : iso.slice(11, 19);
}

function fmtBytes(n) {
  if (n == null) return "";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function esc(value) {
  const div = document.createElement("div");
  div.textContent = String(value);
  return div.innerHTML;
}

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try { detail = (await res.json()).detail || detail; } catch { /* keep default */ }
    throw new Error(detail);
  }
  return res.json();
}

async function send(url, options = {}) {
  const res = await fetch(url, { method: "POST", ...options });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try { detail = (await res.json()).detail || detail; } catch { /* keep default */ }
    throw new Error(detail);
  }
  return res.json();
}

function badge(severity) {
  return `<span class="badge ${esc(severity)}"><span class="dot"></span>${esc(severity)}</span>`;
}

function statusChip(status) {
  return `<span class="status-badge ${esc(status)}">${status === "running" ? '<span class="spinner"></span>' : ""}${esc(status)}</span>`;
}

function hostLink(ip) {
  if (!ip) return "&mdash;";
  return `<a class="host-link mono" data-host="${esc(ip)}" href="#" title="Host detail">${esc(ip)}</a>`;
}

let toastTimer = null;
function toast(message, kind = "error") {
  const el = $("#toast");
  el.textContent = message;
  el.className = `toast ${kind}`;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 6000);
}

/* Minimal, safe markdown renderer for AI reports: headings, lists, bold,
   inline code. Input is escaped first; nothing raw ever reaches innerHTML. */
function renderMarkdown(md) {
  const out = [];
  let list = null; // "ul" | "ol" | null
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  const inline = (s) =>
    s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
     .replace(/`([^`]+)`/g, "<code>$1</code>")
     .replace(/\[#(\d+)\]/g, '<a class="alert-ref" data-alert="$1" href="#">[#$1]</a>');

  for (const raw of esc(md).split("\n")) {
    const line = raw.trimEnd();
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      closeList();
      const level = Math.min(heading[1].length + 1, 5);
      out.push(`<h${level}>${inline(heading[2])}</h${level}>`);
    } else if (/^[-*]\s+/.test(line)) {
      if (list !== "ul") { closeList(); out.push("<ul>"); list = "ul"; }
      out.push(`<li>${inline(line.replace(/^[-*]\s+/, ""))}</li>`);
    } else if (/^\d+[.)]\s+/.test(line)) {
      if (list !== "ol") { closeList(); out.push("<ol>"); list = "ol"; }
      out.push(`<li>${inline(line.replace(/^\d+[.)]\s+/, ""))}</li>`);
    } else if (line === "") {
      closeList();
    } else {
      closeList();
      out.push(`<p>${inline(line)}</p>`);
    }
  }
  closeList();
  return out.join("\n");
}

/* ============ theme ============ */

$("#theme-toggle").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme
    ? root.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  localStorage.setItem("sentryd-theme", root.dataset.theme);
});

/* ============ tooltip ============ */

const tooltip = $("#tooltip");
function showTooltip(html, x, y) {
  tooltip.innerHTML = html;
  tooltip.hidden = false;
  const rect = tooltip.getBoundingClientRect();
  tooltip.style.left = `${Math.min(x + 12, window.innerWidth - rect.width - 8)}px`;
  tooltip.style.top = `${Math.max(y - rect.height - 10, 8)}px`;
}
function hideTooltip() { tooltip.hidden = true; }

/* ============ router ============ */

function parseRoute() {
  const hash = location.hash.replace(/^#\/?/, "");
  if (hash.startsWith("case/")) return { view: "case", id: Number(hash.slice(5)) };
  if (hash === "cases") return { view: "cases" };
  return { view: "dashboard" };
}

function navigate() {
  const route = parseRoute();
  state.route = route.view;
  for (const view of ["dashboard", "cases", "case"]) {
    $(`#view-${view}`).hidden = view !== route.view;
  }
  document.querySelectorAll(".tabs a").forEach((a) => {
    const tab = a.dataset.tab;
    a.classList.toggle(
      "active",
      tab === route.view || (tab === "cases" && route.view === "case")
    );
  });
  closeDrawer();
  if (route.view === "case") {
    state.detailCaseId = route.id;
    loadCaseDetail(route.id).catch((e) => toast(e.message));
  } else if (route.view === "cases") {
    refreshCases().catch((e) => toast(e.message));
  } else {
    refreshDashboard().catch(() => {});
  }
}

window.addEventListener("hashchange", navigate);

/* ============ dashboard ============ */

function caseParam(prefix = "&") {
  return state.caseId ? `${prefix}case=${state.caseId}` : "";
}

async function refreshCaseFilter() {
  const cases = (await fetchJSON("/api/cases")).cases;
  const select = $("#case-filter");
  const current = select.value;
  select.innerHTML = '<option value="">All cases</option>';
  for (const c of cases) {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = `#${c.id} ${c.name}`;
    select.appendChild(opt);
  }
  select.value = current;
}

async function refreshStats() {
  const stats = await fetchJSON(`/api/stats?x=1${caseParam()}`);
  const sev = stats.by_severity;
  const severe = (sev.high || 0) + (sev.critical || 0);
  const ruleCount = Object.keys(stats.by_rule).length;

  $("#kpi-total").textContent = stats.total;
  $("#kpi-total-hint").textContent = stats.total
    ? `across ${ruleCount} rule${ruleCount === 1 ? "" : "s"}`
    : "nothing recorded yet";
  $("#kpi-severe").textContent = severe;
  $("#kpi-severe-hint").textContent = stats.total
    ? `${Math.round((severe / stats.total) * 100)}% of all alerts`
    : "";
  $("#kpi-sources").textContent = stats.sources;
  $("#kpi-triaged").textContent = stats.triaged;
  $("#kpi-triaged-hint").textContent =
    stats.total && !stats.triaged ? "no AI writeups yet" : "AI writeups stored";

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

async function refreshTimeline() {
  const data = await fetchJSON(`/api/timeline?buckets=40${caseParam()}`);
  renderTimeline($("#timeline"), $("#timeline-axis"), data);
}

function renderTimeline(container, axis, data) {
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
          .map((s) => `<div class="tt-row"><span>${s}</span><span>${bucket.by_severity[s]}</span></div>`)
          .join("");
        showTooltip(
          `<div class="tt-title">${bucket.count} alert${bucket.count === 1 ? "" : "s"}</div>
           <div class="tt-row"><span>${fmtTime(bucket.start, false)}</span><span>&ndash;</span><span>${fmtTime(bucket.end, false)}</span></div>${rows}`,
          ev.clientX, ev.clientY
        );
      });
      bar.addEventListener("mouseleave", hideTooltip);
    }
    container.appendChild(bar);
  }
  axis.innerHTML = `<span>${fmtTime(data.start)}</span><span>${fmtTime(data.end)}</span>`;
}

function currentFilters() {
  const params = new URLSearchParams();
  const severity = $("#filter-severity").value;
  const rule = $("#filter-rule").value;
  const status = $("#filter-status").value;
  if (severity) params.set("severity", severity);
  if (rule) params.set("rule", rule);
  if (status) params.set("status", status);
  if (state.caseId) params.set("case", state.caseId);
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
  renderAlertTable();
}

function alertRow(a) {
  return `
    <tr data-id="${a.id}" tabindex="0" ${a.id === state.selectedId ? 'class="selected"' : ""}>
      <td class="num">${a.id}</td>
      <td class="mono">${fmtTime(a.ts)}</td>
      <td>${badge(a.severity)}</td>
      <td class="mono">${esc(a.rule_id)}</td>
      <td>${hostLink(a.src)}</td>
      <td>${hostLink(a.dst)}</td>
      <td class="num"><span class="count-pill">${a.count}</span></td>
      <td class="title-cell" title="${esc(a.title)}">${esc(a.title)}</td>
      <td class="ai-cell">${a.ai_summary ? "&#10003;" : "&mdash;"}</td>
    </tr>`;
}

function bindAlertRows(tbody) {
  for (const tr of tbody.querySelectorAll("tr")) {
    const open = () => openAlertDrawer(Number(tr.dataset.id));
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter") open(); });
  }
  for (const link of tbody.querySelectorAll(".host-link")) {
    link.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      openHostDrawer(link.dataset.host);
    });
  }
}

function renderAlertTable() {
  const needle = $("#filter-search").value.trim();
  const rows = state.alerts.filter((a) => textMatch(a, needle));
  const tbody = $("#alert-table tbody");
  $("#empty").hidden = rows.length > 0;
  tbody.innerHTML = rows.map(alertRow).join("");
  bindAlertRows(tbody);
}

async function refreshDashboard() {
  $("#export-alerts-csv").href = `/api/export/alerts?format=csv${caseParam()}`;
  await Promise.all([refreshCaseFilter(), refreshStats(), refreshTimeline(), refreshAlerts()]);
  $("#updated").textContent = `updated ${new Date().toLocaleTimeString()}`;
}

$("#case-filter").addEventListener("change", () => {
  state.caseId = $("#case-filter").value;
  refreshDashboard().catch((e) => toast(e.message));
});
for (const sel of ["#filter-severity", "#filter-rule", "#filter-status"]) {
  $(sel).addEventListener("change", () => refreshAlerts().catch((e) => toast(e.message)));
}
$("#filter-search").addEventListener("input", renderAlertTable);

/* ============ cases view ============ */

async function refreshCases() {
  const includeArchived = $("#show-archived").checked;
  const data = await fetchJSON(`/api/cases?include_archived=${includeArchived}`);
  const tbody = $("#case-table tbody");
  $("#cases-empty").hidden = data.cases.length > 0;
  tbody.innerHTML = data.cases
    .map(
      (c) => `
      <tr data-id="${c.id}" tabindex="0">
        <td class="num">${c.id}</td>
        <td>${esc(c.name)}</td>
        <td class="mono">${esc(c.source_kind)}:${esc(c.source)}</td>
        <td>${statusChip(c.status)}</td>
        <td class="num">${c.events_processed}</td>
        <td class="num">${c.alert_count}</td>
        <td class="mono">${esc(c.created_at)}</td>
        <td class="ai-cell">${c.ai_report ? "&#10003;" : "&mdash;"}</td>
      </tr>`
    )
    .join("");
  for (const tr of tbody.querySelectorAll("tr")) {
    const open = () => { location.hash = `#/case/${tr.dataset.id}`; };
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter") open(); });
  }
  $("#updated").textContent = `updated ${new Date().toLocaleTimeString()}`;
}

$("#show-archived").addEventListener("change", () => refreshCases().catch((e) => toast(e.message)));

async function uploadPcap(file) {
  const status = $("#upload-status");
  status.hidden = false;
  status.innerHTML = `<span class="spinner"></span> Uploading ${esc(file.name)} (${fmtBytes(file.size)})`;
  const form = new FormData();
  form.append("file", file);
  try {
    const { case: created } = await send("/api/pcaps/upload", { body: form });
    status.innerHTML = `<span class="spinner"></span> Case #${created.id} created, replaying`;
    await watchCase(created.id, status);
  } catch (err) {
    status.innerHTML = `<span class="err">Upload failed: ${esc(err.message)}</span>`;
  }
}

async function watchCase(caseId, statusEl) {
  for (let i = 0; i < 600; i++) {
    const s = await fetchJSON(`/api/cases/${caseId}/status`);
    if (s.status === "complete") {
      statusEl.innerHTML =
        `Case #${caseId} complete: ${s.events_processed} events, ${s.alert_count} alert${s.alert_count === 1 ? "" : "s"}. ` +
        `<a href="#/case/${caseId}">Open case &rarr;</a>`;
      refreshCases().catch(() => {});
      return;
    }
    if (s.status === "failed") {
      statusEl.innerHTML = `<span class="err">Case #${caseId} failed: ${esc(s.error || "unknown error")}</span>`;
      refreshCases().catch(() => {});
      return;
    }
    statusEl.innerHTML = `<span class="spinner"></span> Replaying case #${caseId}: ${s.events_processed} events so far`;
    await new Promise((r) => setTimeout(r, 500));
  }
}

const dropzone = $("#dropzone");
dropzone.addEventListener("click", () => $("#file-input").click());
dropzone.addEventListener("keydown", (ev) => { if (ev.key === "Enter") $("#file-input").click(); });
$("#file-input").addEventListener("change", () => {
  if ($("#file-input").files[0]) uploadPcap($("#file-input").files[0]);
});
for (const evName of ["dragover", "dragenter"]) {
  dropzone.addEventListener(evName, (ev) => { ev.preventDefault(); dropzone.classList.add("hover"); });
}
for (const evName of ["dragleave", "drop"]) {
  dropzone.addEventListener(evName, (ev) => { ev.preventDefault(); dropzone.classList.remove("hover"); });
}
dropzone.addEventListener("drop", (ev) => {
  const file = ev.dataTransfer.files[0];
  if (file) uploadPcap(file);
});

$("#server-path-go").addEventListener("click", async () => {
  const path = $("#server-path").value.trim();
  if (!path) return;
  const status = $("#upload-status");
  status.hidden = false;
  try {
    const { case: created } = await send("/api/replay", {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    status.innerHTML = `<span class="spinner"></span> Case #${created.id} created, replaying`;
    await watchCase(created.id, status);
  } catch (err) {
    status.innerHTML = `<span class="err">Replay failed: ${esc(err.message)}</span>`;
  }
});

/* ============ case detail ============ */

async function loadCaseDetail(caseId) {
  const body = $("#case-body");
  body.innerHTML = `<div class="loading"><span class="spinner"></span> Loading case</div>`;
  const detail = await fetchJSON(`/api/cases/${caseId}`);
  const c = detail.case;
  $("#case-title").textContent = `Case #${c.id}: ${c.name}`;
  $("#case-status-chip").innerHTML = statusChip(c.status);

  const sev = detail.stats.by_severity;
  const sevChips = SEVERITIES.filter((s) => sev[s])
    .map((s) => `<span class="badge ${s}"><span class="dot"></span>${s} ${sev[s]}</span>`)
    .join(" ");
  const span =
    c.start_ts != null ? `${fmtTime(c.start_ts)} to ${fmtTime(c.end_ts)} UTC` : "-";
  const pcapMeta = c.pcap_sha256
    ? `<dt>PCAP</dt><dd class="mono" title="${esc(c.pcap_sha256)}">sha256 ${esc(c.pcap_sha256.slice(0, 20))}&hellip; (${fmtBytes(c.pcap_size)})</dd>`
    : "";

  const clusters = detail.clusters
    .map(
      (cl) => `
      <div class="cluster">
        <div class="cluster-head">
          ${badge(cl.max_severity)}
          <span class="cluster-src">${hostLink(cl.source)}</span>
          <span class="cluster-targets">&rarr; ${cl.targets.length ? cl.targets.map(hostLink).join(", ") : "&mdash;"}</span>
        </div>
        <div class="cluster-chain">${esc(cl.chain)}</div>
        <div class="cluster-meta">${cl.alert_count} alert${cl.alert_count === 1 ? "" : "s"},
          ${fmtTime(cl.first_seen, false)} to ${fmtTime(cl.last_seen, false)} UTC</div>
      </div>`
    )
    .join("");

  body.innerHTML = `
    <section class="card">
      <div class="card-head"><h2>Case summary</h2>
        <div class="btn-row">
          <a class="btn ghost" href="/api/cases/${c.id}/report?format=md" download>Report .md</a>
          <a class="btn ghost" href="/api/cases/${c.id}/report?format=json" download>Bundle .json</a>
          <a class="btn ghost" href="/api/export/alerts?format=csv&case=${c.id}" download>Alerts .csv</a>
          <button class="btn ghost" id="case-archive">${c.status === "archived" ? "Archived" : "Archive"}</button>
          <button class="btn danger" id="case-delete">Delete</button>
        </div>
      </div>
      <div class="case-summary">
        <dl class="meta-grid">
          <dt>Source</dt><dd class="mono">${esc(c.source_kind)}:${esc(c.source)}</dd>
          <dt>Created</dt><dd class="mono">${esc(c.created_at)} UTC</dd>
          <dt>Traffic</dt><dd>${c.events_processed} events, ${span}</dd>
          ${pcapMeta}
          <dt>Alerts</dt><dd>${detail.stats.total} ${sevChips}</dd>
        </dl>
        <div class="notes-row">
          <textarea id="case-notes" rows="2" placeholder="Analyst notes for this case">${esc(c.notes || "")}</textarea>
          <button class="btn" id="save-notes">Save notes</button>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="card-head"><h2>Overall AI review</h2>
        <div class="btn-row">
          <button class="btn primary" id="run-triage">${c.ai_report ? "Regenerate" : "Run AI review"}</button>
        </div>
      </div>
      <div id="triage-body" class="triage-body">
        ${c.ai_report
          ? `<div class="report">${renderMarkdown(c.ai_report)}</div>
             <p class="card-note">generated ${esc(c.ai_report_at)} UTC from a bounded evidence digest</p>`
          : `<div class="empty-inline">No AI review yet. The review sends a size-capped digest of
             alert metadata (never raw packets) to the configured provider.</div>`}
      </div>
    </section>

    <section class="card">
      <div class="card-head"><h2>Correlated activity</h2></div>
      <div class="clusters">${clusters || '<div class="empty-inline">No alerts to correlate.</div>'}</div>
    </section>

    <section class="card chart-card">
      <div class="card-head"><h2>Alert activity</h2><span class="card-note">event time</span></div>
      <div id="case-timeline" class="timeline"></div>
      <div id="case-timeline-axis" class="timeline-axis"></div>
    </section>

    <section class="card table-card">
      <div class="card-head"><h2>Alerts (${detail.stats.total})</h2></div>
      <div class="table-wrap">
        <table class="case-alerts">
          <thead><tr>
            <th class="num">ID</th><th>Time (UTC)</th><th>Severity</th><th>Rule</th>
            <th>Source</th><th>Target</th><th class="num">Count</th><th>Title</th><th>AI</th>
          </tr></thead>
          <tbody></tbody>
        </table>
      </div>
      ${detail.stats.total === 0 ? '<div class="empty"><p>This case produced no alerts.</p></div>' : ""}
    </section>`;

  const timelineData = await fetchJSON(`/api/timeline?buckets=40&case=${c.id}`);
  renderTimeline($("#case-timeline"), $("#case-timeline-axis"), timelineData);

  const alerts = (await fetchJSON(`/api/alerts?case=${c.id}&limit=500`)).alerts;
  const tbody = body.querySelector(".case-alerts tbody");
  tbody.innerHTML = alerts.map(alertRow).join("");
  bindAlertRows(tbody);

  $("#save-notes").addEventListener("click", async () => {
    try {
      await send(`/api/cases/${c.id}/notes`, {
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: $("#case-notes").value }),
      });
      toast("Notes saved", "ok");
    } catch (err) { toast(err.message); }
  });

  $("#case-archive").addEventListener("click", async () => {
    try {
      await send(`/api/cases/${c.id}/archive`);
      toast(`Case #${c.id} archived`, "ok");
      loadCaseDetail(c.id).catch(() => {});
    } catch (err) { toast(err.message); }
  });

  $("#case-delete").addEventListener("click", async () => {
    if (!confirm(`Delete case #${c.id} and all its alerts?`)) return;
    try {
      await fetch(`/api/cases/${c.id}`, { method: "DELETE" });
      location.hash = "#/cases";
    } catch (err) { toast(err.message); }
  });

  $("#run-triage").addEventListener("click", async () => {
    const button = $("#run-triage");
    const target = $("#triage-body");
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span> Reviewing';
    target.innerHTML = `<div class="empty-inline"><span class="spinner"></span>
      Building the evidence digest and asking the AI for an overall review. This can take up to a minute.</div>`;
    try {
      const updated = await send(`/api/cases/${c.id}/triage?force=${Boolean(c.ai_report)}`);
      target.innerHTML = `<div class="report">${renderMarkdown(updated.ai_report)}</div>
        <p class="card-note">generated ${esc(updated.ai_report_at)} UTC from a bounded evidence digest</p>`;
      button.textContent = "Regenerate";
    } catch (err) {
      target.innerHTML = `<div class="empty-inline err">${esc(err.message)}</div>`;
      button.textContent = c.ai_report ? "Regenerate" : "Run AI review";
    } finally {
      button.disabled = false;
    }
  });
}

/* ============ drawers ============ */

function openDrawer() { $("#drawer").hidden = false; $("#scrim").hidden = false; }
function closeDrawer() {
  state.selectedId = null;
  $("#drawer").hidden = true;
  $("#scrim").hidden = true;
}
$("#drawer-close").addEventListener("click", closeDrawer);
$("#scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && !$("#drawer").hidden) closeDrawer();
});

async function openAlertDrawer(id) {
  state.selectedId = id;
  if (state.route === "dashboard") renderAlertTable();

  const a = await fetchJSON(`/api/alerts/${id}`);
  $("#drawer-title").innerHTML = `
    <div class="alert-id">ALERT #${a.id} &middot; ${esc(a.rule_id)}${a.case_id ? ` &middot; <a href="#/case/${a.case_id}">case #${a.case_id}</a>` : ""}</div>
    <div class="alert-title">${esc(a.title)}</div>
    ${badge(a.severity)} <span class="status-chip">&middot; ${esc(a.status)}</span>`;

  const flow =
    `${a.src ?? "?"}${a.src_port ? ":" + a.src_port : ""} &rarr; ` +
    `${a.dst ?? "?"}${a.dst_port ? ":" + a.dst_port : ""}` +
    (a.protocol ? ` (${esc(a.protocol)})` : "");

  const related = (a.related || [])
    .slice(0, 6)
    .map(
      (r) => `<li><a href="#" class="related-link" data-alert="${r.id}">#${r.id}</a>
        ${badge(r.severity)} <span class="mono">${esc(r.rule_id)}</span> ${esc(r.title)}</li>`
    )
    .join("");

  const ai = a.ai_summary
    ? `<div class="ai-writeup">${esc(a.ai_summary)}</div>`
    : `<div class="ai-missing">No AI writeup yet.
       <button class="btn small" id="explain-alert">Explain with AI</button></div>`;

  const volume = [];
  if (a.packet_count != null) volume.push(`${a.packet_count} packets`);
  if (a.byte_count != null) volume.push(`${a.byte_count.toLocaleString()} bytes`);

  const VERDICT_BUTTONS = [
    ["confirmed", "Confirm"],
    ["false_positive", "False positive"],
    ["expected", "Expected"],
    ["ignored", "Ignore"],
    ["new", "Reset"],
  ];
  const verdicts = VERDICT_BUTTONS.map(
    ([value, label]) =>
      `<button class="btn small verdict-btn ${a.status === value ? "primary" : "ghost"}"
        data-verdict="${value}">${label}</button>`
  ).join("");

  $("#drawer-body").innerHTML = `
    <dl class="meta-grid">
      <dt>First seen</dt><dd class="mono">${fmtTime(a.ts)} UTC</dd>
      <dt>Last seen</dt><dd class="mono">${fmtTime(a.last_ts)} UTC</dd>
      <dt>Flow</dt><dd class="mono">${flow}</dd>
      <dt>Confidence</dt><dd>${a.confidence.toFixed(2)}</dd>
      <dt>Occurrences</dt><dd>${a.count}</dd>
      ${volume.length ? `<dt>Volume</dt><dd>${volume.join(", ")}</dd>` : ""}
      <dt>Verdict</dt><dd><span class="status-chip">${esc(a.status)}</span></dd>
    </dl>
    <h3>Verdict</h3>
    <div class="verdict-row btn-row">${verdicts}</div>
    ${a.reason ? `<h3>Why this fired</h3><p class="reason">${esc(a.reason)}</p>` : ""}
    <h3>Evidence</h3>
    <pre class="mono">${esc(JSON.stringify(a.evidence, null, 2))}</pre>
    ${related ? `<h3>Related alerts (same hosts)</h3><ul class="related">${related}</ul>` : ""}
    <h3>Suggested next step</h3>
    <p class="hint">${esc(a.investigation_hint)}</p>
    <h3>AI triage</h3>
    ${ai}`;

  for (const button of $("#drawer-body").querySelectorAll(".verdict-btn")) {
    button.addEventListener("click", async () => {
      try {
        await send(`/api/alerts/${a.id}/status`, {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: button.dataset.verdict }),
        });
        toast(`Marked ${button.dataset.verdict.replace("_", " ")}`, "ok");
        openAlertDrawer(a.id);
        if (state.route === "dashboard") refreshAlerts().catch(() => {});
      } catch (err) {
        toast(err.message);
      }
    });
  }

  for (const link of $("#drawer-body").querySelectorAll(".related-link")) {
    link.addEventListener("click", (ev) => {
      ev.preventDefault();
      openAlertDrawer(Number(link.dataset.alert));
    });
  }
  const explain = $("#explain-alert");
  if (explain) {
    explain.addEventListener("click", async () => {
      explain.disabled = true;
      explain.innerHTML = '<span class="spinner"></span> Explaining';
      try {
        await send(`/api/alerts/${a.id}/explain`);
        openAlertDrawer(a.id);
      } catch (err) {
        explain.replaceWith(Object.assign(document.createElement("span"), {
          className: "err", textContent: err.message,
        }));
      }
    });
  }
  openDrawer();
}

async function openHostDrawer(ip) {
  const scope = state.route === "case" ? `?case=${state.detailCaseId}` : (state.caseId ? `?case=${state.caseId}` : "");
  const host = await fetchJSON(`/api/hosts/${encodeURIComponent(ip)}${scope}`);
  $("#drawer-title").innerHTML = `
    <div class="alert-id">HOST${scope ? " (this case)" : ""}</div>
    <div class="alert-title mono">${esc(host.ip)}</div>`;
  const rows = host.alerts
    .map(
      (a) => `<li><a href="#" class="related-link" data-alert="${a.id}">#${a.id}</a>
        ${badge(a.severity)} <span class="mono">${esc(a.rule_id)}</span> ${esc(a.title)}</li>`
    )
    .join("");
  $("#drawer-body").innerHTML = `
    <dl class="meta-grid">
      <dt>As source</dt><dd>${host.alerts_as_source} alert${host.alerts_as_source === 1 ? "" : "s"}</dd>
      <dt>As target</dt><dd>${host.alerts_as_target} alert${host.alerts_as_target === 1 ? "" : "s"}</dd>
      <dt>Rules</dt><dd class="mono">${host.rules.map(esc).join(", ") || "&mdash;"}</dd>
      ${host.first_seen ? `<dt>First seen</dt><dd class="mono">${fmtTime(host.first_seen)} UTC</dd>` : ""}
      ${host.last_seen ? `<dt>Last seen</dt><dd class="mono">${fmtTime(host.last_seen)} UTC</dd>` : ""}
    </dl>
    <h3>Alerts involving this host</h3>
    ${rows ? `<ul class="related">${rows}</ul>` : '<p class="hint">None recorded.</p>'}`;
  for (const link of $("#drawer-body").querySelectorAll(".related-link")) {
    link.addEventListener("click", (ev) => {
      ev.preventDefault();
      openAlertDrawer(Number(link.dataset.alert));
    });
  }
  openDrawer();
}

/* ============ refresh loop ============ */

setInterval(() => {
  if (!$("#auto-refresh").checked || !$("#drawer").hidden) return;
  if (state.route === "dashboard") refreshDashboard().catch(() => {});
  else if (state.route === "cases") refreshCases().catch(() => {});
}, 5000);

navigate();
