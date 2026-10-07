/* Alert and host detail, shown in the slide-over drawer. */

import { api } from "./api.js";
import { ctx } from "./context.js";
import {
  $, $$, VERDICTS, badge, copyText, esc, fmtDuration, fmtTime, hostLink, icon,
  highlightJSON, plural, verdictChip,
} from "./dom.js";
import { busy, closeDrawer, drawerOpen, openDrawer, toastError } from "./ui.js";

let current = null; // { kind: "alert", alert, table } | { kind: "host", ip }
let loadSeq = 0;

export function currentAlertId() {
  return drawerOpen() && current?.kind === "alert" ? current.alert.id : null;
}

/** Wrap sentryd/tshark commands in investigation hints as copyable code. */
function hintHtml(hint) {
  return esc(hint).replace(
    /(sentryd alerts list(?: --\w+ \w+)*)|(tshark -r &lt;pcap&gt; -Y &#39;.*?&#39;(?: -z [\w,]+)?)/g,
    (cmd) => `<code class="hint-cmd" role="button" tabindex="0" title="Click to copy">${cmd}</code>`
  );
}

function relatedList(alerts) {
  return `<ul class="related">${alerts.map((r) => `
    <li><a href="#" data-alert="${r.id}"><span class="rid">#${r.id}</span>${badge(r.severity)}<span class="rt">${esc(r.title)}</span></a></li>`).join("")}</ul>`;
}

function flowHtml(a) {
  const end = (role, ip, port) => `<div class="flow-end"><span class="role">${role}</span>
    <span class="addr">${ip ? hostLink(ip) : '<span class="dim">unknown</span>'}${port ? `<span class="port">:${port}</span>` : ""}</span></div>`;
  return `<div class="flow">${end("source", a.src, a.src_port)}
    <div class="flow-arrow"><svg viewBox="0 0 40 12" aria-hidden="true"><path d="M2 6h32"/><path d="M30 2l5 4-5 4" style="stroke-dasharray:none;animation:none"/></svg>${esc(a.protocol || "")}</div>
    ${end("target", a.dst, a.dst_port)}</div>`;
}

function alertBody(a) {
  const span = (a.last_ts ?? a.ts) - a.ts;
  const volume = [
    a.packet_count != null ? plural(a.packet_count, "packet") : null,
    a.byte_count != null ? `${a.byte_count.toLocaleString("en-US")} bytes` : null,
  ].filter(Boolean).join(", ");
  const verdicts = VERDICTS.map((v) => `<button type="button" data-verdict="${v.value}" aria-pressed="${a.status === v.value}" title="${v.label} (${v.key})">${icon(v.icon)}${v.label}<kbd>${v.key}</kbd></button>`).join("");
  const ai = a.ai_summary
    ? `<div class="ai-writeup">${esc(a.ai_summary)}</div>`
    : `<div class="ai-missing"><span>No AI writeup yet. Detection and evidence above stand on their own.</span>
       <button class="btn small" type="button" id="explain-alert">${icon("sparkles")}Explain with AI</button></div>`;
  return `
    ${flowHtml(a)}
    <div class="section"><div class="stats-grid">
      <div class="stat"><div class="k">First seen</div><div class="v mono">${fmtTime(a.ts, false)}</div></div>
      <div class="stat"><div class="k">Active for</div><div class="v">${span > 0 ? fmtDuration(span) : "single event"}</div></div>
      <div class="stat"><div class="k">Occurrences</div><div class="v">${a.count}</div></div>
      <div class="stat"><div class="k">Confidence</div><div class="v conf">${a.confidence.toFixed(2)}<span class="meter"><span class="meter-fill" style="width:${a.confidence * 100}%"></span></span></div></div>
      <div class="stat"><div class="k">Last seen</div><div class="v mono">${fmtTime(a.last_ts, false)}</div></div>
      <div class="stat"><div class="k">Volume</div><div class="v">${volume || "-"}</div></div>
    </div></div>
    <div class="section"><h3 class="section-title">Verdict</h3><div class="verdict-seg" role="group" aria-label="Verdict">${verdicts}</div></div>
    ${a.reason ? `<div class="section"><h3 class="section-title">Why this fired</h3><div class="callout">${esc(a.reason)}</div></div>` : ""}
    <div class="section"><h3 class="section-title">Evidence<button class="btn small ghost copy-btn" type="button" data-copy="evidence">${icon("copy")}Copy JSON</button></h3>
      <pre class="code">${highlightJSON(a.evidence)}</pre></div>
    <div class="section"><h3 class="section-title">Suggested next step</h3><p class="callout">${hintHtml(a.investigation_hint)}</p></div>
    ${a.related?.length ? `<div class="section"><h3 class="section-title">Related alerts (same hosts, same case)</h3>${relatedList(a.related.slice(0, 8))}</div>` : ""}
    <div class="section"><h3 class="section-title">AI triage</h3>${ai}</div>`;
}

/** Delegated handlers on the (reused) drawer body; bound once at boot. */
export function initDetails() {
  const body = $("#drawer-body");
  body.addEventListener("click", async (ev) => {
    const host = ev.target.closest(".host-link");
    if (host) { ev.preventDefault(); return openHost(host.dataset.host); }
    const rel = ev.target.closest("[data-alert]");
    if (rel) { ev.preventDefault(); return openAlert(Number(rel.dataset.alert)); }
    const cmd = ev.target.closest(".hint-cmd");
    if (cmd) return flashCopy(cmd, cmd.textContent);
  });
  body.addEventListener("keydown", (ev) => {
    const cmd = ev.target.closest(".hint-cmd");
    if (cmd && (ev.key === "Enter" || ev.key === " ")) { ev.preventDefault(); flashCopy(cmd, cmd.textContent); }
  });
}

async function flashCopy(el, text) {
  if (!(await copyText(text))) return;
  const before = el.innerHTML;
  el.classList.add("done");
  if (el.matches("button")) el.innerHTML = `${icon("check")}Copied`;
  else el.style.outline = "2px solid var(--sev-low)";
  setTimeout(() => {
    el.classList.remove("done");
    if (el.matches("button")) el.innerHTML = before;
    else el.style.outline = "";
  }, 1200);
}

/** Open (or swap the drawer to) one alert. `table` supplies prev/next. */
export async function openAlert(id, table = current?.table ?? ctx.activeTable) {
  const seq = ++loadSeq;
  let a;
  try {
    a = await api(`/api/alerts/${id}`);
  } catch (err) {
    return toastError(err);
  }
  if (seq !== loadSeq) return; // a newer open won the race
  current = { kind: "alert", alert: a, table };
  table?.setSelected(id);
  const nav = table?.neighbors(id) ?? {};
  const title = `
    <div class="drawer-eyebrow">Alert #${a.id} &middot; <span class="mono">${esc(a.rule_id)}</span>${a.case_id ? ` &middot; <a href="#/case/${a.case_id}">case #${a.case_id}</a>` : ""}${nav.index != null ? ` &middot; ${nav.index + 1} of ${table.visible.length}` : ""}</div>
    <h2 class="drawer-heading">${esc(a.title)}</h2>
    <div class="drawer-badges">${badge(a.severity)}${verdictChip(a.status)}</div>`;
  const body = openDrawer({
    title,
    body: alertBody(a),
    prev: nav.prev != null ? () => openAlert(nav.prev, table) : null,
    next: nav.next != null ? () => openAlert(nav.next, table) : null,
  });
  body.querySelector(".verdict-seg").addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-verdict]");
    if (b) setVerdict(b.dataset.verdict);
  });
  body.querySelector('[data-copy="evidence"]').addEventListener("click", (ev) =>
    flashCopy(ev.currentTarget, JSON.stringify(a.evidence, null, 2)));
  const explain = body.querySelector("#explain-alert");
  explain?.addEventListener("click", () => busy(explain, async () => {
    try {
      await api(`/api/alerts/${a.id}/explain`, { method: "POST" });
      await openAlert(a.id, table);
      ctx.sync();
    } catch (err) {
      explain.closest(".ai-missing").innerHTML = `<span class="err">${esc(err.message)}</span>`;
    }
  }));
}

/** Apply a verdict to the alert in the drawer (buttons or keys 1-5). */
export async function setVerdict(status) {
  if (current?.kind !== "alert" || current.alert.status === status) return;
  const { alert, table } = current;
  $$(".verdict-seg button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.verdict === status)));
  await ctx.setVerdict([alert.id], status, { previous: { [alert.id]: alert.status } });
  if (currentAlertId() === alert.id) await openAlert(alert.id, table);
}

export function verdictForKey(key) {
  return VERDICTS.find((v) => v.key === key)?.value ?? null;
}

export async function openHost(ip) {
  const seq = ++loadSeq;
  const scope = ctx.scopeCase?.();
  let host;
  try {
    host = await api(`/api/hosts/${encodeURIComponent(ip)}${scope ? `?case=${scope}` : ""}`);
  } catch (err) {
    return toastError(err);
  }
  if (seq !== loadSeq) return;
  current = { kind: "host", ip, table: current?.table };
  const span = host.first_seen != null ? fmtDuration((host.last_seen ?? host.first_seen) - host.first_seen) : "-";
  const title = `
    <div class="drawer-eyebrow">${icon("host")} Host${scope ? ` &middot; case #${scope}` : " &middot; all cases"}</div>
    <h2 class="drawer-heading mono">${esc(host.ip)}</h2>
    <div class="drawer-badges">${host.rules.map((r) => `<span class="verdict mono">${esc(r)}</span>`).join("")}</div>`;
  const body = openDrawer({
    title,
    body: `
      <div class="section"><div class="stats-grid">
        <div class="stat"><div class="k">As source</div><div class="v">${host.alerts_as_source}</div></div>
        <div class="stat"><div class="k">As target</div><div class="v">${host.alerts_as_target}</div></div>
        <div class="stat"><div class="k">Active for</div><div class="v">${span}</div></div>
        <div class="stat"><div class="k">First seen</div><div class="v mono">${fmtTime(host.first_seen, false)}</div></div>
        <div class="stat"><div class="k">Last seen</div><div class="v mono">${fmtTime(host.last_seen, false)}</div></div>
        <div class="stat"><div class="k">Rules</div><div class="v">${host.rules.length}</div></div>
      </div></div>
      <div class="section btn-row">
        <button class="btn small" type="button" id="host-filter">${icon("filter")}Filter overview to this host</button>
        <button class="btn small ghost copy-btn" type="button" id="host-copy">${icon("copy")}Copy address</button>
      </div>
      <div class="section"><h3 class="section-title">Alerts involving this host</h3>
        ${host.alerts.length ? relatedList(host.alerts) : '<p class="empty-inline">None recorded.</p>'}</div>`,
  });
  body.querySelector("#host-filter").addEventListener("click", () => {
    closeDrawer();
    ctx.filterOverview?.({ q: host.ip });
  });
  body.querySelector("#host-copy").addEventListener("click", (ev) => flashCopy(ev.currentTarget, host.ip));
}
