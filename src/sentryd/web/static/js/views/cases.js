/* Cases: upload a capture (real upload progress, then replay progress) and
   browse every case. */

import { ApiError, api, upload } from "../api.js";
import { ctx } from "../context.js";
import {
  $, emptyState, esc, fmtBytes, fmtNum, icon, plural, skeletonRows, statusChip,
} from "../dom.js";
import { toastError } from "../ui.js";

let listSig = null;
let watching = null; // case id being watched

export function initCases() {
  const dropzone = $("#dropzone");
  const input = $("#file-input");
  dropzone.addEventListener("click", () => input.click());
  dropzone.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); input.click(); }
  });
  input.addEventListener("change", () => {
    if (input.files[0]) startUpload(input.files[0]);
    input.value = "";
  });
  let depth = 0; // dragenter/leave fire for children too
  dropzone.addEventListener("dragenter", (ev) => { ev.preventDefault(); depth += 1; dropzone.classList.add("hover"); });
  dropzone.addEventListener("dragover", (ev) => { ev.preventDefault(); ev.dataTransfer.dropEffect = "copy"; });
  dropzone.addEventListener("dragleave", () => { depth -= 1; if (depth <= 0) { depth = 0; dropzone.classList.remove("hover"); } });
  dropzone.addEventListener("drop", (ev) => {
    ev.preventDefault();
    depth = 0;
    dropzone.classList.remove("hover");
    const file = ev.dataTransfer.files[0];
    if (file) startUpload(file);
  });
  // Dropping anywhere else on the page shouldn't navigate away to the file.
  window.addEventListener("dragover", (ev) => ev.preventDefault());
  window.addEventListener("drop", (ev) => ev.preventDefault());

  $("#server-path-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const path = $("#server-path").value.trim();
    if (!path) return;
    const status = statusBox();
    status.innerHTML = progressHtml(`Requesting replay of <span class="mono">${esc(path)}</span>`, null);
    try {
      const { case: created } = await api("/api/replay", { method: "POST", json: { path } });
      await watchCase(created.id, created.name);
    } catch (err) {
      fail(err);
    }
  });

  $("#show-archived").addEventListener("change", () => { listSig = null; load(); });
  $("#case-list").addEventListener("click", (ev) => {
    const tr = ev.target.closest("tr[data-id]");
    if (tr) ctx.navigate(`#/case/${tr.dataset.id}`);
  });
  $("#case-list").addEventListener("keydown", (ev) => {
    const tr = ev.target.closest("tr[data-id]");
    if (tr && ev.key === "Enter") ctx.navigate(`#/case/${tr.dataset.id}`);
  });
}

function statusBox() {
  const box = $("#upload-status");
  box.hidden = false;
  box.className = "upload-status";
  return box;
}

function progressHtml(label, fraction, detail = "") {
  const indeterminate = fraction == null;
  return `<div class="upload-line"><span class="spinner"></span><span class="grow">${label}</span><span class="dim">${detail}</span></div>
    <div class="progress ${indeterminate ? "indeterminate" : ""}"><span class="progress-fill" style="width:${indeterminate ? "" : `${Math.round(fraction * 100)}%`}"></span></div>`;
}

function fail(err) {
  const box = statusBox();
  box.classList.add("fail");
  box.innerHTML = `<div class="upload-line">${icon("alert")}<span class="grow">${esc(err.message)}</span></div>`;
}

export function openFilePicker() { $("#file-input").click(); }

async function startUpload(file) {
  const box = statusBox();
  const label = `Uploading <span class="mono">${esc(file.name)}</span>`;
  box.innerHTML = progressHtml(label, 0, fmtBytes(file.size));
  const fill = () => box.querySelector(".progress-fill");
  try {
    const { case: created } = await upload("/api/pcaps/upload", file, (f) => {
      fill().style.width = `${Math.round(f * 100)}%`;
      box.querySelector(".dim").textContent = `${Math.round(f * 100)}% of ${fmtBytes(file.size)}`;
    });
    await watchCase(created.id, created.name);
  } catch (err) {
    fail(err instanceof ApiError ? err : new Error(`Upload failed: ${err.message}`));
  }
}

/** Follow a background replay until it completes or fails. */
async function watchCase(caseId, name) {
  watching = caseId;
  const box = statusBox();
  load();
  for (let i = 0; i < 2400 && watching === caseId; i++) {
    let s;
    try {
      s = await api(`/api/cases/${caseId}/status`);
    } catch (err) {
      return fail(err);
    }
    if (s.status === "complete") {
      box.classList.add("ok");
      box.innerHTML = `<div class="upload-line">${icon("check")}<span class="grow">Case #${caseId} <b>${esc(name)}</b> replayed: ${plural(s.events_processed, "event")}, ${plural(s.alert_count, "alert")}</span>
        <a class="btn small primary" href="#/case/${caseId}">Open case ${icon("arrow-right")}</a></div>`;
      watching = null;
      ctx.sync();
      return;
    }
    if (s.status === "failed") {
      watching = null;
      ctx.sync();
      return fail(new Error(`Case #${caseId} failed: ${s.error || "unknown error"}`));
    }
    box.innerHTML = progressHtml(`Replaying case #${caseId} <b>${esc(name)}</b>`, null,
      `${fmtNum(s.events_processed)} events · ${plural(s.alert_count, "alert")}`);
    await new Promise((r) => setTimeout(r, 600));
  }
}

export async function load() {
  const list = $("#case-list");
  if (listSig === null) list.innerHTML = skeletonRows(4);
  let data;
  try {
    data = await api(`/api/cases?include_archived=${$("#show-archived").checked}`);
  } catch (err) {
    return toastError(err);
  }
  const cases = data.cases;
  $("#case-count").textContent = plural(cases.length, "case");
  const sig = JSON.stringify(cases.map((c) => [c.id, c.status, c.events_processed, c.alert_count, c.name, Boolean(c.ai_report)]));
  if (sig === listSig) return; // nothing visible changed: keep the DOM
  listSig = sig;
  if (!cases.length) {
    list.innerHTML = emptyState("cases", "No cases yet", "Drop a capture above to create your first case. Every replay becomes a case with its own alerts, notes and report.");
    return;
  }
  list.innerHTML = `<div class="table-wrap"><table class="tbl">
    <thead><tr><th class="num">ID</th><th>Case</th><th>Status</th><th class="num">Events</th><th class="num">Alerts</th><th>Created (UTC)</th><th>AI</th></tr></thead>
    <tbody>${cases.map((c) => `
      <tr data-id="${c.id}" tabindex="0">
        <td class="num dim">${c.id}</td>
        <td><span class="case-name">${esc(c.name)}</span><span class="case-src mono" title="${esc(c.source)}">${esc(c.source_kind)}:${esc(c.source)}${c.pcap_size ? ` · ${fmtBytes(c.pcap_size)}` : ""}</span></td>
        <td>${statusChip(c.status)}</td>
        <td class="num">${fmtNum(c.events_processed)}</td>
        <td class="num"><span class="count">${fmtNum(c.alert_count)}</span></td>
        <td class="mono dim">${esc(c.created_at)}</td>
        <td>${c.ai_report ? `<span class="ai-mark" title="AI review stored">${icon("sparkles")}</span>` : '<span class="dim">-</span>'}</td>
      </tr>`).join("")}</tbody></table></div>`;
}
