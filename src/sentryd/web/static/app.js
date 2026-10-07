/* sentryd console entry point: routing, live updates, verdicts, keyboard.
   Plain ES modules, no build step. */

import { api, onAuthRequired, setToken } from "./js/api.js";
import { ctx } from "./js/context.js";
import { initDetails, currentAlertId, openAlert, openHost, setVerdict, verdictForKey } from "./js/details.js";
import { $, $$, esc, icon, isTyping, plural, verdictLabel } from "./js/dom.js";
import { isLive, noteRevision, onRevision, onStatus, setLive } from "./js/live.js";
import { openPalette } from "./js/palette.js";
import * as prefs from "./js/prefs.js";
import {
  closeDrawer, closeTopModal, drawerOpen, drawerStep, hideTooltip, modalOpen, openModal,
  promptToken, toast, toastError,
} from "./js/ui.js";
import * as caseView from "./js/views/case.js";
import * as casesView from "./js/views/cases.js";
import * as dashboard from "./js/views/dashboard.js";
import * as settings from "./js/views/settings.js";

const VIEWS = ["dashboard", "cases", "case", "settings"];
const TITLES = { dashboard: "Overview", cases: "Cases", settings: "Settings" };
let route = { view: "dashboard" };

/* ---------- routing ---------- */

function parseRoute() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  if (path.startsWith("case/")) return { view: "case", id: Number(path.slice(5)) };
  if (path === "cases") return { view: "cases" };
  if (path === "settings") return { view: "settings" };
  return { view: "dashboard", query };
}

function navigate() {
  route = parseRoute();
  for (const view of VIEWS) $(`#view-${view}`).hidden = view !== route.view;
  $$(".nav a").forEach((a) => {
    const on = a.dataset.tab === route.view || (a.dataset.tab === "cases" && route.view === "case");
    a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  closeDrawer();
  hideTooltip();
  $("#bulk-bar").classList.remove("show");
  if (TITLES[route.view]) document.title = `${TITLES[route.view]} · sentryd`;
  scrollTo({ top: 0 });
  if (route.view === "dashboard") {
    dashboard.readHash(route.query);
    dashboard.enter();
  } else if (route.view === "cases") {
    ctx.activeTable = null;
    casesView.load();
  } else if (route.view === "case") {
    caseView.load(route.id);
  } else {
    ctx.activeTable = null;
    settings.load();
  }
}

/** Refresh whatever is on screen. quiet = keep the frame, flash new rows. */
function refreshView({ quiet = true } = {}) {
  if (route.view === "dashboard") return dashboard.load({ quiet });
  if (route.view === "cases") return casesView.load();
  if (route.view === "case") return caseView.load(route.id, { quiet });
  return Promise.resolve();
}

/* ---------- context wiring ---------- */

Object.assign(ctx, {
  openAlert,
  openHost,
  navigate(hash) {
    if (location.hash === hash) navigate();
    else location.hash = hash;
  },
  scopeCase() {
    if (route.view === "case") return route.id;
    if (route.view === "dashboard") return dashboard.scopeCase();
    return "";
  },
  filterOverview(filters) {
    if (route.view === "dashboard") return dashboard.applyFilters(filters);
    const p = new URLSearchParams(Object.entries(filters).filter(([, v]) => v));
    location.hash = `#/?${p}`;
  },
  /** Re-read the revision first so the next poll doesn't refresh again. */
  async sync() {
    try { noteRevision((await api("/api/revision")).revision); } catch { /* refresh anyway */ }
    await refreshView({ quiet: true });
  },
  /** Apply a verdict to alerts, with a one-click undo back to `previous`. */
  async setVerdict(ids, status, { previous = {} } = {}) {
    try {
      await api("/api/alerts/bulk-status", { method: "POST", json: { ids, status } });
    } catch (err) {
      return toastError(err);
    }
    const who = ids.length === 1 ? `Alert #${ids[0]}` : plural(ids.length, "alert");
    const what = status === "new" ? "reset to needs review" : `marked ${verdictLabel(status).toLowerCase()}`;
    toast(`${who} ${what}`, {
      kind: "ok",
      action: {
        label: "Undo",
        run: async () => {
          const groups = {};
          for (const id of ids) (groups[previous[id] || "new"] ??= []).push(id);
          try {
            for (const [prev, group] of Object.entries(groups)) {
              await api("/api/alerts/bulk-status", { method: "POST", json: { ids: group, status: prev === "triaged" ? "new" : prev } });
            }
            toast("Verdict restored", { kind: "ok", duration: 2500 });
            if (ids.includes(currentAlertId())) openAlert(currentAlertId());
            await ctx.sync();
          } catch (err) { toastError(err); }
        },
      },
    });
    await ctx.sync();
  },
  async bulkVerdict(ids, status, table) {
    const previous = Object.fromEntries(ids.map((id) => [id, table.statusOf(id)]));
    table.clearChecks();
    await ctx.setVerdict(ids, status, { previous });
  },
});

/* ---------- live updates ---------- */

onRevision(() => refreshView({ quiet: true }));
onStatus((state) => {
  const el = $("#live-status");
  el.dataset.state = state;
  el.querySelector(".live-text").textContent = state;
});

function toggleLive(on = !isLive()) {
  prefs.set("live", on);
  $("#live-toggle").checked = on;
  setLive(on);
  toast(on ? "Live updates on" : "Live updates paused", { duration: 1800 });
}
$("#live-toggle").addEventListener("change", (ev) => toggleLive(ev.target.checked));

/* ---------- theme ---------- */

const THEME_ICON = { system: "monitor", light: "sun", dark: "moon" };
function paintThemeButton() {
  const theme = prefs.get("theme");
  const btn = $("#theme-cycle");
  btn.innerHTML = icon(THEME_ICON[theme]);
  btn.title = `Theme: ${theme} (T)`;
}
$("#theme-cycle").addEventListener("click", () => {
  const next = prefs.cycleTheme();
  toast(`Theme: ${next}`, { duration: 1500 });
});
prefs.onChange((name) => { if (name === "theme") paintThemeButton(); });

/* ---------- palette & help ---------- */

const ACTIONS = [
  { group: "Go to", icon: "dashboard", label: "Overview", hint: "G O", run: () => ctx.navigate("#/") },
  { group: "Go to", icon: "cases", label: "Cases", hint: "G C", run: () => ctx.navigate("#/cases") },
  { group: "Go to", icon: "settings", label: "Settings", hint: "G S", run: () => ctx.navigate("#/settings") },
  { group: "Actions", icon: "upload", label: "Upload a capture", run: () => { ctx.navigate("#/cases"); setTimeout(casesView.openFilePicker, 50); } },
  { group: "Actions", icon: "moon", label: "Cycle theme", hint: "T", run: () => $("#theme-cycle").click() },
  { group: "Actions", icon: "pulse", label: "Toggle live updates", hint: "L", run: () => toggleLive() },
  { group: "Actions", icon: "filter", label: "Clear overview filters", run: () => { ctx.navigate("#/"); dashboard.clearFilters(); } },
  { group: "Actions", icon: "keyboard", label: "Keyboard shortcuts", hint: "?", run: () => showShortcuts() },
];

function showShortcuts() {
  const row = (keys, label) => `<div><span>${label}</span><span>${keys.map((k) => `<kbd>${esc(k)}</kbd>`).join("")}</span></div>`;
  openModal(`<h2>${icon("keyboard")}Keyboard shortcuts</h2>
    <div class="shortcuts">
      <h3>Anywhere</h3>
      ${row([navigator.platform.includes("Mac") ? "⌘" : "Ctrl", "K"], "Command palette")}
      ${row(["/"], "Search alerts")}
      ${row(["G", "O"], "Go to overview")}
      ${row(["G", "C"], "Go to cases")}
      ${row(["G", "S"], "Go to settings")}
      ${row(["T"], "Cycle theme")}
      ${row(["L"], "Toggle live updates")}
      ${row(["?"], "This help")}
      <h3>Alert tables</h3>
      ${row(["J"], "Next alert")}
      ${row(["K"], "Previous alert")}
      ${row(["Enter"], "Open alert")}
      ${row(["X"], "Select alert")}
      ${row(["Shift", "click"], "Select a range")}
      ${row(["Esc"], "Clear selection")}
      <h3>Alert drawer</h3>
      ${row(["J"], "Next alert")}
      ${row(["K"], "Previous alert")}
      ${row(["1"], "Confirm")}
      ${row(["2"], "False positive")}
      ${row(["3"], "Expected")}
      ${row(["4"], "Ignore")}
      ${row(["5"], "Reset verdict")}
      ${row(["Esc"], "Close")}
    </div>
    <div class="modal-actions" style="margin-top:1rem"><button class="btn" type="button" data-close>Done</button></div>`,
  { className: "wide", onMount: (el, close) => el.querySelector("[data-close]").addEventListener("click", () => close()) });
}

$("#open-palette").addEventListener("click", () => openPalette(ACTIONS));
$("#open-help").addEventListener("click", showShortcuts);
if (/Mac|iPhone|iPad/.test(navigator.platform)) $("#palette-kbd").textContent = "⌘K";

/* ---------- keyboard ---------- */

let gPressed = 0;

document.addEventListener("keydown", (ev) => {
  const key = ev.key;
  if ((ev.metaKey || ev.ctrlKey) && key.toLowerCase() === "k") {
    ev.preventDefault();
    if (modalOpen()) closeTopModal();
    else openPalette(ACTIONS);
    return;
  }
  if (modalOpen()) {
    if (key === "Escape") { ev.preventDefault(); closeTopModal(); }
    return;
  }
  if (key === "Escape") {
    if (drawerOpen()) { closeDrawer(); return; }
    if (ctx.activeTable?.checked.size) { ctx.activeTable.clearChecks(); return; }
  }
  if (isTyping(ev.target) || ev.metaKey || ev.ctrlKey || ev.altKey) return;

  if (Date.now() - gPressed < 1200) {
    gPressed = 0;
    const dest = { o: "#/", d: "#/", c: "#/cases", s: "#/settings" }[key.toLowerCase()];
    if (dest) { ev.preventDefault(); ctx.navigate(dest); }
    return;
  }

  if (drawerOpen()) {
    if (key === "j" || key === "ArrowDown") { ev.preventDefault(); drawerStep(1); }
    else if (key === "k" || key === "ArrowUp") { ev.preventDefault(); drawerStep(-1); }
    else if (verdictForKey(key)) { ev.preventDefault(); setVerdict(verdictForKey(key)); }
    return;
  }

  const table = ctx.activeTable;
  switch (key) {
    case "/":
      ev.preventDefault();
      if (route.view === "dashboard") dashboard.focusSearch();
      else openPalette(ACTIONS);
      break;
    case "?": ev.preventDefault(); showShortcuts(); break;
    case "g": gPressed = Date.now(); break;
    case "t": $("#theme-cycle").click(); break;
    case "l": toggleLive(); break;
    case "j": if (table) { ev.preventDefault(); table.move(1); } break;
    case "k": if (table) { ev.preventDefault(); table.move(-1); } break;
    case "x": if (table) { ev.preventDefault(); table.toggleCursor(); } break;
    case "o": if (table) { ev.preventDefault(); table.openCursor(); } break;
    default: break;
  }
});

/* ---------- drawer chrome ---------- */

$("#drawer-close").addEventListener("click", closeDrawer);
$("#scrim").addEventListener("click", closeDrawer);
$("#drawer-prev").addEventListener("click", () => drawerStep(-1));
$("#drawer-next").addEventListener("click", () => drawerStep(1));

/* ---------- boot ---------- */

onAuthRequired(async (reason, opts) => {
  const answer = await promptToken(reason, opts);
  if (!answer) return null;
  setToken(answer.token, answer.remember);
  return answer.token;
});

prefs.apply();
paintThemeButton();
initDetails();
dashboard.initDashboard();
casesView.initCases();
settings.initSettings();
window.addEventListener("hashchange", navigate);
$("#live-toggle").checked = prefs.get("live");
setLive(prefs.get("live"));
navigate();

api("/api/status").then((status) => {
  ctx.status = status;
  $("#foot-meta").textContent = `v${status.version}`;
  $("#foot-meta").title = status.ai.available ? `AI triage via ${status.ai.provider}` : "AI triage not configured";
}).catch(() => { /* surfaced by the views' own requests */ });
