/* Live updates without wasted work.

   Instead of re-fetching every panel on a timer, the console polls
   GET /api/revision (a single integer the store bumps on every alert or
   case write) and only notifies views when it moved. Polling pauses while
   the tab is hidden, resumes immediately when it returns, and backs off
   while the server is unreachable. */

import { api } from "./api.js";

const INTERVAL = 2500;
const MAX_BACKOFF = 30000;

let enabled = true;
let timer = null;
let failures = 0;
let lastRevision = null;
let inFlight = false;
const listeners = new Set();
const statusListeners = new Set();

export function onRevision(fn) { listeners.add(fn); return () => listeners.delete(fn); }
export function onStatus(fn) { statusListeners.add(fn); }

function setStatus(state) { statusListeners.forEach((fn) => fn(state)); }

/** Views that fetched data stamped with a revision report it, so the next
    poll doesn't trigger a redundant refresh of what they already show. */
export function noteRevision(revision) {
  if (revision != null) lastRevision = revision;
}

function schedule(delay) {
  clearTimeout(timer);
  timer = setTimeout(tick, delay);
}

async function tick() {
  if (!enabled) return;
  if (document.hidden) { setStatus("paused"); return; } // resumed by visibilitychange
  if (inFlight) return schedule(INTERVAL);
  inFlight = true;
  try {
    const { revision } = await api("/api/revision");
    failures = 0;
    setStatus("live");
    if (lastRevision !== null && revision !== lastRevision) {
      lastRevision = revision;
      listeners.forEach((fn) => fn(revision));
    }
    lastRevision = revision;
    schedule(INTERVAL);
  } catch {
    failures += 1;
    setStatus("offline");
    schedule(Math.min(INTERVAL * 2 ** failures, MAX_BACKOFF));
  } finally {
    inFlight = false;
  }
}

/** Check now (after a local write, or when the tab becomes visible). */
export function poke() { if (enabled) schedule(0); }

export function setLive(on) {
  enabled = on;
  document.body.classList.toggle("is-live", on);
  if (on) poke();
  else { clearTimeout(timer); setStatus("paused"); }
}

export function isLive() { return enabled; }

document.addEventListener("visibilitychange", () => { if (!document.hidden) poke(); });
