/* Appearance and behavior preferences, kept in localStorage. index.html
   applies theme/density/motion before first paint; this module owns them
   afterwards. */

const KEY = "sentryd-prefs";
const DEFAULTS = { theme: "system", density: "comfortable", motion: "full", live: true };
const listeners = new Set();

function read() {
  try { return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) || "{}") }; } catch { return { ...DEFAULTS }; }
}

let prefs = read();

export function get(name) { return prefs[name]; }

export function onChange(fn) { listeners.add(fn); }

export function set(name, value) {
  prefs = { ...prefs, [name]: value };
  try { localStorage.setItem(KEY, JSON.stringify(prefs)); } catch { /* private mode: session-only */ }
  apply();
  listeners.forEach((fn) => fn(name, value));
}

export function apply() {
  const root = document.documentElement;
  if (prefs.theme === "light" || prefs.theme === "dark") root.dataset.theme = prefs.theme;
  else delete root.dataset.theme;
  if (prefs.motion === "reduced") root.dataset.motion = "reduced";
  else delete root.dataset.motion;
  if (prefs.density === "compact") root.dataset.density = "compact";
  else delete root.dataset.density;
}

const THEME_ORDER = ["system", "light", "dark"];
export function cycleTheme() {
  const next = THEME_ORDER[(THEME_ORDER.indexOf(prefs.theme) + 1) % THEME_ORDER.length];
  set("theme", next);
  return next;
}
