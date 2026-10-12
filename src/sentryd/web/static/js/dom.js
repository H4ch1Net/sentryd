/* Small DOM and formatting helpers shared by every view. */

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export const SEVERITIES = ["critical", "high", "medium", "low"];
export const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

export const VERDICTS = [
  { value: "confirmed", label: "Confirm", key: "1", icon: "alert" },
  { value: "false_positive", label: "False positive", key: "2", icon: "x" },
  { value: "expected", label: "Expected", key: "3", icon: "check" },
  { value: "ignored", label: "Ignore", key: "4", icon: "archive" },
  { value: "new", label: "Reset", key: "5", icon: "undo" },
];

const VERDICT_LABELS = {
  new: "Needs review",
  confirmed: "Confirmed",
  false_positive: "False positive",
  expected: "Expected",
  ignored: "Ignored",
  dismissed: "Dismissed",
  triaged: "Triaged",
};

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Escape anything that came from the server before it enters innerHTML. */
export function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ESCAPES[c]);
}

export function icon(name, cls = "") {
  return `<svg class="ic ${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

export function fmtTime(ts, withDate = true) {
  if (ts == null) return "-";
  const iso = new Date(ts * 1000).toISOString();
  return withDate ? iso.replace("T", " ").slice(0, 19) : iso.slice(11, 19);
}

export function fmtDuration(seconds) {
  if (seconds == null || !isFinite(seconds)) return "-";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 90) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

export function fmtBytes(n) {
  if (n == null) return "";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

/** 1,284 / 12.9K / 4.2M: compact past five digits, exact below. */
export function fmtNum(n) {
  if (n == null) return "-";
  if (Math.abs(n) < 10000) return n.toLocaleString("en-US");
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function plural(n, word, many = `${word}s`) {
  return `${fmtNum(n)} ${n === 1 ? word : many}`;
}

export function relTime(date) {
  const s = Math.max(0, Math.round((Date.now() - date) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

export function debounce(fn, ms) {
  let timer = null;
  const wrapped = (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
  wrapped.flush = (...args) => { clearTimeout(timer); fn(...args); };
  wrapped.cancel = () => clearTimeout(timer);
  return wrapped;
}

export function reducedMotion() {
  return document.documentElement.dataset.motion === "reduced"
    || matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** Tween an element's number from its last value; flags increases. */
export function animateNumber(el, to, format = fmtNum) {
  const from = Number(el.dataset.value ?? to);
  el.dataset.value = String(to);
  if (from === to || reducedMotion()) {
    el.textContent = format(to);
    return;
  }
  if (to > from && el.dataset.ready) {
    el.classList.remove("bumped");
    void el.offsetWidth; // restart the animation
    el.classList.add("bumped");
  }
  el.dataset.ready = "1";
  const start = performance.now();
  const duration = 520;
  const step = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - (1 - t) ** 3;
    el.textContent = format(Math.round(from + (to - from) * eased));
    if (t < 1 && el.dataset.value === String(to)) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = Object.assign(document.createElement("textarea"), { value: text });
    area.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    return ok;
  }
}

export function isTyping(target) {
  const el = target instanceof Element ? target : null;
  return !!el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
}

/* ---------- shared markup ---------- */

export function badge(severity, count) {
  const n = count != null ? ` <span class="n">${fmtNum(count)}</span>` : "";
  return `<span class="badge ${esc(severity)}"><span class="dot"></span>${esc(severity)}${n}</span>`;
}

export function verdictChip(status) {
  const label = VERDICT_LABELS[status] || status;
  return `<span class="verdict ${esc(status)}">${esc(label)}</span>`;
}

export function verdictLabel(status) {
  return VERDICT_LABELS[status] || status;
}

export function statusChip(status) {
  const lead = status === "running" ? '<span class="spinner"></span>'
    : status === "complete" ? icon("check")
    : status === "failed" ? icon("alert") : "";
  return `<span class="status-chip ${esc(status)}">${lead}${esc(status)}</span>`;
}

export function hostLink(ip) {
  if (!ip) return '<span class="dim">-</span>';
  return `<a class="host-link" data-host="${esc(ip)}" href="#" title="Inspect host">${esc(ip)}</a>`;
}

export function emptyState(iconName, title, body = "") {
  return `<div class="empty-state"><div class="empty-art">${icon(iconName)}</div>
    <h3>${esc(title)}</h3>${body ? `<p>${body}</p>` : ""}</div>`;
}

export function skeletonRows(n = 5) {
  return `<div class="skel-rows">${Array.from({ length: n }, (_, i) =>
    `<span class="skeleton" style="height:14px;width:${92 - (i % 3) * 14}%"></span>`).join("")}</div>`;
}

/** Light JSON syntax highlighting over escaped text. */
export function highlightJSON(value) {
  const json = esc(JSON.stringify(value, null, 2));
  return json.replace(
    /(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match, str, colon, bool, num) => {
      if (str) return colon ? `<span class="k">${str}</span>${colon}` : `<span class="s">${str}</span>`;
      if (bool) return `<span class="b">${bool}</span>`;
      if (num) return `<span class="n">${num}</span>`;
      return match;
    }
  );
}

/** Minimal, safe markdown for AI reports: headings, lists, bold, code, alert refs.
    Input is escaped first; nothing raw ever reaches innerHTML. */
export function renderMarkdown(md) {
  const out = [];
  let list = null;
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
