/* Charts, hand-built in HTML/SVG (no library, no build step).

   Mark specs follow the reference method: bars at most 24px thick with 4px
   rounded data ends square at the baseline, a 2px surface gap between
   stacked segments, solid hairline gridlines, clean tick values, a legend
   whenever there are two or more series, and a hover/focus tooltip that
   never gates a value the table doesn't also show. */

import { SEVERITIES, SEVERITY_RANK, esc, fmtNum, fmtTime, plural } from "./dom.js";
import { hideTooltip, showTooltip, tooltipAt } from "./ui.js";

const SEV_VAR = (s) => `var(--sev-${s})`;

/** Clean axis: the smallest nice step whose interval count is 1..5. */
export function niceScale(maxValue) {
  if (maxValue <= 0) return { max: 1, step: 1 };
  for (let p = 1; ; p *= 10) {
    for (const m of [1, 2, 2.5, 5]) {
      const step = m * p;
      if (!Number.isInteger(step)) continue;
      const n = Math.ceil(maxValue / step);
      if (n <= 5) return { max: n * step, step };
    }
  }
}

/* ---------- activity columns (emphasis split) ---------- */

/** Columns over event time: high & critical anchored to the baseline in the
    serious tone, low & medium stacked above in de-emphasis gray. Click a
    column to select its window, shift-click to extend the range. */
export function columnsChart(container, { onSelect } = {}) {
  container.innerHTML = `<div class="cc-y" aria-hidden="true"></div><div class="cc-plot"></div><div class="cc-x" aria-hidden="true"></div>`;
  const yAxis = container.querySelector(".cc-y");
  const plot = container.querySelector(".cc-plot");
  const xAxis = container.querySelector(".cc-x");
  let buckets = [];
  let anchor = null;
  let range = null; // [i, j]
  let focusIdx = 0;

  const severe = (b) => (b.by_severity.high || 0) + (b.by_severity.critical || 0);

  function tipHtml(b) {
    const rows = SEVERITIES.map((s) => `<div class="tt-row"><span class="tt-key" style="--sev:${SEV_VAR(s)}"></span><span class="k">${s}</span><b>${b.by_severity[s] || 0}</b></div>`).join("");
    return `<div class="tt-value">${plural(b.count, "alert")}</div>
      <div class="tt-sub">${fmtTime(b.start, false)} to ${fmtTime(b.end, false)} UTC</div>${rows}`;
  }

  function paintSelection() {
    container.classList.toggle("has-selection", !!range);
    plot.querySelectorAll(".cc-col").forEach((col, i) => {
      const on = !!range && i >= range[0] && i <= range[1];
      col.classList.toggle("selected", on);
      col.setAttribute("aria-pressed", String(on));
    });
  }

  function select(i, extend) {
    if (extend && anchor !== null) {
      range = [Math.min(anchor, i), Math.max(anchor, i)];
    } else if (range && range[0] === i && range[1] === i) {
      range = null;
      anchor = null;
    } else {
      range = [i, i];
      anchor = i;
    }
    paintSelection();
    onSelect?.(range ? { start: buckets[range[0]].start, end: buckets[range[1]].end } : null);
  }

  plot.addEventListener("pointermove", (ev) => {
    const col = ev.target.closest(".cc-col");
    if (!col) return hideTooltip();
    showTooltip(tipHtml(buckets[Number(col.dataset.i)]), ev.clientX, ev.clientY);
  });
  plot.addEventListener("pointerleave", hideTooltip);
  plot.addEventListener("click", (ev) => {
    const col = ev.target.closest(".cc-col");
    if (col) select(Number(col.dataset.i), ev.shiftKey);
  });
  plot.addEventListener("focusin", (ev) => {
    const col = ev.target.closest(".cc-col");
    if (col) tooltipAt(col, tipHtml(buckets[Number(col.dataset.i)]));
  });
  plot.addEventListener("focusout", hideTooltip);
  plot.addEventListener("keydown", (ev) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(ev.key) || !buckets.length) return;
    ev.preventDefault();
    const last = buckets.length - 1;
    focusIdx = ev.key === "Home" ? 0 : ev.key === "End" ? last
      : Math.max(0, Math.min(last, focusIdx + (ev.key === "ArrowRight" ? 1 : -1)));
    const cols = plot.querySelectorAll(".cc-col");
    cols.forEach((c, i) => { c.tabIndex = i === focusIdx ? 0 : -1; });
    cols[focusIdx].focus();
  });

  function update(data) {
    buckets = data.buckets || [];
    if (!buckets.length) {
      plot.innerHTML = `<div class="chart-empty" style="margin:auto">No alerts in this scope yet</div>`;
      yAxis.innerHTML = xAxis.innerHTML = "";
      range = anchor = null;
      paintSelection();
      return;
    }
    const { max, step } = niceScale(Math.max(...buckets.map((b) => b.count)));
    const ticks = [];
    for (let v = 0; v <= max; v += step) ticks.push(v);
    yAxis.innerHTML = ticks.map((v) => `<span style="bottom:${(v / max) * 100}%">${fmtNum(v)}</span>`).join("");

    let cols = [...plot.querySelectorAll(".cc-col")];
    if (cols.length !== buckets.length) {
      plot.innerHTML = ticks.slice(1).map((v) => `<span class="cc-gridline" style="bottom:${(v / max) * 100}%"></span>`).join("")
        + buckets.map((_, i) => `<button type="button" class="cc-col" data-i="${i}" tabindex="${i === 0 ? 0 : -1}"><span class="cc-seg other"></span><span class="cc-seg severe"></span></button>`).join("");
      cols = [...plot.querySelectorAll(".cc-col")];
      focusIdx = 0;
      range = anchor = null;
    } else {
      plot.querySelectorAll(".cc-gridline").forEach((g) => g.remove());
      plot.insertAdjacentHTML("afterbegin", ticks.slice(1).map((v) => `<span class="cc-gridline" style="bottom:${(v / max) * 100}%"></span>`).join(""));
    }
    buckets.forEach((b, i) => {
      const hi = severe(b);
      const lo = b.count - hi;
      const [other, sev] = cols[i].children;
      other.style.height = `${(lo / max) * 100}%`;
      sev.style.height = `${(hi / max) * 100}%`;
      other.classList.toggle("top", lo > 0);
      sev.classList.toggle("top", lo === 0 && hi > 0);
      sev.classList.toggle("gap", lo > 0 && hi > 0);
      cols[i].setAttribute("aria-label", `${fmtTime(b.start)} UTC: ${plural(b.count, "alert")}, ${hi} high or critical`);
    });
    // First paint grows from the baseline; later updates transition in place.
    const mid = buckets[Math.floor(buckets.length / 2)];
    xAxis.innerHTML = `<span>${fmtTime(data.start)}</span><span>${fmtTime(mid.start, false)}</span><span>${fmtTime(data.end)} UTC</span>`;
    paintSelection();
  }

  return {
    update,
    clear() { range = anchor = null; paintSelection(); },
  };
}

/* ---------- ranked bars ---------- */

/** Single-series horizontal bars, keyed so updates animate widths in place. */
export function rankBars(container, rows, { key, label, value, meta = () => "", onClick, active = () => false, empty = "No data yet" }) {
  if (!rows.length) {
    container.innerHTML = `<div class="chart-empty">${esc(empty)}</div>`;
    return;
  }
  container.querySelector(".chart-empty")?.remove();
  const max = Math.max(...rows.map(value), 1);
  const existing = new Map([...container.children].map((el) => [el.dataset.key, el]));
  const tag = onClick ? "button" : "div";
  rows.forEach((row, i) => {
    const k = String(key(row));
    let el = existing.get(k);
    if (!el) {
      el = document.createElement(tag);
      if (onClick) el.type = "button";
      el.className = "bar-row";
      el.dataset.key = k;
      el.style.animationDelay = `${i * 30}ms`;
      el.innerHTML = `<span class="bar-label mono"></span><span class="bar-track"><span class="bar-fill"></span></span><span class="bar-value"></span>`;
      if (onClick) el.addEventListener("click", () => onClick(el._row));
    }
    existing.delete(k);
    el._row = row;
    el.querySelector(".bar-label").innerHTML = label(row);
    el.querySelector(".bar-label").title = el.querySelector(".bar-label").textContent;
    el.querySelector(".bar-value").innerHTML = `${fmtNum(value(row))}${meta(row) ? `<span class="meta">${meta(row)}</span>` : ""}`;
    el.classList.toggle("active", active(row));
    container.appendChild(el); // re-appending reorders without rebuilding
    const fill = el.querySelector(".bar-fill");
    const width = `${(value(row) / max) * 100}%`;
    if (!fill.style.width) requestAnimationFrame(() => { fill.style.width = width; });
    else fill.style.width = width;
  });
  existing.forEach((el) => el.remove());
}

/* ---------- sparkline ---------- */

function downsample(values, n = 24) {
  if (values.length <= n) return values;
  const out = [];
  const size = values.length / n;
  for (let i = 0; i < n; i++) {
    const slice = values.slice(Math.floor(i * size), Math.floor((i + 1) * size));
    out.push(slice.reduce((a, b) => a + b, 0));
  }
  return out;
}

/** Line in the de-emphasis hue, soft area wash, current point in accent. */
export function sparkline(svg, values) {
  const pts = downsample(values);
  if (pts.length < 2 || !pts.some(Boolean)) { svg.innerHTML = ""; return; }
  const w = Math.round(svg.getBoundingClientRect().width) || 240;
  const h = 30;
  const max = Math.max(...pts, 1);
  const x = (i) => (i / (pts.length - 1)) * (w - 8) + 4;
  const y = (v) => h - 4 - (v / max) * (h - 10);
  const line = pts.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(" ");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.innerHTML = `<path class="area" d="${line} L${x(pts.length - 1).toFixed(1)} ${h} L${x(0).toFixed(1)} ${h} Z"/>
    <path class="line" d="${line}"/>
    <circle r="4" cx="${x(pts.length - 1).toFixed(1)}" cy="${y(pts.at(-1)).toFixed(1)}"/>`;
}

/* ---------- risk gauge (the case view's hero figure) ---------- */

export function gauge(score) {
  const length = Math.PI * 90;
  const offset = length * (1 - Math.max(0, Math.min(100, score)) / 100);
  return `<svg class="gauge" viewBox="0 0 210 128" role="img" aria-label="Risk score ${score} of 100">
    <path class="track" d="M 15 110 A 90 90 0 0 1 195 110"/>
    <path class="fill" d="M 15 110 A 90 90 0 0 1 195 110" stroke-dasharray="${length.toFixed(1)}" stroke-dashoffset="${length.toFixed(1)}" data-offset="${offset.toFixed(1)}"/>
    <text class="score" x="105" y="104" text-anchor="middle">${score}</text>
    <text class="of" x="105" y="124" text-anchor="middle">of 100</text>
  </svg>`;
}

/** Sweep gauges in after they are in the DOM. */
export function animateGauges(root) {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    root.querySelectorAll(".gauge .fill").forEach((p) => p.setAttribute("stroke-dashoffset", p.dataset.offset));
  }));
}

/* ---------- kill chain ---------- */

export function killChain(phases) {
  return `<ol class="chain">${phases.map((p, i) => `
    <li class="phase" style="animation-delay:${i * 80}ms">
      <span class="phase-dot">${i + 1}</span>
      <p class="phase-name">${esc(p.phase)}</p>
      <p class="phase-meta"><span class="mono">${fmtTime(p.first_seen, false)}</span> &middot; ${plural(p.alert_ids.length, "alert")}</p>
      <p class="phase-meta">${p.rules.map(esc).join(", ")}</p>
    </li>`).join("")}</ol>`;
}

/* ---------- attack graph ---------- */

const MAX_PER_COLUMN = 14;

/** Bipartite host graph: pure sources left, pure targets right, hosts that
    do both in the middle. Edge color is the pair's highest severity, edge
    weight its alert count. Hover focuses a host or edge; click a host to
    inspect it. */
export function attackGraph(container, alerts, { onHost } = {}) {
  const hosts = new Map();
  const edges = new Map();
  const host = (ip) => {
    if (!hosts.has(ip)) hosts.set(ip, { ip, out: 0, in: 0, sev: null });
    return hosts.get(ip);
  };
  for (const a of alerts) {
    if (!a.src || !a.dst || a.src === a.dst) continue;
    const s = host(a.src);
    s.out += 1;
    if (!s.sev || SEVERITY_RANK[a.severity] > SEVERITY_RANK[s.sev]) s.sev = a.severity;
    host(a.dst).in += 1;
    const k = `${a.src}\u0000${a.dst}`;
    const e = edges.get(k) || { src: a.src, dst: a.dst, count: 0, sev: "low", rules: new Set() };
    e.count += 1;
    e.rules.add(a.rule_id);
    if (SEVERITY_RANK[a.severity] > SEVERITY_RANK[e.sev]) e.sev = a.severity;
    edges.set(k, e);
  }
  if (!edges.size) return false;

  const weight = (h) => h.out * 3 + h.in;
  const cols = [
    { label: "Sources", nodes: [...hosts.values()].filter((h) => h.out && !h.in) },
    { label: "Source and target", nodes: [...hosts.values()].filter((h) => h.out && h.in) },
    { label: "Targets", nodes: [...hosts.values()].filter((h) => !h.out && h.in) },
  ].filter((c) => c.nodes.length);
  cols.forEach((c) => {
    c.nodes.sort((a, b) => weight(b) - weight(a));
    c.more = Math.max(0, c.nodes.length - MAX_PER_COLUMN);
    c.nodes = c.nodes.slice(0, MAX_PER_COLUMN);
  });

  const W = Math.max(container.clientWidth - 12, 560);
  // Middle-column labels sit above and below their node, so give them room.
  const ROW = cols.length === 3 ? 66 : 54;
  const rows = Math.max(...cols.map((c) => c.nodes.length + (c.more ? 1 : 0)));
  const H = rows * ROW + 46;
  const xs = cols.length === 1 ? [W / 2] : cols.length === 2 ? [180, W - 180] : [180, W / 2, W - 180];
  const pos = new Map();
  cols.forEach((c, ci) => {
    c.x = xs[ci];
    c.side = cols.length === 1 ? "mid" : ci === 0 ? "left" : ci === cols.length - 1 ? "right" : "mid";
    const offset = ((rows - c.nodes.length) * ROW) / 2;
    c.nodes.forEach((n, i) => pos.set(n.ip, { x: c.x, y: 46 + offset + i * ROW + ROW / 2, side: c.side }));
  });

  const edgeList = [...edges.values()].filter((e) => pos.has(e.src) && pos.has(e.dst));
  const pathFor = (e) => {
    const a = pos.get(e.src);
    const b = pos.get(e.dst);
    if (a.x === b.x) {
      const bend = a.x + 70 + Math.abs(a.y - b.y) * 0.25;
      return `M${a.x + 10} ${a.y} C${bend} ${a.y} ${bend} ${b.y} ${b.x + 10} ${b.y}`;
    }
    const mx = (a.x + b.x) / 2;
    return `M${a.x + 10} ${a.y} C${mx} ${a.y} ${mx} ${b.y} ${b.x - 10} ${b.y}`;
  };
  const edgeSvg = edgeList.map((e, i) => {
    const d = pathFor(e);
    const width = (1.5 + Math.min(4, Math.log2(e.count))).toFixed(1);
    return `<path class="edge" data-e="${i}" d="${d}" pathLength="1" stroke-width="${width}" style="--sev:${SEV_VAR(e.sev)};animation-delay:${Math.min(i * 40, 600)}ms"/>
      <path class="edge-hit" data-e="${i}" d="${d}"/>`;
  }).join("");

  const label = (n, side) => {
    const sub = [n.out ? `${n.out} out` : "", n.in ? `${n.in} in` : ""].filter(Boolean).join(" · ");
    const [anchor, x, y] = side === "left" ? ["end", -16, 4] : side === "right" ? ["start", 16, 4] : ["middle", 0, -16];
    const subY = side === "mid" ? 25 : y + 14;
    return `<text x="${x}" y="${y}" text-anchor="${anchor}">${esc(n.ip)}</text>
      <text class="sub" x="${x}" y="${subY}" text-anchor="${anchor}">${sub}</text>`;
  };
  const nodeSvg = cols.map((c) => c.nodes.map((n) => {
    const p = pos.get(n.ip);
    const sev = n.sev ? SEV_VAR(n.sev) : "var(--other)";
    return `<g class="node" data-host="${esc(n.ip)}" transform="translate(${p.x} ${p.y})" tabindex="0" role="button" aria-label="Host ${esc(n.ip)}: ${n.out} alerts as source, ${n.in} as target">
      <circle class="halo" r="10"/><circle class="core" r="5" style="--sev:${sev}"/>${label(n, c.side)}</g>`;
  }).join("") + (c.more ? `<text class="col-label" x="${c.x}" y="${46 + ((rows - c.nodes.length - 1) * ROW) / 2 + c.nodes.length * ROW + ROW / 2}" text-anchor="middle">+${c.more} more</text>` : "")).join("");
  const colLabels = cols.map((c) => `<text class="col-label" x="${c.x}" y="16" text-anchor="middle">${c.label}</text>`).join("");

  container.innerHTML = `<svg class="graph" viewBox="0 0 ${W} ${H}" height="${H}" role="group" aria-label="Attack graph">${colLabels}<g>${edgeSvg}</g><g>${nodeSvg}</g></svg>`;
  const svg = container.querySelector("svg");

  const focus = (hot) => {
    svg.classList.toggle("focusing", !!hot);
    svg.querySelectorAll(".hot").forEach((el) => el.classList.remove("hot"));
    if (!hot) return;
    hot.edges.forEach((i) => svg.querySelector(`.edge[data-e="${i}"]`)?.classList.add("hot"));
    hot.hosts.forEach((ip) => svg.querySelector(`.node[data-host="${CSS.escape(ip)}"]`)?.classList.add("hot"));
  };
  const hostFocus = (ip) => {
    const touching = edgeList.flatMap((e, i) => (e.src === ip || e.dst === ip ? [i] : []));
    const peers = new Set([ip, ...touching.flatMap((i) => [edgeList[i].src, edgeList[i].dst])]);
    return { edges: touching, hosts: [...peers] };
  };
  const hostTip = (ip) => {
    const n = hosts.get(ip);
    return `<div class="tt-value mono">${esc(ip)}</div>
      <div class="tt-row"><span class="k">alerts as source</span><b>${n.out}</b></div>
      <div class="tt-row"><span class="k">alerts as target</span><b>${n.in}</b></div>
      ${n.sev ? `<div class="tt-row"><span class="tt-key" style="--sev:${SEV_VAR(n.sev)}"></span><span class="k">highest as source</span><b>${n.sev}</b></div>` : ""}
      <div class="tt-sub">click to inspect</div>`;
  };
  const edgeTip = (e) => `<div class="tt-value">${plural(e.count, "alert")}</div>
    <div class="tt-sub mono">${esc(e.src)} to ${esc(e.dst)}</div>
    <div class="tt-row"><span class="tt-key" style="--sev:${SEV_VAR(e.sev)}"></span><span class="k">highest severity</span><b>${e.sev}</b></div>
    <div class="tt-row"><span class="k">${[...e.rules].map(esc).join(", ")}</span></div>`;

  svg.addEventListener("pointermove", (ev) => {
    const node = ev.target.closest(".node");
    const edge = ev.target.closest(".edge-hit, .edge");
    if (node) {
      focus(hostFocus(node.dataset.host));
      showTooltip(hostTip(node.dataset.host), ev.clientX, ev.clientY);
    } else if (edge) {
      const e = edgeList[Number(edge.dataset.e)];
      focus({ edges: [Number(edge.dataset.e)], hosts: [e.src, e.dst] });
      showTooltip(edgeTip(e), ev.clientX, ev.clientY);
    } else {
      focus(null);
      hideTooltip();
    }
  });
  svg.addEventListener("pointerleave", () => { focus(null); hideTooltip(); });
  svg.addEventListener("click", (ev) => {
    const node = ev.target.closest(".node");
    if (node) onHost?.(node.dataset.host);
  });
  svg.addEventListener("focusin", (ev) => {
    const node = ev.target.closest(".node");
    if (!node) return;
    focus(hostFocus(node.dataset.host));
    tooltipAt(node, hostTip(node.dataset.host));
  });
  svg.addEventListener("focusout", () => { focus(null); hideTooltip(); });
  svg.addEventListener("keydown", (ev) => {
    const node = ev.target.closest(".node");
    if (node && (ev.key === "Enter" || ev.key === " ")) {
      ev.preventDefault();
      onHost?.(node.dataset.host);
    }
  });
  return true;
}
