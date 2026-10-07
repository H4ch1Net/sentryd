/* Command palette (Ctrl/Cmd+K): jump to any view, case, alert or host,
   or run an action, by typing a few characters. */

import { ctx } from "./context.js";
import { esc, icon } from "./dom.js";
import { modalOpen, openModal } from "./ui.js";

const IP = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i;

/** Subsequence match; rewards prefixes, word starts and runs. */
function score(text, query) {
  if (!query) return { score: 1, marks: [] };
  const t = text.toLowerCase();
  let ti = 0;
  let total = 0;
  let run = 0;
  const marks = [];
  for (const ch of query.toLowerCase()) {
    const found = t.indexOf(ch, ti);
    if (found === -1) return null;
    run = found === ti ? run + 1 : 0;
    const wordStart = found === 0 || /[\s#._:/-]/.test(t[found - 1]);
    total += 1 + run * 2 + (wordStart ? 3 : 0) - Math.min(found - ti, 6) * 0.2;
    marks.push(found);
    ti = found + 1;
  }
  if (t.startsWith(query.toLowerCase())) total += 8;
  return { score: total, marks };
}

function highlight(text, marks) {
  const set = new Set(marks);
  return [...text].map((ch, i) => (set.has(i) ? `<mark>${esc(ch)}</mark>` : esc(ch))).join("");
}

function sources(actions) {
  const items = [...actions];
  for (const c of ctx.cases.slice(0, 60)) {
    items.push({ group: "Cases", icon: "cases", label: `#${c.id} ${c.name}`, hint: `${c.status} · ${c.alert_count} alerts`, run: () => ctx.navigate(`#/case/${c.id}`) });
  }
  const table = ctx.activeTable;
  const hosts = new Map();
  for (const a of table?.alerts.slice(0, 300) ?? []) {
    items.push({ group: "Alerts", icon: "alert", label: `#${a.id} ${a.title}`, hint: a.severity, run: () => ctx.openAlert(a.id, table) });
    for (const h of [a.src, a.dst]) if (h) hosts.set(h, (hosts.get(h) || 0) + 1);
  }
  for (const [h, n] of [...hosts].sort((x, y) => y[1] - x[1]).slice(0, 60)) {
    items.push({ group: "Hosts", icon: "host", label: h, hint: `${n} alerts`, run: () => ctx.openHost(h) });
  }
  return items;
}

function dynamic(query) {
  const q = query.trim();
  const id = q.match(/^#?(\d+)$/);
  const out = [];
  if (id) {
    out.push({ group: "Jump", icon: "alert", label: `Open alert #${id[1]}`, run: () => ctx.openAlert(Number(id[1])) });
    out.push({ group: "Jump", icon: "cases", label: `Open case #${id[1]}`, run: () => ctx.navigate(`#/case/${id[1]}`) });
  }
  if (IP.test(q)) {
    out.push({ group: "Jump", icon: "host", label: `Inspect host ${q}`, run: () => ctx.openHost(q) });
    out.push({ group: "Jump", icon: "filter", label: `Filter overview to ${q}`, run: () => ctx.filterOverview({ q }) });
  }
  return out;
}

export function openPalette(actions) {
  if (modalOpen()) return;
  const all = sources(actions);
  openModal(
    `<div class="palette-input">${icon("search")}<input type="text" placeholder="Search views, cases, alerts, hosts, or type #id / an IP" aria-label="Command" autocomplete="off" spellcheck="false" autofocus></div>
     <div class="palette-list" role="listbox"></div>
     <div class="palette-foot"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span></div>`,
    {
      className: "palette",
      onMount(el, close) {
        const input = el.querySelector("input");
        const list = el.querySelector(".palette-list");
        let shown = [];
        let active = 0;

        const paint = () => {
          list.querySelectorAll(".palette-item").forEach((b, i) => b.setAttribute("aria-selected", String(i === active)));
          list.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
        };
        const render = () => {
          const q = input.value.trim();
          const ranked = [...dynamic(q), ...all]
            .map((it) => ({ it, m: it.group === "Jump" ? { score: 1e6, marks: [] } : score(it.label, q) }))
            .filter((x) => x.m)
            .sort((a, b) => b.m.score - a.m.score);
          const perGroup = new Map();
          shown = ranked.filter(({ it }) => {
            const n = perGroup.get(it.group) || 0;
            perGroup.set(it.group, n + 1);
            return n < (q ? 6 : 4);
          }).slice(0, 36);
          const order = [...new Set(shown.map((x) => x.it.group))];
          shown.sort((a, b) => order.indexOf(a.it.group) - order.indexOf(b.it.group));
          active = 0;
          let group = null;
          list.innerHTML = shown.length ? shown.map(({ it, m }, i) => {
            const head = it.group !== group ? `<div class="palette-group">${esc(it.group)}</div>` : "";
            group = it.group;
            return `${head}<button type="button" class="palette-item" role="option" data-i="${i}">${icon(it.icon)}<span class="pi-label">${highlight(it.label, m.marks)}</span>${it.hint ? `<span class="pi-hint">${esc(it.hint)}</span>` : ""}</button>`;
          }).join("") : `<div class="palette-empty">Nothing matches “${esc(q)}”</div>`;
          paint();
        };
        const run = (i) => {
          const pick = shown[i]?.it;
          if (!pick) return;
          close();
          setTimeout(() => pick.run(), 0);
        };

        input.addEventListener("input", render);
        input.addEventListener("keydown", (ev) => {
          if (ev.key === "ArrowDown") { ev.preventDefault(); active = Math.min(shown.length - 1, active + 1); paint(); }
          else if (ev.key === "ArrowUp") { ev.preventDefault(); active = Math.max(0, active - 1); paint(); }
          else if (ev.key === "Enter") { ev.preventDefault(); run(active); }
        });
        list.addEventListener("click", (ev) => {
          const b = ev.target.closest(".palette-item");
          if (b) run(Number(b.dataset.i));
        });
        list.addEventListener("pointermove", (ev) => {
          const b = ev.target.closest(".palette-item");
          if (b && Number(b.dataset.i) !== active) { active = Number(b.dataset.i); paint(); }
        });
        render();
      },
    }
  );
}
