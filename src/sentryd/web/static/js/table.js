/* Alert table: keyed rendering, sorting, multi-select, keyboard cursor.

   Rows are reused by alert id and only rebuilt when that alert's visible
   fields changed, so a live refresh touches a handful of rows instead of
   re-rendering hundreds. One delegated listener set serves every row. */

import {
  $, SEVERITY_RANK, VERDICTS, badge, esc, fmtTime, hostLink, icon, plural, verdictChip,
} from "./dom.js";

const COLUMNS = [
  { key: "id", label: "ID", num: true, sort: (a) => a.id },
  { key: "ts", label: "First seen (UTC)", sort: (a) => a.ts },
  { key: "severity", label: "Severity", sort: (a) => SEVERITY_RANK[a.severity] * 1e12 + a.ts },
  { key: "rule_id", label: "Rule", sort: (a) => a.rule_id },
  { key: "src", label: "Source" },
  { key: "dst", label: "Target" },
  { key: "title", label: "Title" },
  { key: "status", label: "Verdict", sort: (a) => a.status },
];

const signature = (a) => `${a.status}|${a.count}|${a.severity}|${a.ai_summary ? 1 : 0}|${a.last_ts}|${a.title}`;

function rowHtml(a) {
  return `<td class="check"><label class="cbox"><input type="checkbox" data-check aria-label="Select alert #${a.id}"><span>${icon("check")}</span></label></td>
    <td class="num dim">${a.id}</td>
    <td class="mono" title="${fmtTime(a.ts)} UTC">${fmtTime(a.ts).slice(5)}</td>
    <td>${badge(a.severity)}</td>
    <td class="mono">${esc(a.rule_id)}</td>
    <td>${hostLink(a.src)}</td>
    <td>${hostLink(a.dst)}</td>
    <td class="title-cell" title="${esc(a.title)}">${a.count > 1 ? `<span class="count" title="${a.count} occurrences merged by dedup">×${a.count}</span> ` : ""}${a.ai_summary ? `<span class="ai-mark" title="AI writeup stored">${icon("sparkles")}</span> ` : ""}${esc(a.title)}</td>
    <td>${verdictChip(a.status)}</td>`;
}

export class AlertTable {
  constructor(container, { onOpen, onHost, onBulk, emptyHtml, limit = 500 }) {
    this.container = container;
    this.onOpen = onOpen;
    this.onHost = onHost;
    this.onBulk = onBulk;
    this.emptyHtml = emptyHtml;
    this.limit = limit;
    this.alerts = [];
    this.visible = [];
    this.needle = "";
    this.sort = { key: "ts", dir: "desc" };
    this.checked = new Set();
    this.selectedId = null;
    this.cursor = 0;
    this.lastChecked = null;
    this.seen = null; // ids rendered before; null until first data arrives
    this.rows = new Map(); // id -> { tr, sig }

    container.innerHTML = `<div class="table-wrap"><table class="tbl">
        <thead><tr>
          <th class="check"><label class="cbox"><input type="checkbox" data-check-all aria-label="Select all visible alerts"><span>${icon("check")}</span></label></th>
          ${COLUMNS.map((c) => `<th class="${c.num ? "num" : ""} ${c.cls ?? ""}" data-col="${c.key}">${c.sort
            ? `<button type="button" class="sort" data-sort="${c.key}">${c.label}${icon("chevron-down")}</button>` : c.label}</th>`).join("")}
        </tr></thead><tbody></tbody></table></div>
      <div class="table-empty" hidden></div>
      <div class="table-foot" hidden></div>`;
    this.tbody = container.querySelector("tbody");
    this.checkAll = container.querySelector("[data-check-all]");
    this.bind();
    this.paintSort();
  }

  bind() {
    this.container.querySelector("thead").addEventListener("click", (ev) => {
      const b = ev.target.closest("button[data-sort]");
      if (!b) return;
      const key = b.dataset.sort;
      this.sort = this.sort.key === key
        ? { key, dir: this.sort.dir === "desc" ? "asc" : "desc" }
        : { key, dir: key === "rule_id" || key === "status" ? "asc" : "desc" };
      this.paintSort();
      this.render();
    });
    this.checkAll.addEventListener("change", () => {
      const on = this.checkAll.checked;
      for (const a of this.visible) on ? this.checked.add(a.id) : this.checked.delete(a.id);
      this.paintChecks();
    });
    this.tbody.addEventListener("click", (ev) => {
      const tr = ev.target.closest("tr[data-id]");
      if (!tr) return;
      const id = Number(tr.dataset.id);
      if (ev.target.closest(".cbox")) {
        if (ev.target.matches("input[data-check]")) this.toggle(id, ev.shiftKey);
        return;
      }
      const host = ev.target.closest(".host-link");
      if (host) {
        ev.preventDefault();
        this.onHost?.(host.dataset.host);
        return;
      }
      this.setCursor(this.visible.findIndex((a) => a.id === id));
      this.onOpen?.(id, this);
    });
    this.tbody.addEventListener("keydown", (ev) => {
      if (ev.target.matches("input")) return;
      if (ev.key === "ArrowDown") { ev.preventDefault(); this.move(1); }
      else if (ev.key === "ArrowUp") { ev.preventDefault(); this.move(-1); }
      else if (ev.key === "Enter") { ev.preventDefault(); this.openCursor(); }
      else if (ev.key === " ") { ev.preventDefault(); this.toggleCursor(); }
    });
  }

  paintSort() {
    this.container.querySelectorAll("th[data-col]").forEach((th) => {
      if (th.dataset.col === this.sort.key) th.setAttribute("aria-sort", this.sort.dir === "asc" ? "ascending" : "descending");
      else th.removeAttribute("aria-sort");
    });
  }

  /** New data from the server; highlightNew flashes rows not seen before. */
  setAlerts(alerts, { highlightNew = false } = {}) {
    const fresh = highlightNew && this.seen ? new Set(alerts.filter((a) => !this.seen.has(a.id)).map((a) => a.id)) : new Set();
    this.seen = new Set(alerts.map((a) => a.id));
    this.alerts = alerts;
    const known = new Set(this.seen);
    for (const id of this.checked) if (!known.has(id)) this.checked.delete(id);
    this.render(fresh);
  }

  setFilter(needle) {
    this.needle = needle.trim().toLowerCase();
    this.render();
  }

  render(fresh = new Set()) {
    const n = this.needle;
    let rows = n
      ? this.alerts.filter((a) => `${a.id} ${a.title} ${a.src ?? ""} ${a.dst ?? ""} ${a.rule_id} ${a.dst_port ?? ""}`.toLowerCase().includes(n))
      : this.alerts.slice();
    const col = COLUMNS.find((c) => c.key === this.sort.key);
    if (col?.sort && !(this.sort.key === "ts" && this.sort.dir === "desc")) {
      const dir = this.sort.dir === "asc" ? 1 : -1;
      rows.sort((a, b) => {
        const x = col.sort(a);
        const y = col.sort(b);
        return (x < y ? -1 : x > y ? 1 : b.id - a.id) * dir;
      });
    }
    this.visible = rows;

    const keep = new Set();
    const frag = document.createDocumentFragment();
    for (const a of rows) {
      keep.add(a.id);
      let entry = this.rows.get(a.id);
      const sig = signature(a);
      if (!entry) {
        const tr = document.createElement("tr");
        tr.dataset.id = a.id;
        tr.tabIndex = -1;
        entry = { tr, sig: null };
        this.rows.set(a.id, entry);
      }
      if (entry.sig !== sig) {
        entry.tr.innerHTML = rowHtml(a);
        entry.sig = sig;
      }
      if (fresh.has(a.id)) {
        entry.tr.classList.remove("is-new");
        void entry.tr.offsetWidth;
        entry.tr.classList.add("is-new");
      }
      frag.appendChild(entry.tr);
    }
    for (const [id, entry] of this.rows) {
      if (!keep.has(id)) { entry.tr.remove(); this.rows.delete(id); }
    }
    this.tbody.appendChild(frag);

    const empty = this.container.querySelector(".table-empty");
    empty.hidden = rows.length > 0;
    if (!rows.length) empty.innerHTML = typeof this.emptyHtml === "function" ? this.emptyHtml(this) : this.emptyHtml;
    this.container.querySelector(".table-wrap").hidden = !rows.length;

    const foot = this.container.querySelector(".table-foot");
    foot.hidden = !this.alerts.length;
    const capped = this.alerts.length >= this.limit;
    foot.innerHTML = `<span>Showing ${plural(rows.length, "alert")}${rows.length !== this.alerts.length ? ` of ${this.alerts.length}` : ""}${capped ? ` (newest ${this.limit}; narrow the filters to reach older ones)` : ""}</span>
      <span><kbd>J</kbd> <kbd>K</kbd> move &middot; <kbd>Enter</kbd> open &middot; <kbd>X</kbd> select</span>`;

    this.cursor = Math.min(this.cursor, Math.max(0, rows.length - 1));
    this.paintChecks();
    this.paintSelected();
  }

  /* ---------- selection & cursor ---------- */

  toggle(id, range = false) {
    const idx = this.visible.findIndex((a) => a.id === id);
    const on = !this.checked.has(id);
    if (range && this.lastChecked !== null) {
      const from = this.visible.findIndex((a) => a.id === this.lastChecked);
      if (from !== -1) {
        const [lo, hi] = [Math.min(from, idx), Math.max(from, idx)];
        for (const a of this.visible.slice(lo, hi + 1)) on ? this.checked.add(a.id) : this.checked.delete(a.id);
      }
    } else {
      on ? this.checked.add(id) : this.checked.delete(id);
    }
    this.lastChecked = id;
    this.paintChecks();
  }

  clearChecks() {
    this.checked.clear();
    this.paintChecks();
  }

  paintChecks() {
    for (const [id, { tr }] of this.rows) {
      const on = this.checked.has(id);
      tr.classList.toggle("checked", on);
      const box = tr.querySelector("input[data-check]");
      if (box) box.checked = on;
    }
    const visibleChecked = this.visible.filter((a) => this.checked.has(a.id)).length;
    this.checkAll.checked = visibleChecked > 0 && visibleChecked === this.visible.length;
    this.checkAll.indeterminate = visibleChecked > 0 && visibleChecked < this.visible.length;
    this.paintBulkBar();
  }

  paintBulkBar() {
    const bar = $("#bulk-bar");
    if (!this.isActive()) return;
    const n = this.checked.size;
    bar.classList.toggle("show", n > 0);
    bar.inert = n === 0;
    if (!n) return;
    bar.innerHTML = `<span class="n">${plural(n, "alert")} selected</span>
      ${VERDICTS.map((v) => `<button class="btn small" type="button" data-bulk="${v.value}">${icon(v.icon)}${v.value === "new" ? "Reset" : v.label}</button>`).join("")}
      <button class="icon-btn" type="button" data-bulk-clear aria-label="Clear selection">${icon("x")}</button>`;
    bar.onclick = (ev) => {
      if (ev.target.closest("[data-bulk-clear]")) return this.clearChecks();
      const b = ev.target.closest("[data-bulk]");
      if (b) this.onBulk?.([...this.checked], b.dataset.bulk, this);
    };
  }

  isActive() { return this.container.offsetParent !== null; }

  setSelected(id) {
    this.selectedId = id;
    this.paintSelected();
  }

  paintSelected() {
    for (const [id, { tr }] of this.rows) tr.classList.toggle("selected", id === this.selectedId);
    this.rows.forEach(({ tr }) => { tr.tabIndex = -1; });
    const at = this.visible[this.cursor];
    if (at) this.rows.get(at.id).tr.tabIndex = 0;
  }

  setCursor(i) {
    if (i < 0 || i >= this.visible.length) return;
    this.cursor = i;
    this.paintSelected();
  }

  move(delta) {
    if (!this.visible.length) return;
    const next = Math.max(0, Math.min(this.visible.length - 1, this.cursor + delta));
    this.setCursor(next);
    const tr = this.rows.get(this.visible[next].id).tr;
    tr.focus({ preventScroll: true });
    tr.scrollIntoView({ block: "nearest" });
  }

  openCursor() {
    const a = this.visible[this.cursor];
    if (a) this.onOpen?.(a.id, this);
  }

  toggleCursor() {
    const a = this.visible[this.cursor];
    if (a) this.toggle(a.id);
  }

  /** Neighbors of an alert in the current visible order (drawer prev/next). */
  neighbors(id) {
    const i = this.visible.findIndex((a) => a.id === id);
    if (i === -1) return { prev: null, next: null };
    return { prev: this.visible[i - 1]?.id ?? null, next: this.visible[i + 1]?.id ?? null, index: i };
  }

  statusOf(id) {
    return this.alerts.find((a) => a.id === id)?.status;
  }
}
