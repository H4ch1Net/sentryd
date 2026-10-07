/* UI primitives: toasts, tooltip, drawer, modals, segmented controls, menus. */

import { $, esc, icon } from "./dom.js";

/* ---------- toasts ---------- */

const TOAST_ICONS = { ok: "check", error: "alert", info: "info" };

/** toast("Saved", { kind: "ok", action: { label: "Undo", run } }) */
export function toast(message, { kind = "info", action = null, duration = 5000 } = {}) {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.setAttribute("role", kind === "error" ? "alert" : "status");
  el.innerHTML = `<span class="t-icon">${icon(TOAST_ICONS[kind] || "info")}</span>
    <span class="t-msg"></span>
    ${action ? `<button class="btn small ghost t-action" type="button">${esc(action.label)}</button>` : ""}
    <button class="icon-btn" type="button" aria-label="Dismiss">${icon("x")}</button>
    <span class="t-timer" style="animation-duration:${duration}ms"></span>`;
  el.querySelector(".t-msg").textContent = message;
  const host = $("#toasts");
  while (host.children.length >= 4) host.firstElementChild.remove();
  host.appendChild(el);

  const dismiss = () => {
    if (el.classList.contains("leaving")) return;
    el.classList.add("leaving");
    el.addEventListener("animationend", () => el.remove(), { once: true });
    setTimeout(() => el.remove(), 400);
  };
  el.querySelector(".t-timer").addEventListener("animationend", dismiss);
  el.querySelector(".icon-btn").addEventListener("click", dismiss);
  if (action) {
    el.querySelector(".t-action").addEventListener("click", async () => {
      dismiss();
      await action.run();
    });
  }
  return dismiss;
}

export const toastError = (err) => toast(err?.message || String(err), { kind: "error", duration: 7000 });

/* ---------- tooltip ---------- */

const tip = () => $("#tooltip");
let tipFrame = 0;

export function showTooltip(html, x, y) {
  const el = tip();
  el.innerHTML = html;
  cancelAnimationFrame(tipFrame);
  tipFrame = requestAnimationFrame(() => {
    const rect = el.getBoundingClientRect();
    const left = Math.max(8, Math.min(x + 14, innerWidth - rect.width - 8));
    const top = y - rect.height - 12 < 8 ? y + 18 : y - rect.height - 12;
    el.style.setProperty("--tx", `${left}px`);
    el.style.setProperty("--ty", `${top}px`);
    el.classList.add("show");
  });
}

export function hideTooltip() {
  cancelAnimationFrame(tipFrame);
  tip().classList.remove("show");
}

/** Tooltip for an element on hover and keyboard focus alike. */
export function tooltipAt(el, html) {
  const rect = el.getBoundingClientRect();
  showTooltip(html, rect.left + rect.width / 2 - 14, rect.top);
}

/* ---------- drawer ---------- */

let drawerReturnFocus = null;
let drawerNav = { prev: null, next: null };
const drawerCloseHandlers = new Set();

export function onDrawerClose(fn) { drawerCloseHandlers.add(fn); }

export function drawerOpen() { return $("#drawer").classList.contains("open"); }

export function openDrawer({ title, body, prev = null, next = null }) {
  const drawer = $("#drawer");
  const wasOpen = drawerOpen();
  $("#drawer-title").innerHTML = title;
  const bodyEl = $("#drawer-body");
  bodyEl.innerHTML = body;
  bodyEl.scrollTop = 0;
  bodyEl.classList.remove("swap");
  if (wasOpen) { void bodyEl.offsetWidth; bodyEl.classList.add("swap"); }
  drawerNav = { prev, next };
  $("#drawer-prev").hidden = $("#drawer-next").hidden = !prev && !next;
  $("#drawer-prev").disabled = !prev;
  $("#drawer-next").disabled = !next;
  if (!wasOpen) {
    drawerReturnFocus = document.activeElement;
    drawer.inert = false;
    drawer.setAttribute("aria-hidden", "false");
    drawer.classList.add("open");
    $("#scrim").classList.add("open");
    $("#shell").inert = true;
    requestAnimationFrame(() => $("#drawer-close").focus({ preventScroll: true }));
  }
  return bodyEl;
}

export function closeDrawer() {
  if (!drawerOpen()) return;
  const drawer = $("#drawer");
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
  drawer.inert = true;
  $("#scrim").classList.remove("open");
  $("#shell").inert = false;
  hideTooltip();
  drawerCloseHandlers.forEach((fn) => fn());
  if (drawerReturnFocus?.isConnected) drawerReturnFocus.focus({ preventScroll: true });
}

export function drawerStep(direction) {
  const go = direction < 0 ? drawerNav.prev : drawerNav.next;
  if (go) go();
}

/* ---------- modals ---------- */

const modals = [];

/** Open a modal; resolves with whatever close(value) is called with. */
export function openModal(html, { className = "", onMount } = {}) {
  return new Promise((resolve) => {
    const backdrop = document.createElement("div");
    backdrop.className = "modal-backdrop";
    backdrop.innerHTML = `<div class="modal ${className}" role="dialog" aria-modal="true">${html}</div>`;
    const returnFocus = document.activeElement;
    const entry = {
      el: backdrop,
      close(value = null) {
        const i = modals.indexOf(entry);
        if (i === -1) return;
        modals.splice(i, 1);
        backdrop.classList.add("closing");
        setTimeout(() => backdrop.remove(), 180);
        if (!modals.length) {
          $("#shell").inert = drawerOpen();
          $("#drawer").inert = !drawerOpen();
        }
        if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
        resolve(value);
      },
    };
    backdrop.addEventListener("mousedown", (ev) => { if (ev.target === backdrop) entry.close(null); });
    $("#modal-root").appendChild(backdrop);
    modals.push(entry);
    $("#shell").inert = true;
    $("#drawer").inert = true;
    onMount?.(backdrop.querySelector(".modal"), entry.close);
    const focusable = backdrop.querySelector("[autofocus], input, button");
    focusable?.focus();
  });
}

export function modalOpen() { return modals.length > 0; }
export function closeTopModal() { modals.at(-1)?.close(null); }

export function confirmDialog({ title, body, confirmLabel = "Confirm", danger = false }) {
  return openModal(
    `<h2>${icon(danger ? "alert" : "info")}${esc(title)}</h2>
     <p>${body}</p>
     <div class="modal-actions">
       <button class="btn ghost" type="button" data-act="cancel">Cancel</button>
       <button class="btn ${danger ? "danger solid" : "primary"}" type="button" data-act="ok" autofocus>${esc(confirmLabel)}</button>
     </div>`,
    {
      className: danger ? "danger" : "",
      onMount(el, close) {
        el.querySelector('[data-act="cancel"]').addEventListener("click", () => close(false));
        el.querySelector('[data-act="ok"]').addEventListener("click", () => close(true));
      },
    }
  ).then(Boolean);
}

export function promptToken(reason, { rejected = false } = {}) {
  return openModal(
    `<h2>${icon("key")}API token required</h2>
     <p>This server gates its API with <code>SENTRYD_API_TOKEN</code>. Enter the token to continue.</p>
     <form>
       <input type="password" name="token" placeholder="token" autocomplete="current-password" autofocus aria-label="API token">
       ${rejected ? `<p class="err">That token was rejected. Check SENTRYD_API_TOKEN on the server.</p>` : ""}
       <label class="remember"><span class="cbox"><input type="checkbox" name="remember"><span>${icon("check")}</span></span>Remember on this device</label>
       <div class="modal-actions">
         <button class="btn ghost" type="button" data-act="cancel">Cancel</button>
         <button class="btn primary" type="submit">Unlock</button>
       </div>
     </form>`,
    {
      onMount(el, close) {
        const form = el.querySelector("form");
        el.querySelector('[data-act="cancel"]').addEventListener("click", () => close(null));
        form.addEventListener("submit", (ev) => {
          ev.preventDefault();
          const value = form.token.value.trim();
          if (value) close({ token: value, remember: form.remember.checked });
        });
      },
    }
  );
}

/* ---------- segmented control ---------- */

/** Radio-style segmented control with a sliding indicator and arrow keys. */
export function segmented(root, { value = "", onChange } = {}) {
  const buttons = [...root.querySelectorAll("button[data-value]")];
  const indicator = root.querySelector(".seg-indicator");
  let current = value;

  const place = () => {
    const active = buttons.find((b) => b.dataset.value === current) || buttons[0];
    if (!active || !indicator || !active.offsetWidth) return;
    indicator.style.setProperty("--x", `${active.offsetLeft}px`);
    indicator.style.setProperty("--w", `${active.offsetWidth}px`);
  };
  const set = (next, notify = false) => {
    current = next;
    for (const b of buttons) {
      const on = b.dataset.value === next;
      b.setAttribute("aria-checked", String(on));
      b.tabIndex = on ? 0 : -1;
    }
    place();
    if (notify) onChange?.(next);
  };

  root.addEventListener("click", (ev) => {
    const b = ev.target.closest("button[data-value]");
    if (b && b.dataset.value !== current) set(b.dataset.value, true);
  });
  root.addEventListener("keydown", (ev) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(ev.key)) return;
    ev.preventDefault();
    const i = buttons.findIndex((b) => b.dataset.value === current);
    const n = ev.key === "Home" ? 0 : ev.key === "End" ? buttons.length - 1
      : (i + (ev.key === "ArrowRight" ? 1 : -1) + buttons.length) % buttons.length;
    set(buttons[n].dataset.value, true);
    buttons[n].focus();
  });
  // Appears at size 0 while its view is hidden: re-place once it has layout.
  root.classList.add("no-anim");
  new ResizeObserver(() => {
    place();
    requestAnimationFrame(() => root.classList.remove("no-anim"));
  }).observe(root);
  set(value);
  return { set: (v) => set(v), get: () => current };
}

/* ---------- menus ---------- */

/** Dropdown menu anchored to a button; items: [{label, icon, sub, run}] */
export function attachMenu(button, items) {
  const wrap = button.parentElement;
  let list = null;
  const close = () => {
    list?.remove();
    list = null;
    button.setAttribute("aria-expanded", "false");
    document.removeEventListener("mousedown", outside, true);
  };
  const outside = (ev) => { if (!wrap.contains(ev.target)) close(); };
  button.setAttribute("aria-haspopup", "menu");
  button.setAttribute("aria-expanded", "false");
  button.addEventListener("click", () => {
    if (list) return close();
    list = document.createElement("div");
    list.className = "menu-list";
    list.setAttribute("role", "menu");
    list.innerHTML = items.map((it, i) =>
      `<button type="button" role="menuitem" data-i="${i}">${icon(it.icon)}${esc(it.label)}${it.sub ? `<span class="mi-sub">${esc(it.sub)}</span>` : ""}</button>`).join("");
    wrap.appendChild(list);
    button.setAttribute("aria-expanded", "true");
    list.querySelector("button")?.focus();
    list.addEventListener("click", (ev) => {
      const b = ev.target.closest("button[data-i]");
      if (!b) return;
      close();
      items[Number(b.dataset.i)].run();
    });
    list.addEventListener("keydown", (ev) => {
      const all = [...list.querySelectorAll("button")];
      const i = all.indexOf(document.activeElement);
      if (ev.key === "Escape") { ev.stopPropagation(); close(); button.focus(); }
      if (ev.key === "ArrowDown") { ev.preventDefault(); all[(i + 1) % all.length].focus(); }
      if (ev.key === "ArrowUp") { ev.preventDefault(); all[(i - 1 + all.length) % all.length].focus(); }
    });
    setTimeout(() => document.addEventListener("mousedown", outside, true));
  });
}

/** Mark a button busy (spinner, disabled) for the duration of a promise. */
export async function busy(button, work) {
  button.classList.add("is-busy");
  button.disabled = true;
  try {
    return await work();
  } finally {
    button.classList.remove("is-busy");
    button.disabled = false;
  }
}
