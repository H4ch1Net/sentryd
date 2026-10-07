/* Settings: appearance, live updates, instance facts, token access, rules. */

import { api, hasToken, setToken } from "../api.js";
import { ctx } from "../context.js";
import { $, esc, fmtNum, icon } from "../dom.js";
import { setLive } from "../live.js";
import * as prefs from "../prefs.js";
import { segmented, toast, toastError } from "../ui.js";

let themeSeg;
let densitySeg;

export function initSettings() {
  themeSeg = segmented($("#pref-theme"), { value: prefs.get("theme"), onChange: (v) => prefs.set("theme", v) });
  densitySeg = segmented($("#pref-density"), { value: prefs.get("density"), onChange: (v) => prefs.set("density", v) });
  const motion = $("#pref-motion");
  motion.checked = prefs.get("motion") === "reduced";
  motion.addEventListener("change", () => prefs.set("motion", motion.checked ? "reduced" : "full"));
  const live = $("#pref-live");
  live.checked = prefs.get("live");
  live.addEventListener("change", () => { prefs.set("live", live.checked); setLive(live.checked); });
  prefs.onChange((name, value) => {
    if (name === "theme") themeSeg.set(value);
    if (name === "live") { live.checked = value; $("#live-toggle").checked = value; }
  });

  $("#settings-rules").addEventListener("change", async (ev) => {
    const box = ev.target.closest("input[data-rule]");
    if (!box) return;
    const disabled = !box.checked;
    const card = box.closest(".rule-card");
    card.classList.toggle("off", disabled);
    try {
      await api(`/api/rules/${encodeURIComponent(box.dataset.rule)}/toggle?disabled=${disabled}`, { method: "POST" });
      toast(`${box.dataset.rule} ${disabled ? "disabled" : "enabled"} for future runs`, { kind: "ok" });
    } catch (err) {
      box.checked = !box.checked;
      card.classList.toggle("off", !box.checked);
      toastError(err);
    }
  });
}

export async function load() {
  densitySeg.set(prefs.get("density"));
  themeSeg.set(prefs.get("theme"));
  let status;
  let rules;
  try {
    [status, rules] = await Promise.all([api("/api/status"), api("/api/rules")]);
  } catch (err) {
    return toastError(err);
  }
  ctx.status = status;
  const ai = status.ai.available
    ? `<span class="status-chip complete">${icon("check")}configured &middot; ${esc(status.ai.provider)}</span>`
    : `<span class="status-chip" style="text-transform:none">Not configured</span> <span class="dim" style="font-size:.76rem">set OPENROUTER_API_KEY to enable</span>`;
  $("#instance-sub").textContent = `sentryd ${status.version}`;
  $("#settings-instance").innerHTML = `
    <dt>AI triage</dt><dd>${ai}</dd>
    <dt>Database</dt><dd class="mono">${esc(status.db_path)}</dd>
    <dt>Cases</dt><dd>${fmtNum(status.cases)}</dd>
    <dt>Alerts</dt><dd>${fmtNum(status.alerts)}</dd>`;

  const access = $("#settings-access");
  access.innerHTML = hasToken()
    ? `<div class="access-row"><span>${icon("key")} An API token is stored in this browser.</span><button class="btn small" type="button" id="forget-token">Forget token</button></div>`
    : "";
  access.querySelector("#forget-token")?.addEventListener("click", () => {
    setToken("");
    toast("Token forgotten; you'll be asked again if the server requires one", { kind: "ok" });
    load();
  });

  const cards = rules.rules.map((r) => {
    const off = !r.effective_enabled;
    const settings = Object.entries(r.config)
      .filter(([, v]) => typeof v !== "object" || v === null || (Array.isArray(v) && v.every((x) => typeof x !== "object")))
      .map(([k, v]) => `<span title="${esc(k)}">${esc(k)}=${esc(Array.isArray(v) ? `[${v.length}]` : v)}</span>`).join("");
    const watch = Array.isArray(r.config.ports) ? `<span>${r.config.ports.length} watched ports</span>` : "";
    return `<article class="rule-card ${off ? "off" : ""}">
      <div class="rule-card-head">
        <span class="rule-card-name">${esc(r.rule_id)}</span>
        <label class="switch" title="${r.config_enabled ? "" : "disabled in the config file"}">
          <input type="checkbox" role="switch" data-rule="${esc(r.rule_id)}" ${off ? "" : "checked"} ${r.config_enabled ? "" : "disabled"} aria-label="Enable ${esc(r.rule_id)}">
          <span class="switch-track"><span class="switch-knob"></span></span>
        </label>
      </div>
      <p>${esc(r.summary || "")}${r.config_enabled ? "" : ' <b>Off in config.</b>'}</p>
      <div class="kv">${settings}${watch}</div>
    </article>`;
  });
  const sigCount = rules.signatures.length;
  cards.push(`<article class="rule-card ${rules.disabled.includes("signature") || !sigCount ? "off" : ""}">
    <div class="rule-card-head"><span class="rule-card-name">signature</span>
      <label class="switch"><input type="checkbox" role="switch" data-rule="signature" ${rules.disabled.includes("signature") ? "" : "checked"} ${sigCount ? "" : "disabled"} aria-label="Enable signatures">
      <span class="switch-track"><span class="switch-knob"></span></span></label></div>
    <p>Config-driven stateless matcher: protocol, CIDRs, port ranges and TCP flags declared under <code>signatures:</code>, no code needed.</p>
    <div class="kv"><span>${sigCount} signature${sigCount === 1 ? "" : "s"}</span></div>
  </article>`);
  $("#settings-rules").innerHTML = cards.join("");
}
