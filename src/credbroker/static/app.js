"use strict";

const REFRESH_MS = 1000;

let lastState = null;
let lastLoadedSha = null;

function apiFetch(path, options = {}) {
  const headers = Object.assign({ "X-Credbroker-GUI": "1" }, options.headers || {});
  if (options.method && options.method !== "GET") {
    headers["Content-Type"] = "application/json";
  }
  return fetch(path, Object.assign({}, options, { headers }));
}

function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

function td(text) {
  const cell = document.createElement("td");
  cell.textContent = text;
  return cell;
}

function requestText(kind, detail) {
  if (kind === "exec") {
    let text = (detail.args || []).join(" ");
    if (detail.reason) text += `  — reason: ${detail.reason}`;
    return text;
  }
  if (kind === "git") {
    let text = `${detail.op} ${detail.repo}`;
    const refs = detail.refs || [];
    if (refs.length) {
      text += " " + refs.map((r) => (r.refname !== undefined ? r.refname : r)).join(", ");
    }
    return text;
  }
  return JSON.stringify(detail);
}

function peerLabel(state, peer) {
  const name = state.peer_names && state.peer_names[peer];
  return name ? `${name} (${peer})` : peer;
}

function distinctAgents(state) {
  const agents = new Set();
  for (const item of state.pending) if (item.agent) agents.add(item.agent);
  for (const item of state.history) if (item.agent) agents.add(item.agent);
  return Array.from(agents).sort();
}

function rebuildAgentFilter(state) {
  const select = document.getElementById("filter-agent");
  const current = select.value || "all";
  clear(select);
  const allOpt = document.createElement("option");
  allOpt.value = "all";
  allOpt.textContent = "all";
  select.appendChild(allOpt);
  for (const agent of distinctAgents(state)) {
    const opt = document.createElement("option");
    opt.value = agent;
    opt.textContent = agent;
    select.appendChild(opt);
  }
  const known = Array.from(select.options).some((o) => o.value === current);
  select.value = known ? current : "all";
}

function matchesFilters(entry, decisionOf) {
  const agentFilter = document.getElementById("filter-agent").value;
  const kindFilter = document.getElementById("filter-kind").value;
  const decisionFilter = document.getElementById("filter-decision").value;
  const search = document.getElementById("filter-search").value.trim().toLowerCase();

  if (agentFilter !== "all" && (entry.agent || null) !== agentFilter) return false;
  if (kindFilter !== "all" && entry.kind !== kindFilter) return false;
  if (decisionFilter !== "all" && decisionOf != null && decisionOf !== decisionFilter) return false;
  if (search && !JSON.stringify(entry).toLowerCase().includes(search)) return false;
  return true;
}

function resolveIds(ids, decision) {
  apiFetch("/api/resolve", {
    method: "POST",
    body: JSON.stringify({ ids, decision }),
  }).then(refresh);
}

function renderPending(state) {
  const tbody = document.querySelector("#pending-table tbody");
  clear(tbody);
  const now = state.now;
  const visible = state.pending.filter((item) => matchesFilters(item, null));
  for (const item of visible) {
    const row = document.createElement("tr");
    row.appendChild(td(Math.max(0, now - item.created).toFixed(0)));
    row.appendChild(td(Math.max(0, item.expires - now).toFixed(0)));
    row.appendChild(td(item.agent ?? "?"));
    row.appendChild(td(peerLabel(state, item.peer)));
    row.appendChild(td(item.kind));
    row.appendChild(td(requestText(item.kind, item.detail)));

    const approveCell = document.createElement("td");
    const approveBtn = document.createElement("button");
    approveBtn.type = "button";
    approveBtn.textContent = "Approve";
    approveBtn.addEventListener("click", () => resolveIds([item.id], "allow"));
    approveCell.appendChild(approveBtn);
    row.appendChild(approveCell);

    const denyCell = document.createElement("td");
    const denyBtn = document.createElement("button");
    denyBtn.type = "button";
    denyBtn.textContent = "Deny";
    denyBtn.addEventListener("click", () => resolveIds([item.id], "deny"));
    denyCell.appendChild(denyBtn);
    row.appendChild(denyCell);

    tbody.appendChild(row);
  }

  const approveAllBtn = document.getElementById("approve-all");
  approveAllBtn.textContent = `Approve all (${visible.length})`;
  approveAllBtn.onclick = () => {
    if (visible.length === 0) return;
    resolveIds(visible.map((item) => item.id), "allow");
  };
}

function renderHistory(state) {
  const tbody = document.querySelector("#history-table tbody");
  clear(tbody);
  for (const entry of state.history.slice(0, 500)) {
    if (!matchesFilters(entry, entry.decision)) continue;
    const row = document.createElement("tr");
    row.appendChild(td(entry.ts));
    row.appendChild(td(entry.agent ?? "?"));
    row.appendChild(td(peerLabel(state, entry.peer)));
    row.appendChild(td(entry.kind));
    row.appendChild(td(requestText(entry.kind, entry.detail)));
    row.appendChild(td(entry.decision));
    row.appendChild(td(entry.via));
    row.appendChild(td(entry.exit !== undefined ? entry.exit : ""));
    tbody.appendChild(row);
  }
}

function renderBanners(state) {
  const errorBanner = document.getElementById("error-banner");
  if (state.policy_status.error) {
    errorBanner.textContent = `Policy on disk is invalid; running previous policy: ${state.policy_status.error}`;
    errorBanner.hidden = false;
  } else {
    errorBanner.hidden = true;
  }
  document.getElementById("restart-banner").hidden = !state.policy_status.restart_required;
  document.getElementById("backend-badge").textContent = state.prompt_backend;
  document.getElementById("notify-toggle").checked = state.notify_while_open;
}

function render(state) {
  lastState = state;
  rebuildAgentFilter(state);
  renderBanners(state);
  renderPending(state);
  renderHistory(state);
}

async function refresh() {
  try {
    const resp = await apiFetch("/api/state");
    if (!resp.ok) throw new Error("bad status");
    const state = await resp.json();
    document.getElementById("conn-banner").hidden = true;
    render(state);
  } catch (e) {
    document.getElementById("conn-banner").hidden = false;
  }
}

function setupFilters() {
  for (const id of ["filter-agent", "filter-kind", "filter-decision"]) {
    document.getElementById(id).addEventListener("change", () => {
      if (lastState) render(lastState);
    });
  }
  document.getElementById("filter-search").addEventListener("input", () => {
    if (lastState) render(lastState);
  });
}

function setupNotifyToggle() {
  document.getElementById("notify-toggle").addEventListener("change", (e) => {
    apiFetch("/api/settings", {
      method: "POST",
      body: JSON.stringify({ notify_while_open: e.target.checked }),
    });
  });
}

async function loadPolicy() {
  const resp = await apiFetch("/api/policy");
  const data = await resp.json();
  document.getElementById("policy-text").value = data.text;
  lastLoadedSha = data.sha256;
  document.getElementById("policy-status").textContent = "";
}

async function savePolicy() {
  const text = document.getElementById("policy-text").value;
  const resp = await apiFetch("/api/policy", {
    method: "PUT",
    body: JSON.stringify({ text, sha256: lastLoadedSha }),
  });
  const data = await resp.json();
  const statusEl = document.getElementById("policy-status");
  if (resp.ok) {
    lastLoadedSha = data.sha256;
    statusEl.textContent = data.restart_required
      ? "Saved and applied — restart unit to rebind listen/gui_listen"
      : "Saved and applied";
  } else {
    statusEl.textContent = data.error || "save failed";
  }
}

function openPolicyPanel() {
  document.getElementById("policy-overlay").hidden = false;
  loadPolicy();
}

function closePolicyPanel() {
  document.getElementById("policy-overlay").hidden = true;
}

function setupPolicy() {
  document.getElementById("policy-save").addEventListener("click", savePolicy);
  document.getElementById("policy-reload").addEventListener("click", loadPolicy);
  document.getElementById("policy-toggle").addEventListener("click", openPolicyPanel);
  document.getElementById("policy-close").addEventListener("click", closePolicyPanel);
  document.getElementById("policy-overlay").addEventListener("click", (e) => {
    if (e.target.id === "policy-overlay") closePolicyPanel();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !document.getElementById("policy-overlay").hidden) closePolicyPanel();
  });
}

function main() {
  setupFilters();
  setupNotifyToggle();
  setupPolicy();
  refresh();
  setInterval(refresh, REFRESH_MS);
}

document.addEventListener("DOMContentLoaded", main);
