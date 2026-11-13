// Author: DanyTech
// ForkSploit dashboard -- frontend.
//
// This file is a PROJECTION + control surface ONLY. It renders what the
// server's /api/state returns and forwards every action to the server, which
// runs the real CLI script as a subprocess. It contains NO system logic: no
// validation of wallets/chains beyond what the server already enforces, no
// re-implementation of any safety check, no local state that could disagree
// with the server.

let actionSchemas = {};
let currentRunId = null;
let currentWs = null;
let currentWatchedChain = null;
let latestState = {};

const WATERMARKS = { eth: "eth_watermark.png", etc: "etc_watermark.png" };

const VIEW_TITLES = {
  overview: "Overview",
  run: "Run an operation",
  runs: "Active runs",
  console: "Console",
  wallet: "Wallet policy",
  rpc: "RPC overrides",
  contracts: "Contracts",
  findings: "Findings",
  logs: "Run logs",
  processes: "Processes and AttackWallets",
};

// --------------------------------------------------------------------------
// Router (hash-based, so a view is linkable and survives a refresh)
// --------------------------------------------------------------------------
function currentView() {
  const h = (location.hash || "").replace(/^#\/?/, "");
  return VIEW_TITLES[h] ? h : "overview";
}

function showView(name) {
  if (!VIEW_TITLES[name]) name = "overview";
  document.querySelectorAll(".view").forEach((v) => {
    v.classList.toggle("active", v.dataset.view === name);
  });
  document.querySelectorAll(".nav-item").forEach((a) => {
    a.classList.toggle("active", a.dataset.view === name);
  });
  document.getElementById("crumb").textContent = VIEW_TITLES[name];
}

function navigate(name) {
  if (location.hash !== `#/${name}`) location.hash = `#/${name}`;
  else showView(name);
}

window.addEventListener("hashchange", () => showView(currentView()));

// --------------------------------------------------------------------------
// Live network-identity check (unchanged discipline: never infer eth/etc
// from the dropdown text -- always read the real eth_chainId).
// --------------------------------------------------------------------------
async function applyNetworkCheck(chain) {
  const badge = document.getElementById("network-badge-text");
  const banner = document.getElementById("network-mismatch-banner");
  const watermark = document.getElementById("watermark");
  const root = document.documentElement.style;

  let result;
  try {
    result = await fetchJSON(`/api/verify-chain?chain=${encodeURIComponent(chain)}`);
  } catch (e) {
    result = { chain, error: String(e) };
  }

  if (result.error) {
    root.setProperty("--network-color", "var(--bad)");
    badge.textContent = `${chain}: RPC unreachable (${result.error})`;
    banner.style.display = "block";
    banner.textContent = `WARNING: could not verify the actual chain ID for '${chain}' -- the RPC did not respond. Do NOT trust the chain selection until this is fixed.`;
    watermark.style.backgroundImage = "";
    return;
  }

  if (result.family === "eth") {
    watermark.style.backgroundImage = `url(${WATERMARKS.eth})`;
    root.setProperty("--network-color", "var(--eth-color)");
  } else if (result.family === "etc") {
    watermark.style.backgroundImage = `url(${WATERMARKS.etc})`;
    root.setProperty("--network-color", "var(--etc-color)");
  } else {
    watermark.style.backgroundImage = "";
    root.setProperty("--network-color", "var(--muted)");
  }

  if (result.match) {
    badge.textContent = `${chain} -- live verified (chain ID ${result.actual_chain_id})`;
    banner.style.display = "none";
  } else {
    badge.textContent = `${chain} -- chain ID MISMATCH!`;
    banner.style.display = "block";
    banner.textContent = `WARNING: the selected chain '${chain}' expects chain ID ${result.expected_chain_id}, but the RPC actually returns ${result.actual_chain_id} (${result.family.toUpperCase()}). Check the RPC override/setting BEFORE you run anything -- a wrong choice between ETH and ETC is a serious risk.`;
  }
}

function watchChainField() {
  const el = document.getElementById("field-chain");
  const badge = document.getElementById("network-badge-text");
  if (!el) {
    badge.textContent = "this script has no --chain option";
    document.getElementById("watermark").style.backgroundImage = "";
    document.documentElement.style.setProperty("--network-color", "var(--muted)");
    currentWatchedChain = null;
    return;
  }
  currentWatchedChain = el.value;
  applyNetworkCheck(currentWatchedChain);
  el.addEventListener("change", () => {
    currentWatchedChain = el.value;
    applyNetworkCheck(currentWatchedChain);
  });
}

// Re-verify periodically -- an RPC override or the node itself can change
// mid-session; the watermark/badge must reflect reality, not a stale check.
setInterval(() => { if (currentWatchedChain) applyNetworkCheck(currentWatchedChain); }, 10000);

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  return res.json();
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

function setTbody(id, html) {
  const el = document.querySelector(`#${id} tbody`);
  if (el) el.innerHTML = html;
}

// --------------------------------------------------------------------------
// State rendering (one function per data set; ALL /api/state keys shown)
// --------------------------------------------------------------------------
async function refreshState() {
  const state = await fetchJSON("/api/state");
  latestState = state;

  const banner = document.getElementById("warning-banner");
  if (state.rpc_override_warning) {
    const chains = Object.keys(state.rpc_overrides).join(", ");
    banner.style.display = "block";
    banner.textContent = `WARNING: an active RPC override for: ${chains} -- check that this is not left over from a previous fork-test session.`;
  } else {
    banner.style.display = "none";
  }

  renderOverview(state);
  renderRuns(state);
  renderWallets(state);
  renderAttackWallets(state);
  renderContracts(state);
  renderOverrides(state);
  renderFindings(state);
  renderLogs(state);
  renderProcesses(state);

  // Sidebar counters.
  document.getElementById("pill-runs").textContent =
    String(Object.keys(state.dashboard_runs || {}).length);
  document.getElementById("pill-findings").textContent =
    String((state.vulnerabilities_found || []).length);
}

function renderOverview(state) {
  const cards = document.getElementById("overview-cards");
  if (!cards) return;
  const wallets = Object.keys(state.wallets || {}).length;
  const overrides = Object.keys(state.rpc_overrides || {}).length;
  const findings = (state.vulnerabilities_found || []).length;
  const running = Object.values(state.dashboard_runs || {}).filter((r) => !r.finished).length;
  const procs = (state.external_processes || []).length;
  cards.innerHTML = `
    <div class="card"><div class="k">Wallet policy</div><div class="v">${wallets}</div></div>
    <div class="card"><div class="k">RPC overrides</div><div class="v ${overrides ? "warn" : ""}">${overrides}</div></div>
    <div class="card"><div class="k">Findings (plan.json)</div><div class="v">${findings}</div></div>
    <div class="card"><div class="k">Active runs</div><div class="v ${running ? "ok" : ""}">${running}</div></div>
    <div class="card"><div class="k">External processes</div><div class="v">${procs}</div></div>`;

  const rows = (state.recent_logs || []).slice(0, 6).map((entry) =>
    `<tr><td>${esc(entry.file)}</td><td class="muted">${esc(entry.modified)}</td><td>${(entry.outcome_lines || []).map(esc).join("<br/>")}</td></tr>`
  ).join("");
  setTbody("overview-recent", rows || `<tr><td colspan="3" class="muted">No logs.</td></tr>`);
}

function renderRuns(state) {
  const runs = Object.entries(state.dashboard_runs || {});
  const rows = runs.map(([id, r]) => {
    const status = r.finished
      ? `<span class="ok">finished (exit ${esc(r.exit_code)})</span>`
      : (r.awaiting_input ? `<span class="warn">awaiting confirmation</span>` : `<span class="ok">running</span>`);
    const stop = r.finished ? "" : `<button class="danger" onclick="stopRunById('${esc(id)}')">Stop</button>`;
    return `<tr><td class="mono">${esc(id)}</td><td>${esc(r.script)}</td><td class="muted">${esc(r.started_at)}</td><td>${status}</td><td>${stop}</td></tr>`;
  }).join("");
  setTbody("runs-table", rows || `<tr><td colspan="5" class="muted">No run has been started from the dashboard.</td></tr>`);
}

function renderWallets(state) {
  const rows = Object.entries(state.wallets || {}).map(([chain, w]) => {
    const note = w.client_note ? esc(w.client_note) : `<span class="muted">(no note)</span>`;
    return `<tr><td>${esc(chain)}</td><td class="mono">${esc(w.funding_wallet || "")}</td><td class="mono">${esc(w.recovery_wallet || "")}</td><td>${note}</td></tr>`;
  }).join("");
  setTbody("wallets-table", rows || `<tr><td colspan="4" class="muted">No wallet policies registered.</td></tr>`);
}

function renderAttackWallets(state) {
  const rows = Object.entries(state.attack_wallets || {}).map(([chain, info]) => {
    const bal = info.error ? `<span class="bad">${esc(info.error)}</span>` : esc(info.balance_eth);
    return `<tr><td>${esc(chain)}</td><td class="mono">${esc(info.address)}</td><td>${bal}</td></tr>`;
  }).join("");
  setTbody("attack-wallets-table", rows || `<tr><td colspan="3" class="muted">No AttackWallets registered.</td></tr>`);
}

function renderContracts(state) {
  // contracts.json is a FLAT map keyed "chain:address" (see
  // wallet_policy.register_contract): each value is {address, chain, source,
  // first_seen, runs:[...]}. Render every field that exists.
  const rows = Object.entries(state.contracts || {}).map(([key, info]) => {
    if (!info || typeof info !== "object") {
      return `<tr><td colspan="4" class="mono">${esc(key)}</td></tr>`;
    }
    const chain = info.chain || (key.includes(":") ? key.split(":")[0] : "");
    const addr = info.address || (key.includes(":") ? key.split(":")[1] : key);
    const runs = Array.isArray(info.runs) ? info.runs.length : 0;
    const src = info.source || "";
    return `<tr><td>${esc(chain)}</td><td class="mono">${esc(addr)}</td><td>${esc(src)}</td><td class="muted">${runs} run(s)</td></tr>`;
  }).join("");
  setTbody("contracts-table", rows || `<tr><td colspan="4" class="muted">No contracts recorded.</td></tr>`);
}

function renderOverrides(state) {
  const entries = Object.entries(state.rpc_overrides || {});
  const rows = entries.map(([chain, url]) =>
    `<tr><td>${esc(chain)}</td><td class="mono">${esc(url)}</td><td><button class="danger" onclick="clearOverride('${esc(chain)}')">Clear</button></td></tr>`
  ).join("");
  setTbody("overrides-table", rows || `<tr><td colspan="3" class="muted">No override is active -- every chain uses its default RPC.</td></tr>`);
}

function renderFindings(state) {
  const rows = (state.vulnerabilities_found || []).map((p) =>
    `<tr><td class="mono">${esc(p)}</td></tr>`).join("");
  setTbody("findings-table", rows || `<tr><td class="muted">No findings (plan.json) in work_dir/vulnerabilities or auto_work/*/vulnerabilities.</td></tr>`);
}

function renderLogs(state) {
  const rows = (state.recent_logs || []).map((entry) =>
    `<tr><td>${esc(entry.file)}</td><td class="muted">${esc(entry.modified)}</td><td>${(entry.outcome_lines || []).map(esc).join("<br/>")}</td></tr>`
  ).join("");
  setTbody("logs-table", rows || `<tr><td colspan="3" class="muted">No logs.</td></tr>`);
}

function renderProcesses(state) {
  const rows = (state.external_processes || []).map((line) =>
    `<tr><td class="muted mono">${esc(line)}</td></tr>`).join("");
  setTbody("processes-table", rows || `<tr><td class="muted">No external processes.</td></tr>`);
}

// --------------------------------------------------------------------------
// Operations (all forwarded to the server -- no local logic)
// --------------------------------------------------------------------------
async function clearOverride(chain) {
  await fetchJSON(`/api/rpc-override/${encodeURIComponent(chain)}`, { method: "DELETE" });
  await refreshState();
}

async function setOverride() {
  const chain = document.getElementById("ov-chain").value;
  const url = document.getElementById("ov-url").value;
  const result = document.getElementById("ov-result");
  if (!url) { result.textContent = "RPC URL is required."; return; }
  const res = await fetchJSON("/api/rpc-override", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chain, url }),
  });
  result.textContent = res.ok ? `Set: ${chain} -> ${url}` : (res.error || "error");
  await refreshState();
}

async function registerWalletPolicy() {
  const chain = document.getElementById("wp-chain").value;
  const confirm_chain = document.getElementById("wp-confirm-chain").value;
  const funding_wallet = document.getElementById("wp-funding").value;
  const recovery_wallet = document.getElementById("wp-recovery").value;
  const client_note = document.getElementById("wp-client-note").value;
  const force = document.getElementById("wp-force").checked;
  const result = document.getElementById("wp-result");
  if (confirm_chain !== chain) {
    result.innerHTML = `<span class="bad">Chain '${esc(chain)}' and confirmation '${esc(confirm_chain)}' do NOT match -- retype it exactly, without copying.</span>`;
    return;
  }
  const res = await fetchJSON("/api/wallet-policy", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chain, confirm_chain, funding_wallet, recovery_wallet, client_note, force }),
  });
  if (res.error) {
    result.innerHTML = `<span class="bad">${esc(res.error)}</span>`;
  } else {
    result.innerHTML = `<span class="ok">Registered: ${esc(chain)}</span>`;
    await refreshState();
  }
}

function populateQuickActionChainSelects() {
  const chainField = actionSchemas.auto_pipeline && actionSchemas.auto_pipeline.fields.find((f) => f.dest === "chain");
  const choices = (chainField && chainField.choices) || [];
  for (const id of ["wp-chain", "ov-chain"]) {
    const sel = document.getElementById(id);
    if (!sel) continue;
    sel.innerHTML = "";
    for (const c of choices) {
      const opt = document.createElement("option");
      opt.value = c; opt.textContent = c;
      sel.appendChild(opt);
    }
  }
}

function renderForm(scriptName) {
  const schema = actionSchemas[scriptName];
  const container = document.getElementById("action-form");
  container.innerHTML = "";
  for (const field of schema.fields) {
    const wrap = document.createElement("div");
    wrap.className = "field";
    const label = document.createElement("label");
    label.textContent = `${field.flag}${field.required ? " *" : ""} -- ${field.help}`;
    wrap.appendChild(label);

    let input;
    if (field.type === "flag") {
      input = document.createElement("input");
      input.type = "checkbox";
    } else if (field.choices) {
      input = document.createElement("select");
      for (const c of field.choices) {
        const opt = document.createElement("option");
        opt.value = c; opt.textContent = c;
        input.appendChild(opt);
      }
      if (field.default !== null && field.default !== undefined) input.value = field.default;
    } else {
      input = document.createElement("input");
      input.type = (field.type === "int" || field.type === "float") ? "number" : "text";
      if (field.default !== null && field.default !== undefined) input.value = field.default;
    }
    input.dataset.dest = field.dest;
    input.id = `field-${field.dest}`;
    wrap.appendChild(input);
    container.appendChild(wrap);
  }
  watchChainField();
}

async function loadActions() {
  actionSchemas = await fetchJSON("/api/actions");
  const select = document.getElementById("script-select");
  select.innerHTML = "";
  for (const [name, schema] of Object.entries(actionSchemas)) {
    const opt = document.createElement("option");
    opt.value = name; opt.textContent = schema.label;
    select.appendChild(opt);
  }
  renderForm(select.value);
  select.onchange = () => renderForm(select.value);
  populateQuickActionChainSelects();
}

function collectArgs(scriptName) {
  const schema = actionSchemas[scriptName];
  const args = {};
  for (const field of schema.fields) {
    const el = document.getElementById(`field-${field.dest}`);
    if (field.type === "flag") args[field.dest] = el.checked;
    else args[field.dest] = el.value;
  }
  return args;
}

function appendConsole(text) {
  const c = document.getElementById("console");
  c.textContent += text + "\n";
  c.scrollTop = c.scrollHeight;
}

function connectStream(runId) {
  if (currentWs) currentWs.close();
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/api/run/${runId}/stream`);
  currentWs = ws;
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "line") {
      appendConsole(msg.text);
    } else if (msg.type === "awaiting_input") {
      document.getElementById("confirm-box").style.display = "block";
      document.getElementById("confirm-text").textContent = "The script is awaiting human confirmation (see the console for the exact prompt).";
    } else if (msg.type === "exit") {
      appendConsole(`--- process finished (exit code ${msg.code}) ---`);
      document.getElementById("stop-button").style.display = "none";
      document.getElementById("confirm-box").style.display = "none";
      refreshState();
    } else if (msg.type === "error") {
      appendConsole(`--- error: ${msg.text} ---`);
    }
  };
}

async function startRun() {
  const scriptName = document.getElementById("script-select").value;
  const args = collectArgs(scriptName);
  document.getElementById("console").textContent = "";
  const result = await fetchJSON("/api/run", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ script: scriptName, args }),
  });
  if (result.error) {
    appendConsole(`--- error while starting: ${result.error} ---`);
    return;
  }
  currentRunId = result.run_id;
  document.getElementById("current-run-info").textContent = `Run ${currentRunId} (${scriptName}), argv: ${result.argv.join(" ")}`;
  document.getElementById("stop-button").style.display = "inline-block";
  document.getElementById("confirm-box").style.display = "none";
  connectStream(currentRunId);
  navigate("console");
}

async function sendConfirmation() {
  const text = document.getElementById("confirm-input").value;
  await fetchJSON(`/api/run/${currentRunId}/input`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  document.getElementById("confirm-box").style.display = "none";
  document.getElementById("confirm-input").value = "";
}

async function stopRun() {
  await fetchJSON(`/api/run/${currentRunId}/stop`, { method: "POST" });
  appendConsole("--- SIGINT sent, waiting for a clean shutdown ---");
}

// Stop a run chosen from the "Active runs" table (not necessarily the
// one currently streamed into the console).
async function stopRunById(runId) {
  await fetchJSON(`/api/run/${runId}/stop`, { method: "POST" });
  await refreshState();
}

// --------------------------------------------------------------------------
// Wiring
// --------------------------------------------------------------------------
function initSidebar() {
  document.querySelectorAll(".nav-head").forEach((head) => {
    head.addEventListener("click", () => {
      head.parentElement.classList.toggle("collapsed");
    });
  });
  document.querySelectorAll(".nav-item").forEach((a) => {
    a.addEventListener("click", () => navigate(a.dataset.view));
  });
}

document.getElementById("run-button").addEventListener("click", startRun);
document.getElementById("confirm-send").addEventListener("click", sendConfirmation);
document.getElementById("stop-button").addEventListener("click", stopRun);
document.getElementById("ov-set-button").addEventListener("click", setOverride);
document.getElementById("wp-register-button").addEventListener("click", registerWalletPolicy);

initSidebar();
showView(currentView());
loadActions();
refreshState();
setInterval(refreshState, 5000);
