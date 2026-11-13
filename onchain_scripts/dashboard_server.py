#!/usr/bin/env python3
"""dashboard_server.py -- lightweight local web dashboard that PROJECTS
ForkSploit's real state (wallet policy, RPC overrides, deployed
AttackWallets + live balances, tested contracts, recent run outcomes,
running processes) and lets a human launch real CLI scripts and answer
their confirmation prompts from the browser instead of the terminal.

This is an orchestration/projection layer ONLY -- it never re-implements
any safety check. Every real action (wallet_policy, --confirm-mainnet,
the exact "DA" confirmation in dex_arbitrage_scanner.py's
ask_human_confirmation()) still runs inside the SAME script the CLI
already runs, as a real subprocess; this server only starts it, streams
its real stdout, and relays a typed answer back into its real stdin.

SECURITY: binds to 127.0.0.1 ONLY. Never expose this port externally
(no 0.0.0.0, no reverse proxy, no tunnel) -- it can read wallet/contract
state and launch scripts that sign real transactions. It never accepts a
raw private key over the API, only a path to an existing key file,
passed straight through as a CLI argument exactly like the terminal
would.

Usage:
    python3 onchain_scripts/dashboard_server.py [--port 4114]
    Then open http://127.0.0.1:4114 in a browser.
    (Or use onchain_scripts/server_run.sh, which picks a free port, starts the
    server and opens the browser -- 8765 is deliberately avoided, it is often
    taken by other local services.)
"""
import argparse
import json
import queue
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))  # so sibling modules import the same way the CLI scripts themselves do

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import auto_pipeline
import batch_pipeline
import chains
import dex_arbitrage_scanner
import monitor
import aave_flashloan_runner
import wallet_policy

REPO_ROOT = HERE.parent
STATIC_DIR = HERE / "dashboard_static"
FORKSPLOIT_BIN = REPO_ROOT / "target" / "release" / "forksploit"

# Every script this dashboard can launch. Each one's form is introspected
# directly from its OWN build_parser() (factored out of main() for exactly
# this, 2026-11-02) -- never hand-duplicated, so a future CLI flag shows up
# here automatically.
SCRIPTS = {
    "auto_pipeline": {"module": auto_pipeline, "file": HERE / "auto_pipeline.py", "label": "auto_pipeline.py -- register→fund→fuzz→exploit→recover"},
    "dex_arbitrage_scanner": {"module": dex_arbitrage_scanner, "file": HERE / "dex_arbitrage_scanner.py", "label": "dex_arbitrage_scanner.py -- cross-DEX arbitrage scanner"},
    "batch_pipeline": {"module": batch_pipeline, "file": HERE / "batch_pipeline.py", "label": "batch_pipeline.py -- register→fund→fuzz→exploit→recover, več tarč hkrati"},
    "monitor": {"module": monitor, "file": HERE / "monitor.py", "label": "monitor.py -- stalen nadzor že deployane pogodbe, samodejno reševanje sredstev"},
    "aave_flashloan_runner": {"module": aave_flashloan_runner, "file": HERE / "aave_flashloan_runner.py", "label": "aave_flashloan_runner.py -- resnična Aave V3 flashloan validacija"},
}

# Direct Rust fuzzer launch (./target/release/forksploit evm ...) -- not a
# Python script, so there's no argparse to introspect; this is a hand-held
# subset of the most commonly used flags (see README's own "Pogosti CLI
# delotoki" and zmogljivosti.md's CLI reference for the full set). Handled
# as a special case in api_run() below rather than going through SCRIPTS,
# since it launches a different binary entirely, not `sys.executable`.
RUST_FUZZER_FIELDS = [
    {"dest": "target", "flag": "-t", "type": "str", "default": None, "required": True, "help": "Glob do lokalne .bin/.abi, ALI 0x naslov že deployane pogodbe", "choices": None},
    {"dest": "chain_type", "flag": "-c", "type": "str", "default": None, "required": False, "help": "Veriga za onchain cilj (eth, etc, sepolia, mordor, bsc, polygon, ...)", "choices": None},
    {"dest": "onchain_url", "flag": "-u", "type": "str", "default": None, "required": False, "help": "RPC URL -- VEDNO podaj eksplicitno pri lokalnih/forkanih vozliščih", "choices": None},
    {"dest": "onchain_block_number", "flag": "-b", "type": "str", "default": None, "required": False, "help": "Blok, na katerem se fork/branje stanja zgodi (privzeto najnovejši)", "choices": None},
    {"dest": "onchain_etherscan_api_key", "flag": "-k", "type": "str", "default": None, "required": False, "help": "API ključ za verificiran ABI (brez njega EVMole dekompilacija)", "choices": None},
    {"dest": "flashloan", "flag": "-f", "type": "flag", "default": False, "required": False, "help": "Omogoči flashloan simulacijo (Aave V3/Balancer V2)", "choices": None},
    {"dest": "run_forever", "flag": "--run-forever", "type": "flag", "default": False, "required": False, "help": "Ne ustavi se ob prvi najdbi -- nadaljuj do izteka časa", "choices": None},
    {"dest": "detectors", "flag": "-d", "type": "str", "default": "all", "required": False, "help": "'all' (privzeto) ali 'high_confidence'", "choices": None},
    {"dest": "spec_id", "flag": "--spec-id", "type": "str", "default": None, "required": False, "help": "EVM hardfork (za ETC/Mordor VEDNO 'Shanghai')", "choices": None},
    {"dest": "concolic", "flag": "--concolic", "type": "flag", "default": False, "required": False, "help": "Omogoči Z3-podprto simbolično reševanje", "choices": None},
    {"dest": "concolic_caller", "flag": "--concolic-caller", "type": "flag", "default": False, "required": False, "help": "Obravnava klicatelja kot simboličnega (z --concolic)", "choices": None},
    {"dest": "max_call_depth", "flag": "--max-call-depth", "type": "int", "default": None, "required": False, "help": "Globina analize klicne verige (privzeto 15)", "choices": None},
    {"dest": "work_dir", "flag": "-w", "type": "str", "default": None, "required": False, "help": "Kam se zapišejo corpus/dnevniki/najdbe (privzeto work_dir)", "choices": None},
]

# Substrings this dashboard recognizes as "this subprocess is now blocked
# on input() waiting for a human" -- matched against each raw stdout line
# as it streams in. Deliberately a short, explicit, enumerable list (not a
# generic heuristic) so a new confirmation prompt added to some future
# script is a conscious one-line addition here, never silently invisible
# to the dashboard.
CONFIRMATION_PROMPT_MARKERS = [
    "Ali naj izvedem to trgovino",  # dex_arbitrage_scanner.py's ask_human_confirmation()
]


class RunState:
    def __init__(self, run_id: str, script: str, argv: list):
        self.run_id = run_id
        self.script = script
        self.argv = argv
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.log: list[str] = []
        self.lock = threading.Lock()
        self.awaiting_input = False
        self.finished = False
        self.exit_code: int | None = None
        self.queues: list[queue.Queue] = []  # one per connected websocket, so each gets every new line
        self.popen: subprocess.Popen | None = None

    def append_line(self, line: str) -> None:
        with self.lock:
            self.log.append(line)
            if any(marker in line for marker in CONFIRMATION_PROMPT_MARKERS):
                self.awaiting_input = True
            for q in self.queues:
                q.put(line)

    def snapshot(self) -> list[str]:
        with self.lock:
            return list(self.log)


RUNS: dict[str, RunState] = {}


def _reader_thread(run: RunState) -> None:
    """Reads char-by-char, NOT line-by-line, on purpose -- confirmed live
    (this project's own confirm_harness.py test, 2026-11-02) that
    Python's input("prompt") writes the prompt with NO trailing newline
    at all (it waits for the human on the SAME line), so a `for line in
    stdout` loop (which blocks for a '\\n' or EOF) never sees that prompt
    as a line until something ELSE later happens to flush one -- the
    dashboard's confirmation detection would otherwise silently never
    fire for the one prompt this whole feature exists to bridge. Flushes
    the accumulated buffer as a line the MOMENT a known confirmation
    marker (CONFIRMATION_PROMPT_MARKERS) has fully appeared in it,
    instead of waiting for a newline that will never come for that
    specific line; every other line still flushes normally on '\\n'."""
    assert run.popen is not None and run.popen.stdout is not None
    buf = ""
    while True:
        ch = run.popen.stdout.read(1)
        if ch == "":
            break
        if ch == "\n":
            run.append_line(buf)
            buf = ""
            continue
        buf += ch
        if not run.awaiting_input and any(marker in buf for marker in CONFIRMATION_PROMPT_MARKERS):
            run.append_line(buf)
            buf = ""
    if buf:
        run.append_line(buf)
    run.popen.wait()
    with run.lock:
        run.finished = True
        run.exit_code = run.popen.returncode
        for q in run.queues:
            q.put(None)  # sentinel: stream closed


def _build_argv_from_fields(fields: list, args: dict) -> list:
    """Shared by _build_argv (argparse-backed scripts) and the hand-held
    RUST_FUZZER_FIELDS schema (the Rust binary has no argparse to
    introspect) -- the SAME {dest: value} -> argv translation either way,
    so there's exactly one place this logic lives."""
    argv = []
    for field in fields:
        if field["dest"] not in args:
            continue
        value = args[field["dest"]]
        flag = field["flag"]
        if field["type"] == "flag":
            if value:
                argv.append(flag)
        else:
            if value is None or value == "":
                continue
            argv.append(flag)
            argv.append(str(value))
    return argv


def _build_argv(parser: argparse.ArgumentParser, args: dict) -> list:
    """Turns {dest: value} (as sent by the browser form, itself built from
    GET /api/actions' introspection of this SAME parser) into the argv
    list argparse itself would accept -- the single place form input
    becomes real CLI arguments, so it can never drift from what
    GET /api/actions advertised."""
    return _build_argv_from_fields(_serialize_parser(parser), args)


def _serialize_parser(parser: argparse.ArgumentParser) -> list:
    """The exact CLI surface (name/type/default/required/help/choices) as
    JSON, for the frontend to build a form from -- see this file's own
    module doc for why this beats a hand-maintained copy."""
    fields = []
    for action in parser._actions:
        if not action.option_strings or action.dest == "help":
            continue
        is_flag = isinstance(action, argparse._StoreTrueAction)
        fields.append({
            "dest": action.dest,
            "flag": action.option_strings[0],
            "type": "flag" if is_flag else (action.type.__name__ if action.type else "str"),
            "default": action.default,
            "required": bool(getattr(action, "required", False)),
            "help": action.help or "",
            "choices": list(action.choices) if action.choices else None,
        })
    return fields


app = FastAPI(title="ForkSploit Dashboard")


@app.middleware("http")
async def no_store_static(request, call_next):
    """Never let a browser cache the dashboard's own HTML/JS/CSS.

    Confirmed live: after a frontend change the browser kept showing the OLD
    page, because StaticFiles sends no cache-control and the browser reuses its
    copy. A local control panel must always reflect the current files (and a
    stale UI could mislead an operator), so mark the static assets -- and only
    those, not the /api/* JSON -- `no-store`. The API responses are already
    fresh per request and keep their own semantics."""
    response = await call_next(request)
    path = request.url.path
    if not path.startswith("/api/") and request.method == "GET":
        response.headers["Cache-Control"] = "no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response


@app.get("/api/actions")
def api_actions():
    result = {name: {"label": cfg["label"], "fields": _serialize_parser(cfg["module"].build_parser())} for name, cfg in SCRIPTS.items()}
    result["forksploit_evm"] = {"label": "forksploit evm -- direkten Rust fuzzer zagon (brez financiranja/exploit avtomatizacije)", "fields": RUST_FUZZER_FIELDS}
    return result


@app.get("/api/verify-chain")
def api_verify_chain(chain: str):
    """Live network-identity check for the dashboard's own watermark/
    warning display -- NEVER trust the selected --chain NAME alone, the
    same discipline SKILL.md's own FAZA 1 and chains.py's
    require_mainnet_confirmation() already apply, because 'eth' and 'etc'
    are one letter apart and both real mainnets. Calls the REAL
    configured RPC's eth_chainId (chains.make_w3 already respects any
    active rpc_overrides.json entry, so this reflects the SAME endpoint
    a real run would actually sign against) and compares it against
    chains.CHAIN_IDS' expected value -- never infers family from the
    dropdown text."""
    expected = chains.CHAIN_IDS.get(chain)
    try:
        w3 = chains.make_w3(chain)
        actual = w3.eth.chain_id
    except Exception as e:
        return JSONResponse({"chain": chain, "error": str(e)}, status_code=200)

    if actual == 1:
        family = "eth"
    elif actual in (61, 63):  # ETC mainnet or Mordor (ETC's own testnet)
        family = "etc"
    else:
        family = "other"

    return {
        "chain": chain,
        "expected_chain_id": expected,
        "actual_chain_id": actual,
        "match": expected is not None and actual == expected,
        "family": family,
    }


@app.get("/api/state")
def api_state():
    wallets = wallet_policy._load_json(wallet_policy.WALLETS_FILE, {})
    overrides = chains._load_overrides()
    contracts = wallet_policy._load_json(wallet_policy.CONTRACTS_FILE, {})
    attack_wallets = auto_pipeline._load_json(auto_pipeline.ATTACK_WALLET_REGISTRY, {})

    attack_wallet_balances = {}
    for chain, address in attack_wallets.items():
        try:
            w3 = chains.make_w3(chain)
            bal_wei = w3.eth.get_balance(w3.to_checksum_address(address))
            attack_wallet_balances[chain] = {"address": address, "balance_eth": str(w3.from_wei(bal_wei, "ether"))}
        except Exception as e:
            attack_wallet_balances[chain] = {"address": address, "error": str(e)}

    recent_logs = []
    logs_dir = auto_pipeline.LOGS_DIR
    if logs_dir.exists():
        log_files = sorted(logs_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:25]
        for p in log_files:
            try:
                text = p.read_text()
            except OSError:
                continue
            # Deliberately excludes every "[fuzzer] ..." line (auto_pipeline.py's
            # run_fuzzer() pipes the Rust binary's own raw stdout into this SAME
            # log file, prefixed exactly that way): those lines are
            # SIMULATION-level only (ForkSploit's own ConfidenceTier, now
            # printed as "sim-confirmed"/"sim-review" -- see oracle.rs -- not
            # this uppercase CONFIRMED/NOT CONFIRMED vocabulary at all). Only
            # this script's own tee.log() lines further down -- gated on a
            # REAL on-chain balance check in execute_plan() -- ever use these
            # tags, but this filter stays explicit about excluding "[fuzzer]"
            # lines anyway: a dashboard status badge is the one place a
            # future accidental string collision (e.g. a new bug_type name
            # containing "CONFIRMED" in caps) would be mistaken for real,
            # on-chain proof instead of a simulation-only pattern match.
            outcome_lines = [
                line for line in text.splitlines()
                if not line.startswith("[fuzzer] ")
                and any(tag in line for tag in ("CONFIRMED", "NOT CONFIRMED", "EXECUTED, NO PROFIT", "INCONCLUSIVE", "PROFITABLE"))
            ]
            recent_logs.append({
                "file": p.name,
                "modified": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
                "outcome_lines": outcome_lines[-5:],
            })

    vulnerabilities = []
    for vuln_dir in [REPO_ROOT / "work_dir" / "vulnerabilities", *HERE.glob("auto_work/*/vulnerabilities")]:
        if vuln_dir.exists():
            for p in sorted(vuln_dir.glob("*.plan.json")):
                vulnerabilities.append(str(p.relative_to(REPO_ROOT)))

    known_script_names = ("auto_pipeline.py", "monitor.py", "dex_arbitrage_scanner.py", "batch_pipeline.py", "anvil")
    external_processes = []
    try:
        ps_out = subprocess.run(["ps", "ax", "-o", "pid,args"], capture_output=True, text=True, timeout=5).stdout
        for line in ps_out.splitlines()[1:]:
            if any(name in line for name in known_script_names) and "dashboard_server.py" not in line:
                external_processes.append(line.strip())
    except Exception:
        pass

    return JSONResponse({
        "wallets": wallets,
        "rpc_overrides": overrides,
        "rpc_override_warning": bool(overrides),
        "contracts": contracts,
        "attack_wallets": attack_wallet_balances,
        "recent_logs": recent_logs,
        "vulnerabilities_found": vulnerabilities,
        "dashboard_runs": {
            run_id: {
                "script": r.script, "started_at": r.started_at, "finished": r.finished,
                "exit_code": r.exit_code, "awaiting_input": r.awaiting_input,
            }
            for run_id, r in RUNS.items()
        },
        "external_processes": external_processes,
    })


class RunRequest(BaseModel):
    script: str
    args: dict


@app.post("/api/run")
def api_run(req: RunRequest):
    if req.script == "forksploit_evm":
        if not FORKSPLOIT_BIN.exists():
            return JSONResponse({"error": f"{FORKSPLOIT_BIN} ne obstaja -- najprej 'cargo build --release' v korenu repozitorija."}, status_code=400)
        argv = _build_argv_from_fields(RUST_FUZZER_FIELDS, req.args)
        cmd = [str(FORKSPLOIT_BIN), "evm", *argv]
        cwd = str(REPO_ROOT)
    elif req.script in SCRIPTS:
        cfg = SCRIPTS[req.script]
        argv = _build_argv(cfg["module"].build_parser(), req.args)
        # "-u": confirmed live (2026-11-02) that without it, a child
        # process whose stdout is a PIPE (never a TTY) silently switches
        # Python's own print()/tee.log() output to FULLY block-buffered
        # (not line-buffered) -- every log line just sat in the child's
        # own internal buffer, invisible to this server, for as long as
        # the run kept going. bufsize=1 below only controls OUR read
        # side; it does nothing about the CHILD's own buffering. The
        # Rust binary above doesn't need this -- std::io::Stdout's
        # LineWriter flushes on newline regardless of TTY vs pipe,
        # unlike Python/libc's full-buffering-when-piped default.
        cmd = [sys.executable, "-u", str(cfg["file"]), *argv]
        cwd = str(HERE)
    else:
        return JSONResponse({"error": f"unknown script '{req.script}'"}, status_code=400)

    run_id = uuid.uuid4().hex[:12]
    run = RunState(run_id, req.script, argv)
    popen = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    run.popen = popen
    RUNS[run_id] = run
    threading.Thread(target=_reader_thread, args=(run,), daemon=True).start()
    return {"run_id": run_id, "argv": argv}


@app.post("/api/run/{run_id}/input")
def api_run_input(run_id: str, body: dict):
    run = RUNS.get(run_id)
    if run is None or run.popen is None or run.popen.stdin is None:
        return JSONResponse({"error": "no such run, or it has no stdin"}, status_code=404)
    text = body.get("text", "")
    run.popen.stdin.write(text + "\n")
    run.popen.stdin.flush()
    with run.lock:
        run.awaiting_input = False
    return {"ok": True}


@app.post("/api/run/{run_id}/stop")
def api_run_stop(run_id: str):
    run = RUNS.get(run_id)
    if run is None or run.popen is None:
        return JSONResponse({"error": "no such run"}, status_code=404)
    run.popen.send_signal(signal.SIGINT)  # soft stop first -- let each script's own KeyboardInterrupt/finally cleanup run
    def _escalate():
        time.sleep(10)
        if run.popen.poll() is None:
            run.popen.terminate()
    threading.Thread(target=_escalate, daemon=True).start()
    return {"ok": True}


@app.websocket("/api/run/{run_id}/stream")
async def ws_run_stream(websocket: WebSocket, run_id: str):
    await websocket.accept()
    run = RUNS.get(run_id)
    if run is None:
        await websocket.send_json({"type": "error", "text": "no such run"})
        await websocket.close()
        return
    q: queue.Queue = queue.Queue()
    with run.lock:
        for line in run.log:
            await websocket.send_json({"type": "line", "text": line})
        if run.awaiting_input:
            await websocket.send_json({"type": "awaiting_input"})
        if run.finished:
            await websocket.send_json({"type": "exit", "code": run.exit_code})
            await websocket.close()
            return
        run.queues.append(q)
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, q.get)
            if line is None:
                await websocket.send_json({"type": "exit", "code": run.exit_code})
                break
            await websocket.send_json({"type": "line", "text": line})
            if any(marker in line for marker in CONFIRMATION_PROMPT_MARKERS):
                await websocket.send_json({"type": "awaiting_input"})
    except WebSocketDisconnect:
        pass
    finally:
        with run.lock:
            if q in run.queues:
                run.queues.remove(q)


class RpcOverrideRequest(BaseModel):
    chain: str
    url: str


@app.post("/api/rpc-override")
def api_set_rpc_override(req: RpcOverrideRequest):
    """Thin wrapper around chains.set_rpc_override -- the exact same
    function SKILL.md's FAZA 3 has a human run via `python3 -c ...`
    today. No extra validation added here beyond what that function
    already does -- this is a convenience for a step that already
    existed, not a new safety surface."""
    if req.chain not in chains.known_chains():
        return JSONResponse({"error": f"unknown chain '{req.chain}'"}, status_code=400)
    chains.set_rpc_override(req.chain, req.url)
    return {"ok": True, "chain": req.chain, "url": req.url}


@app.delete("/api/rpc-override/{chain}")
def api_clear_rpc_override(chain: str):
    """See FAZA 9's own warning: clearing a stale override (e.g. still
    pointed at a long-gone Anvil fork) matters before the NEXT real run
    on that chain accidentally signs against it."""
    cleared = chains.clear_rpc_override(chain)
    return {"ok": True, "cleared": cleared, "chain": chain}


class WalletPolicyRequest(BaseModel):
    chain: str
    confirm_chain: str
    funding_wallet: str
    recovery_wallet: str
    force: bool = False
    client_note: str = ""


@app.post("/api/wallet-policy")
def api_register_wallet_policy(req: WalletPolicyRequest):
    """Thin wrapper around wallet_policy.register_policy -- the frontend
    form REQUIRES chain and confirm_chain to be typed into two SEPARATE
    fields (never pre-filled from one into the other), preserving the
    exact anti-typo double-entry register_policy() itself already
    enforces (chain/confirm_chain mismatch -> SystemExit) -- this
    endpoint doesn't add or relax that check, just surfaces its real
    error message instead of letting SystemExit crash the server
    process."""
    try:
        wallet_policy.register_policy(req.chain, req.confirm_chain, req.funding_wallet, req.recovery_wallet, force=req.force, client_note=req.client_note)
    except SystemExit as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return {"ok": True, "chain": req.chain}


app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


def main() -> int:
    import uvicorn
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=4114)
    args = parser.parse_args()
    print(f"ForkSploit dashboard: http://127.0.0.1:{args.port} (localhost ONLY -- never expose this port externally)")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
