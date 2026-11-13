#!/usr/bin/env python3
"""batch_pipeline.py -- runs auto_pipeline.py's full register -> fund ->
fuzz -> exploit -> recover flow across MANY targets in one invocation,
under exactly ONE funding wallet and ONE recovery wallet for the whole
batch.

Why this exists as its own script rather than "just call auto_pipeline.py
N times": calling a script N times means re-typing (or re-scripting)
--key/--recovery-wallet N times, and nothing stops the Nth invocation
from accidentally carrying a different, wrong recovery wallet than the
first (a - copy-paste slip)) especially when testing many contracts back
to back. This script takes the wallet pair exactly once, strictly
enforces it via wallet_policy.enforce_wallet_policy() a single time
BEFORE touching any target, and then re-uses that one signer/one
recovery wallet for every target in the list -- there is no code path
here that could use a different wallet for target #7 than for target #1.

Every target is still independent otherwise: a failure on one target
(compile error, fuzzer crash, no exploit found) is caught, logged, and
the batch moves on to the next target rather than aborting the whole run
-- only a wallet-policy failure (wrong key, wrong recovery wallet) aborts
before anything is touched, since that is the one failure mode where
"keep going anyway" would be actively dangerous.

Usage:
    # targets.txt: one target per line (a .sol/.bin path, or a deployed
    # 0x address), blank lines and lines starting with # are ignored.
    python3 batch_pipeline.py \\
        --targets targets.txt \\
        --recovery-wallet 0xYourMainWallet \\
        [--key key.txt] [--chain sepolia] [--fund-eth 0.01] \\
        [--fuzz-seconds 300] [--detectors all]
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from eth_account import Account
from web3 import Web3

from auto_pipeline import (
    PLAN_CONFIRMED,
    PLAN_EXECUTED_NO_PROFIT,
    PLAN_INCONCLUSIVE,
    PLAN_NOT_CONFIRMED,
    PLAN_OVERSIZED_GAS,
    PLAN_SKIPPED_NOT_EXTRACTABLE,
    PLAN_SKIPPED_UNPROFITABLE,
    Tee,
    _start_fork,
    compile_contract,
    deploy,
    determine_negative_result_verdict,
    estimate_plan_gas_on_fork,
    execute_plan,
    get_or_deploy_attack_wallet,
    preflight_skip_reason,
    report_coverage,
    report_surface_triage,
    report_unexecuted_findings,
    run_fuzzer,
    run_static_analysis,
    send_call,
    skip_status_for,
)
from chains import known_chains, make_w3, native_symbol_for_w3, require_mainnet_confirmation, verify_rpc_identity
from gas_utils import format_wei_signed
from wallet_policy import enforce_wallet_policy, register_contract
import strategy_layer

HERE = Path(__file__).parent
LOGS_DIR = HERE / "logs"


def _read_targets(path: Path) -> list[str]:
    targets = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def run_one_target(
    w3: Web3, acct, nonce_box: dict, attack_wallet: str, target_arg: str, args, batch_run_id: str, tee: Tee
) -> dict:
    """Mirrors auto_pipeline.main()'s per-target body, minus the parts
    that happen once for the whole batch (signer/attack-wallet setup) --
    kept here instead of re-imported so each target's own run_id and
    work_dir stay distinct while sharing the one Tee log for the batch.
    """
    result = {"target": target_arg, "address": None, "plans": [], "error": None}
    target_run_id = f"{batch_run_id}_{len(target_arg) % 1000:03d}_{datetime.now(timezone.utc).strftime('%H%M%S%f')}"
    try:
        if target_arg.startswith("0x") and len(target_arg) == 42:
            target_address = Web3.to_checksum_address(target_arg)
            tee.log(f"[{target_arg}] Using already-deployed target {target_address}")
        else:
            target_path = Path(target_arg)
            if not target_path.exists():
                raise RuntimeError(f"target path {target_path} does not exist")
            if target_path.suffix == ".sol":
                run_static_analysis(target_path, tee)
            data = compile_contract(target_path, tee)
            target_address = deploy(w3, acct, nonce_box, data, tee, f"[{target_arg}] Target")
        result["address"] = target_address

        register_contract(
            args.chain,
            target_address,
            source=target_arg,
            run_id=target_run_id,
            script="batch_pipeline",
            funding_wallet=acct.address,
            recovery_wallet=args.recovery_wallet,
        )

        if args.fund_eth > 0:
            current = w3.eth.get_balance(target_address)
            if current == 0:
                wei = w3.to_wei(args.fund_eth, "ether")
                tee.log(f"[{target_arg}] Funding target with {args.fund_eth} {native_symbol_for_w3(w3)} ...")
                send_call(w3, acct, nonce_box, target_address, b"", tee, f"[{target_arg}] Fund target", value=wei)
            else:
                tee.log(f"[{target_arg}] Target already has {w3.from_wei(current, 'ether')} {native_symbol_for_w3(w3)}, skipping funding.")

        work_dir = HERE / "auto_work" / target_run_id
        fuzz_seconds_actual = run_fuzzer(target_address, args.chain, args.detectors, args.fuzz_seconds, work_dir, tee)
        min_instr_pct, min_branch_pct = report_coverage(work_dir, tee)

        findings = strategy_layer.load_findings(work_dir)
        findings.sort(key=strategy_layer.ordering_key)
        plan_files = [f["plan_path"] for f in findings]
        tee.log(f"[{target_arg}] Found {len(plan_files)} exploit plan(s) after fuzzing.")
        vuln_file = work_dir / "vuln_info.jsonl"
        any_findings_at_all = vuln_file.exists() and vuln_file.stat().st_size > 0
        if not plan_files and not any_findings_at_all:
            determine_negative_result_verdict(
                min_instr_pct, min_branch_pct, fuzz_seconds_actual, args.detectors, args.chain, tee
            )
        report_unexecuted_findings(work_dir, len(plan_files), tee)
        report_surface_triage(findings, tee)

        # Every plan for THIS target is tried regardless of whether an
        # earlier one (for this target, or an earlier target in the
        # batch) was confirmed -- see PLAN_CONFIRMED's own doc in
        # auto_pipeline.py for why the three-way status, not a bool,
        # matters for getting a trustworthy per-bug signal.
        #
        # Same free pre-flight gate as auto_pipeline.main(): a throwaway
        # Anvil fork of this node state, started AFTER the target is
        # deployed so it forks the same on-chain state the plans act on,
        # and torn down when this target is done.
        fork_proc, fork_w3 = (None, None)
        if not getattr(args, "no_preflight", False):
            fork_proc, fork_w3 = _start_fork(args.chain, tee)
        native_symbol = native_symbol_for_w3(w3)
        no_preflight = getattr(args, "no_preflight", False)

        def _unpack5(result: tuple) -> tuple:
            """Normalises an execute_plan result into the 5-tuple
            (status, delta, gas_spent_wei, net_wei, gas_units); a 4-/2-tuple
            (skip path or older caller) defaults the missing fields to 0, so
            a shape difference never breaks the run."""
            r = tuple(result)
            if len(r) >= 5:
                return r[0], r[1], r[2], r[3], r[4]
            if len(r) == 4:
                return r[0], r[1], r[2], r[3], 0
            return r[0], r[1], 0, 0, 0

        def _gate_reason(plan_, finding_=None):
            """The pre-flight decision for one plan, honouring --no-preflight
            (which bypasses the ENTIRE gate, metadata included -- the flag
            means "run every plan for real"). Returns None when the plan may
            be sent, else a human reason. `finding_` supplies the fuzzer's own
            metadata when available; a composed plan falls back to the plan's
            own fields (defaulting to replayable/exploitable so a composition
            is never skipped for a missing field)."""
            if no_preflight:
                return None
            meta = finding_ if finding_ is not None else {
                "plan": plan_,
                "contract_name": plan_.get("contract_name", "?"),
                "kind": plan_.get("kind"),
                "atomic_replayable": plan_.get("atomic_replayable", True),
                "distinct_callers": plan_.get("distinct_callers", 1),
                "confirmed_exploitable": plan_.get("confirmed_exploitable", True),
                "owner_impersonation": plan_.get("owner_impersonation", False),
            }
            return preflight_skip_reason(
                meta, fork_w3, acct, attack_wallet, args.recovery_wallet, args.chain, tee, native_symbol
            )

        try:
            for finding in findings:
                plan = finding["plan"]
                # FAZA 1.2/1.3: stamp the plan's own gas reality (the node's
                # own eth_estimateGas vs the real block.gasLimit) BEFORE the
                # gate, so an oversized plan is flagged and never sent. This
                # mirrors auto_pipeline.main(); without it, batch runs would
                # bypass the FAZA 1 gas guard entirely.
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
                skip_reason = _gate_reason(plan, finding)
                if skip_reason is not None:
                    tee.log(
                        f"[{target_arg}] SKIP (pre-flight, no real tx sent): plan '{plan['contract_name']}' "
                        f"({plan['kind']}) -- {skip_reason}."
                    )
                    result["plans"].append({
                        "contract_name": plan["contract_name"],
                        "kind": plan["kind"],
                        "status": skip_status_for(skip_reason),
                        "recovery_delta_wei": 0,
                        "gas_spent_wei": 0,
                        "net_profit_wei": 0,
                        "gas_estimate": plan.get("gas_estimate"),
                        "gas_used": plan.get("gas_estimate"),
                        "fits_block_gas_limit": plan.get("fits_block_gas_limit"),
                    })
                    continue
                status, recovery_delta_wei, gas_spent_wei, net_wei, gas_units = _unpack5(
                    execute_plan(
                        w3, acct, nonce_box, attack_wallet, plan, args.recovery_wallet, tee,
                        chain=args.chain, return_units=True,
                    )
                )
                # FAZA 1.1: plan.json carries BOTH gas_estimate (stamped above)
                # and the actual gas_used; fall back to the fork estimate when
                # the plan was never sent, mirroring auto_pipeline.main().
                if not gas_units and gas_fit_info is not None:
                    gas_units = gas_fit_info.get("gas_estimate", 0)
                plan["gas_used"] = gas_units
                try:
                    finding["plan_path"].write_text(json.dumps(plan, indent=2))
                except OSError:
                    pass
                result["plans"].append({
                    "contract_name": plan["contract_name"],
                    "kind": plan["kind"],
                    "status": status,
                    "recovery_delta_wei": recovery_delta_wei,
                    "gas_spent_wei": gas_spent_wei,
                    "net_profit_wei": net_wei,
                    "gas_estimate": plan.get("gas_estimate"),
                    "gas_used": gas_units,
                    "fits_block_gas_limit": plan.get("fits_block_gas_limit"),
                })

            # Strategy Layer, phase 2 -- see strategy_layer.py's module doc and
            # auto_pipeline.py's identical wiring for the full rationale. The
            # same gate wraps the composed attempts via `gated_execute_plan`.
            def gated_execute_plan(w3_, acct_, nonce_box_, attack_wallet_, plan_, recovery_wallet_, tee_, chain="sepolia"):
                # `chain` (not `chain_`): strategy_layer calls this callback as
                # execute_plan_fn(..., chain=chain), matching execute_plan's own
                # signature. See auto_pipeline.py's identical wrapper for the
                # TypeError this naming mismatch used to cause.
                reason = _gate_reason(plan_)
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

            already_confirmed = {r["contract_name"] for r in result["plans"] if r["status"] == PLAN_CONFIRMED}
            chain_results = strategy_layer.run_chain_attempts(
                gated_execute_plan, w3, acct, nonce_box, attack_wallet, findings, already_confirmed,
                args.recovery_wallet, tee, chain=args.chain,
            )
            for cr in chain_results:
                result["plans"].append({
                    "contract_name": cr["merged_contract_name"],
                    "kind": f"flat, chained: {cr['unlock_contract_name']} -> {cr['objective_contract_name']}",
                    "status": cr["status"],
                    "recovery_delta_wei": cr["recovery_delta_wei"],
                    "gas_spent_wei": cr.get("gas_spent_wei", 0),
                    "net_profit_wei": cr.get("net_profit_wei", 0),
                    "gas_estimate": cr.get("gas_estimate"),
                    "fits_block_gas_limit": cr.get("fits_block_gas_limit"),
                })
        finally:
            if fork_proc is not None:
                fork_proc.terminate()
                try:
                    fork_proc.wait(timeout=5)
                except Exception:
                    fork_proc.kill()
    except Exception as e:
        tee.log(f"[{target_arg}] ERROR: {e}", alert=True)
        result["error"] = str(e)
    return result


def build_parser() -> argparse.ArgumentParser:
    """Factored out of main() (2026-11-02) so dashboard_server.py can
    introspect the REAL CLI surface to build its own launch form from --
    see that file's own module doc."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--targets", required=True, help="Path to a file listing one target (.sol/.bin path or 0x address) per line")
    parser.add_argument("--recovery-wallet", required=True, help="The ONE address every recovered asset across the whole batch is swept to")
    parser.add_argument(
        "--key",
        required=True,
        help="Path to the ONE funding wallet's private key file for the whole batch -- pays every gas fee. "
        "Required, no default: this, --targets, and --recovery-wallet are the three addresses this run "
        "commits to -- funding wallet, target contract(s), and final profit destination -- and none of them "
        "should ever be silently assumed.",
    )
    parser.add_argument("--chain", default="sepolia", choices=known_chains())
    parser.add_argument("--confirm-mainnet", action="store_true")
    parser.add_argument("--fund-eth", type=float, default=0.0)
    parser.add_argument(
        "--no-gas-oracle",
        action="store_true",
        help="Skip the official explorer gas-PRICE oracle (Etherscan v2 for ETH, Blockscout v2 "
        "for ETC) and price every transaction from the node's own quote only. ON by default "
        "(same as auto_pipeline.py) -- matters most on ETC, where there is no EIP-1559 refund, so "
        "a padded node gasPrice is paid in full on every tx. Best-effort: any official-source "
        "failure already degrades to the node quote.",
    )
    parser.add_argument("--fuzz-seconds", type=int, default=300)
    parser.add_argument(
        "--detectors",
        default="all",
        help="Default 'all' (see auto_pipeline.py's own --detectors help for why this changed from "
        "'high_confidence') -- pass --detectors high_confidence explicitly for the old, lower-noise behavior.",
    )
    parser.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip the pre-flight profitability gate (see auto_pipeline.py's own --no-preflight help "
        "for the full rationale). On by default: each plan is checked against its own metadata and "
        "replayed on a free, throwaway Anvil fork before anything real is signed, so a plan that "
        "provably reverts or cannot out-earn its gas is skipped without spending a wei.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    require_mainnet_confirmation(args.chain, args.confirm_mainnet)

    targets_path = Path(args.targets)
    if not targets_path.exists():
        raise SystemExit(f"--targets file {targets_path} does not exist")
    targets = _read_targets(targets_path)
    if not targets:
        raise SystemExit(f"--targets file {targets_path} has no targets in it")

    batch_run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tee = Tee(LOGS_DIR / f"batch_pipeline_{batch_run_id}.log")
    tee.log(f"=== batch_pipeline run {batch_run_id}: {len(targets)} target(s), chain={args.chain} ===")
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
            tee.log(f"ERROR: key file {key_path} not found.")
            return 1
        w3 = make_w3(args.chain)
        verify_rpc_identity(args.chain, tee, w3=w3)
        acct = Account.from_key(key_path.read_text().strip())

        # Enforced exactly once, before ANY target is touched: this is the
        # whole point of this script existing separately from calling
        # auto_pipeline.py N times -- one wrong wallet here aborts the
        # entire batch up front instead of possibly slipping through on
        # one target out of many.
        enforce_wallet_policy(args.chain, acct.address, args.recovery_wallet)

        balance = w3.eth.get_balance(acct.address)
        tee.log(f"Signer (shared across whole batch): {acct.address}, balance {w3.from_wei(balance, 'ether')} {native_symbol_for_w3(w3)}")
        if balance == 0:
            tee.log("ERROR: signer wallet is not funded. Fund it and re-run.")
            return 1
        nonce_box = {"nonce": w3.eth.get_transaction_count(acct.address)}

        attack_wallet = get_or_deploy_attack_wallet(w3, acct, nonce_box, args.chain, args.recovery_wallet, tee)

        results = []
        for i, target_arg in enumerate(targets):
            tee.log(f"--- Target {i + 1}/{len(targets)}: {target_arg} ---")
            results.append(run_one_target(w3, acct, nonce_box, attack_wallet, target_arg, args, batch_run_id, tee))

        tee.log("=== Batch summary (per-bug, not just per-target) ===")
        ok_count = 0
        status_label = {
            PLAN_CONFIRMED: "CONFIRMED",
            PLAN_NOT_CONFIRMED: "NOT CONFIRMED",
            PLAN_INCONCLUSIVE: "INCONCLUSIVE",
            PLAN_EXECUTED_NO_PROFIT: "EXECUTED, NO PROFIT (not confirmed for reporting)",
            PLAN_SKIPPED_UNPROFITABLE: "SKIPPED, UNPROFITABLE (pre-flight proved it reverts or cannot out-earn its gas -- no real tx sent)",
            PLAN_SKIPPED_NOT_EXTRACTABLE: "SKIPPED, NOT EXTRACTABLE (found, but no runnable extraction step -- heuristic / un-replayable / multi-caller; no real tx sent)",
            PLAN_OVERSIZED_GAS: "OVERSIZED GAS (measured gas footprint exceeds the block gas limit -- un-includable in one block; no real tx sent)",
        }
        total_confirmed_delta_wei = 0
        total_confirmed_gas_wei = 0
        for r in results:
            if r["error"]:
                tee.log(f"  {r['target']} -> {r['address']}: ERROR: {r['error']}")
                continue
            ok_count += 1
            if not r["plans"]:
                tee.log(f"  {r['target']} -> {r['address']}: no exploit plan generated")
                continue
            tee.log(f"  {r['target']} -> {r['address']}:")
            for p in r["plans"]:
                # recovery_delta_wei is this plan's own measured on-chain
                # balance increase -- see execute_plan's doc in
                # auto_pipeline.py for why CONFIRMED alone isn't proof.
                delta_note = ""
                if p["status"] == PLAN_CONFIRMED:
                    delta_note = f" -- gained {w3.from_wei(p['recovery_delta_wei'], 'ether')} {native_symbol_for_w3(w3)}"
                    gas_spent = p.get("gas_spent_wei", 0)
                    if gas_spent:
                        net = p.get("net_profit_wei", p["recovery_delta_wei"] - gas_spent)
                        delta_note += (
                            f" (net {format_wei_signed(w3, net)} {native_symbol_for_w3(w3)} after "
                            f"{w3.from_wei(gas_spent, 'ether')} {native_symbol_for_w3(w3)} gas"
                            + (", NET LOSS)" if net < 0 else ")")
                        )
                    total_confirmed_delta_wei += p["recovery_delta_wei"]
                    total_confirmed_gas_wei += p.get("gas_spent_wei", 0)
                tee.log(f"    {p['contract_name']} ({p['kind']}): {status_label[p['status']]}{delta_note}")
        final_recovery_balance = w3.eth.get_balance(Web3.to_checksum_address(args.recovery_wallet))
        tee.log(
            f"=== Batch complete: {ok_count}/{len(results)} target(s) processed without error. Sum of CONFIRMED "
            f"recovery-wallet gains this batch: {w3.from_wei(total_confirmed_delta_wei, 'ether')} {native_symbol_for_w3(w3)} gross, "
            f"{format_wei_signed(w3, total_confirmed_delta_wei - total_confirmed_gas_wei)} {native_symbol_for_w3(w3)} net "
            f"(after {w3.from_wei(total_confirmed_gas_wei, 'ether')} {native_symbol_for_w3(w3)} of gas actually paid). Recovery "
            f"wallet {args.recovery_wallet} final balance: {w3.from_wei(final_recovery_balance, 'ether')} {native_symbol_for_w3(w3)} ==="
        )
        tee.log(f"Full log: {LOGS_DIR / f'batch_pipeline_{batch_run_id}.log'}")
        return 0
    finally:
        tee.close()


if __name__ == "__main__":
    sys.exit(main())
