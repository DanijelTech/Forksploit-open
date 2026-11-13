#!/usr/bin/env python3
"""monitor.py -- continuous post-deployment watcher for a live contract.

Pre-deployment testing (fuzzing, static analysis, invariant checks) can
only ever check against attack patterns that exist TODAY. The one thing
that protects against a technique nobody has seen yet is watching the
deployed contract's real activity and reacting within minutes instead of
finding out after the fact. That is this script's entire job: it does
not try to predict attacks, it watches for the SYMPTOMS of one already
happening (an abnormal balance drop, a function nobody has ever called
before suddenly firing) and alerts loudly, immediately.

This polls the chain (no websocket/mempool feed needed): every interval,
it reads the current ETH balance and scans any new blocks for
transactions addressed to the target, and flags:
  - a balance drop bigger than --balance-drop-pct in a single check
    (default 10%) -- the main signal of an in-progress drain.
  - a function selector seen for the first time ever on this contract
    (an admin function nobody has used before, e.g.) -- not inherently
    bad, but worth a human's attention the first time it happens.
  - a single incoming transaction moving more than --large-tx-eth ETH
    (default: 50% of the balance at the time) -- worth knowing about
    regardless of direction.

Optionally (--rescan-interval > 0, on by default) it also periodically
re-runs the real forksploit fuzzer against the live contract in the
background of the watch loop, keeping a running list of exploit plans
that are known to work RIGHT NOW -- not just whatever was found once
before deployment. If --key and --safe-wallet are both given, a balance-
drop alert immediately tries to fire any already-known plan through the
same reusable AttackWallet auto_pipeline.py uses, sweeping anything that
can still be grabbed to the safe wallet -- racing to save what's left
instead of letting the rest be drained too.

Honest limit on that rescue, worth repeating out loud: it can only save
funds from a drain that takes more than one block/transaction. A single
atomic transaction (the common case for a flash-loan-style exploit)
empties the contract before this script's next poll even runs -- by the
time the balance-drop alert fires, there is nothing left to rescue. This
helps against a slower or repeated drain, not a one-shot one.

Everything is logged to both the terminal (ALERT lines are loud) and a
timestamped file under onchain_scripts/logs/, exactly like
auto_pipeline.py, so a run left going in the background still leaves a
full transcript.

Usage (watch-only, as before, single target):
    python3 monitor.py --address 0xYourDeployedContract --chain sepolia \\
        [--poll-interval 20] [--balance-drop-pct 10] [--large-tx-eth 0]

Usage (with periodic re-fuzzing and automatic rescue on a drain alert):
    python3 monitor.py --address 0xYourDeployedContract --chain sepolia \\
        --key key.txt --safe-wallet 0xYourSafeWallet \\
        [--rescan-interval 600] [--rescan-seconds 60]

Usage (multiple targets, possibly on different chains, watched
concurrently -- one thread per target, one log file per target):
    python3 monitor.py --config targets.json \\
        [--key key.txt --safe-wallet 0xYourSafeWallet]

    targets.json:
    [
        {"chain": "eth", "address": "0xFirstContract..."},
        {"chain": "arbitrum", "address": "0xSecondContract..."}
    ]

    --key/--safe-wallet (when given) apply to every target in the
    config: the SAME signer is used for rescue on all of them, each
    chain registered under wallet_policy.py as usual. Two targets on the
    SAME chain safely share that chain's nonce sequence -- a lock
    serializes any rescue attempts against the same (chain, signer) pair
    so concurrent threads never race for the same nonce.

Stop with Ctrl+C (stops every target's thread, not just one).
"""
import argparse
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from eth_account import Account
from web3 import Web3

from auto_pipeline import PLAN_CONFIRMED, execute_plan, get_or_deploy_attack_wallet, run_fuzzer
from chains import chain_banner, known_chains, make_w3, require_mainnet_confirmation, verify_rpc_identity
from gas_utils import format_wei_signed
from wallet_policy import enforce_wallet_policy, register_contract

HERE = Path(__file__).parent
LOGS_DIR = HERE / "logs"
MONITOR_WORK_DIR = HERE / "monitor_work"

# Guards the interleaving of Tee.log's terminal print + file write across
# every target's thread -- without this, two threads logging around the
# same instant can interleave their lines' characters in the terminal
# (each Tee still has its OWN log file, so only the shared terminal
# stream needs this).
_PRINT_LOCK = threading.Lock()


class Tee:
    def __init__(self, log_path: Path):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self._fh = open(log_path, "w", buffering=1)

    def log(self, msg: str = "", alert: bool = False) -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        prefix = "!!! ALERT !!!" if alert else "    "
        line = f"[{ts}] {prefix} {msg}"
        with _PRINT_LOCK:
            print(line)
            self._fh.write(line + "\n")

    def close(self) -> None:
        self._fh.close()


def _load_targets(args) -> list[dict]:
    """Returns a list of {"chain": ..., "address": ...} dicts: either the
    single --address/--chain pair, or every entry in --config's JSON
    file. Validated here (not left to fail deep inside a worker thread)
    so a typo'd chain name or malformed address is reported immediately,
    against every target, not just the first one reached."""
    if args.config:
        try:
            raw = json.loads(Path(args.config).read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise SystemExit(f"Failed to read/parse --config {args.config}: {e}")
        if not isinstance(raw, list) or not raw:
            raise SystemExit(f"--config {args.config} must be a non-empty JSON list of {{chain, address}} objects.")
        targets = []
        for i, entry in enumerate(raw):
            chain = entry.get("chain")
            address = entry.get("address")
            if chain not in known_chains():
                raise SystemExit(
                    f"--config entry {i}: chain '{chain}' is not one onchain_scripts/chains.py knows about. "
                    f"Known chains: {', '.join(known_chains())}"
                )
            try:
                address = Web3.to_checksum_address(address)
            except ValueError as e:
                raise SystemExit(f"--config entry {i}: '{address}' is not a valid address: {e}")
            targets.append({"chain": chain, "address": address})
        return targets
    return [{"chain": args.chain, "address": Web3.to_checksum_address(args.address)}]


def watch_target(
    chain: str,
    address: str,
    args,
    acct,
    nonce_locks: dict,
    stop_event: threading.Event,
) -> None:
    """Watches a single (chain, address) pair until stop_event is set.
    Runs standalone in its own thread when there is more than one
    target; called directly otherwise. `acct` is the already-loaded
    signer (shared across every target/thread) or None for watch-only."""
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tee = Tee(LOGS_DIR / f"monitor_{address[:10]}_{run_id}.log")
    tee.log(f"=== monitor run {run_id}: watching {address} on {chain} ===")
    tee.log(f"Chain selected: {chain_banner(chain)}")
    tee.log(f"poll_interval={args.poll_interval}s balance_drop_pct={args.balance_drop_pct}%")

    w3 = make_w3(chain)
    # Resolve what the endpoint REALLY serves and refuse to continue on a
    # mismatch, before anything is signed -- a typo'd --chain or a stale
    # rpc_overrides.json entry must be caught here, not from a wrong-chain
    # transaction.
    verify_rpc_identity(chain, tee, w3=w3)

    nonce_lock = None
    if acct and args.safe_wallet:
        enforce_wallet_policy(chain, acct.address, args.safe_wallet)
        nonce_lock = nonce_locks.setdefault(f"{chain}:{acct.address.lower()}", threading.Lock())
        tee.log(f"Automatic rescue ARMED: signer={acct.address}, safe_wallet={args.safe_wallet}")
        tee.log(
            "Reminder: rescue can only save a drain that spans more than one transaction/block -- a single "
            "atomic drain (e.g. a flash-loan-style exploit) leaves nothing to grab by the time an alert fires."
        )
    else:
        tee.log("Automatic rescue not configured (no --key/--safe-wallet) -- running watch-only.")

    register_contract(
        chain,
        address,
        source="monitor (pre-existing, watched)",
        run_id=run_id,
        script="monitor",
        funding_wallet=acct.address if acct else "(watch-only, no signer)",
        recovery_wallet=args.safe_wallet if acct else "(watch-only, no signer)",
    )

    attack_wallet_box = {"value": None}
    known_plans: list[dict] = []

    def rescan(reason: str) -> None:
        if args.rescan_interval <= 0:
            return
        tee.log(f"=== Periodic re-fuzz ({reason}): checking {address} for currently-exploitable bugs ===")
        work_dir = MONITOR_WORK_DIR / f"{address[:10]}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        try:
            run_fuzzer(address, chain, args.rescan_detectors, args.rescan_seconds, work_dir, tee)
        except Exception as e:
            tee.log(f"Re-fuzz run failed: {e}")
            return
        vuln_dir = work_dir / "vulnerabilities"
        if not vuln_dir.exists():
            tee.log("Re-fuzz: no vulnerabilities dir produced.")
            return
        new_plans = 0
        for plan_file in sorted(vuln_dir.glob("*.plan.json")):
            try:
                plan = json.loads(plan_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            if plan not in known_plans:
                known_plans.append(plan)
                new_plans += 1
        tee.log(f"Re-fuzz done: {new_plans} new exploit plan(s) found, {len(known_plans)} known in total.")

    def attempt_rescue(trigger: str, current_balance: int) -> None:
        if not (acct and args.safe_wallet):
            return
        if current_balance == 0:
            tee.log("Rescue skipped: contract balance is already 0, nothing left to grab.", alert=True)
            return
        if not known_plans:
            tee.log(
                "Rescue skipped: no known exploit plan for this contract yet (periodic re-fuzz hasn't found one). "
                "Nothing to execute.",
                alert=True,
            )
            return
        # Serialize against any other target on the SAME (chain, signer)
        # pair -- two targets sharing a signer must never send at the
        # same time, or they'd race for the same nonce.
        with nonce_lock:
            tee.log(f"RESCUE ATTEMPT triggered by: {trigger}. Trying {len(known_plans)} known plan(s)...", alert=True)
            # Re-sync with the chain's real pending nonce right before
            # acting, now that we hold the lock -- this signer may be
            # idle for the whole --rescan-interval between rescues, long
            # enough for a stale cached nonce to be wrong. One nonce_box
            # is shared by both the (possibly one-time) AttackWallet
            # deploy below and every step execute_plan sends after it,
            # exactly like auto_pipeline.py's own main() does.
            nonce_box = {"nonce": w3.eth.get_transaction_count(acct.address, "pending")}
            if attack_wallet_box["value"] is None:
                attack_wallet_box["value"] = get_or_deploy_attack_wallet(w3, acct, nonce_box, chain, args.safe_wallet, tee)
            # Every known plan is tried regardless of whether an earlier
            # one confirmed or not -- one plan not reproducing says
            # nothing about whether a different known bug is still real
            # and rescuable.
            rescued_any = False
            for plan in known_plans:
                try:
                    status, recovery_delta_wei, gas_spent_wei, net_wei = execute_plan(
                        w3, acct, nonce_box, attack_wallet_box["value"], plan, args.safe_wallet, tee, chain=chain
                    )
                    # recovery_delta_wei is this plan's own measured real
                    # balance increase on the safe wallet -- see
                    # execute_plan's doc in auto_pipeline.py for why
                    # PLAN_CONFIRMED alone (every step succeeding without
                    # a revert) isn't itself proof funds were rescued.
                    delta_note = ""
                    if status == PLAN_CONFIRMED:
                        delta_note = f", gained {w3.from_wei(recovery_delta_wei, 'ether')} ETH"
                        if gas_spent_wei:
                            delta_note += (
                                f" (net {format_wei_signed(w3, net_wei)} ETH after "
                                f"{w3.from_wei(gas_spent_wei, 'ether')} ETH gas"
                                + (", NET LOSS)" if net_wei < 0 else ")")
                            )
                    tee.log(f"  {plan.get('contract_name')} ({plan.get('kind')}): {status}{delta_note}")
                    if status == PLAN_CONFIRMED:
                        rescued_any = True
                except Exception as e:
                    tee.log(f"Plan '{plan.get('contract_name')}' raised an error during rescue: {e}")
            if rescued_any:
                tee.log(f"Rescue attempt finished -- check safe wallet {args.safe_wallet} for what was recovered.", alert=True)
            else:
                tee.log("Rescue attempt finished -- no plan executed successfully, nothing was recovered this way.", alert=True)

    known_selectors: set[str] = set()
    last_balance = None
    last_checked_block = None
    # A target this thread is solely responsible for must never go
    # unwatched just because one RPC call hiccupped (confirmed live: a
    # single transient 429 from a free public endpoint used to kill this
    # whole thread silently, leaving that target unmonitored for the rest
    # of the run while OTHER targets' threads kept going -- exactly the
    # kind of unnoticed gap a security monitor can't afford). Retry with
    # a short backoff instead of letting setup's own RPC calls raise.
    while last_balance is None and not stop_event.is_set():
        try:
            last_balance = w3.eth.get_balance(address)
            last_checked_block = w3.eth.block_number
        except Exception as e:
            tee.log(f"Initial chain read failed, retrying: {e}", alert=True)
            if stop_event.wait(timeout=min(args.poll_interval, 10.0)):
                return
    if stop_event.is_set():
        tee.close()
        return
    last_rescan = time.time()
    tee.log(f"Starting balance: {w3.from_wei(last_balance, 'ether')} ETH, starting block: {last_checked_block}")
    rescan("initial")

    try:
        while not stop_event.is_set():
            # wait() instead of sleep() so Ctrl+C (which sets stop_event
            # from the main thread) wakes this up promptly instead of
            # leaving it asleep for up to a full --poll-interval.
            if stop_event.wait(timeout=args.poll_interval):
                break

            try:
                if args.rescan_interval > 0 and time.time() - last_rescan >= args.rescan_interval:
                    rescan("scheduled")
                    last_rescan = time.time()

                current_block = w3.eth.block_number
                for block_num in range(last_checked_block + 1, current_block + 1):
                    block = w3.eth.get_block(block_num, full_transactions=True)
                    for tx in block["transactions"]:
                        if tx.get("to") is None or Web3.to_checksum_address(tx["to"]) != address:
                            continue
                        selector = tx["input"].hex()[:8] if len(tx["input"]) >= 4 else "(no selector / plain transfer)"
                        value_eth = w3.from_wei(tx["value"], "ether")
                        tee.log(f"tx {tx['hash'].hex()} in block {block_num}: from={tx['from']} selector={selector} value={value_eth} ETH")
                        if selector not in known_selectors:
                            known_selectors.add(selector)
                            if len(known_selectors) > 1:  # don't alert on the very first tx ever observed
                                tee.log(f"Selector {selector} called for the FIRST TIME on this contract.", alert=True)
                        large_threshold = args.large_tx_eth if args.large_tx_eth > 0 else float(w3.from_wei(last_balance, "ether")) * 0.5
                        if value_eth >= large_threshold and large_threshold > 0:
                            tee.log(f"Large incoming transfer: {value_eth} ETH (threshold {large_threshold}).", alert=True)
                last_checked_block = current_block

                current_balance = w3.eth.get_balance(address)
                if last_balance > 0:
                    drop_pct = (last_balance - current_balance) / last_balance * 100
                    if drop_pct >= args.balance_drop_pct:
                        tee.log(
                            f"Balance dropped {drop_pct:.1f}% in one check: "
                            f"{w3.from_wei(last_balance, 'ether')} ETH -> {w3.from_wei(current_balance, 'ether')} ETH",
                            alert=True,
                        )
                        attempt_rescue("balance drop", current_balance)
                last_balance = current_balance
                tee.log(f"balance={w3.from_wei(current_balance, 'ether')} ETH, block={current_block}, known selectors={len(known_selectors)}")
            except Exception as e:
                # Never let a transient RPC hiccup (rate limiting, a
                # dropped connection, a node briefly out of sync) kill
                # this target's monitoring permanently -- confirmed live
                # that an uncaught HTTPError here used to silently end
                # the whole thread while OTHER targets kept going.
                # last_checked_block/last_balance are only rebound above
                # on success, so a failed cycle naturally retries the
                # exact same range next time instead of skipping it.
                tee.log(f"Poll cycle failed, will retry next cycle: {e}", alert=True)
    finally:
        tee.log("Stopped.")
        tee.close()


def build_parser() -> argparse.ArgumentParser:
    """Factored out of main() (2026-11-02) so dashboard_server.py can
    introspect the REAL CLI surface to build its own launch form from --
    see that file's own module doc."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--address", default=None, help="Deployed contract address to watch (ignored if --config is given)")
    parser.add_argument("--chain", default="sepolia", choices=known_chains(), help="Ignored if --config is given")
    parser.add_argument("--config", default=None, help="JSON file: a list of {chain, address} objects to watch concurrently")
    parser.add_argument("--poll-interval", type=float, default=20.0, help="Seconds between checks")
    parser.add_argument(
        "--balance-drop-pct", type=float, default=10.0, help="Alert if balance drops by more than this %% in one check"
    )
    parser.add_argument(
        "--large-tx-eth",
        type=float,
        default=0.0,
        help="Alert on any single incoming tx moving at least this much ETH (0 = auto: 50%% of current balance)",
    )
    parser.add_argument(
        "--rescan-interval",
        type=float,
        default=600.0,
        help="Seconds between periodic re-fuzzing runs against the live contract (0 disables re-fuzzing entirely)",
    )
    parser.add_argument("--rescan-seconds", type=int, default=60, help="How long each periodic re-fuzzing burst runs")
    parser.add_argument(
        "--rescan-detectors",
        default="all",
        help="Default 'all' (see auto_pipeline.py's own --detectors help for why this changed from "
        "'high_confidence') -- pass --rescan-detectors high_confidence explicitly for the old, lower-noise behavior.",
    )
    parser.add_argument(
        "--key", default=None, help="Path to a private key file -- required (with --safe-wallet) to enable automatic rescue"
    )
    parser.add_argument(
        "--safe-wallet",
        default=None,
        help="Address everything rescued is swept to, on every watched target. Required (with --key) to enable "
        "automatic rescue on a balance-drop alert",
    )
    parser.add_argument(
        "--confirm-mainnet",
        action="store_true",
        help="Required, together with --key/--safe-wallet, to enable rescue signing against any chain not in "
        "chains.TESTNET_CHAINS. Not needed for plain watch-only monitoring (no --key), which is read-only.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.config and not args.address:
        parser.error("either --address (with --chain) or --config is required")

    targets = _load_targets(args)

    acct = None
    if args.key and args.safe_wallet:
        key_path = Path(args.key)
        if not key_path.exists():
            print(f"ERROR: --key file {key_path} not found.", file=sys.stderr)
            return 1
        acct = Account.from_key(key_path.read_text().strip())
        for t in targets:
            require_mainnet_confirmation(t["chain"], args.confirm_mainnet)
    elif args.key or args.safe_wallet:
        print("WARNING: --key and --safe-wallet must both be given to enable automatic rescue -- running watch-only.", file=sys.stderr)

    nonce_locks: dict = {}
    stop_event = threading.Event()

    if len(targets) == 1:
        # No real need for a thread with exactly one target -- run it
        # directly on the main thread, exactly as before this feature
        # existed, so Ctrl+C behaves exactly like it always did.
        t = targets[0]
        try:
            watch_target(t["chain"], t["address"], args, acct, nonce_locks, stop_event)
        except KeyboardInterrupt:
            pass
        return 0

    threads = [
        threading.Thread(
            target=watch_target,
            args=(t["chain"], t["address"], args, acct, nonce_locks, stop_event),
            name=f"watch-{t['chain']}-{t['address'][:10]}",
        )
        for t in targets
    ]
    for th in threads:
        th.start()
    try:
        while any(th.is_alive() for th in threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopping all watched targets...", file=sys.stderr)
        stop_event.set()
        for th in threads:
            th.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
