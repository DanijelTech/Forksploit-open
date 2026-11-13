#!/usr/bin/env python3
# Author: DanyTech
"""wallet_policy.py -- strict, per-chain wallet-role lock-in, enforced by
every onchain_scripts/ tool that signs or sweeps a transaction.

Why this exists: auto_pipeline.py and monitor.py always had "a signer
wallet" (funds everything), "a target" (the contract under test), and "a
recovery/safe wallet" (where recovered funds get swept). All three came
from plain CLI arguments on every single invocation, with nothing
checking them against anything -- a wrong `--key` file, a copy-pasted
typo in `--recovery-wallet`, or a mixed-up `--target` in a batch of many
would silently proceed. The names `wallets.json`/`contracts.json` were
already reserved in .gitignore (see chains.py's own module doc) for
exactly this, but neither file nor any enforcement code ever actually
existed -- this module is that missing piece, written for real.

Two registries, both local, gitignored, per-user:

  wallets.json    -- EXACTLY one funding wallet + one recovery wallet
                      locked in per chain. Written once via `register`
                      (requires --confirm), read-only after that unless
                      --force is explicitly passed to change it.
  contracts.json  -- append-only log of every contract this system has
                      ever deployed or pointed at: address, chain, first
                      seen, source, and every run (funding/recovery
                      wallet used, run id, timestamp) -- so a contract
                      tested weeks ago can still be looked up for a later
                      fix or a repeat run, without having to dig through
                      onchain_scripts/logs/ by hand.

enforce_wallet_policy() is the actual gate: call it after loading the
signer account and before it signs anything. It raises SystemExit (not a
silently-ignorable warning) if the chain has no registered policy yet, if
the key file's own address doesn't match the chain's registered funding
wallet, or if the recovery/safe wallet argument doesn't match the chain's
registered recovery wallet. This is what stops "wrong key file" and
"typo'd recovery address" from ever reaching a real transaction.

CLI usage:
    # One-time setup per chain (refuses to silently overwrite an existing
    # registration -- pass --force if you really mean to change it).
    # --confirm-chain must repeat --chain exactly, typed separately -- an
    # anti-typo check specifically for 'eth' vs 'etc' (one letter apart,
    # both real mainnets) and 'eth'/'etc' vs their testnets:
    python3 wallet_policy.py register --chain etc --confirm-chain etc \\
        --funding-wallet 0xYourGasPayingWallet \\
        --recovery-wallet 0xYourProfitWallet --confirm

    # Inspect what's currently locked in:
    python3 wallet_policy.py show [--chain etc]

    # Inspect every contract this system has ever touched:
    python3 wallet_policy.py contracts [--chain etc]
"""
import argparse
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from web3 import Web3

from chains import chain_banner, known_chains

HERE = Path(__file__).parent
WALLETS_FILE = HERE / "wallets.json"
CONTRACTS_FILE = HERE / "contracts.json"

# Guards every read-modify-write of WALLETS_FILE/CONTRACTS_FILE. Needed
# since monitor.py's --config mode calls register_contract() from one
# thread per watched target -- without this, two threads can both read
# the same old JSON and each write back a version missing the other's
# entry (last writer wins, first thread's update silently lost).
_FILE_LOCK = threading.Lock()


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return default


def _save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2))


def _checksum(addr: str, label: str) -> str:
    try:
        return Web3.to_checksum_address(addr)
    except ValueError as e:
        raise SystemExit(f"'{addr}' is not a valid address for {label}: {e}")


def load_policy(chain: str) -> dict | None:
    """Returns {"funding_wallet": ..., "recovery_wallet": ..., ...} for
    `chain`, or None if nothing is registered yet."""
    return _load_json(WALLETS_FILE, {}).get(chain)


def register_policy(chain: str, confirm_chain: str, funding_wallet: str, recovery_wallet: str, force: bool = False, client_note: str = "") -> None:
    # Catches a typo (e.g. "ethereum" instead of "eth") at registration
    # time with a clear message, instead of a confusing "no policy
    # registered for 'eth'" later when auto_pipeline.py's own --chain
    # (which IS restricted to known_chains() via argparse) can never
    # match a misspelled registration.
    if chain not in known_chains():
        raise SystemExit(
            f"Chain '{chain}' is not one onchain_scripts/chains.py knows about. "
            f"Known chains: {', '.join(known_chains())}"
        )
    # --chain and --confirm-chain must be typed out SEPARATELY and match
    # exactly -- the standard anti-typo pattern (confirming a password,
    # typing a repo's name to delete it) for exactly the case this
    # module's own module doc calls out: Ethereum (eth) and Ethereum
    # Classic (etc) are one letter apart, both real mainnets, and this
    # registration is the ONE place that's deliberately hard to undo
    # (every later run's enforce_wallet_policy() trusts whatever gets
    # locked in here). A single --chain typo can't pass this on its own;
    # it would have to be typo'd identically twice, in two separately
    # typed arguments, to slip through.
    if confirm_chain != chain:
        raise SystemExit(
            f"--chain ('{chain}') and --confirm-chain ('{confirm_chain}') must match exactly -- "
            "this is deliberately NOT the same value copy-pasted once; type the chain name out a "
            "second time to confirm you meant it, especially since 'eth' and 'etc' are one letter "
            "apart and both real mainnets."
        )
    print(f"Registering a wallet policy for: {chain_banner(chain)}")
    funding_wallet = _checksum(funding_wallet, "--funding-wallet")
    recovery_wallet = _checksum(recovery_wallet, "--recovery-wallet")
    with _FILE_LOCK:
        policy = _load_json(WALLETS_FILE, {})
        existing = policy.get(chain)
        if existing and not force:
            raise SystemExit(
                f"Chain '{chain}' already has a registered wallet policy "
                f"(funding={existing['funding_wallet']}, recovery={existing['recovery_wallet']}). "
                "Re-run with --force to change it -- this is deliberately hard to do by accident, "
                "since it controls where every recovered asset on this chain ends up."
            )
        if funding_wallet == recovery_wallet:
            print(
                f"WARNING: funding wallet and recovery wallet are the same address ({funding_wallet}) "
                "on this chain -- unusual, but not blocked if that's genuinely intended.",
                file=sys.stderr,
            )
        policy[chain] = {
            "funding_wallet": funding_wallet,
            "recovery_wallet": recovery_wallet,
            "registered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            # Purely informational -- never read by enforce_wallet_policy()
            # or any signing path, so a wrong/missing note can never
            # affect where funds actually go. Exists because
            # recovery_wallet is, by this project's own working model,
            # ALWAYS the audited contract's own owner (the client) --
            # it changes per engagement, and a bare hex address alone
            # doesn't say whose it currently is. See dashboard_server.py's
            # wallet-policy panel, which surfaces this next to the address.
            "client_note": client_note or "",
        }
        _save_json(WALLETS_FILE, policy)
    note_suffix = f" ({client_note})" if client_note else ""
    print(f"Locked in for chain '{chain}': funding_wallet={funding_wallet}, recovery_wallet={recovery_wallet}{note_suffix}")


def enforce_wallet_policy(chain: str, signer_address: str, recovery_or_safe_wallet: str) -> None:
    """Call this right after the signing account is loaded from its key
    file, before it is used to send anything. Exits the process (not a
    warning) on any mismatch -- these three checks are exactly the "wrong
    wallet" accidents real money is lost to.
    """
    policy = load_policy(chain)
    if policy is None:
        raise SystemExit(
            f"Refusing to sign anything on chain '{chain}': no wallet policy registered for it yet. "
            f"Run: python3 {Path(__file__).name} register --chain {chain} "
            "--funding-wallet 0x... --recovery-wallet 0x... --confirm"
        )
    signer_address = _checksum(signer_address, "signer key")
    recovery_or_safe_wallet = _checksum(recovery_or_safe_wallet, "--recovery-wallet/--safe-wallet")
    if signer_address != policy["funding_wallet"]:
        raise SystemExit(
            f"Refusing to sign on chain '{chain}': the loaded key resolves to {signer_address}, but the "
            f"wallet registered as this chain's funding wallet is {policy['funding_wallet']}. Wrong key "
            "file, or the registered policy is stale -- fix one or the other before proceeding; this check "
            "exists specifically to catch a wrong key file before it pays for anything."
        )
    if recovery_or_safe_wallet != policy["recovery_wallet"]:
        raise SystemExit(
            f"Refusing to proceed on chain '{chain}': --recovery-wallet/--safe-wallet is "
            f"{recovery_or_safe_wallet}, but the wallet registered as this chain's recovery wallet is "
            f"{policy['recovery_wallet']}. Recovered funds are only ever allowed to sweep to the "
            "registered recovery wallet -- fix the argument, or re-register the policy (--force) if the "
            "recovery wallet genuinely changed."
        )


def register_contract(
    chain: str,
    address: str,
    source: str,
    run_id: str,
    script: str,
    funding_wallet: str,
    recovery_wallet: str,
) -> None:
    """Appends a run record for `address` on `chain` to contracts.json --
    the persisted "what have we ever deployed/pointed at, with which
    wallets, when" log the strict wallet system exists to make possible,
    so a contract tested before can be found again for a fix or a repeat
    run without grepping through onchain_scripts/logs/ by hand.
    """
    address = _checksum(address, "contract address")
    with _FILE_LOCK:
        registry = _load_json(CONTRACTS_FILE, {})
        key = f"{chain}:{address.lower()}"
        entry = registry.setdefault(
            key,
            {
                "address": address,
                "chain": chain,
                "source": source,
                "first_seen": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "runs": [],
            },
        )
        entry["runs"].append(
            {
                "run_id": run_id,
                "script": script,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "funding_wallet": funding_wallet,
                "recovery_wallet": recovery_wallet,
            }
        )
        _save_json(CONTRACTS_FILE, registry)


def _cmd_register(args) -> int:
    if not args.confirm:
        raise SystemExit(
            "Refusing to register a wallet policy without --confirm -- this is a deliberate "
            "speed bump: these two addresses control where test funds come from and where "
            "recovered funds go, on every future run against this chain."
        )
    register_policy(args.chain, args.confirm_chain, args.funding_wallet, args.recovery_wallet, force=args.force, client_note=args.client_note)
    return 0


def _cmd_show(args) -> int:
    policy = _load_json(WALLETS_FILE, {})
    chains = [args.chain] if args.chain else sorted(policy)
    if not chains:
        print("No wallet policy registered for any chain yet.")
        return 0
    for chain in chains:
        entry = policy.get(chain)
        if entry is None:
            print(f"{chain}: no policy registered.")
            continue
        note_suffix = f" -- {entry['client_note']}" if entry.get("client_note") else ""
        print(f"{chain_banner(chain)}: funding_wallet={entry['funding_wallet']} recovery_wallet={entry['recovery_wallet']}{note_suffix} (registered {entry['registered_at']})")
    return 0


def _cmd_contracts(args) -> int:
    registry = _load_json(CONTRACTS_FILE, {})
    entries = [e for e in registry.values() if args.chain is None or e["chain"] == args.chain]
    if not entries:
        print("No contracts recorded yet.")
        return 0
    for e in sorted(entries, key=lambda e: e["first_seen"]):
        print(f"{chain_banner(e['chain'])}: {e['address']} (source={e['source']}, first_seen={e['first_seen']}, {len(e['runs'])} run(s))")
        for run in e["runs"]:
            print(f"    [{run['timestamp']}] {run['script']} run_id={run['run_id']} funding={run['funding_wallet']} recovery={run['recovery_wallet']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_register = sub.add_parser("register", help="Lock in the funding/recovery wallets for a chain")
    p_register.add_argument("--chain", required=True)
    p_register.add_argument(
        "--confirm-chain",
        required=True,
        help="Type the SAME chain name again, separately -- required anti-typo confirmation, not a "
        "copy-paste of --chain (see register_policy's own doc for why: 'eth' and 'etc' are one "
        "letter apart and both real mainnets).",
    )
    p_register.add_argument("--funding-wallet", required=True, help="Address that pays for every step (gas, deploys, exploit execution)")
    p_register.add_argument("--recovery-wallet", required=True, help="Address every recovered asset is swept to")
    p_register.add_argument("--force", action="store_true", help="Overwrite an existing registration for this chain")
    p_register.add_argument(
        "--client-note",
        default="",
        help="Purely informational label (e.g. a client/engagement name) for WHOSE wallet --recovery-wallet "
        "currently is -- recovery_wallet is, by this project's own working model, always the audited "
        "contract's own owner, so it changes per engagement and a bare address alone doesn't say whose "
        "it is right now. Never read by enforce_wallet_policy() or any signing path.",
    )
    p_register.add_argument("--confirm", action="store_true", help="Required -- acknowledges this locks in real wallet addresses")
    p_register.set_defaults(func=_cmd_register)

    p_show = sub.add_parser("show", help="Show the registered wallet policy")
    p_show.add_argument("--chain", default=None)
    p_show.set_defaults(func=_cmd_show)

    p_contracts = sub.add_parser("contracts", help="Show every contract this system has deployed/tested")
    p_contracts.add_argument("--chain", default=None)
    p_contracts.set_defaults(func=_cmd_contracts)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
