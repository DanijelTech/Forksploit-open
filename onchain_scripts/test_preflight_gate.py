#!/usr/bin/env python3
# Author: DanyTech
"""test_preflight_gate.py -- a plan that provably reverts, or that moves
value but costs more gas than it recovers, must be skipped BEFORE any real
transaction is signed.

Regression test for a real ETC mainnet run (2026-11-07): 11 plans were found,
10 of them executed cleanly and recovered nothing, and one single plan burned
7,878,136 gas (~0.0206 ETC) doing it. Every wei of that was already knowable
from free reads -- the plan's own metadata and a fork simulation -- so the
gate exists to make that spend impossible.

No network: a fake Web3 stands in for the throwaway Anvil fork, so the real
simulate_plan_on_fork / preflight_skip_reason functions run unmodified.

Run: python -m unittest onchain_scripts/test_preflight_gate.py -v
 or: python onchain_scripts/test_preflight_gate.py
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_account import Account  # noqa: E402
from web3 import Web3  # noqa: E402
from web3.datastructures import AttributeDict  # noqa: E402

import auto_pipeline  # noqa: E402
from auto_pipeline import (  # noqa: E402
    PLAN_SKIPPED_UNPROFITABLE,
    metadata_skip_reason,
    preflight_skip_reason,
    simulate_plan_on_fork,
)

SIGNER = Account.from_key("0x" + "11" * 32)
ATTACK_WALLET = "0x" + "aa" * 20
RECOVERY = "0x" + "bb" * 20
TARGET = "0x" + "cc" * 20
GAS_PRICE = 2_600_000_000


def _plan(steps=None, kind="flat", repeat_step=None):
    return {
        "contract_name": "Ctest_0",
        "kind": kind,
        "needs_funding": False,
        "total_value": "0",
        "steps": steps
        or [{"contract": TARGET, "calldata": "deadbeef", "value": "0", "caller": SIGNER.address}],
        "repeat_step": repeat_step,
    }


class _FakeProvider:
    def __init__(self, balances):
        self.balances = balances
        self._snapshots = []
        self.reverted = 0

    def make_request(self, method, params):
        if method == "evm_snapshot":
            self._snapshots.append(dict(self.balances))
            return {"result": hex(len(self._snapshots))}
        if method == "evm_revert":
            if self._snapshots:
                self.balances.clear()
                self.balances.update(self._snapshots.pop())
            self.reverted += 1
            return {"result": True}
        if method == "anvil_setBalance":
            self.balances[params[0].lower()] = int(params[1], 16)
            return {"result": True}
        raise AssertionError(f"unexpected provider method {method}")


class _FakeEth:
    chain_id = 61
    gas_price = GAS_PRICE

    def __init__(self, balances, script, token_balances):
        # `script` is one entry per send, each: (status, gas_used, balance_delta)
        self._balances = balances
        self._token_balances = token_balances
        self._script = list(script)
        self._next = 0
        self._nonce = 0
        self.sent = []
        self.estimates = 0

    def get_block(self, which):
        # Legacy-style block (no baseFeePerGas) -- matches ETC.
        return {"number": 1, "gasLimit": 8_000_000}

    def get_balance(self, addr, block="latest"):
        return self._balances.get(Web3.to_checksum_address(addr).lower(), 0)

    def get_transaction_count(self, addr, block="latest"):
        n = self._nonce
        self._nonce += 1
        return n

    def estimate_gas(self, tx):
        self.estimates += 1
        raise AssertionError("fork simulation must not call estimate_gas")

    def call(self, tx):
        # balanceOf(address) reads against the fake token registry, so the
        # ERC20 branch of simulate_plan_on_fork can run for real.
        data = tx["data"]
        if isinstance(data, str):
            data = bytes.fromhex(data.removeprefix("0x"))
        if data[:4].hex() == "70a08231":
            holder = "0x" + data[16:36].hex()
            token = Web3.to_checksum_address(tx["to"]).lower()
            return self._token_balances.get(token, {}).get(holder.lower(), 0).to_bytes(32, "big")
        raise AssertionError(f"unexpected eth_call data {data.hex()}")

    def send_raw_transaction(self, raw):
        self.sent.append(raw)
        return b"\xab" * 32

    def wait_for_transaction_receipt(self, tx_hash, timeout=180):
        if self._next >= len(self._script):
            raise AssertionError("more sends than the script describes")
        entry = self._script[self._next]
        self._next += 1
        status, gas_used, delta = entry[0], entry[1], entry[2]
        token_delta = entry[3] if len(entry) > 3 else {}
        for addr, change in delta.items():
            key = Web3.to_checksum_address(addr).lower()
            self._balances[key] = self._balances.get(key, 0) + change
        for (token, holder), change in token_delta.items():
            tkey = Web3.to_checksum_address(token).lower()
            hkey = Web3.to_checksum_address(holder).lower()
            bucket = self._token_balances.setdefault(tkey, {})
            bucket[hkey] = bucket.get(hkey, 0) + change
        return AttributeDict({"status": status, "gasUsed": gas_used, "effectiveGasPrice": GAS_PRICE})


class _FakeForkW3:
    def __init__(self, script, attack_wallet_balance=0, recovery_balance=0, token_balances=None):
        balances = {
            ATTACK_WALLET.lower(): attack_wallet_balance,
            RECOVERY.lower(): recovery_balance,
            SIGNER.address.lower(): Web3.to_wei(1, "ether"),
        }
        self.provider = _FakeProvider(balances)
        self.eth = _FakeEth(balances, script, token_balances or {})
        self.from_wei = Web3.from_wei
        self.to_wei = Web3.to_wei


class _NullTee:
    def __init__(self):
        self.lines = []

    def log(self, msg="", alert=False):
        self.lines.append(msg)


class MetadataSkipReasonTest(unittest.TestCase):
    def test_atomic_unreplayable_is_skipped(self):
        reason = metadata_skip_reason({"atomic_replayable": False})
        self.assertIsNotNone(reason)
        self.assertIn("atomic_replayable", reason)

    def test_multiple_callers_is_skipped(self):
        reason = metadata_skip_reason({"atomic_replayable": True, "distinct_callers": 3})
        self.assertIsNotNone(reason)
        self.assertIn("3 distinct caller", reason)

    def test_single_replayable_caller_is_not_skipped(self):
        self.assertIsNone(metadata_skip_reason({"atomic_replayable": True, "distinct_callers": 1}))

    def test_missing_fields_default_to_replayable(self):
        # A composed plan (phase 2) carries no fuzzer metadata -- it must not
        # be skipped for a missing field.
        self.assertIsNone(metadata_skip_reason({}))

    def test_review_tier_heuristic_is_skipped(self):
        # confirmed_exploitable=false is the Rust layer's own verdict that no
        # oracle observed real fund movement (e.g. Stale Guard Counter). Such a
        # plan has no extraction step to replay, so running it for real can
        # only burn gas -- exactly the ETC mainnet run where 1022 heuristic
        # hits produced 805 plans, none of which moved a wei.
        reason = metadata_skip_reason({
            "atomic_replayable": True, "distinct_callers": 1,
            "confirmed_exploitable": False, "kind": "flat",
        })
        self.assertIsNotNone(reason)
        self.assertIn("Review-tier", reason)

    def test_confirmed_exploitable_is_not_skipped(self):
        self.assertIsNone(metadata_skip_reason({
            "atomic_replayable": True, "distinct_callers": 1,
            "confirmed_exploitable": True, "kind": "flat",
        }))

    def test_reentrancy_plan_is_never_skipped_by_the_heuristic_rule(self):
        # Reentrancy has its own dedicated extraction path and does not carry
        # the confirmed_exploitable flag the same way -- it must not be
        # skipped by this rule.
        self.assertIsNone(metadata_skip_reason({
            "atomic_replayable": True, "distinct_callers": 1,
            "confirmed_exploitable": False, "kind": "reentrancy",
        }))

    def test_owner_impersonation_is_skipped(self):
        # The fuzzer's caller is an address harvested from the TARGET's own
        # storage (its owner/admin/multisig). The "attack" is the privileged
        # party calling its own owner-gated function -- e.g. escapeHatch()
        # gated on require(msg.sender == owner), reported as "Fund Loss" on
        # ETC target 0x9f5304... . No external signer can reproduce it, so it
        # must be skipped, never attempted.
        reason = metadata_skip_reason({
            "atomic_replayable": True, "distinct_callers": 1,
            "confirmed_exploitable": True, "owner_impersonation": True, "kind": "flat",
        })
        self.assertIsNotNone(reason)
        self.assertIn("storage", reason)

    def test_missing_owner_impersonation_defaults_to_not_flagged(self):
        # Older plans predate the flag; absent must mean "not impersonation".
        self.assertIsNone(metadata_skip_reason({
            "atomic_replayable": True, "distinct_callers": 1,
            "confirmed_exploitable": True, "kind": "flat",
        }))

    def test_owner_gated_is_skipped_with_the_semantic_reason(self):
        # PHASE 3.2: the semantic shape -- the trace calls the target AS an
        # identity harvested from THAT contract's own storage
        # (require(msg.sender == owner) satisfied by impersonation).
        reason = metadata_skip_reason({
            "atomic_replayable": True, "distinct_callers": 1,
            "confirmed_exploitable": True, "owner_gated": True, "kind": "flat",
        })
        self.assertIsNotNone(reason)
        self.assertIn("owner_gated", reason)

    def test_owner_gated_takes_precedence_over_broad_owner_impersonation(self):
        reason = metadata_skip_reason({
            "atomic_replayable": True, "distinct_callers": 1,
            "confirmed_exploitable": True,
            "owner_impersonation": True, "owner_gated": True, "kind": "flat",
        })
        self.assertIsNotNone(reason)
        self.assertIn("owner_gated", reason)
        self.assertNotIn("harvested from the target's own storage (owner/admin", reason)

    def test_review_tier_wins_over_owner_impersonation(self):
        # A heuristic finding that happens to carry a storage-harvested caller
        # (a low-order word misread as an address) is still primarily a
        # heuristic -- the reason must say so, not mislabel it.
        reason = metadata_skip_reason({
            "atomic_replayable": True, "distinct_callers": 1,
            "confirmed_exploitable": False, "owner_impersonation": True, "kind": "flat",
        })
        self.assertIsNotNone(reason)
        self.assertIn("Review-tier", reason)

    def test_missing_confirmed_exploitable_defaults_to_allowed(self):
        # Older plans predate the flag; absent must mean "allow", not "skip".
        self.assertIsNone(metadata_skip_reason({
            "atomic_replayable": True, "distinct_callers": 1, "kind": "flat",
        }))


class SimulatePlanOnForkTest(unittest.TestCase):
    def test_unprofitable_plan_reports_delta_below_gas(self):
        # One step succeeds, moves nothing, costs real gas -> delta 0 <= gas.
        fork = _FakeForkW3(script=[(1, 46_878, {})])
        delta, gas, reverted, tokens = simulate_plan_on_fork(
            fork, SIGNER, ATTACK_WALLET, _plan(), RECOVERY, "etc", _NullTee()
        )
        self.assertFalse(reverted)
        self.assertEqual(delta, 0)
        self.assertGreater(gas, 0)
        self.assertLessEqual(delta, gas)

    def test_profitable_plan_reports_delta_above_gas(self):
        # Step leaves ETH in AttackWallet; the sweep moves it to recovery.
        gain = Web3.to_wei(0.05, "ether")
        fork = _FakeForkW3(
            script=[
                (1, 46_878, {ATTACK_WALLET: gain}),          # execute: value lands in wallet
                (1, 36_973, {ATTACK_WALLET: -gain, RECOVERY: gain}),  # sweep to recovery
            ]
        )
        delta, gas, reverted, tokens = simulate_plan_on_fork(
            fork, SIGNER, ATTACK_WALLET, _plan(), RECOVERY, "etc", _NullTee()
        )
        self.assertFalse(reverted)
        self.assertEqual(delta, gain)
        self.assertGreater(delta, gas)

    def test_reverting_step_is_reported_as_reverted(self):
        fork = _FakeForkW3(script=[(0, 46_878, {})])
        delta, gas, reverted, tokens = simulate_plan_on_fork(
            fork, SIGNER, ATTACK_WALLET, _plan(), RECOVERY, "etc", _NullTee()
        )
        self.assertTrue(reverted)
        self.assertEqual(delta, 0)

    def test_fork_is_always_reverted_after_replay(self):
        fork = _FakeForkW3(script=[(1, 46_878, {})])
        simulate_plan_on_fork(fork, SIGNER, ATTACK_WALLET, _plan(), RECOVERY, "etc", _NullTee())
        self.assertEqual(fork.provider.reverted, 1)

    def test_fork_is_reverted_even_when_replay_reverts(self):
        fork = _FakeForkW3(script=[(0, 46_878, {})])
        simulate_plan_on_fork(fork, SIGNER, ATTACK_WALLET, _plan(), RECOVERY, "etc", _NullTee())
        self.assertEqual(fork.provider.reverted, 1)

    def test_no_estimate_gas_is_called(self):
        # A fork-specific estimate quirk must never make the gate lie -- the
        # fork path signs at the cap directly and never estimates.
        fork = _FakeForkW3(script=[(1, 46_878, {})])
        simulate_plan_on_fork(fork, SIGNER, ATTACK_WALLET, _plan(), RECOVERY, "etc", _NullTee())
        self.assertEqual(fork.eth.estimates, 0)

    def test_undecidable_simulation_returns_none(self):
        # A script too short for the sends raises mid-replay -> None, meaning
        # "could not decide", never "unprofitable".
        fork = _FakeForkW3(script=[])
        self.assertIsNone(
            simulate_plan_on_fork(fork, SIGNER, ATTACK_WALLET, _plan(), RECOVERY, "etc", _NullTee())
        )
        # ...and the fork is still reverted.
        self.assertEqual(fork.provider.reverted, 1)

    def test_token_draining_plan_reports_token_gain(self):
        # A plan whose native delta is exactly 0 (a token drain) must still
        # report the real token gain, so preflight never skips it as worthless.
        token = "0x" + "dd" * 20
        amount = 1_000_000
        steps = [{"contract": token, "calldata": "deadbeef", "value": "0",
                  "caller": SIGNER.address, "stolen_asset": token}]
        # step 1: execute moves the token into AttackWallet; step 2: sweepToken
        # moves it to recovery (the plan has no native value at all).
        fork = _FakeForkW3(
            script=[
                (1, 46_878, {}, {(token, ATTACK_WALLET): amount}),
                (1, 36_973, {}, {(token, ATTACK_WALLET): -amount, (token, RECOVERY): amount}),
            ]
        )
        delta, gas, reverted, tokens = simulate_plan_on_fork(
            fork, SIGNER, ATTACK_WALLET, _plan(steps=steps), RECOVERY, "etc", _NullTee()
        )
        self.assertFalse(reverted)
        self.assertEqual(delta, 0)
        self.assertEqual(tokens.get(Web3.to_checksum_address(token)), amount)


class PreflightSkipReasonTest(unittest.TestCase):
    def test_metadata_skip_applies_without_a_fork(self):
        finding = {"plan": _plan(), "atomic_replayable": False, "distinct_callers": 1}
        reason = preflight_skip_reason(finding, None, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC")
        self.assertIsNotNone(reason)
        self.assertIn("metadata", reason)

    def test_no_fork_and_ok_metadata_allows_the_attempt(self):
        finding = {"plan": _plan(), "atomic_replayable": True, "distinct_callers": 1}
        reason = preflight_skip_reason(finding, None, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC")
        self.assertIsNone(reason)

    def test_unprofitable_replay_is_skipped(self):
        finding = {"plan": _plan(), "atomic_replayable": True, "distinct_callers": 1}
        fork = _FakeForkW3(script=[(1, 46_878, {})])
        reason = preflight_skip_reason(finding, fork, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC")
        self.assertIsNotNone(reason)
        self.assertIn("not profitable", reason)

    def test_reverting_replay_is_skipped(self):
        finding = {"plan": _plan(), "atomic_replayable": True, "distinct_callers": 1}
        fork = _FakeForkW3(script=[(0, 46_878, {})])
        reason = preflight_skip_reason(finding, fork, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC")
        self.assertIsNotNone(reason)
        self.assertIn("reverted", reason)

    def test_profitable_replay_passes(self):
        finding = {"plan": _plan(), "atomic_replayable": True, "distinct_callers": 1}
        gain = Web3.to_wei(0.05, "ether")
        fork = _FakeForkW3(
            script=[
                (1, 46_878, {ATTACK_WALLET: gain}),
                (1, 36_973, {ATTACK_WALLET: -gain, RECOVERY: gain}),
            ]
        )
        reason = preflight_skip_reason(finding, fork, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC")
        self.assertIsNone(reason)

    def test_token_draining_replay_is_not_skipped(self):
        # Native delta is 0 but a real token gain exists -- execute_plan would
        # call this CONFIRMED, so the gate must never skip it.
        token = "0x" + "dd" * 20
        amount = 1_000_000
        steps = [{"contract": token, "calldata": "deadbeef", "value": "0",
                  "caller": SIGNER.address, "stolen_asset": token}]
        finding = {"plan": _plan(steps=steps), "atomic_replayable": True, "distinct_callers": 1}
        fork = _FakeForkW3(
            script=[
                (1, 46_878, {}, {(token, ATTACK_WALLET): amount}),
                (1, 36_973, {}, {(token, ATTACK_WALLET): -amount, (token, RECOVERY): amount}),
            ]
        )
        reason = preflight_skip_reason(finding, fork, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC")
        self.assertIsNone(reason)


class StartForkTest(unittest.TestCase):
    def test_missing_anvil_disables_gate_without_raising(self):
        with mock.patch.object(auto_pipeline.shutil, "which", return_value=None):
            proc, w3 = auto_pipeline._start_fork("etc", _NullTee())
        self.assertIsNone(proc)
        self.assertIsNone(w3)


class SkippedStatusIsDistinctTest(unittest.TestCase):
    def test_skipped_status_is_its_own_value(self):
        # Must never be conflated with executed-no-profit (which paid gas) or
        # inconclusive (which decided nothing).
        self.assertEqual(PLAN_SKIPPED_UNPROFITABLE, "skipped_unprofitable")
        self.assertNotEqual(PLAN_SKIPPED_UNPROFITABLE, auto_pipeline.PLAN_EXECUTED_NO_PROFIT)
        self.assertNotEqual(PLAN_SKIPPED_UNPROFITABLE, auto_pipeline.PLAN_INCONCLUSIVE)

    def test_metadata_skip_reports_not_extractable(self):
        # A metadata-layer skip means "no runnable extraction step", which is
        # a different claim from a fork-proven "unprofitable" skip.
        finding = {"plan": _plan(), "atomic_replayable": False, "distinct_callers": 1}
        reason = preflight_skip_reason(finding, None, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC")
        self.assertTrue(reason.startswith("metadata:"))
        self.assertEqual(
            auto_pipeline.skip_status_for(reason), auto_pipeline.PLAN_SKIPPED_NOT_EXTRACTABLE
        )

    def test_fork_skip_reports_unprofitable(self):
        fork_reason = "fork replay: would gain 0 ETC but cost 0.0001 ETC in gas -- not profitable"
        self.assertEqual(
            auto_pipeline.skip_status_for(fork_reason), PLAN_SKIPPED_UNPROFITABLE
        )


class StrategyLayerPropagationTest(unittest.TestCase):
    """strategy_layer.load_findings/compose_plan must carry the fuzzer's own
    `confirmed_exploitable` verdict, so the phase-2 composed attempts are
    gated by the same rule as the standalone pass."""

    def _write_plan(self, tmpdir, name, **meta):
        import json
        from pathlib import Path
        vuln = Path(tmpdir) / "vulnerabilities"
        vuln.mkdir(parents=True, exist_ok=True)
        plan = {
            "contract_name": name,
            "kind": meta.pop("kind", "flat"),
            "needs_funding": False,
            "total_value": "0",
            "steps": [{"contract": TARGET, "calldata": "deadbeef", "value": "0", "caller": SIGNER.address}],
            "repeat_step": None,
            **meta,
        }
        (vuln / f"{name}.plan.json").write_text(json.dumps(plan))
        return vuln

    def test_load_findings_reads_confirmed_exploitable(self):
        import tempfile
        import strategy_layer
        with tempfile.TemporaryDirectory() as tmp:
            self._write_plan(tmp, "Cheuristic_0", confirmed_exploitable=False,
                             bug_types=["Stale Guard Counter"])
            self._write_plan(tmp, "Creal_1", confirmed_exploitable=True,
                             bug_types=["Fund Loss"])
            findings = strategy_layer.load_findings(__import__("pathlib").Path(tmp))
        by_name = {f["contract_name"]: f for f in findings}
        self.assertFalse(by_name["Cheuristic_0"]["confirmed_exploitable"])
        self.assertTrue(by_name["Creal_1"]["confirmed_exploitable"])

    def test_compose_plan_is_confirmed_only_if_a_member_is(self):
        import strategy_layer
        heuristic = {"contract_name": "H", "plan": {"steps": []}, "bug_types": set(),
                     "kind": "flat", "atomic_replayable": True, "confirmed_exploitable": False,
                     "needs_funding": False, "step_count": 0}
        real = {"contract_name": "R", "plan": {"steps": []}, "bug_types": set(),
                "kind": "flat", "atomic_replayable": True, "confirmed_exploitable": True,
                "needs_funding": False, "step_count": 0}
        self.assertFalse(strategy_layer.compose_plan([heuristic])["confirmed_exploitable"])
        self.assertTrue(strategy_layer.compose_plan([heuristic, real])["confirmed_exploitable"])


if __name__ == "__main__":
    unittest.main()
