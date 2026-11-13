#!/usr/bin/env python3
# Author: DanyTech
"""test_pipeline_resilience.py -- one plan raising must not abort the plans
after it.

Regression test for a real ETC mainnet failure: a single execute_plan() call
raised an uncaught exception (a tx stuck in the mempool -- see
gas_utils.MAX_GAS_LIMIT) and killed a run that still had 1945 plans left to
try. The per-finding loop in auto_pipeline.main() now wraps each call, and
strategy_layer.run_chain_attempts() does the same for composed attempts.

No network: execute_plan_fn is a plain callable that raises for the first
plan and returns a real result for the rest, so the real loop logic runs.

Run: python -m unittest onchain_scripts/test_pipeline_resilience.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import strategy_layer  # noqa: E402


class _Tee:
    def __init__(self):
        self.lines = []

    def log(self, msg, alert=False):
        self.lines.append(str(msg))


def _finding(name, bug_types, kind="flat"):
    return {
        "contract_name": name,
        "bug_types": set(bug_types),
        "kind": kind,
        "atomic_replayable": True,
        "plan": {"contract_name": name, "kind": kind, "steps": []},
        "plan_path": f"/tmp/{name}.plan.json",
    }


class ChainAttemptsResilienceTest(unittest.TestCase):
    def _run(self, findings, raising_names):
        calls = []

        def execute_plan_fn(w3, acct, nonce_box, attack_wallet, plan, recovery_wallet, tee, chain=None):
            name = plan["contract_name"]
            calls.append(name)
            if name in raising_names:
                raise RuntimeError("replacement transaction underpriced")
            return "confirmed", 10**18, 10**15, 10**18 - 10**15

        tee = _Tee()
        results = strategy_layer.run_chain_attempts(
            execute_plan_fn, None, None, {}, "0x" + "44" * 20,
            findings, set(), "0x" + "22" * 20, tee,
        )
        return results, calls

    def test_one_raising_attempt_does_not_abort_the_rest(self):
        # Two unlock->objective composition groups; the first group's
        # objective raises, so the second must still be attempted.
        findings = [
            _finding("A", ("Reentrancy",)),
            _finding("B", ("Fund Loss",)),
            _finding("C", ("Reentrancy",)),
            _finding("D", ("Fund Loss",)),
        ]
        results, calls = self._run(findings, raising_names={"B"})
        self.assertIn("D", calls)
        statuses = {r["objective_contract_name"]: r["status"] for r in results}
        self.assertEqual(statuses.get("B"), "inconclusive")
        self.assertEqual(statuses.get("D"), "confirmed")


class ChainAttemptsGasFieldsTest(unittest.TestCase):
    """PHASE 1.2: a composed attempt must surface the composed plan's OWN gas
    reality, exactly like a standalone plan. The gate stamps the measured
    fields onto the merged plan; run_chain_attempts must carry them into the
    result so the report is not silent about a composed plan's gas."""

    def test_composed_gas_fields_are_surfaced(self):
        def execute_plan_fn(w3, acct, nonce_box, attack_wallet, plan, recovery_wallet, tee, chain=None):
            # The gate (gated_execute_plan) stamps the measurement onto the
            # merged plan before executing it; simulate that here.
            plan["gas_estimate"] = 49_610_942
            plan["fits_block_gas_limit"] = False
            plan["gas_headroom_pct"] = -520.14
            plan["block_gas_limit"] = 8_000_000
            return "oversized_gas", 0, 0, 0, 0

        findings = [_finding("A", ("Reentrancy",)), _finding("B", ("Fund Loss",))]
        tee = _Tee()
        results = strategy_layer.run_chain_attempts(
            execute_plan_fn, None, None, {}, "0x" + "44" * 20,
            findings, set(), "0x" + "22" * 20, tee,
        )
        self.assertTrue(results)
        r = results[0]
        self.assertEqual(r["status"], "oversized_gas")
        self.assertEqual(r["gas_estimate"], 49_610_942)
        self.assertFalse(r["fits_block_gas_limit"])
        self.assertEqual(r["block_gas_limit"], 8_000_000)


class ChainCallbackSignatureContractTest(unittest.TestCase):
    """Regression for a real, confirmed bug: `run_chain_attempts` invokes the
    callback as `execute_plan_fn(..., chain=chain)` (mirroring
    `execute_plan`'s own signature), but the production wrappers
    (`gated_execute_plan`) named their parameter `chain_`. Every composed
    attempt therefore raised `TypeError: got an unexpected keyword argument
    'chain'` and the WHOLE strategy/chaining phase was silently dead -- 13
    such TypeErrors in one real ETC run, all logged as INCONCLUSIVE.

    The existing tests above did not catch it because their fake callbacks
    already used the correct `chain=None` name, so they exercised a signature
    the production code did not actually have. This test pins the CONTRACT
    itself: the callback `run_chain_attempts` calls must accept `chain=`, so
    it inspects the real production wrappers' signatures.
    """

    def test_run_chain_attempts_calls_callback_with_chain_keyword(self):
        # A callback that accepts ONLY `chain` (not `chain_`) must work --
        # this is the exact contract the production code must honour.
        def execute_plan_fn(w3, acct, nonce_box, attack_wallet, plan, recovery_wallet, tee, chain=None):
            return "confirmed", 10**18, 10**15, 10**18 - 10**15

        findings = [_finding("A", ("Reentrancy",)), _finding("B", ("Fund Loss",))]
        tee = _Tee()
        # Must NOT raise TypeError from the keyword name.
        results = strategy_layer.run_chain_attempts(
            execute_plan_fn, None, None, {}, "0x" + "44" * 20,
            findings, set(), "0x" + "22" * 20, tee,
        )
        self.assertTrue(results)
        self.assertTrue(all(r["status"] == "confirmed" for r in results))

    def test_production_wrappers_use_the_chain_keyword(self):
        """The production `gated_execute_plan` wrappers (in auto_pipeline.py
        and batch_pipeline.py) must name their chain parameter `chain`, not
        `chain_`, or run_chain_attempts' `chain=` call raises TypeError."""
        import re

        here = os.path.dirname(os.path.abspath(__file__))
        for fname in ("auto_pipeline.py", "batch_pipeline.py"):
            with open(os.path.join(here, fname)) as f:
                src = f.read()
            m = re.search(r"def gated_execute_plan\(([^)]*)\)", src)
            self.assertIsNotNone(m, f"{fname}: gated_execute_plan not found")
            params = m.group(1)
            self.assertRegex(
                params, r"(^|,)\s*chain\s*=",
                f"{fname}: gated_execute_plan must take a `chain=` parameter "
                "(run_chain_attempts calls it with chain=chain)",
            )
            self.assertNotRegex(
                params, r"(^|,)\s*chain_\s*=",
                f"{fname}: gated_execute_plan must NOT name the parameter `chain_` "
                "-- that is the exact mismatch that killed the chaining phase",
            )


class W5DependencyOrderingTest(unittest.TestCase):
    """W5: a prerequisite step must run before the step that depends on it,
    even when the fuzzer recorded them in the opposite order. Pins the
    explicit rule set (approve -> transferFrom, deposit -> withdraw) and the
    cycle fall-back (never silently reorder a cycle into something wrong)."""

    def _step(self, contract, selector, caller="0x" + "44" * 20, calldata="0x"):
        return {"contract": contract, "fn_selector": selector, "calldata": calldata, "value": "0", "caller": caller}

    def test_approve_moved_before_transfer_from(self):
        token = "0x" + "aa" * 20
        # transferFrom FIRST, approve SECOND -- must be reordered.
        steps = [self._step(token, "0x23b872dd"), self._step(token, "0x095ea7b3")]
        ordered, notes = strategy_layer.order_steps_by_dependencies(steps)
        self.assertEqual([s["fn_selector"] for s in ordered], ["0x095ea7b3", "0x23b872dd"])
        self.assertTrue(any("approve creates the allowance" in n for n in notes))

    def test_unrelated_steps_keep_order(self):
        a, b = "0x" + "aa" * 20, "0x" + "bb" * 20
        steps = [self._step(a, "0x11111111"), self._step(b, "0x22222222")]
        ordered, notes = strategy_layer.order_steps_by_dependencies(steps)
        self.assertEqual(ordered, steps, "no edges => order unchanged")
        self.assertEqual(notes, [])

    def test_approve_on_a_different_token_does_not_reorder(self):
        t1, t2 = "0x" + "aa" * 20, "0x" + "bb" * 20
        steps = [self._step(t1, "0x23b872dd"), self._step(t2, "0x095ea7b3")]
        ordered, _ = strategy_layer.order_steps_by_dependencies(steps)
        self.assertEqual(ordered, steps, "an approve on another token is not a prerequisite")

    def test_deposit_before_withdraw(self):
        weth = "0x" + "cc" * 20
        steps = [self._step(weth, "0x2e1a7d4d"), self._step(weth, "0xd0e30db0")]
        ordered, notes = strategy_layer.order_steps_by_dependencies(steps)
        self.assertEqual([s["fn_selector"] for s in ordered], ["0xd0e30db0", "0x2e1a7d4d"])
        self.assertTrue(any("deposit" in n for n in notes))

    def test_compose_plan_orders_dependencies(self):
        token = "0x" + "aa" * 20
        findings = [_finding("Unlock", ("Reentrancy",)), _finding("Drain", ("Fund Loss",))]
        findings[0]["plan"]["steps"] = [self._step(token, "0x23b872dd", calldata="0x23b872dd" + "00" * 96)]
        findings[1]["plan"]["steps"] = [self._step(token, "0x095ea7b3", calldata="0x095ea7b3" + "11" * 64)]
        plan = strategy_layer.compose_plan(findings, composed_caller="0x" + "44" * 20)
        sels = [s["fn_selector"] for s in plan["steps"]]
        self.assertLess(sels.index("0x095ea7b3"), sels.index("0x23b872dd"),
                        "compose_plan must put the approve before the transferFrom it authorizes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
