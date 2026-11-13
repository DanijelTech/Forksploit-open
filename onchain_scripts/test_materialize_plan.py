#!/usr/bin/env python3
"""Tests for materialize_plan.py -- pure, offline, no chain."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import materialize_plan as mp  # noqa: E402


TARGET = "0x9f5304da62a5408416ea58a17a92611019bd5ce3"


def _plan(target=TARGET, steps=None, chain="etc", bug_types=None, **meta):
    plan = {
        "contract_name": "C",
        "target": target,
        "chain": chain,
        "kind": "flat",
        "steps": steps or [],
        "bug_types": bug_types or [],
        **meta,
    }
    return plan


def _step(sel, leak=0xFFFFFFFF, contract=TARGET):
    return {"contract": contract, "fn_selector": sel, "caller": TARGET, "call_leak": leak}


class SelectorClassify(unittest.TestCase):
    def test_balanceof_is_token_balance(self):
        self.assertEqual(mp.classify_selector("0x70a08231"), mp.TOKEN_BALANCE)

    def test_owner_getter_is_auth_guard(self):
        self.assertEqual(mp.classify_selector("0x893d20e8"), mp.AUTH_GUARD)

    def test_escape_hatch_is_auth_guard(self):
        self.assertEqual(mp.classify_selector("0x1554611f"), mp.AUTH_GUARD)

    def test_proxy_withdraw_is_signature(self):
        self.assertEqual(mp.classify_selector("0xe3ce9714"), mp.SIGNATURE)

    def test_unknown_selector(self):
        self.assertEqual(mp.classify_selector("0xdeadbeef"), mp.UNKNOWN)

    def test_none_selector(self):
        self.assertEqual(mp.classify_selector(None), mp.UNKNOWN)

    def test_case_insensitive(self):
        self.assertEqual(mp.classify_selector("0x70A08231"), mp.TOKEN_BALANCE)

    def test_multisig_confirm_is_auth_guard(self):
        self.assertEqual(mp.classify_selector("0x797af627"), mp.AUTH_GUARD)

    def test_daily_limit_read_is_storage_read(self):
        self.assertEqual(mp.classify_selector("0xf1736d86"), mp.STORAGE_READ)

    def test_get_my_balance_is_token_balance(self):
        self.assertEqual(mp.classify_selector("0x7e3ef7cd"), mp.TOKEN_BALANCE)


class Recipes(unittest.TestCase):
    def test_auth_guard_not_materializable(self):
        _, materializable = mp.RECIPES[mp.AUTH_GUARD]
        self.assertFalse(materializable)

    def test_reentrancy_callback_not_materializable(self):
        _, materializable = mp.RECIPES[mp.REENTRANCY_CALLBACK]
        self.assertFalse(materializable)

    def test_price_oracle_materializable(self):
        recipe, materializable = mp.RECIPES[mp.PRICE_ORACLE]
        self.assertTrue(materializable)
        self.assertIn("swap", recipe)

    def test_every_class_has_a_recipe(self):
        for cls in [
            mp.TOKEN_BALANCE, mp.TOKEN_APPROVE, mp.TOKEN_TRANSFER, mp.NATIVE_WRAP,
            mp.NATIVE_UNWRAP, mp.PRICE_ORACLE, mp.SIGNATURE, mp.STORAGE_READ,
            mp.EXTERNAL_CALL, mp.AUTH_GUARD, mp.REENTRANCY_CALLBACK, mp.UNKNOWN,
        ]:
            self.assertIn(cls, mp.RECIPES, cls)


class LeakedSteps(unittest.TestCase):
    def test_u32max_is_not_a_leak(self):
        plan = _plan(steps=[_step("0x70a08231", leak=0xFFFFFFFF)])
        self.assertEqual(mp.leaked_steps(plan), [])

    def test_zero_leak_is_a_leak(self):
        plan = _plan(steps=[_step("0x70a08231", leak=0)])
        steps = mp.leaked_steps(plan)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["fn_selector"], "0x70a08231")

    def test_missing_field_is_not_a_leak(self):
        plan = _plan(steps=[{"contract": TARGET, "fn_selector": "0x70a08231"}])
        self.assertEqual(mp.leaked_steps(plan), [])


class CallbackDetection(unittest.TestCase):
    def test_leak_into_other_contract_is_callback(self):
        other = "0x1953cab0e5bfa6d4a9bad6e05fd46c1cc6527a5a"
        plan = _plan(steps=[_step("0xa9059cbb", leak=0, contract=other)])
        self.assertTrue(mp.is_callback_leak(plan["steps"][0], plan))

    def test_leak_into_target_is_not_callback(self):
        plan = _plan(steps=[_step("0x70a08231", leak=0)])
        self.assertFalse(mp.is_callback_leak(plan["steps"][0], plan))


class WorklistTierFilter(unittest.TestCase):
    """A Review-tier heuristic surface must NOT appear in the materialization
    worklist, even when it carries a per-step call_leak -- otherwise hundreds
    of unactionable surfaces drown the real NEEDS_MATERIALIZATION ones."""

    def _work(self, tmp, plans):
        import json
        v = Path(tmp) / "vulnerabilities"
        v.mkdir(parents=True, exist_ok=True)
        for i, p in enumerate(plans):
            (v / f"C_{i}.plan.json").write_text(json.dumps(p))
        return Path(tmp)

    def test_heuristic_only_surface_is_excluded(self):
        import tempfile
        # confirmed_exploitable=False + non-reentrancy kind => HEURISTIC_ONLY
        heuristic = _plan(
            steps=[_step("0x02ef6c86", leak=0)],
            bug_types=["Stale Guard Counter"],
        )
        heuristic["confirmed_exploitable"] = False
        confirmed = _plan(
            steps=[_step("0x1554611f", leak=0)],
            bug_types=["Fund Loss"],
        )
        confirmed["confirmed_exploitable"] = True
        confirmed["atomic_replayable"] = False
        with tempfile.TemporaryDirectory() as tmp:
            report = mp.worklist([self._work(tmp, [heuristic, confirmed])])
        selectors = {g["selector"] for g in report["groups"]}
        self.assertIn("0x1554611f", selectors)
        self.assertNotIn("0x02ef6c86", selectors)
        self.assertEqual(report["distinct_surfaces"], 1)


class Lookup(unittest.TestCase):
    """--lookup enriches UNKNOWN groups from 4byte.directory; it must never
    raise, and must leave resolvable-but-unresolved groups untouched."""

    def test_apply_lookup_fills_unknown_group(self):
        report = {"groups": [{
            "leak_class": mp.UNKNOWN, "selector": "0xdeadbeef",
            "recipe": "unclassified", "materializable": False,
        }]}
        orig = mp.lookup_selector
        mp.lookup_selector = lambda s, timeout=8.0: "frobnicate(uint256)"
        try:
            resolved = mp.apply_lookup(report)
        finally:
            mp.lookup_selector = orig
        self.assertEqual(resolved, [{"selector": "0xdeadbeef", "signature": "frobnicate(uint256)"}])
        self.assertEqual(report["groups"][0]["resolved_signature"], "frobnicate(uint256)")

    def test_apply_lookup_skips_known_classes(self):
        report = {"groups": [{
            "leak_class": mp.AUTH_GUARD, "selector": "0x1554611f",
            "recipe": "x", "materializable": False,
        }]}
        called = []
        orig = mp.lookup_selector
        mp.lookup_selector = lambda s, timeout=8.0: called.append(s) or "x()"
        try:
            resolved = mp.apply_lookup(report)
        finally:
            mp.lookup_selector = orig
        self.assertEqual(resolved, [])
        self.assertEqual(called, [])

    def test_lookup_selector_never_raises_on_network_error(self):
        # A malformed/absent selector must return None, not raise.
        self.assertIsNone(mp.lookup_selector(""))
        self.assertIsNone(mp.lookup_selector(None))

    def test_lookup_selector_bad_host_returns_none(self):
        orig = mp.lookup_selector
        # simulate the network layer failing by patching urlopen indirectly:
        # call the real function against a bad selector that 4byte 400s on.
        try:
            r = mp.lookup_selector("0xzzzzzzzz", timeout=3.0)
        except Exception as e:  # pragma: no cover - the point is it must not
            self.fail(f"lookup_selector raised: {e}")
        self.assertIsNone(r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
