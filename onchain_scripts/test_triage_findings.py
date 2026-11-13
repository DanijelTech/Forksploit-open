#!/usr/bin/env python3
"""test_triage_findings.py -- the triage layer must collapse duplicate plans
into distinct surfaces and classify each surface's viability from the plan's
own metadata, without touching a network or a chain.

Run: python -m unittest onchain_scripts/test_triage_findings.py -v
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import triage_findings as tf  # noqa: E402

UINT32_MAX = 0xFFFFFFFF


def _step(contract="0x" + "aa" * 20, selector="0xdeadbeef", leak=UINT32_MAX):
    return {
        "contract": contract,
        "calldata": "deadbeef",
        "value": "0",
        "caller": "0x" + "11" * 20,
        "fn_selector": selector,
        "stolen_asset": None,
        "call_leak": leak,
    }


def _plan(name, steps, kind="flat", **meta):
    plan = {
        "contract_name": name,
        "kind": kind,
        "needs_funding": False,
        "total_value": "0",
        "steps": steps,
        "repeat_step": None,
        "target": "0x" + "cc" * 20,
        "chain": "etc",
        **meta,
    }
    return plan


def _write_work(tmp, plans):
    vuln = Path(tmp) / "vulnerabilities"
    vuln.mkdir(parents=True, exist_ok=True)
    for i, plan in enumerate(plans):
        (vuln / f"{plan['contract_name']}_{i}.plan.json").write_text(json.dumps(plan))
    return Path(tmp)


class ClassifyTest(unittest.TestCase):
    def test_runnable_confirmed_replayable_single_caller(self):
        finding = {
            "plan": _plan("C", [_step()]),
            "bug_types": {"Fund Loss"},
            "confirmed_exploitable": True, "atomic_replayable": True,
            "distinct_callers": 1, "kind": "flat",
        }
        tier, _ = tf.classify(finding)
        self.assertEqual(tier, tf.RUNNABLE)

    def test_control_leak_needs_materialization(self):
        finding = {
            "plan": _plan("C", [_step(leak=7)]),
            "bug_types": {"Fund Loss"},
            "confirmed_exploitable": True, "atomic_replayable": False,
            "distinct_callers": 1, "kind": "flat",
        }
        tier, detail = tf.classify(finding)
        self.assertEqual(tier, tf.NEEDS_MATERIALIZATION)
        self.assertIn("faked call return", detail)

    def test_multi_caller_needs_multi_sender(self):
        finding = {
            "plan": _plan("C", [_step()]),
            "bug_types": {"Fund Loss"},
            "confirmed_exploitable": True, "atomic_replayable": True,
            "distinct_callers": 2, "kind": "flat",
        }
        tier, _ = tf.classify(finding)
        self.assertEqual(tier, tf.NEEDS_MULTI_SENDER)

    def test_review_tier_is_heuristic_only(self):
        finding = {
            "plan": _plan("C", [_step()]),
            "bug_types": {"Stale Guard Counter"},
            "confirmed_exploitable": False, "atomic_replayable": True,
            "distinct_callers": 1, "kind": "flat",
        }
        tier, _ = tf.classify(finding)
        self.assertEqual(tier, tf.HEURISTIC_ONLY)

    def test_reentrancy_is_not_demoted_to_heuristic(self):
        finding = {
            "plan": _plan("C", [_step()], kind="reentrancy"),
            "bug_types": {"Reentrancy"},
            "confirmed_exploitable": False, "atomic_replayable": True,
            "distinct_callers": 1, "kind": "reentrancy",
        }
        tier, _ = tf.classify(finding)
        self.assertNotEqual(tier, tf.HEURISTIC_ONLY)


class LeakedStepsTest(unittest.TestCase):
    def test_neutral_leak_is_not_reported(self):
        plan = _plan("C", [_step(leak=UINT32_MAX)])
        self.assertEqual(tf._leaked_steps(plan), [])

    def test_non_neutral_leak_reports_contract_and_selector(self):
        plan = _plan("C", [_step(contract="0x" + "dd" * 20, selector="0x12345678", leak=3)])
        leaked = tf._leaked_steps(plan)
        self.assertEqual(len(leaked), 1)
        self.assertEqual(leaked[0]["fn_selector"], "0x12345678")
        self.assertEqual(leaked[0]["index"], 0)


class DedupTest(unittest.TestCase):
    def test_duplicate_plans_collapse_to_one_surface(self):
        # Same target, same bug, same selector, same leak profile -> one surface.
        plans = [
            _plan("Cdup", [_step(selector="0xaaaaaaa1", leak=5)],
                  bug_types=["Fund Loss"], confirmed_exploitable=True,
                  atomic_replayable=False, distinct_callers=1, step_count=1),
            _plan("Cdup", [_step(selector="0xaaaaaaa1", leak=5)],
                  bug_types=["Fund Loss"], confirmed_exploitable=True,
                  atomic_replayable=False, distinct_callers=1, step_count=1),
            _plan("Cdup", [_step(selector="0xaaaaaaa1", leak=5)],
                  bug_types=["Fund Loss"], confirmed_exploitable=True,
                  atomic_replayable=False, distinct_callers=1, step_count=1),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            report = tf.triage([_write_work(tmp, plans)])
        self.assertEqual(report["total_plans"], 3)
        self.assertEqual(report["distinct_surfaces"], 1)
        entry = report["by_tier"][tf.NEEDS_MATERIALIZATION][0]
        self.assertEqual(entry["duplicate_plans"], 3)

    def test_different_surfaces_stay_separate(self):
        plans = [
            _plan("Ca", [_step(selector="0xaaaaaaa1")], bug_types=["Fund Loss"],
                  confirmed_exploitable=True, atomic_replayable=True, distinct_callers=1, step_count=1),
            _plan("Cb", [_step(selector="0xbbbbbbb2")], bug_types=["Fund Loss"],
                  confirmed_exploitable=True, atomic_replayable=True, distinct_callers=1, step_count=1),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            report = tf.triage([_write_work(tmp, plans)])
        self.assertEqual(report["distinct_surfaces"], 2)

    def test_surface_keeps_most_actionable_tier(self):
        # One runnable plan + one leaky duplicate of the same surface: the
        # surface must report RUNNABLE, not NEEDS_MATERIALIZATION.
        base = dict(bug_types=["Fund Loss"], confirmed_exploitable=True, step_count=1)
        plans = [
            _plan("Cs", [_step(selector="0xccccccc3")], atomic_replayable=False,
                  distinct_callers=1, **base),
            _plan("Cs", [_step(selector="0xccccccc3")], atomic_replayable=True,
                  distinct_callers=1, **base),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            report = tf.triage([_write_work(tmp, plans)])
        self.assertEqual(report["distinct_surfaces"], 1)
        self.assertEqual(len(report["by_tier"][tf.RUNNABLE]), 1)


if __name__ == "__main__":
    unittest.main()
