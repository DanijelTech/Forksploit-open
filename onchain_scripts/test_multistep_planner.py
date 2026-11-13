#!/usr/bin/env python3
"""test_multistep_planner.py -- end-to-end proof that ForkSploit reaches a
bug that is ONLY reachable through a multi-transaction (setup -> attack)
sequence (BLOCKERS.md B1).

Fixture: tests/evm/two_step/ (contract `TwoStep`):

    arm()   -> stage = 1     (value stays 0; invariant holds)
    fire()  -> require(stage == 1); value = 2   (breaks `value() <= 1`)

A single transaction can NEVER break the invariant: arm() alone leaves value
at 0, and fire() alone reverts because stage is still 0. Only the SEQUENCE
arm() then fire() breaks it. The bug is surfaced by the declarative invariant
oracle (--invariants, P4).

The multi-step capability is real and default: `full_trace` + `print_txn_corpus`
are default Cargo features, so `TxnTrace::from_idx` genealogy is recorded on
every execution (src/fuzzer.rs) and `cov_stage`/`minimizer` replay the sequence
(root -> arm -> fire). This test pins that behaviour with three scenarios
against the real release binary (no mocks):

  POSITIVE  two_step + invariants.json       -> MUST fire; the emitted trace
            MUST contain BOTH `arm()` and `fire()` (a genuine 2-tx sequence).
  NEGATIVE  two_step + invariants_safe.json  -> MUST NOT fire. Same fixture,
            same run path, only the declared bound differs (cap=2): the
            sequence alone is not a bug, so this rules out "it fires on any
            sequence".
  PROBE     two_step + probe_always_false.json -> MUST fire at genesis. This
            proves the NEGATIVE result is a true negative (the oracle does
            evaluate on this fixture), not a silently-never-run check.

Scope / honesty (BLOCKERS.md B1): this proves the existing genealogy-driven
multi-step search works and is measured; it does NOT add an explicit
sequence planner. See LIMITATIONS.md for the measured depth curve (found-rate vs.
sequence length) and the remaining limitation.

Run: python -m unittest onchain_scripts.test_multistep_planner -v
"""
import os
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.path.join(REPO_ROOT, "target", "release", "forksploit")

FIXTURE = "tests/evm/two_step"
POSITIVE_SPEC = f"{FIXTURE}/invariants.json"
NEGATIVE_SPEC = f"{FIXTURE}/invariants_safe.json"
PROBE_SPEC = f"{FIXTURE}/probe_always_false.json"


def _run(invariants_path, timeout=30):
    """Run the fuzzer on the two_step fixture with only the invariant detector,
    returning its combined stdout."""
    work_dir = tempfile.mkdtemp(prefix="multistep_")
    cmd = [
        BINARY,
        "evm",
        "-t",
        f"{FIXTURE}/*",
        "-f",
        "-d",
        "invariant",
        "--invariants",
        invariants_path,
        "-w",
        work_dir,
    ]
    try:
        p = subprocess.run(
            cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return p.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        # A timeout is the expected outcome for the NEGATIVE run (nothing to
        # find, so the fuzzer keeps going until the wall clock stops it).
        return (e.stdout or b"").decode("utf-8", errors="replace")


@unittest.skipUnless(os.path.exists(BINARY), f"release binary not built at {BINARY}")
class TestMultiStepPlanner(unittest.TestCase):
    def test_positive_requires_the_arm_then_fire_sequence(self):
        out = _run(POSITIVE_SPEC)
        self.assertIn(
            "Invariant Violation", out,
            "the 2-step-only bug must be found (arm() then fire())",
        )
        self.assertIn("sim-confirmed", out)
        # The winning trace must be an actual SEQUENCE, not a single tx.
        self.assertIn("arm()", out, "the setup transaction arm() must be in the trace")
        self.assertIn("fire()", out, "the attack transaction fire() must be in the trace")

    def test_negative_same_sequence_is_not_a_bug(self):
        out = _run(NEGATIVE_SPEC)
        self.assertNotIn(
            "Invariant Violation", out,
            "with the correct bound (value<=2) the arm->fire sequence is legal "
            "and must NOT be reported",
        )

    def test_probe_confirms_the_oracle_evaluates_on_this_fixture(self):
        out = _run(PROBE_SPEC)
        self.assertIn(
            "Invariant Violation", out,
            "the always-false probe must fire, proving the NEGATIVE result is a "
            "true negative, not a never-run oracle",
        )


if __name__ == "__main__":
    unittest.main()
