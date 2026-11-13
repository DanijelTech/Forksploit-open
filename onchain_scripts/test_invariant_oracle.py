#!/usr/bin/env python3
"""test_invariant_oracle.py -- end-to-end proof for the declarative invariant
oracle (src/evm/oracles/invariant.rs).

A user-written invariant is the mechanism that closes the gap where an
economic bug outside the built-in oracle fingerprints is otherwise
unchecked. This test proves the mechanism actually works, in three
scenarios against the real release binary (no mocks):

  POSITIVE  tests/evm/eth_backing/         -- `creditMyself()` credits a
            balance without any real ETH, so the declared invariant
            "sum(balances) <= native balance" MUST fire.
  NEGATIVE  tests/evm_never_pass/invariant_safe/ -- the SAME invariant on a
            correctly-backed bank MUST NOT fire (no false positive).
  PROBE     a deliberately-false invariant on the SAFE fixture MUST fire --
            this rules out the alternative explanation for NEGATIVE ("the
            oracle simply never evaluated anything there"): the same
            fixture, same run path, does evaluate and does fire when the
            declared relationship is actually false.

Skips (does not fail) when the release binary is absent, so it never
blocks a machine that hasn't built the fuzzer.

Run: python -m unittest onchain_scripts/test_invariant_oracle.py -v
"""
import glob
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.path.join(REPO_ROOT, "target", "release", "forksploit")

POSITIVE_DIR = "tests/evm/eth_backing"
NEGATIVE_DIR = "tests/evm_never_pass/invariant_safe"

# A contract whose gate (`require(x * x == secret)`, secret a fixed keccak
# that is not a perfect square) can never be satisfied, so `solved` stays 0.
# This is the regression fixture for the concolic/uninitialized-state false
# positive: raw corpus seeds carry an EMPTY world state, every slot reads 0,
# the gate passes with x == 0, and the concolic solution was reported as a
# `sim-confirmed` violation even though the real transaction reverts.
CONCOLIC_NEGATIVE_DIR = "tests/evm_never_pass/concolic_uninit_state"

# A deliberately-false invariant used only as an "is the oracle evaluating
# here at all?" probe on the NEGATIVE fixture.
PROBE_SPEC = """{ "invariants": [
  { "name": "PROBE: contract must hold no ETH (expected to FIRE)",
    "op": "le",
    "lhs": { "native_balance": true },
    "rhs": { "literal": "0" } }
] }
"""


def _run(fixture_dir, invariants_path, timeout=120, extra_args=(), work_dir=None):
    """Run the fuzzer on `fixture_dir` with `--invariants` and only the
    invariant detector, returning its combined stdout.

    Pass `work_dir` to keep the fuzzer's output directory (so a caller can
    inspect the `*.plan.json` it wrote); otherwise a fresh temp dir is used."""
    if work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="inv_oracle_")
    cmd = [
        BINARY,
        "evm",
        "-t",
        f"{fixture_dir}/*",
        "-f",
        "-d",
        "invariant",
        "--invariants",
        invariants_path,
        "-w",
        work_dir,
        *extra_args,
    ]
    try:
        p = subprocess.run(
            cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return p.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        # A timeout is a legitimate outcome for a NEGATIVE run (nothing to
        # find, so the fuzzer keeps going until the wall clock stops it).
        out = e.stdout or b""
        return out.decode("utf-8", errors="replace")


@unittest.skipUnless(os.path.exists(BINARY), f"release binary not built at {BINARY}")
class TestInvariantOracle(unittest.TestCase):
    def test_positive_fixture_fires(self):
        out = _run(POSITIVE_DIR, f"{POSITIVE_DIR}/invariants.json")
        self.assertIn(
            "Invariant Violation", out,
            "the user invariant should fire on the unbacked 'bank' fixture",
        )
        self.assertIn("sim-confirmed", out)

    def test_invariant_plan_is_confirmed_exploitable(self):
        # Regression for a real bug (the two-list drift): the oracle JSON
        # stamped an Invariant Violation finding `sim-confirmed`, but the
        # emitted plan.json carried `confirmed_exploitable: false` because
        # `is_confirmed_exploitable_bug`'s list omitted "Invariant Violation".
        # `auto_pipeline.py` treats `confirmed_exploitable == false` as a
        # Review-tier heuristic and skips the plan as non-extractable, so
        # EVERY user-declared invariant finding was silently never run.
        #
        # This inspects the REAL plan.json the release binary wrote, so it
        # fails if either half of the fix regresses (the list, or the
        # confidence helper reading the tier off the wrong list).
        import json

        work_dir = tempfile.mkdtemp(prefix="inv_oracle_plan_")
        try:
            out = _run(POSITIVE_DIR, f"{POSITIVE_DIR}/invariants.json", work_dir=work_dir)
            self.assertIn("Invariant Violation", out, "precondition: the invariant must fire")

            plans = glob.glob(os.path.join(work_dir, "vulnerabilities", "*.plan.json"))
            self.assertTrue(plans, "a plan.json must be emitted for the invariant finding")
            with open(plans[0]) as f:
                plan = json.load(f)
            self.assertIn(
                "Invariant Violation", plan.get("bug_types", []),
                "the plan must list the Invariant Violation bug_type",
            )
            self.assertTrue(
                plan.get("confirmed_exploitable"),
                "confirmed_exploitable must be true so auto_pipeline.py does NOT skip "
                "the invariant finding as a non-extractable heuristic",
            )
            self.assertEqual(
                plan.get("confidence"), "sim-confirmed",
                "a clean invariant plan must be sim-confirmed, matching the oracle JSON",
            )
        finally:
            import shutil
            shutil.rmtree(work_dir, ignore_errors=True)

    def test_negative_fixture_does_not_fire(self):
        out = _run(NEGATIVE_DIR, f"{NEGATIVE_DIR}/invariants.json")
        self.assertNotIn(
            "Invariant Violation", out,
            "the same invariant must NOT fire on the correctly-backed bank",
        )

    def test_probe_confirms_the_oracle_evaluates_on_negative_fixture(self):
        # Same fixture as the negative test, but a relationship that IS
        # actually false -- proves the negative result above is a real
        # true-negative, not a silently-never-run oracle.
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write(PROBE_SPEC)
            probe_path = f.name
        try:
            out = _run(NEGATIVE_DIR, probe_path)
            self.assertIn(
                "Invariant Violation", out,
                "the probe invariant must fire, proving the oracle evaluates "
                "on this fixture",
            )
        finally:
            os.unlink(probe_path)

    def test_concolic_on_uninitialized_state_does_not_fire(self):
        # Regression: with `--concolic`, an uninitialized corpus seed (empty
        # world state) must NOT be turned into a `sim-confirmed` violation.
        # Before the fix the concolic stage ran on such seeds, emitted
        # solution testcases that inherited the empty state, and the oracle
        # saw a post-state write (`solved = 1`) that never happens on-chain.
        out = _run(
            CONCOLIC_NEGATIVE_DIR,
            f"{CONCOLIC_NEGATIVE_DIR}/invariants.json",
            extra_args=("--concolic",),
        )
        self.assertNotIn(
            "Invariant Violation", out,
            "concolic must not fabricate a violation from an uninitialized state",
        )

    def test_concolic_still_runs_on_this_fixture(self):
        # Guards the test above from passing vacuously (e.g. concolic silently
        # disabled): the stage must actually have been exercised.
        out = _run(
            CONCOLIC_NEGATIVE_DIR,
            f"{CONCOLIC_NEGATIVE_DIR}/invariants.json",
            extra_args=("--concolic",),
        )
        self.assertIn("concolic: testcase #", out)


def _run_concolic(fixture_dir, timeout=90):
    """Run the fuzzer with `--concolic` on `fixture_dir`, typed_bug detector,
    returning its combined stdout.

    `--concolic-timeout 5000`: solving `y * 2 == LARGE_CONSTANT` needs more
    than the 1000ms default Z3 budget (measured: at 1000ms the solve is
    timing-dependent and often misses; at 5000ms it is deterministic). The
    default stays at 1000 for interactive runs -- this test just gives the
    solver enough headroom to be a reliable proof.
    """
    work_dir = tempfile.mkdtemp(prefix="concolic_retval_")
    cmd = [
        BINARY, "evm", "-t", f"{fixture_dir}/*", "-f", "-d", "typed_bug",
        "--concolic", "--concolic-caller", "--concolic-num-threads", "1",
        "--concolic-timeout", "5000",
        "-w", work_dir,
    ]
    try:
        p = subprocess.run(
            cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return p.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b"").decode("utf-8", errors="replace")


# FAZA 2.5: the gate depends on the RETURN VALUE of an external self-call
# (`this.helper(y)` returns `y * 2`). Before FAZA 2.5 the concolic result of
# a CALL was always concrete, so these gates were unreachable.
CONCOLIC_RETVAL_DIR = "tests/evm/concolic_retval"
CONCOLIC_RETVAL_UNSAT_DIR = "tests/evm_never_pass/concolic_retval_unsat"

# The source map concolic needs lives in `combined.json`, which is gitignored
# (`.gitignore`), so a fresh checkout does NOT have it -- and without it
# `concolic_host.rs`'s need_solve is always false and concolic "solves
# nothing". Regenerate it from the committed `.sol` with the same pinned
# solc the rest of the project uses; skip (never fail) if solc is absent.
def _find_solc():
    pinned = os.path.join(os.path.expanduser("~"), ".svm", "0.8.24", "solc-0.8.24")
    return pinned if os.path.exists(pinned) else "solc"


def _ensure_combined_json(fixture_dir):
    """Return True if `fixture_dir/combined.json` exists or was generated."""
    combined = os.path.join(REPO_ROOT, fixture_dir, "combined.json")
    if os.path.exists(combined):
        return True
    solc = _find_solc()
    # Expand the glob ourselves: subprocess does not run a shell, so a literal
    # "*.sol" argument would reach solc unexpanded and fail.
    sources = sorted(glob.glob(os.path.join(REPO_ROOT, fixture_dir, "*.sol")))
    if not sources:
        return False
    try:
        p = subprocess.run(
            [solc, *sources, "-o", f"{fixture_dir}/", "--bin",
             "--abi", "--overwrite", "--base-path", ".", "--combined-json",
             "bin-runtime,srcmap-runtime"],
            cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return p.returncode == 0 and os.path.exists(combined)


@unittest.skipUnless(os.path.exists(BINARY), f"release binary not built at {BINARY}")
class TestConcolicReturnValue(unittest.TestCase):
    def setUp(self):
        # concolic is a no-op without the source map; build it if the pinned
        # solc is available, otherwise skip rather than report a false negative.
        for d in (CONCOLIC_RETVAL_DIR, CONCOLIC_RETVAL_UNSAT_DIR):
            if not _ensure_combined_json(d):
                self.skipTest(f"solc unavailable and {d}/combined.json missing")

    def test_return_value_gate_is_solved(self):
        # `require(this.helper(y) == EVEN_SECRET)` with `helper` returning
        # `y * 2`: the concolic return-value splice must make `y * 2 ==
        # secret` solvable and fire the typed bug.
        out = _run_concolic(CONCOLIC_RETVAL_DIR)
        self.assertIn(
            "0x3322", out,
            "concolic must solve a gate over a CALL's return value",
        )
        self.assertIn("sim-confirmed", out)

    def test_unsatisfiable_return_gate_does_not_fire(self):
        # `require(this.helper(y) == ODD_SECRET)`: `y * 2` is always even, so
        # no `y` works. A correct concolic must not report it -- this rules
        # out a false positive from guessing a constant return.
        out = _run_concolic(CONCOLIC_RETVAL_UNSAT_DIR, timeout=60)
        self.assertNotIn(
            "0x3322", out,
            "an unsatisfiable return-value gate must not be reported",
        )

    def test_concolic_ran_on_the_unsat_fixture(self):
        # Guards the negative test from passing vacuously.
        out = _run_concolic(CONCOLIC_RETVAL_UNSAT_DIR, timeout=60)
        self.assertIn("concolic: testcase #", out)


if __name__ == "__main__":
    unittest.main()
