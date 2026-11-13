#!/usr/bin/env python3
# Author: DanyTech
"""test_monitor_cli.py -- proof (R1) that `monitor.py`'s argument handling
works when required arguments are missing.

Regression for a real bug: `main()` called `build_parser().parse_args()` and
then `parser.error(...)`, but `parser` was never bound in `main()`'s scope
(it only existed inside `build_parser()`), so running the tool without
`--address`/`--config` raised `NameError: name 'parser' is not defined` --
a Python traceback instead of the intended argparse usage error.

The test drives the REAL script as a subprocess, so it exercises the same
code path a user hits; it needs no network and no wallet (both invocations
exit before any RPC call).

Run: python -m unittest onchain_scripts/test_monitor_cli.py -v
"""
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "monitor.py"


def run_monitor(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
    )


class MonitorCliTest(unittest.TestCase):
    def test_missing_required_args_is_a_clean_usage_error(self):
        proc = run_monitor()
        # argparse exits 2 on a usage error; the point is that it must NOT
        # crash with a traceback first.
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr, "must not raise a Python traceback")
        self.assertNotIn("NameError", proc.stderr, "parser must be bound in main()")
        self.assertIn("either --address", proc.stderr)

    def test_help_exits_zero(self):
        proc = run_monitor("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("usage", proc.stdout.lower())


if __name__ == "__main__":
    unittest.main()
