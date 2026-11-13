#!/usr/bin/env python3
# Author: DanyTech
"""test_auto_setup.py -- end-to-end proof for `--auto-setup`
(src/evm/auto_setup.rs).

`setup.json` must normally be hand-written, and the `--target 0x...` path has
no fixture directory to read one from at all. `--auto-setup` derives the
mechanical wiring calls (`setX(address)` links between deployed contracts)
directly from the deployed contract set. This test proves it against the real
release binary (no mocks) using the erc4626 fixture, whose ONLY precondition
is exactly such a wiring call (`Vault.setAsset(Asset)`).

The fixture is copied to a temp dir WITHOUT its `setup.json`, so the wiring
cannot be coming from a file -- it must have been derived.

Skips (does not fail) when the release binary is absent.

Run: python -m unittest onchain_scripts/test_auto_setup.py -v
"""
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.path.join(REPO_ROOT, "target", "release", "forksploit")
SRC_FIXTURE = os.path.join(REPO_ROOT, "tests", "evm", "erc4626")


def _stage_fixture_without_setup(tmpdir):
    """Copy only the compiled artifacts (.bin/.abi), never setup.json."""
    for path in glob.glob(os.path.join(SRC_FIXTURE, "*.bin")) + glob.glob(
        os.path.join(SRC_FIXTURE, "*.abi")
    ):
        shutil.copy(path, tmpdir)


def _run(target_glob, extra_args, timeout=90):
    work_dir = tempfile.mkdtemp(prefix="auto_setup_")
    cmd = [BINARY, "evm", "-t", target_glob, "-f", "-w", work_dir, *extra_args]
    try:
        p = subprocess.run(
            cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return p.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b"").decode("utf-8", errors="replace")


@unittest.skipUnless(os.path.exists(BINARY), f"release binary not built at {BINARY}")
class TestAutoSetup(unittest.TestCase):
    def test_derives_the_setasset_wiring_without_a_setup_file(self):
        with tempfile.TemporaryDirectory(prefix="erc4626_nosetup_") as tmpdir:
            _stage_fixture_without_setup(tmpdir)
            self.assertFalse(
                os.path.exists(os.path.join(tmpdir, "setup.json")),
                "the staged fixture must not contain setup.json",
            )
            out = _run(f"{tmpdir}/*", ["--auto-setup"])
            self.assertIn("--auto-setup: derived 1 wiring call(s)", out)
            self.assertIn("setAsset(address)", out)
            # and it must actually have been executed before fuzzing
            self.assertIn("Applied 1 setup.json call(s) before fuzzing", out)

    def test_no_derivation_without_the_flag(self):
        with tempfile.TemporaryDirectory(prefix="erc4626_noflag_") as tmpdir:
            _stage_fixture_without_setup(tmpdir)
            out = _run(f"{tmpdir}/*", [])
            self.assertNotIn("--auto-setup: derived", out)
            self.assertNotIn("Applied 1 setup.json call(s)", out)


if __name__ == "__main__":
    unittest.main()
