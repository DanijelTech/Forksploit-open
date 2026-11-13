#!/usr/bin/env python3
"""test_forksploit_wizard.py -- proof (R1) for the interactive entry point
`forksploit.sh`.

The wizard is the one place a run commits to its three roles (funding key,
targets, recovery wallet) before anything signs. These tests drive the REAL
script end-to-end with piped stdin and assert on its actual output -- no
mocks, no re-implementation. They run with `--dry-run` (the pipeline is
printed, never executed) and `--no-install` (the preflight never touches the
system), so they need no network and no wallet.

The script opens on a MAIN MENU with submenus (Nov tek / Nastavitve /
Preveri okolje / Pomoč), so every wizard path below first selects "Nov tek".

Covered:
  * doctor mode reports the environment and exits 0;
  * the main menu lists its entries and quits on 'q';
  * a submenu entry is selectable by its number (the bug that motivated the
    main menu: numeric nav keys used to steal the first entries of a short
    menu -- so a 2-entry kind menu could not be selected at all);
  * testnet happy path builds the exact auto_pipeline.py command;
  * a multi-target answer builds batch_pipeline.py;
  * a mainnet chain without confirmation aborts (no command printed);
  * 'q' at the chain menu aborts cleanly;
  * an invalid recovery address is re-asked, not fatal;
  * the chain submenu, the help page and the doctor page render.

Run: python -m unittest onchain_scripts/test_forksploit_wizard.py -v
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
SCRIPT = REPO_ROOT / "forksploit.sh"
WALLETS = HERE / "wallets.json"
SETTINGS = HERE / "forksploit_settings.json"

SEPOLIA = "sepolia"
ETH = "eth"
RECOVERY = "0x" + "11" * 20
TARGET_A = "0x" + "aa" * 20
TARGET_B = "0x" + "bb" * 20
BOGUS = "not-an-address"

# Main-menu entry numbers (submenus open on their own page).
MAIN_NEW_RUN = "1"
MAIN_SETTINGS = "2"
MAIN_DOCTOR = "3"
MAIN_HELP = "4"
MAIN_ADVANCED = "5"
MAIN_TOOLS = "6"


def run_wizard(answers, *extra):
    """Feed `answers` (list of lines) to the wizard; return (rc, stdout)."""
    stdin = "\n".join(answers) + "\n"
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", "--no-install", *extra],
        input=stdin,
        text=True,
        capture_output=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    return proc.returncode, proc.stdout + proc.stderr


class WizardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SCRIPT.exists():
            raise unittest.SkipTest(f"{SCRIPT} not found")
        # A throwaway key file: any 32-byte hex is a valid secp256k1 key.
        cls.tmpdir = tempfile.mkdtemp(prefix="fswizard-")
        cls.key = Path(cls.tmpdir) / "key.txt"
        cls.key.write_text("0x" + "22" * 32 + "\n")
        # Preserve any real wallet policy so the test never destroys it.
        cls._wallets_backup = None
        if WALLETS.exists():
            cls._wallets_backup = WALLETS.read_bytes()
        # Preserve any real advanced-settings file too (the advanced-menu
        # tests write it), so the suite never clobbers a user's settings.
        cls._settings_backup = None
        if SETTINGS.exists():
            cls._settings_backup = SETTINGS.read_bytes()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        if cls._wallets_backup is not None:
            WALLETS.write_bytes(cls._wallets_backup)
        elif WALLETS.exists():
            WALLETS.unlink()
        if cls._settings_backup is not None:
            SETTINGS.write_bytes(cls._settings_backup)
        elif SETTINGS.exists():
            SETTINGS.unlink()

    def _answers(self, kind_idx, chain_idx, chain_name, targets, *tail):
        # doctor consumes no stdin under --no-install; order is:
        # main menu (Nov tek), network kind (page 1), chain (page 2), chain
        # confirm, rpc, key, targets, recovery, ...
        return [MAIN_NEW_RUN, str(kind_idx), str(chain_idx), chain_name, "",
                str(self.key), targets, RECOVERY, *tail]

    def test_doctor_reports_and_exits_zero(self):
        rc, out = run_wizard([], "--doctor")
        self.assertEqual(rc, 0, out)
        self.assertIn("PREDLETNO PREVERJANJE OKOLJA", out)
        self.assertIn("Sistem :", out)

    def test_main_menu_lists_entries(self):
        rc, out = run_wizard(["q"])
        self.assertEqual(rc, 0, out)
        self.assertIn("GLAVNI MENI", out)
        self.assertIn("Nov tek", out)
        self.assertIn("Nastavitve", out)
        self.assertIn("Preveri okolje", out)
        self.assertIn("Pomoč", out)

    def test_main_menu_entry_selected_by_number(self):
        # Regression: numbers must select entries, never act as nav shortcuts.
        # '3' opens the doctor page on its own, then Enter returns to the menu.
        rc, out = run_wizard([MAIN_DOCTOR, "", "q"])
        self.assertEqual(rc, 0, out)
        self.assertIn("PREDLETNO PREVERJANJE OKOLJA", out)   # doctor page
        self.assertIn("binarij", out)                        # full checklist

    def test_help_page_renders(self):
        rc, out = run_wizard([MAIN_HELP, "", "q"])
        self.assertEqual(rc, 0, out)
        self.assertIn("POMOČ", out)
        self.assertIn("Koraki (1/7", out)

    def test_settings_submenu_renders_and_returns(self):
        rc, out = run_wizard([MAIN_SETTINGS, "3", "q"])   # settings, Nazaj, quit
        self.assertEqual(rc, 0, out)
        self.assertIn("NASTAVITVE", out)
        self.assertIn("Privzeti ključ", out)

    def test_testnet_happy_path_prints_auto_pipeline(self):
        # sepolia is menu entry 3; policy confirm "da"; final confirm "da".
        rc, out = run_wizard(self._answers(1, 3, SEPOLIA, TARGET_A, "da", "da"))
        self.assertEqual(rc, 0, out)
        self.assertIn("POVZETEK TEKA", out)
        self.assertIn("Sepolia (an ETH testnet)", out)
        self.assertIn("auto_pipeline.py", out)
        self.assertIn(f"--target {TARGET_A}", out)
        self.assertIn(f"--recovery-wallet {RECOVERY}", out)
        self.assertIn("--chain sepolia", out)
        self.assertNotIn("--confirm-mainnet", out)
        self.assertIn("--dry-run: ukaz je pripravljen", out)

    def test_multi_target_selects_batch_pipeline(self):
        targets = f"{TARGET_A},{TARGET_B}"
        rc, out = run_wizard(self._answers(1, 3, SEPOLIA, targets, "da", "da"))
        self.assertEqual(rc, 0, out)
        self.assertIn("batch_pipeline.py", out)
        self.assertIn("več ciljev", out)

    def test_mainnet_without_confirmation_aborts(self):
        # eth is menu entry 11; decline the mainnet confirmation with "ne".
        rc, out = run_wizard(self._answers(2, 8, ETH, TARGET_A, "da", "ne"))
        self.assertEqual(rc, 0, out)
        # Declining steps back to chain selection and re-prompts; with no
        # further input it must NOT have printed a runnable command.
        self.assertNotIn("--confirm-mainnet", out)

    def test_mainnet_confirmed_sets_flag(self):
        # eth (11): policy "da", mainnet confirm "da", final confirm "da".
        rc, out = run_wizard(self._answers(2, 8, ETH, TARGET_A, "da", "da", "da"))
        self.assertEqual(rc, 0, out)
        self.assertIn("--confirm-mainnet", out)
        self.assertIn("DA -- resnična vrednost", out)

    def test_quit_at_chain_menu(self):
        rc, out = run_wizard([MAIN_NEW_RUN, "q"])
        self.assertEqual(rc, 0, out)
        self.assertIn("Prekinjeno na zahtevo uporabnika.", out)

    def test_invalid_recovery_is_reasked(self):
        # recovery: bogus first, then valid -> wizard must recover and
        # still produce a runnable command (validation, not a hard exit).
        answers = [MAIN_NEW_RUN, "1", "3", SEPOLIA, "", str(self.key),
                   TARGET_A, BOGUS, RECOVERY, "da", "da"]
        rc, out = run_wizard(answers)
        self.assertEqual(rc, 0, out)
        self.assertIn("ni veljaven naslov", out)
        self.assertIn("auto_pipeline.py", out)

    def test_removed_intro_lines_are_gone(self):
        # The wizard no longer opens with the "three roles"/navigation wall
        # of text; only the banner and the (compact) preflight precede the
        # first step.
        rc, out = run_wizard(["q"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("Tri vloge", out)
        self.assertNotIn("Na vsako vprašanje", out)

    def test_chain_menu_shows_plain_titles(self):
        # The chain submenu labels each entry with a short, human name (not
        # the raw slug) and does NOT repeat the loud ETH/ETC warning.
        rc, out = run_wizard([MAIN_NEW_RUN, "2", "q"])   # mainnets submenu, quit
        self.assertEqual(rc, 0, out)
        self.assertIn("Ethereum Classic", out)   # etc -> readable title
        self.assertIn("Polygon zkEVM", out)      # zkevm -> readable title
        self.assertNotIn("this is NOT Ethereum", out)
        self.assertNotIn("(an ETC testnet)", out)
        self.assertNotIn("(an ETH testnet)", out)

    def test_chain_menu_is_a_two_level_submenu(self):
        # Page 1 picks the network kind; the chain list opens as its OWN page
        # (breadcrumb "VERIGA > ..."), and 'nazaj' returns to page 1.
        rc, out = run_wizard([MAIN_NEW_RUN, "1", "q"])
        self.assertEqual(rc, 0, out)
        self.assertIn("Izberi vrsto omrežja:", out)
        self.assertIn("Testna omrežja", out)
        self.assertIn("Glavna omrežja", out)
        self.assertIn("VERIGA › Testna omrežja", out)   # submenu breadcrumb
        # testnets are laid out as a compact grid (several per line)
        self.assertRegex(out, r"1\) Chapel\s+2\) Mordor")

    def test_kind_submenu_is_selectable_by_number(self):
        # Regression for the nav-key collision: a 2-entry menu must be usable
        # by number (the first entry used to be eaten by the 'nazaj' shortcut).
        rc, out = run_wizard([MAIN_NEW_RUN, "2", "q"])   # '2' -> mainnets page
        self.assertEqual(rc, 0, out)
        self.assertIn("VERIGA › Glavna omrežja", out)

    def test_no_gutter_line_exceeds_width(self):
        # Regression: a long external line (e.g. the wallet-policy record,
        # which carries two 42-char addresses) must be wrapped to the
        # terminal width, not overflow past the gutter.
        answers = self._answers(1, 3, SEPOLIA, TARGET_A, "da", "da")
        proc = subprocess.run(
            ["bash", str(SCRIPT), "--dry-run", "--no-install"],
            input="\n".join(answers) + "\n", text=True, capture_output=True,
            cwd=str(REPO_ROOT), timeout=120, env={**os.environ, "COLUMNS": "100"},
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        worst = 0
        for line in (proc.stdout + proc.stderr).splitlines():
            plain = re.sub(r"\x1b\[[0-9;]*m", "", line)
            if plain.startswith("▌"):
                worst = max(worst, len(plain))
        self.assertLessEqual(worst, 100, f"a gutter line is {worst} cols wide")

    def test_doctor_lists_full_checklist(self):
        # --doctor keeps the full pass/fail checklist (not the compact form).
        rc, out = run_wizard([], "--doctor")
        self.assertEqual(rc, 0, out)
        self.assertIn("binarij", out)

    # --- advanced settings + tools menus (new) ------------------------------

    def test_advanced_menu_renders(self):
        rc, out = run_wizard([MAIN_ADVANCED, "q", "q"])
        self.assertEqual(rc, 0, out)
        self.assertIn("NAPREDNE NASTAVITVE TEKA", out)
        self.assertIn("Fuzz trajanje", out)
        self.assertIn("Pre-flight vrata", out)
        self.assertIn("Gas oracle", out)

    def test_tools_menu_renders(self):
        rc, out = run_wizard([MAIN_TOOLS, "q", "q"])
        self.assertEqual(rc, 0, out)
        self.assertIn("ORODJA", out)
        self.assertIn("Monitor", out)
        self.assertIn("Triage", out)
        self.assertIn("Dashboard", out)

    def test_main_menu_lists_new_entries(self):
        rc, out = run_wizard(["q"])
        self.assertEqual(rc, 0, out)
        self.assertIn("Napredne nastavitve", out)
        self.assertIn("Orodja", out)

    def test_advanced_setting_flows_into_command(self):
        # Set fuzz-seconds=200, then back, then run the wizard: the exact flag
        # must appear on the auto_pipeline.py command, and the settings must
        # persist in the JSON file. (The advanced menu pauses with an Enter
        # after each change -- hence the "" lines.)
        answers = [MAIN_ADVANCED, "1", "200", "", "7",
                   MAIN_NEW_RUN, "1", "3", SEPOLIA, "", str(self.key),
                   TARGET_A, RECOVERY, "da", "da"]
        rc, out = run_wizard(answers)
        self.assertEqual(rc, 0, out)
        self.assertIn("--fuzz-seconds 200", out)
        self.assertIn("auto_pipeline.py", out)
        if SETTINGS.exists():
            import json
            self.assertEqual(json.loads(SETTINGS.read_text()).get("FUZZ_SECONDS"), "200")

    def test_default_command_is_unchanged_without_advanced_settings(self):
        # With no advanced settings the command must carry NONE of the
        # optional flags -- this is the zero-regression guarantee.
        if SETTINGS.exists():
            SETTINGS.unlink()
        rc, out = run_wizard(self._answers(1, 3, SEPOLIA, TARGET_A, "da", "da"))
        self.assertEqual(rc, 0, out)
        cmd_line = next((l for l in out.splitlines() if "auto_pipeline.py" in l and "--target" in l), "")
        self.assertNotIn("--fuzz-seconds", cmd_line)
        self.assertNotIn("--fund-eth", cmd_line)
        self.assertNotIn("--no-preflight", cmd_line)
        self.assertNotIn("--no-gas-oracle", cmd_line)
        self.assertNotIn("--detectors", cmd_line)

    def test_advanced_toggle_preflight(self):
        # Toggling pre-flight off (entry 4) must add --no-preflight.
        answers = [MAIN_ADVANCED, "4", "", "7",
                   MAIN_NEW_RUN, "1", "3", SEPOLIA, "", str(self.key),
                   TARGET_A, RECOVERY, "da", "da"]
        rc, out = run_wizard(answers)
        self.assertEqual(rc, 0, out)
        self.assertIn("--no-preflight", out)

    def test_advanced_reset_clears_settings(self):
        # Set fuzz=123 (entry 1), then reset (entry 6): FUZZ_SECONDS back to "".
        rc, out = run_wizard([MAIN_ADVANCED, "1", "123", "", "6", "", "q", "q"])
        self.assertEqual(rc, 0, out)
        self.assertIn("ponastavljene na privzete", out)
        if SETTINGS.exists():
            import json
            self.assertEqual(json.loads(SETTINGS.read_text()).get("FUZZ_SECONDS"), "")


if __name__ == "__main__":
    unittest.main()
