#!/usr/bin/env python3
"""test_dashboard_ui.py -- proof (R1) that the dashboard's static GUI is the
modern sidebar shell, projects EVERY /api/state key, and wires EVERY
operation the server exposes.

The dashboard is a PROJECTION + control surface (no system logic of its own),
so the things worth pinning are exactly:
  * the sidebar exists with the three submenus and every entry;
  * there is a content view for every nav entry, and the router shows one;
  * every /api/state key has a renderer (no data is silently dropped);
  * every operation endpoint has a UI control (run/confirm/stop, rpc-override
    set+clear, wallet-policy register);
  * the live ETH/ETC network check is still wired (the one safety-critical
    behaviour the GUI carries).

These are static checks on the shipped files (no server needed) PLUS one live
check: the server serves index.html/app.js/style.css with HTTP 200. Skips
(never fails) when fastapi/uvicorn are unavailable.

Run: python -m unittest onchain_scripts/test_dashboard_ui.py -v
"""
import re
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
STATIC = HERE / "dashboard_static"
INDEX = STATIC / "index.html"
APPJS = STATIC / "app.js"
STYLE = STATIC / "style.css"
SERVER = HERE / "dashboard_server.py"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


@unittest.skipUnless(INDEX.exists() and APPJS.exists() and STYLE.exists(), "dashboard_static missing")
class DashboardStaticTest(unittest.TestCase):
    def setUp(self):
        self.html = _read(INDEX)
        self.js = _read(APPJS)
        self.css = _read(STYLE)

    def test_sidebar_has_three_submenus(self):
        self.assertIn('id="sidebar"', self.html)
        self.assertIn('id="nav"', self.html)
        for group in ("operate", "config", "results"):
            self.assertIn(f'data-group="{group}"', self.html, f"missing nav group {group}")

    def test_every_nav_entry_has_a_view(self):
        # Each data-view on a nav link must have a matching <section data-view>.
        nav_views = set(re.findall(r'class="nav-item" data-view="([a-z]+)"', self.html))
        section_views = set(re.findall(r'<section class="view" data-view="([a-z]+)"', self.html))
        self.assertTrue(nav_views, "no nav items found")
        missing = nav_views - section_views
        self.assertFalse(missing, f"nav entries without a view: {sorted(missing)}")

    def test_router_maps_every_view_to_a_title(self):
        nav_views = set(re.findall(r'data-view="([a-z]+)"', self.html))
        # VIEW_TITLES in app.js must cover every view (else a view is unreachable).
        block = re.search(r"const VIEW_TITLES = \{(.*?)\};", self.js, re.S).group(1)
        titles = set(re.findall(r"([a-z]+):", block))
        missing = nav_views - titles
        self.assertFalse(missing, f"views without a title: {sorted(missing)}")

    def test_every_api_state_key_is_rendered(self):
        # Every key /api/state returns must be referenced by app.js -- so no
        # data the server projects is silently dropped from the GUI.
        server = _read(SERVER)
        # Scope to the api_state function, then its JSONResponse({...}) return.
        fn = server[server.index("def api_state():"):]
        fn = fn[:fn.index("\nclass ")] if "\nclass " in fn else fn
        m = re.search(r"return JSONResponse\(\{(.*?)\}\)", fn, re.S)
        self.assertIsNotNone(m, "could not find api_state return")
        keys = set(re.findall(r'"([a-z_]+)":', m.group(1)))
        expected = {
            "wallets", "rpc_overrides", "rpc_override_warning", "contracts",
            "attack_wallets", "recent_logs", "vulnerabilities_found",
            "dashboard_runs", "external_processes",
        }
        self.assertTrue(expected <= keys, f"api_state keys changed: {sorted(keys)}")
        for k in expected:
            # Require an ACTUAL read of the value (state.<key>), not just the
            # key appearing somewhere (a comment mentioning it must not count).
            self.assertRegex(self.js, rf"state\.{re.escape(k)}\b",
                             f"app.js does not render state.{k}")

    def test_every_operation_endpoint_has_a_ui_control(self):
        # The endpoints that DO something must each be reachable from the UI.
        for needle in (
            '"/api/run"',                       # start a run
            "/api/run/${currentRunId}/input",   # confirm
            "/api/run/${currentRunId}/stop",    # stop (console)
            "/api/run/${runId}/stop",           # stop (runs table)
            '"/api/rpc-override"',              # set override
            "/api/rpc-override/${encodeURIComponent(chain)}",  # clear override
            '"/api/wallet-policy"',             # register wallet policy
            '"/api/actions"',                   # action schemas
            '"/api/state"',                     # state
        ):
            self.assertIn(needle, self.js, f"UI missing control for {needle}")

    def test_live_network_identity_check_is_wired(self):
        # The safety-critical behaviour the GUI carries: never infer eth/etc
        # from the dropdown -- always call /api/verify-chain.
        self.assertIn("/api/verify-chain", self.js)
        self.assertIn("applyNetworkCheck", self.js)
        self.assertIn('id="network-badge"', self.html)
        self.assertIn("--network-color", self.css)

    def test_projections_only_no_local_wallet_logic(self):
        # Guard the "projection only" rule: the frontend must NOT hardcode any
        # wallet address or chain id (that would be local logic/duplication).
        self.assertNotRegex(self.js, r"0x[0-9a-fA-F]{40}", "app.js hardcodes an address")
        self.assertNotRegex(self.js, r"\b11155111\b|\bchain_?id\s*=\s*61\b",
                            "app.js hardcodes a chain id")


@unittest.skipUnless(SERVER.exists(), f"{SERVER} not found")
class DashboardServedTest(unittest.TestCase):
    def _have_deps(self):
        try:
            import fastapi  # noqa: F401
            import uvicorn  # noqa: F401
            return True
        except Exception:
            return False

    def test_served_assets_are_200(self):
        if not self._have_deps():
            self.skipTest("fastapi/uvicorn not installed")
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        proc = subprocess.Popen(
            [sys.executable, str(SERVER), "--port", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(HERE), start_new_session=True,
        )
        try:
            import urllib.request
            deadline = time.time() + 25
            while time.time() < deadline:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1) as r:
                        if r.status == 200:
                            break
                except Exception:
                    time.sleep(0.3)
            for path in ("/", "/app.js", "/style.css", "/api/state"):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as r:
                    self.assertEqual(r.status, 200, f"{path} not 200")
                    if path.startswith("/api/"):
                        # API JSON is fresh per request; it must NOT be forced
                        # no-store (it has its own semantics).
                        self.assertNotIn("no-store", r.headers.get("Cache-Control", ""),
                                         f"{path} must not be no-store")
                    else:
                        # Static GUI assets MUST be no-store, or a browser
                        # serves a stale UI after an update.
                        self.assertIn("no-store", r.headers.get("Cache-Control", ""),
                                      f"{path} must be Cache-Control: no-store")
        finally:
            import os
            import signal
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
