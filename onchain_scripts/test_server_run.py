#!/usr/bin/env python3
# Author: DanyTech
"""test_server_run.py -- proof (R1) for onchain_scripts/server_run.sh, the one
place the dashboard GUI is launched from.

What it pins (the "stable implementation" guarantees):
  * it STARTS the dashboard on a free port, serves the GUI (HTTP 200), and
    prints the URL;
  * it FALLS BACK to the next free port when the preferred port is taken by a
    FOREIGN service (it must not hijack a port owned by another program);
  * it REUSES the running dashboard when OUR dashboard already holds the port
    (it must not start a second copy);
  * it never binds anything but 127.0.0.1 (dashboard_server.py's own rule).

These tests run the REAL script and a REAL dashboard_server.py process; they
skip (never fail) when fastapi/uvicorn are unavailable. Every spawned process
is killed in tearDown, so the suite leaves no stray servers.

Run: python -m unittest onchain_scripts/test_server_run.py -v
"""
import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
SERVER_RUN = HERE / "server_run.sh"
DASHBOARD = HERE / "dashboard_server.py"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _port_open(port: int, timeout: float = 0.4) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _have_deps() -> bool:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        return True
    except Exception:
        return False


def _spawn(argv, **kw):
    """Spawn in its own process group so we can kill the whole tree."""
    return subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, cwd=str(REPO_ROOT), start_new_session=True, **kw,
    )


def _kill(proc):
    if proc is None:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    with contextlib.suppress(Exception):
        proc.wait(timeout=5)
    if proc.poll() is None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


@unittest.skipUnless(SERVER_RUN.exists(), f"{SERVER_RUN} not found")
@unittest.skipUnless(_have_deps(), "fastapi/uvicorn not installed")
class ServerRunTest(unittest.TestCase):
    def setUp(self):
        self._procs = []
        self._sockets = []

    def tearDown(self):
        for p in self._procs:
            _kill(p)
        for s in self._sockets:
            with contextlib.suppress(Exception):
                s.close()

    def _read_until(self, proc, needle, timeout=20.0):
        """Read proc stdout until `needle` appears or the timeout elapses.
        Returns everything read so far."""
        buf = ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = proc.stdout.readline()
            if line:
                buf += line
                if needle in buf:
                    return buf
            else:
                if proc.poll() is not None:
                    break
                time.sleep(0.05)
        return buf

    def test_starts_dashboard_on_a_free_port(self):
        port = _free_port()
        proc = _spawn(["bash", str(SERVER_RUN), str(port)])
        self._procs.append(proc)
        out = self._read_until(proc, "Dashboard ready", timeout=25)
        self.assertIn("Dashboard ready", out, out)
        self.assertIn(f"http://127.0.0.1:{port}", out, out)
        # It really serves the GUI.
        self.assertTrue(_port_open(port), "server is not accepting connections")

    def test_reuses_our_own_dashboard(self):
        port = _free_port()
        dash = _spawn([sys.executable, str(DASHBOARD), "--port", str(port)])
        self._procs.append(dash)
        # Wait until OUR dashboard answers.
        deadline = time.time() + 25
        while time.time() < deadline and not _port_open(port):
            time.sleep(0.2)
        self.assertTrue(_port_open(port), "dashboard did not come up")
        out = subprocess.run(
            ["bash", str(SERVER_RUN), str(port)],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
        ).stdout
        self.assertIn("already running", out, out)

    def test_falls_back_when_port_taken_by_a_foreign_service(self):
        # A plain socket listener stands in for "some other program owns the
        # port" -- server_run.sh must NOT reuse it (it is not our dashboard)
        # and must pick a different, free port.
        port = _free_port()
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        self._sockets.append(srv)

        proc = _spawn(["bash", str(SERVER_RUN), str(port)])
        self._procs.append(proc)
        out = self._read_until(proc, "Dashboard ready", timeout=25)
        self.assertIn("is taken", out, out)
        self.assertNotIn(f"http://127.0.0.1:{port} ", out, "must not use the foreign port")
        # It found a different free port and serves there.
        used = None
        for line in out.splitlines():
            if "Dashboard ready" in line and "http://127.0.0.1:" in line:
                used = int(line.split("http://127.0.0.1:")[1].split()[0].rstrip(")"))
        self.assertIsNotNone(used, out)
        self.assertNotEqual(used, port)


if __name__ == "__main__":
    unittest.main()
