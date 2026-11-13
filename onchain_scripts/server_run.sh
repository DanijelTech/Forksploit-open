#!/usr/bin/env bash
# Author: DanyTech
# server_run.sh -- start the ForkSploit dashboard (the static GUI served by
# dashboard_server.py) and open it in a browser.
#
# This is the ONE place the GUI launch lives. forksploit.sh's "Dashboard"
# entry and its "Materialize" entry both call it, so the launch logic is not
# duplicated in two branches.
#
# Safe to run directly:
#     onchain_scripts/server_run.sh [preferred_port]
#
# Behaviour (all of it deliberate -- this is the "stable" part):
#   * binds 127.0.0.1 ONLY, exactly like dashboard_server.py itself -- the
#     dashboard can read wallet/contract state and launch signing scripts, so
#     it must never be exposed externally;
#   * if the preferred port is already taken by ANOTHER service, it picks the
#     next free port and says so, instead of hijacking or failing;
#   * if the preferred port is taken by THIS dashboard (a previous run), it
#     reuses it and just opens the browser -- never starts a second copy;
#   * starts the server, WAITS until it actually accepts connections, then
#     opens the browser (xdg-open / open / wslview); if none is available it
#     prints the URL so the user can open it by hand;
#   * the URL is always printed; the server runs in the FOREGROUND until
#     Ctrl-C, so the caller (forksploit.sh) blocks exactly like the old
#     inline dashboard launch did.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
PREFERRED="${1:-4114}"
HOST="127.0.0.1"

# Respect an existing .venv, else system python3 (same rule as forksploit.sh).
PYTHON="python3"
[[ -x "$REPO_ROOT/.venv/bin/python3" ]] && PYTHON="$REPO_ROOT/.venv/bin/python3"

if ! "$PYTHON" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
    echo "ERROR: dashboard_server.py needs 'fastapi' and 'uvicorn'." >&2
    echo "Install:  $PYTHON -m pip install -r $HERE/requirements.txt" >&2
    exit 2
fi

if [[ ! -f "$HERE/dashboard_server.py" ]]; then
    echo "ERROR: $HERE/dashboard_server.py does not exist." >&2
    exit 2
fi

# Decide which port to use. One python helper answers all three questions at
# once (is the preferred port free? is the thing on it OUR dashboard? what is
# the next free port?), so the decision lives in exactly one place:
#   reuse <port>  -- our dashboard is already running there -> just open it
#   use <port>    -- start a new server on <port>
#   error         -- no usable port found
DECISION="$("$PYTHON" - "$PREFERRED" <<'PY'
import json, socket, sys, urllib.request

start = int(sys.argv[1])


def is_open(port: int) -> bool:
    s = socket.socket()
    s.settimeout(0.4)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def is_our_dashboard(port: int) -> bool:
    """True only if /api/state answers with our own dashboard's JSON shape.
    A bare 'the port is open' is NOT enough -- some other service could be
    sitting there, and opening the browser at it would be wrong."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=1.5) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        # dashboard_server.py's /api/state always returns these keys (see its
        # api_state(): wallets, rpc_overrides, contracts, attack_wallets, ...).
        return isinstance(data, dict) and {"wallets", "rpc_overrides"} <= set(data)
    except Exception:
        return False


def first_free(port: int):
    for p in range(port, port + 50):
        if not is_open(p):
            return p
    return None


if is_open(start):
    if is_our_dashboard(start):
        print(f"reuse {start}")
    else:
        free = first_free(start + 1)
        print(f"use {free}" if free else "error")
else:
    print(f"use {start}")
PY
)"

case "$DECISION" in
    reuse\ *)
        PORT="${DECISION#reuse }"
        URL="http://$HOST:$PORT"
        echo "Dashboard already running at $URL -- opening the browser."
        ;;
    use\ *)
        PORT="${DECISION#use }"
        URL="http://$HOST:$PORT"
        if [[ "$PORT" != "$PREFERRED" ]]; then
            echo "Port $PREFERRED is taken -- using the free port $PORT."
        fi
        ;;
    *)
        echo "ERROR: no free port number around $PREFERRED (I tried 50 consecutive ones)." >&2
        exit 3
        ;;
esac

open_browser() {
    local url="$1"
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$url" >/dev/null 2>&1 && return 0
    fi
    if command -v open >/dev/null 2>&1; then          # macOS
        open "$url" >/dev/null 2>&1 && return 0
    fi
    if command -v wslview >/dev/null 2>&1; then       # WSL
        wslview "$url" >/dev/null 2>&1 && return 0
    fi
    return 1
}

if [[ "$DECISION" == reuse\ * ]]; then
    open_browser "$URL" || echo "Open manually: $URL"
    exit 0
fi

# A writable log location (logs/ is gitignored; fall back to /tmp).
LOG_DIR="$HERE/logs"
mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR="${TMPDIR:-/tmp}"
LOG="$LOG_DIR/dashboard_${PORT}.log"

echo "Starting the ForkSploit dashboard at $URL ..."
# Run the script directly (no subshell): dashboard_server.py inserts its own
# directory into sys.path, so it works from any cwd, and the PID we keep is
# the real server process (so the trap can stop it).
"$PYTHON" "$HERE/dashboard_server.py" --port "$PORT" >"$LOG" 2>&1 &
SRV_PID=$!

cleanup() { kill "$SRV_PID" 2>/dev/null; }
trap cleanup INT TERM

# Wait (bounded, ~15 s) until the server actually accepts connections.
ready=0
for _ in $(seq 1 75); do
    if "$PYTHON" - "$PORT" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(0.3)
try:
    s.connect(("127.0.0.1", int(sys.argv[1]))); sys.exit(0)
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
    then ready=1; break; fi
    sleep 0.2
done

if (( ! ready )); then
    echo "ERROR: the dashboard did not start within 15 s. Last log lines ($LOG):" >&2
    tail -n 20 "$LOG" >&2 2>/dev/null || true
    cleanup
    exit 4
fi

echo "Dashboard ready: $URL   (local only -- never expose this port externally)"
open_browser "$URL" || echo "(could not open the browser automatically -- open manually: $URL)"
echo "Press Ctrl-C to stop."

# Foreground: block until the server exits or the user presses Ctrl-C.
wait "$SRV_PID"
