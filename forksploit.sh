#!/usr/bin/env bash
# Author: DanyTech
# forksploit.sh -- the one interactive entry point for running ForkSploit's
# full register -> fund -> fuzz -> exploit -> recover pipeline.
#
# UPGRADED v2.0 - Matrix Theme (black, green, dark gray)
# - The "ForkSploit" logo is always shown at the top of every screen
# - Main menu with its own submenus (new run / settings / doctor / help)
# - Framed boxes for data-entry fields
# - Navigation: back (one step), main menu, exit
#
# What this script does, in order, before it touches anything:
#   1. PREFLIGHT ("doctor"): detect the OS, verify the build/runtime
#      prerequisites (Rust toolchain, z3 + pkg-config + clang/cmake, python3
#      + the onchain_scripts requirements, the built binary), and -- only
#      with your explicit confirmation -- install whatever is missing and
#      build the release binary. Nothing is installed silently.
#   2. MAIN MENU: a persistent menu with submenus -- New run (the wizard),
#      Settings (default key / per-chain RPC), Check environment (full
#      doctor report), Help (what the tool does), exit (quit).
#   3. WIZARD: ask the three roles the whole run commits to -- WHO funds
#      (private-key file), WHAT is audited (one or more contracts), WHERE
#      recovered funds go (recovery wallet) -- plus the chain and RPC, with
#      a final read-back summary you confirm before anything signs.
#   4. EXEC: hand off to auto_pipeline.py (one target) or batch_pipeline.py
#      (many), exactly as the old script did.
#
# Navigation: every question accepts "back" (redo the previous step),
# "main menu" (return to main menu), and "exit" (abort cleanly).
# A plain invalid answer re-asks the SAME question or steps back --
# it never kills the script. Only a genuine pipeline failure AFTER the
# wizard (the final exec) still exits hard.
#
# Flags:  --doctor    run the preflight checks and exit (no wizard)
#         --dry-run   run everything, then print the command instead of exec
#         --no-install  preflight only REPORTS what is missing, never
#                       prompts to install anything (safe, non-interactive)
#         -h|--help   this help
#
# Usage: ./forksploit.sh [--doctor|--dry-run] [--no-install]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$HERE"
SCRIPTS_DIR="$HERE/onchain_scripts"
REQ_FILE="$SCRIPTS_DIR/requirements.txt"
BIN="$REPO_ROOT/target/release/forksploit"
DEFAULT_KEY="$SCRIPTS_DIR/key.txt"
SETTINGS_FILE="$SCRIPTS_DIR/forksploit_settings.json"

# Advanced run settings (persisted in $SETTINGS_FILE; empty = omit the flag,
# so the pipeline's own default applies). These map 1:1 onto REAL flags of
# auto_pipeline.py / batch_pipeline.py -- never invented options.
FUZZ_SECONDS=""
DETECTORS=""
FUND_ETH=""
NO_PREFLIGHT=0
NO_GAS_ORACLE=0

DRY_RUN=0
DOCTOR_ONLY=0
NO_INSTALL=0
CHECK_FULL=0        # set while rendering the standalone doctor page
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --doctor)  DOCTOR_ONLY=1 ;;
        --no-install) NO_INSTALL=1 ;;
        -h|--help) sed -n '3,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'unknown flag: %s (try --help)\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Colours, width and drawing helpers  --  MATRIX THEME
# ---------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_R=$'\033[0m'
    C_B=$'\033[1m'
    C_DIM=$'\033[2m'
    C_ITALIC=$'\033[3m'

    # Matrix green palette
    C_GREEN=$'\033[38;5;46m'       # bright green (primary text)
    C_GRN=$'\033[38;5;118m'        # medium green (success, highlights)
    C_DARK_GREEN=$'\033[38;5;22m'  # dark green (subtle accents)

    # Dark gray palette
    C_GRAY=$'\033[38;5;245m'       # light gray (secondary text)
    C_DGRAY=$'\033[38;5;241m'      # dark gray (borders, frames)
    C_BLACK_BG=$'\033[48;5;235m'   # very dark background

    # Accent colors
    C_RED=$'\033[38;5;196m'        # red
    C_YEL=$'\033[38;5;226m'        # yellow
    C_BLU=$'\033[38;5;45m'         # cyan-blue
    C_CYN=$'\033[38;5;159m'        # light cyan
    C_MAG=$'\033[38;5;205m'        # magenta
    C_GUT=$'\033[38;5;46m'         # green gutter

    # Frame color - matrix green for borders
    C_FRAME="$C_GREEN"
else
    C_R=""; C_B=""; C_DIM=""; C_ITALIC=""
    C_GREEN=""; C_GRN=""; C_DARK_GREEN=""
    C_GRAY=""; C_DGRAY=""; C_BLACK_BG=""
    C_RED=""; C_YEL=""; C_BLU=""; C_CYN=""; C_MAG=""; C_GUT=""
    C_FRAME="$C_CYN"
fi

term_width() {
    local w
    w="$(tput cols 2>/dev/null || echo 80)"
    [[ -z "$w" || "$w" -lt 46 ]] && w=80
    [[ "$w" -gt 100 ]] && w=100
    printf '%s' "$w"
}
W="$(term_width)"

_fill() { printf "%${1}s" '' | sed "s/ /${2}/g"; }
bold()  { printf '%s%s%s\n' "$C_B" "$1" "$C_R"; }
err()   { printf '%s%s%s\n' "$C_RED" "$1" "$C_R" >&2; }
ok()    { printf '%s✓%s %s\n' "$C_GRN" "$C_R" "$1"; }
warn()  { printf '%s!%s %s\n' "$C_YEL" "$C_R" "$1"; }
info()  { printf '%s·%s %s\n' "$C_BLU" "$C_R" "$1"; }
# Same glyphs as ok/warn/info, but WITHOUT the trailing newline, so a result
# can be buffered in an array and printed as one block (see check_env).
ok_s()   { printf '%s✓%s %s' "$C_GRN" "$C_R" "$1"; }
warn_s() { printf '%s!%s %s' "$C_YEL" "$C_R" "$1"; }
info_s() { printf '%s·%s %s' "$C_BLU" "$C_R" "$1"; }

# Box/frame drawing helpers - Matrix style
box_top() {
    local fill
    fill="$(_fill $((W - 2)) '─')"
    printf '%s╔%s%s╗%s\n' "$C_FRAME" "$fill" "$C_FRAME" "$C_R"
}
box_mid() {
    local fill
    fill="$(_fill $((W - 2)) '─')"
    printf '%s╠%s%s╣%s\n' "$C_FRAME" "$fill" "$C_FRAME" "$C_R"
}
box_bot() {
    local fill
    fill="$(_fill $((W - 2)) '─')"
    printf '%s╚%s%s╝%s\n' "$C_FRAME" "$fill" "$C_FRAME" "$C_R"
}

# Print one content line inside the box, padded to the frame width.
box_line() {
    local text="$1" plain len pad max
    plain="$(printf '%s' "$text" | sed 's/\x1b\[[0-9;]*m//g')"
    len=${#plain}
    max=$(( W - 4 ))
    if (( len > max )); then
        text="${plain:0:$((max - 1))}…"
        len=$(( max ))
    fi
    pad=$(( W - 4 - len ))
    (( pad < 0 )) && pad=0
    printf '%s│%s %s%s %s│%s\n' "$C_FRAME" "$C_R" "$text" "$(_fill "$pad" ' ')" "$C_FRAME" "$C_R"
}
box_blank() { box_line ""; }

# Input field with frame borders - Matrix style
input_field_top() {
    local label="$1"
    local fill
    fill="$(_fill $((W - 4)) '─')"
    printf '%s║%s %s %s%s%s ║%s\n' "$C_FRAME" "$C_GREEN" "$label" "$C_DIM" "$fill" "$C_GREEN" "$C_R"
}
input_field() {
    local label="$1" value="$2"
    printf '%s║%s  %s: %s%s%s  ║%s\n' "$C_FRAME" "$C_GRAY" "$label" "$C_GREEN" "$value" "$C_GRAY" "$C_R"
}
input_field_bottom() {
    printf '%s╚%s%s╝%s\n' "$C_FRAME" "$(_fill $((W - 4)) '─')" "$C_FRAME" "$C_R"
}

# A light one-column gutter for questions inside the wizard. A line that fits
# is printed verbatim (its own indentation and spacing preserved); only a line
# too long for the terminal is hard-wrapped on spaces, so prose can never
# overflow the line or overlap the next one. A coloured value (e.g. a wallet)
# is measured with its colour codes stripped, so the wrap point stays correct.
gut_wrap() { # gut_wrap <ansi-prefix> <ansi-suffix> <text>
    local pre="$1" post="$2" text="$3"
    local width=$(( W - 2 ))
    local plain; plain="$(printf '%s' "$text" | sed 's/\x1b\[[0-9;]*m//g')"
    if (( ${#plain} <= width )); then
        printf '%s▌%s %s%s%s\n' "$C_GUT" "$C_R" "$pre" "$text" "$post"
        return
    fi
    local indent=""
    if [[ "$text" =~ ^([[:space:]]+) ]]; then indent="${BASH_REMATCH[1]}"; fi
    local line="" plain_line="" word plain_word
    local -a words
    read -ra words <<< "$text"
    if (( ${#words[@]} == 0 )); then
        printf '%s▌%s\n' "$C_GUT" "$C_R"; return
    fi
    for word in "${words[@]}"; do
        plain_word="$(printf '%s' "$word" | sed 's/\x1b\[[0-9;]*m//g')"
        if [[ -z "$plain_line" ]]; then
            line="${indent}${word}"; plain_line="${indent}${plain_word}"
        elif (( ${#plain_line} + 1 + ${#plain_word} <= width )); then
            line="$line $word"; plain_line="$plain_line $plain_word"
        else
            printf '%s▌%s %s%s%s\n' "$C_GUT" "$C_R" "$pre" "$line" "$post"
            line="${indent}${word}"; plain_line="${indent}${plain_word}"
        fi
    done
    printf '%s▌%s %s%s%s\n' "$C_GUT" "$C_R" "$pre" "$line" "$post"
}
# Single gutter line, truncated (never wrapped) so a fixed-width list row --
# a menu entry with its indent and padding -- keeps its alignment.
gut_fit() {
    local text="$1" plain max
    plain="$(printf '%s' "$text" | sed 's/\x1b\[[0-9;]*m//g')"
    max=$(( W - 2 ))
    if (( ${#plain} > max )); then text="${plain:0:$((max - 1))}…"; fi
    printf '%s▌%s %s\n' "$C_GUT" "$C_R" "$text"
}
gut()  { gut_wrap "" "" "$1"; }
gutb() { gut_wrap "$C_B" "$C_R" "$1"; }
gutc() { gut_wrap "$C_DIM" "$C_R" "$1"; }
# gut_block <indent> -- wrap every stdin line to the terminal width, keeping
# the given indent (used for multi-line tool output echoed back to the user).
gut_block() {
    local __ind="$1" __l
    while IFS= read -r __l; do gut_wrap "" "" "${__ind}${__l}"; done
}

# Open a fresh page (used when a menu leads to a submenu)
new_page() {
    if [[ -t 1 ]]; then printf '\033[2J\033[3J\033[H'; else printf '\n'; fi
}
matrix_logo() {
    box_top
    box_line ""
    box_line "  ${C_GREEN}${C_B}███████╗ ██████╗ ██████╗ ██╗  ██╗${C_R}"
    box_line "  ${C_GREEN}${C_B}██╔════╝██╔═══██╗██╔══██╗██║ ██╔╝${C_R}"
    box_line "  ${C_GREEN}${C_B}█████╗  ██║   ██║██████╔╝█████╔╝ ${C_R}"
    box_line "  ${C_GREEN}${C_B}██╔══╝  ██║   ██║██╔══██╗██╔═██╗ ${C_R}"
    box_line "  ${C_GREEN}${C_B}██║     ╚██████╔╝██║  ██║██║  ██╗${C_R}"
    box_line "  ${C_GREEN}${C_B}╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝${C_R}"
    box_line "  ${C_GREEN}${C_B}FORKSPLOIT${C_R}  ${C_GRAY}· on-chain audit + exploit pipeline${C_R}"
    box_line ""
    local tagline="ForkSploit Matrix v2.0"
    local tag_len=${#tagline}
    local left_pad=$(( (W - 4 - tag_len) / 2 ))
    local right_pad=$(( W - 4 - tag_len - left_pad ))
    printf '%s║%s%s%s %s ║%s\n' "$C_FRAME" "$(_fill $left_pad ' ')" "$C_DIM" "$tagline" "$(_fill $right_pad ' ')" "$C_R"
    box_line ""
    box_bot
}

# ---------------------------------------------------------------------------
# OS detection and package-manager helpers
# ---------------------------------------------------------------------------
OS_ID="unknown"; OS_LIKE=""; OS_NAME="$(uname -s)"; PKG_MGR=""
detect_os() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        OS_ID="darwin"; OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null)"
        PKG_MGR="brew"; return
    fi
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-unknown}"; OS_LIKE="${ID_LIKE:-}"; OS_NAME="${PRETTY_NAME:-$OS_ID}"
    fi
    case "$OS_ID $OS_LIKE" in
        *debian*|*ubuntu*) PKG_MGR="apt" ;;
        *fedora*|*rhel*|*centos*|*rocky*|*alma*) PKG_MGR="dnf" ;;
        *arch*|*manjaro*) PKG_MGR="pacman" ;;
        *suse*|*opensuse*) PKG_MGR="zypper" ;;
        *alpine*) PKG_MGR="apk" ;;
        *) PKG_MGR="" ;;
    esac
}

# Map a logical dependency name to the distro's package name(s).
pkg_name() {
    case "$PKG_MGR:$1" in
        apt:z3) echo "libz3-dev" ;;
        dnf:z3) echo "z3-devel" ;;
        pacman:z3) echo "z3" ;;
        apk:z3) echo "z3-dev" ;;
        brew:z3) echo "z3" ;;
        apt:pkgconfig) echo "pkg-config" ;;
        dnf:pkgconfig) echo "pkgconf-pkg-config" ;;
        pacman:pkgconfig) echo "pkgconf" ;;
        apk:pkgconfig) echo "pkgconf" ;;
        brew:pkgconfig) echo "pkg-config" ;;
        apt:clang) echo "clang" ;;
        dnf:clang) echo "clang" ;;
        pacman:clang) echo "clang" ;;
        apk:clang) echo "clang" ;;
        brew:clang) echo "" ;;
        apt:cmake) echo "cmake" ;;
        dnf:cmake) echo "cmake" ;;
        pacman:cmake) echo "cmake" ;;
        apk:cmake) echo "cmake" ;;
        brew:cmake) echo "cmake" ;;
        apt:buildbase) echo "build-essential" ;;
        dnf:buildbase) echo "gcc gcc-c++ make" ;;
        pacman:buildbase) echo "base-devel" ;;
        apk:buildbase) echo "build-base" ;;
        brew:buildbase) echo "" ;;
        apt:python) echo "python3 python3-pip python3-venv" ;;
        dnf:python) echo "python3 python3-pip" ;;
        pacman:python) echo "python python-pip" ;;
        apk:python) echo "python3 py3-pip" ;;
        brew:python) echo "python" ;;
        apt:git) echo "git" ;;
        dnf:git) echo "git" ;;
        pacman:git) echo "git" ;;
        apk:git) echo "git" ;;
        brew:git) echo "git" ;;
        apt:curl) echo "curl" ;;
        dnf:curl) echo "curl" ;;
        pacman:curl) echo "curl" ;;
        apk:curl) echo "curl" ;;
        brew:curl) echo "curl" ;;
        *) echo "" ;;
    esac
}

pkg_install_cmdline() {
    # Print the exact install command(s) for the given logical packages.
    local names="" l n
    for l in "$@"; do
        n="$(pkg_name "$l")"
        [[ -n "$n" ]] && names="$names $n"
    done
    names="${names# }"
    [[ -z "$names" ]] && return 1
    case "$PKG_MGR" in
        apt)     printf 'sudo apt-get update && sudo apt-get install -y %s' "$names" ;;
        dnf)     printf 'sudo dnf install -y %s' "$names" ;;
        pacman)  printf 'sudo pacman -S --needed --noconfirm %s' "$names" ;;
        zypper)  printf 'sudo zypper install -y %s' "$names" ;;
        apk)     printf 'sudo apk add %s' "$names" ;;
        brew)    printf 'brew install %s' "$names" ;;
        *)       return 1 ;;
    esac
}

pkg_install_run() {
    case "$PKG_MGR" in
        apt)     sudo apt-get update && sudo apt-get install -y "$(pkg_name_list "$@")" ;;
        dnf)     sudo dnf install -y "$(pkg_name_list "$@")" ;;
        pacman)  sudo pacman -S --needed --noconfirm "$(pkg_name_list "$@")" ;;
        zypper)  sudo zypper install -y "$(pkg_name_list "$@")" ;;
        apk)     sudo apk add "$(pkg_name_list "$@")" ;;
        brew)    brew install "$(pkg_name_list "$@")" ;;
        *)       return 1 ;;
    esac
}
pkg_name_list() {
    local l n out=""
    for l in "$@"; do n="$(pkg_name "$l")"; [[ -n "$n" ]] && out="$out $n"; done
    printf '%s' "${out# }"
}

# ---------------------------------------------------------------------------
# Python interpreter selection (respects an existing .venv, else system python3)
# ---------------------------------------------------------------------------
PYTHON="python3"
if [[ -x "$REPO_ROOT/.venv/bin/python3" ]]; then
    PYTHON="$REPO_ROOT/.venv/bin/python3"
fi

# ---------------------------------------------------------------------------
# Persisted advanced settings (Settings -> Advanced settings)
# ---------------------------------------------------------------------------
# A tiny JSON map of the advanced run settings, written/read with python3
# (stdlib json; no jq dependency). All values are strings so the file is
# trivially stable; an empty string means "unset -- omit the flag and let the
# pipeline use its own default". NEVER stores secrets (no keys, no RPC URLs).
load_settings() {
    [[ -f "$SETTINGS_FILE" ]] || return 0
    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            DEFAULT_KEY)    [[ -n "$v" ]] && DEFAULT_KEY="$v" ;;
            FUZZ_SECONDS)   FUZZ_SECONDS="$v" ;;
            DETECTORS)      DETECTORS="$v" ;;
            FUND_ETH)       FUND_ETH="$v" ;;
            NO_PREFLIGHT)   NO_PREFLIGHT="${v:-0}" ;;
            NO_GAS_ORACLE)  NO_GAS_ORACLE="${v:-0}" ;;
        esac
    done < <("$PYTHON" - "$SETTINGS_FILE" <<'PYEOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
if isinstance(d, dict):
    for k in ("DEFAULT_KEY","FUZZ_SECONDS","DETECTORS","FUND_ETH","NO_PREFLIGHT","NO_GAS_ORACLE"):
        if k in d and d[k] is not None:
            print(f"{k}\t{d[k]}")
PYEOF
)
}

save_settings() {
    "$PYTHON" - "$SETTINGS_FILE" \
        "DEFAULT_KEY=$DEFAULT_KEY" "FUZZ_SECONDS=$FUZZ_SECONDS" \
        "DETECTORS=$DETECTORS" "FUND_ETH=$FUND_ETH" \
        "NO_PREFLIGHT=$NO_PREFLIGHT" "NO_GAS_ORACLE=$NO_GAS_ORACLE" <<'PYEOF'
import json, sys
path, pairs = sys.argv[1], sys.argv[2:]
d = {}
for p in pairs:
    k, _, v = p.partition("=")
    d[k] = v
with open(path, "w") as f:
    json.dump(d, f, indent=2, sort_keys=True)
    f.write("\n")
PYEOF
}

# An optional-flag helper: echo the flag only when it is set, so the built
# command is byte-identical to today's when no advanced setting is chosen.
build_advanced_flags() {
    # Sets the global ADVANCED_FLAGS array from the (possibly unset) advanced
    # settings. Only REAL auto_pipeline.py / batch_pipeline.py flags are used.
    ADVANCED_FLAGS=()
    [[ -n "$FUZZ_SECONDS" ]] && ADVANCED_FLAGS+=(--fuzz-seconds "$FUZZ_SECONDS")
    [[ -n "$DETECTORS" ]]    && ADVANCED_FLAGS+=(--detectors "$DETECTORS")
    [[ -n "$FUND_ETH" ]]     && ADVANCED_FLAGS+=(--fund-eth "$FUND_ETH")
    (( NO_PREFLIGHT ))       && ADVANCED_FLAGS+=(--no-preflight)
    (( NO_GAS_ORACLE ))      && ADVANCED_FLAGS+=(--no-gas-oracle)
    return 0
}

# A short human summary of the advanced settings, for the wizard summary page.
advanced_summary() {
    local s=""
    [[ -n "$FUZZ_SECONDS" ]] && s+="fuzz=${FUZZ_SECONDS}s "
    [[ -n "$DETECTORS" ]]    && s+="detectors=${DETECTORS} "
    [[ -n "$FUND_ETH" ]]     && s+="fund=${FUND_ETH}ETH "
    (( NO_PREFLIGHT ))       && s+="no-preflight "
    (( NO_GAS_ORACLE ))      && s+="no-gas-oracle "
    [[ -z "$s" ]] && s="defaults (no extra flags)"
    printf '%s' "$s"
}

py_help() { # py_help <func-name> [args...]
    "$PYTHON" - "$@" <<PYEOF
import sys
sys.path.insert(0, "$SCRIPTS_DIR")
fn = sys.argv[1]
args = sys.argv[2:]
if fn == "banner":
    from chains import chain_banner
    print(chain_banner(args[0]))
elif fn == "rpc":
    from chains import get_rpc_url
    print(get_rpc_url(args[0]))
elif fn == "set_rpc":
    from chains import set_rpc_override
    set_rpc_override(args[0], args[1])
elif fn == "wallet_from_key":
    from eth_account import Account
    print(Account.from_key(open(args[0]).read().strip()).address)
elif fn == "is_testnet":
    from chains import TESTNET_CHAINS
    print("yes" if args[0] in TESTNET_CHAINS else "no")
elif fn == "list_chains":
    from chains import DEFAULT_RPC, TESTNET_CHAINS, chain_banner, chain_title
    tests = sorted(c for c in DEFAULT_RPC if c in TESTNET_CHAINS)
    mains = sorted(c for c in DEFAULT_RPC if c not in TESTNET_CHAINS)
    for c in tests + mains:
        tag = "testnet" if c in TESTNET_CHAINS else "mainnet"
        print(f"{c}|{chain_title(c)}|{chain_banner(c)}|{tag}")
else:
    sys.exit("unknown helper function: " + fn)
PYEOF
}

have_python_deps() {
    "$PYTHON" -c "import web3, fastapi, uvicorn, requests, retry" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# PREFLIGHT / DOCTOR
# ---------------------------------------------------------------------------
MISSING_PKGS=()
PKG_OK=()
declare -a CHECK_LINES=()

# record <ok|warn|info> <line> -- buffer one environment-check result. In the
# full doctor report every line is printed; in the compact wizard preflight
# only the non-ok lines are (see check_env).
record() {
    local status="$1" line="$2"
    CHECK_LINES+=("$status|$line")
}

# need_pkg <logical> <human-desc> <shell-test>
need_pkg() {
    local logical="$1" desc="$2" test="$3"
    if eval "$test" >/dev/null 2>&1; then
        PKG_OK+=("$logical")
        record ok "$(ok_s "$(printf '%-22s %s' "$desc" "${C_DIM}ok${C_R}")")"
    else
        MISSING_PKGS+=("$logical")
        record warn "$(warn_s "$(printf '%-22s %s' "$desc" "${C_YEL}missing${C_R}")")"
    fi
}

check_env() {
    MISSING_PKGS=(); PKG_OK=(); CHECK_LINES=()
    detect_os

    box_top
    box_line "  ${C_B}PREFLIGHT ENVIRONMENT CHECK${C_R} ${C_DIM}(doctor)${C_R}"
    box_mid
    box_line "  System : ${C_CYN}${OS_NAME}${C_R} ${C_DIM}($(uname -m))${C_R}"
    if [[ -n "$PKG_MGR" ]]; then
        box_line "  Packages: ${C_CYN}${PKG_MGR}${C_R}"
    else
        box_line "  Packages: ${C_YEL}unknown package manager -- I will not install anything myself${C_R}"
    fi
    box_line "  Python : ${C_CYN}${PYTHON}${C_R}"
    box_bot
    echo

    need_pkg z3        "z3 (libz3-dev)"        'pkg-config --exists z3 2>/dev/null || [[ -e /usr/include/z3.h || -e /usr/local/include/z3.h || -e /opt/homebrew/include/z3.h ]]'
    need_pkg pkgconfig "pkg-config"            'command -v pkg-config'
    need_pkg clang     "clang"                 'command -v clang'
    need_pkg cmake     "cmake"                 'command -v cmake'
    need_pkg python    "python3"               'command -v python3'
    need_pkg buildbase "C/C++ toolchain"       'command -v cc || command -v gcc || command -v clang'
    need_pkg git       "git"                   'command -v git'
    need_pkg curl      "curl"                  'command -v curl'

    # Rust toolchain (special: installed via rustup, not the distro).
    local rust_ok=1
    if command -v cargo >/dev/null 2>&1; then
        record ok "$(ok_s "$(printf '%-22s %s' "cargo (Rust)" "$(cargo --version 2>/dev/null)")")"
    else
        rust_ok=0
        record warn "$(warn_s "$(printf '%-22s %s' "cargo (Rust)" "missing -- install via rustup")")"
    fi
    if command -v rustup >/dev/null 2>&1; then
        record ok "$(ok_s "$(printf '%-22s %s' "rustup" "ok")")"
    else
        rust_ok=0
        record warn "$(warn_s "$(printf '%-22s %s' "rustup" "missing")")"
    fi

    # Python requirements (special: installed via pip).
    local deps_ok=1
    if have_python_deps; then
        record ok "$(ok_s "$(printf '%-22s %s' "python dependencies" "web3, fastapi, uvicorn, ...")")"
    else
        deps_ok=0
        record warn "$(warn_s "$(printf '%-22s %s' "python dependencies" "missing -- see onchain_scripts/requirements.txt")")"
    fi

    # Optional (never blocks a run).
    if command -v anvil >/dev/null 2>&1; then
        record ok "$(ok_s "$(printf '%-22s %s' "anvil (optional)" "ok -- pre-flight fork simulation will be available")")"
    else
        record info "$(info_s "$(printf '%-22s %s' "anvil (optional)" "not installed -- pre-flight fork simulation will be skipped")")"
    fi
    if command -v solc >/dev/null 2>&1 || [[ -x "$HOME/.svm/0.8.24/solc-0.8.24" ]]; then
        record ok "$(ok_s "$(printf '%-22s %s' "solc (optional)" "ok")")"
    else
        record info "$(info_s "$(printf '%-22s %s' "solc (optional)" "not installed -- needed only for .sol targets")")"
    fi

    # Built binary.
    local bin_ok=0
    if [[ -x "$BIN" ]]; then
        bin_ok=1
        record ok "$(ok_s "$(printf '%-22s %s' "binary" "$BIN")")"
    else
        record warn "$(warn_s "$(printf '%-22s %s' "binary" "$BIN is not built")")"
    fi

    # Show the results. The full doctor report (--doctor) prints every line;
    # the wizard preflight prints only what needs attention, so the menu is
    # not buried under a wall of "ok" rows.
    if (( DOCTOR_ONLY || CHECK_FULL )); then
        local entry
        for entry in "${CHECK_LINES[@]}"; do
            printf '%s\n' "${entry#*|}"
        done
    else
        local entry status line n_warn=0
        for entry in "${CHECK_LINES[@]}"; do
            status="${entry%%|*}"; line="${entry#*|}"
            if [[ "$status" == "warn" ]]; then
                n_warn=$((n_warn + 1))
            fi
            if [[ "$status" != "ok" ]]; then
                printf '%s\n' "$line"
            fi
        done
        if (( n_warn == 0 )); then
            ok "Environment is ready (everything required is in place)."
        else
            info "$n_warn item(s) missing -- see above (optional '·' lines are not a problem)."
        fi
    fi

    # Install missing system packages (one confirmation for all).
    if (( ${#MISSING_PKGS[@]} > 0 )); then
        echo
        if [[ -n "$PKG_MGR" ]]; then
            local cmdline; cmdline="$(pkg_install_cmdline "${MISSING_PKGS[@]}")" || cmdline=""
            if [[ -n "$cmdline" ]]; then
                bold "${#MISSING_PKGS[@]} system dependencies missing. I will install them with:"
                echo "    $cmdline"
                if (( NO_INSTALL )); then
                    info "Skipped (--no-install). Install manually: $cmdline"
                else
                    local ans
                    read -rp "  ➜ Install now? (yes/no) [Enter = no]: " ans
                    if [[ "$ans" == "yes" ]]; then
                        if pkg_install_run "${MISSING_PKGS[@]}"; then
                            ok "System dependencies installed."
                            MISSING_PKGS=()
                        else
                            err "Installation failed -- install manually: $cmdline"
                        fi
                    else
                        info "Skipped. Install manually: $cmdline"
                    fi
                fi
            fi
        else
            warn "I do not know the package manager for this system. Install manually (see README.md, Installation section)."
        fi
    fi

    # Rust toolchain install offer.
    if (( rust_ok == 0 )); then
        echo
        bold "Rust toolchain is missing. Official install command:"
        echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
        if (( NO_INSTALL )); then
            info "Skipped (--no-install). Install manually with the command above."
        else
            local ans
            read -rp "  ➜ Run the official rustup installer now? (yes/no) [Enter = no]: " ans
            if [[ "$ans" == "yes" ]]; then
                if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; then
                    # shellcheck disable=SC1091
                    [[ -f "$HOME/.cargo/env" ]] && . "$HOME/.cargo/env"
                    command -v cargo >/dev/null 2>&1 && ok "Rust installed." || warn "Rust installed, but 'cargo' is not on PATH yet -- open a new shell."
                else
                    err "Rust installation failed."
                fi
            else
                info "Skipped. Install manually with the command above."
            fi
        fi
    fi

    # Python requirements install offer.
    if (( deps_ok == 0 )); then
        echo
        bold "Python dependencies are missing. Suggested command:"
        echo "    $PYTHON -m pip install -r $REQ_FILE"
        if (( NO_INSTALL )); then
            info "Skipped (--no-install)."
        else
            local ans
            read -rp "  ➜ Install them now? (yes/no) [Enter = no]: " ans
            if [[ "$ans" == "yes" ]]; then
                if "$PYTHON" -m pip install -r "$REQ_FILE"; then
                    ok "Python dependencies installed."
                else
                    err "pip install failed (possibly 'externally-managed-environment')."
                    info "Try: python3 -m venv .venv && .venv/bin/pip install -r $REQ_FILE"
                fi
            else
                info "Skipped."
            fi
        fi
    fi

    # Build the release binary if it is missing and cargo is available.
    if (( bin_ok == 0 )) && command -v cargo >/dev/null 2>&1; then
        echo
        bold "The binary is not built yet. I will build it with:"
        echo "    cargo build --release"
        if (( NO_INSTALL )); then
            info "Skipped (--no-install). Build manually: cargo build --release"
        else
            local ans
            read -rp "  ➜ Build now? (may take several minutes) (yes/no) [Enter = yes]: " ans
            if [[ -z "$ans" || "$ans" == "yes" ]]; then
                info "Building ... (this may take a while)"
                if (cd "$REPO_ROOT" && cargo build --release); then
                    ok "Built: $BIN"
                    bin_ok=1
                else
                    err "Build failed -- fix the errors above and try again."
                fi
            else
                info "Skipped."
            fi
        fi
    fi

    echo
    if [[ ! -x "$BIN" ]]; then
        err "The binary '$BIN' is still missing -- the pipeline cannot run without it."
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Wizard helpers
# ---------------------------------------------------------------------------
NAV_ACTION=""
REPLY_VAL=""
MENU_IDX=1

# prompt_nav <prompt> [default] -- with main menu navigation
prompt_nav() {
    local __prompt="$1" __default="${2:-}" __input
    local __hint=" ${C_DIM}(back = previous · main menu = MM · exit = EXIT)${C_R}"
    if ! read -rp "${__prompt}${__hint}" __input; then
        NAV_ACTION="quit"; return 1
    fi
    if [[ -z "$__input" && -n "$__default" ]]; then
        __input="$__default"
    fi
    case "$__input" in
        nazaj|back) NAV_ACTION="back"; return 1 ;;
        glavni\ meni|main\ menu|MM) NAV_ACTION="main_menu"; return 1 ;;
        izhod|exit|EXIT) NAV_ACTION="quit"; return 1 ;;
        *) NAV_ACTION=""; REPLY_VAL="$__input"; return 0 ;;
    esac
}

# menu [--root] <title> <opt...> -- numbered selection; each opt is
# "value|label". An opt whose value is "#" is a non-selectable section header
# (printed as a dim line; it does not consume a number). Entries are laid out
# in a compact multi-column grid, so a long list never becomes a single-column
# wall.
#
# Navigation is by WORD only -- 'back'/'main menu'/'exit' (aliases 0, MM, q).
# Numbers belong to the entries alone: an earlier version also bound 1/2/3
# to back/main/exit, which silently stole the first three entries of any short
# menu (a 3-entry submenu could not be selected by number at all).
# Sets REPLY_VAL=value (and MENU_IDX) on 0; NAV_ACTION=back|main_menu|quit on 1.
menu() {
    local __root=0
    if [[ "$1" == "--root" ]]; then __root=1; shift; fi
    local __title="$1"; shift
    local -a __opts=("$@")
    local -a __vals=()
    local i __in __val __lbl n=0 __k
    for i in "${!__opts[@]}"; do
        [[ "${__opts[$i]%%|*}" == "#" ]] && continue
        n=$((n + 1))
    done
    local nw=${#n}

    # Render the pending section's entries as a grid, then clear it. Bash's
    # dynamic scoping lets this see menu's locals.
    local -a __ents=()
    _menu_flush() {
        (( ${#__ents[@]} == 0 )) && return
        local e p maxw=0
        for e in "${__ents[@]}"; do
            p="$(printf '%s' "$e" | sed 's/\x1b\[[0-9;]*m//g')"
            (( ${#p} > maxw )) && maxw=${#p}
        done
        local colw=$(( maxw + 3 ))
        local cols=$(( (W - 4) / colw )); (( cols < 1 )) && cols=1
        local cnt=${#__ents[@]}
        local rows=$(( (cnt + cols - 1) / cols ))
        local r c k line pad
        for (( r = 0; r < rows; r++ )); do
            line=""
            for (( c = 0; c < cols; c++ )); do
                k=$(( r * cols + c )); (( k >= cnt )) && break
                e="${__ents[$k]}"
                p="$(printf '%s' "$e" | sed 's/\x1b\[[0-9;]*m//g')"
                line+="$e"
                # Pad between columns, but never after the last entry on the
                # row -- trailing spaces would smear the gutter edge.
                if (( c < cols - 1 && k < cnt - 1 )); then
                    pad=$(( colw - ${#p} )); (( pad < 1 )) && pad=1
                    line+="$(printf '%*s' "$pad" '')"
                fi
            done
            gut_fit "$line"
        done
        __ents=()
    }

    # Draw title bar with frame
    box_top
    box_line "  ${C_GREEN}${C_B}◆ $__title ◆${C_R}"
    box_mid

    gutb "$__title"
    local idx=0
    for i in "${!__opts[@]}"; do
        __val="${__opts[$i]%%|*}"; __lbl="${__opts[$i]#*|}"
        if [[ "$__val" == "#" ]]; then
            _menu_flush
            gut_fit "$__lbl"
            continue
        fi
        idx=$((idx + 1)); __vals+=("$__val")
        __ents+=("$(printf '%*d) %s' "$nw" "$idx" "$__lbl")")
    done
    _menu_flush

    # Draw navigation bar with frame. The root menu has no 'main menu'
    # (it *is* the main menu) and no 'back' (nowhere to go back to).
    echo
    input_field_top "NAVIGATION"
    if (( __root )); then
        input_field "Back (step)" "none -- main menu"
        input_field "Main menu" "you are already here"
        input_field "Exit" "exit"
    else
        input_field "Back (step)" "back"
        input_field "Main menu" "main menu"
        input_field "Exit" "exit"
    fi
    input_field_bottom

    # Default on a bare Enter: the value named by MENU_DEFAULT_VAL if present
    # in the list, else the first entry.
    local __def=1
    if [[ -n "${MENU_DEFAULT_VAL:-}" ]]; then
        for __k in "${!__vals[@]}"; do
            if [[ "${__vals[$__k]}" == "$MENU_DEFAULT_VAL" ]]; then __def=$((__k + 1)); break; fi
        done
    fi
    while true; do
        if ! read -rp "  ➜ Choose [1-$n] (Enter = $__def): " __in; then
            NAV_ACTION="quit"; return 1
        fi
        [[ -z "$__in" ]] && __in=$__def
        case "$__in" in
            0|nazaj|back)
                if (( __root )); then
                    err "  There is no 'back' in the main menu -- pick a row or 'exit'."
                    continue
                fi
                NAV_ACTION="back"; return 1 ;;
            glavni\ meni|main\ menu|MM)
                if (( __root )); then
                    err "  You are already in the main menu -- pick a row or 'exit'."
                    continue
                fi
                NAV_ACTION="main_menu"; return 1 ;;
            izhod|exit|EXIT|q|Q) NAV_ACTION="quit"; return 1 ;;
        esac
        if [[ "$__in" =~ ^[0-9]+$ ]] && (( __in >= 1 && __in <= n )); then
            MENU_IDX="$__in"; REPLY_VAL="${__vals[$((__in - 1))]}"; NAV_ACTION=""; return 0
        fi
        local __low="${__in,,}"
        for __k in "${!__vals[@]}"; do
            if [[ "${__vals[$__k],,}" == "$__low" ]]; then
                MENU_IDX=$((__k + 1)); REPLY_VAL="${__vals[$__k]}"; NAV_ACTION=""; return 0
            fi
        done
        err "  Invalid choice -- enter a number 1-$n, a name, 'back', 'main menu' or 'exit'."
    done
}

quit_wizard() {
    echo
    bold "Aborted at the user's request."
    exit 0
}

# ---------------------------------------------------------------------------
# Run-state reset (used when a wizard run starts from the main menu, so a
# second run cannot inherit a stale answer from a previous one).
# ---------------------------------------------------------------------------
reset_run_state() {
    CHAIN=""; RPC_VALUE=""
    KEY_FILE=""; FUNDING_WALLET=""
    TARGETS_INPUT=""; RECOVERY_WALLET=""
    CONFIRM_MAINNET_FLAG=()
    declare -ga TARGET_PARTS=()
    IS_LIST_FILE=0
    STEP=1
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
main_menu() {
    # Sets MAIN_CHOICE to one of: wizard, settings, doctor, help, quit.
    local -a opts=(
        "#|${C_DIM}Overview and execution${C_R}"
        "wizard|New run -- wizard (chain → RPC → key → targets → recovery → confirm)"
        "#|${C_DIM}Settings and help${C_R}"
        "settings|Settings (default key, per-chain RPC)"
        "doctor|Check environment (doctor) -- what is available, what is missing"
        "help|Help -- what ForkSploit does and what the steps mean"
        "#|${C_DIM}Advanced and tools${C_R}"
        "advanced|Advanced run settings (fuzzing, funding, pre-flight)"
        "tools|Tools -- monitor, triage, materialize, dashboard, DEX, fixture"
    )
    MENU_DEFAULT_VAL="wizard"
    while true; do
        new_page
        matrix_logo
        echo
        if menu --root "MAIN MENU" "${opts[@]}"; then
            MAIN_CHOICE="$REPLY_VAL"; return 0
        fi
        [[ "$NAV_ACTION" == "quit" ]] && { MAIN_CHOICE="quit"; return 0; }
        # --root rejects 'back'/'main menu', so nothing else can land here.
    done
}

# ---------------------------------------------------------------------------
# Settings submenu
# ---------------------------------------------------------------------------
settings_menu() {
    while true; do
        new_page
        matrix_logo
        echo
        gutb "SETTINGS"
        gutc "Persistent defaults, saved between runs."
        echo
        box_top
        box_line "  ${C_GREEN}◆ SETTINGS ◆${C_R}"
        box_mid
        input_field "Default key" "$DEFAULT_KEY"
        input_field "RPC (chain)" "${CHAIN:-none selected}"
        box_bot
        echo

        local -a opts=(
            "key|Set the default key (file path)"
            "rpc|Set the RPC for a chain"
            "back|Back to main menu"
        )
        MENU_DEFAULT_VAL="back"
        if ! menu "Choose a setting:" "${opts[@]}"; then
            [[ "$NAV_ACTION" == "quit" ]] && { quit_wizard; }
            return 0                     # 'back'/'main menu' -> main menu
        fi
        case "$REPLY_VAL" in
            key)
                local kf
                if ! prompt_nav "  ➜ Path to the key file [$DEFAULT_KEY]: " "$DEFAULT_KEY"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                kf="$REPLY_VAL"
                if [[ ! -f "$kf" ]]; then
                    err "  File '$kf' does not exist."
                    continue
                fi
                local wallet
                if ! wallet="$(py_help wallet_from_key "$kf" 2>&1)"; then
                    err "  '$kf' does not contain a valid private key."
                    continue
                fi
                DEFAULT_KEY="$kf"
                ok "Default key set: ${C_CYN}${wallet}${C_R}  (${kf})"
                ;;
            rpc)
                local ch
                if ! prompt_nav "  ➜ Chain (e.g. sepolia, eth, etc) [${CHAIN:-sepolia}]: " "${CHAIN:-sepolia}"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                ch="$REPLY_VAL"
                local cur
                if ! cur="$(py_help rpc "$ch" 2>&1)"; then
                    err "  Chain '$ch' is not known to ForkSploit."
                    continue
                fi
                gut "  Current RPC for '$ch': ${C_CYN}${cur}${C_R}"
                local url
                if ! prompt_nav "  ➜ New RPC URL (Enter = keep): " ""; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                url="$REPLY_VAL"
                if [[ -z "$url" ]]; then
                    info "  Kept: $cur"
                elif py_help set_rpc "$ch" "$url"; then
                    ok "  RPC saved for '$ch': $url"
                else
                    err "  Saving the RPC failed."
                fi
                ;;
            back) return 0 ;;
        esac
        echo
        read -rp "  ➜ Enter to continue ..." _ || true
    done
}

# ---------------------------------------------------------------------------
# Advanced run settings (Settings -> Advanced settings)
# ---------------------------------------------------------------------------
# Exposes only REAL auto_pipeline.py / batch_pipeline.py flags. Values are
# persisted in $SETTINGS_FILE; an empty value means "unset". Each editor
# validates its input and re-asks on a bad value (never a hard exit).
advanced_menu() {
    while true; do
        new_page
        matrix_logo
        echo
        gutb "ADVANCED RUN SETTINGS"
        gutc "Apply to every run started from the wizard. Empty = default (the flag is omitted)."
        echo
        box_top
        box_line "  ${C_GREEN}◆ ADVANCED SETTINGS ◆${C_R}"
        box_mid
        input_field "Fuzz duration" "${FUZZ_SECONDS:+${FUZZ_SECONDS}s}"
        input_field "Detectors" "${DETECTORS:-default (all)}"
        input_field "Funding" "${FUND_ETH:+${FUND_ETH} ETH}"
        input_field "Pre-flight gate" "$( (( NO_PREFLIGHT )) && echo 'DISABLED' || echo 'enabled (default)' )"
        input_field "Gas oracle" "$( (( NO_GAS_ORACLE )) && echo 'DISABLED' || echo 'enabled (default)' )"
        box_bot
        echo

        local -a opts=(
            "fuzz|Set the fuzzing duration (seconds, e.g. 300)"
            "det|Set the detectors (all / high_confidence / list)"
            "fund|Set the initial funding of the target (ETH, e.g. 0.01)"
            "preflight|Toggle the pre-flight profitability gate (on/off)"
            "gasoracle|Toggle the gas-fee oracle (on/off)"
            "reset|Reset all advanced settings to their defaults"
            "back|Back to main menu"
        )
        MENU_DEFAULT_VAL="back"
        if ! menu "Choose a setting:" "${opts[@]}"; then
            [[ "$NAV_ACTION" == "quit" ]] && { quit_wizard; }
            return 0
        fi
        case "$REPLY_VAL" in
            fuzz)
                local v
                if ! prompt_nav "  ➜ Fuzz duration in seconds (Enter = default/clear): " "$FUZZ_SECONDS"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                v="$REPLY_VAL"
                if [[ -z "$v" ]]; then FUZZ_SECONDS=""
                elif [[ "$v" =~ ^[0-9]+$ ]] && (( v > 0 )); then FUZZ_SECONDS="$v"
                else err "  '$v' is not a positive whole number of seconds -- try again."; continue; fi
                save_settings; ok "Saved."
                ;;
            det)
                local v
                if ! prompt_nav "  ➜ Detectors (all / high_confidence / e.g. reentrancy,erc20): " "$DETECTORS"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                v="$REPLY_VAL"
                # Accept "all", "high_confidence", or a comma-separated list of
                # known detector names -- validated against the binary's own
                # OracleType::from_strs mapping via --detectors help is not
                # available, so accept any non-empty token list (the binary
                # rejects an unknown one loudly, and we surface that at run).
                if [[ -z "$v" ]]; then DETECTORS=""
                elif [[ "$v" =~ ^[a-z_,-]+$ ]]; then DETECTORS="$v"
                else err "  Invalid input -- use 'all', 'high_confidence' or comma-separated names."; continue; fi
                save_settings; ok "Saved."
                ;;
            fund)
                local v
                if ! prompt_nav "  ➜ Initial funding of the target in ETH (Enter = none): " "$FUND_ETH"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                v="$REPLY_VAL"
                if [[ -z "$v" ]]; then FUND_ETH=""
                elif [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]]; then FUND_ETH="$v"
                else err "  '$v' is not a valid number (e.g. 0.01) -- try again."; continue; fi
                save_settings; ok "Saved."
                ;;
            preflight)
                (( NO_PREFLIGHT )) && NO_PREFLIGHT=0 || NO_PREFLIGHT=1
                save_settings
                (( NO_PREFLIGHT )) && warn "Pre-flight gate: DISABLED (runs every plan for real)." || ok "Pre-flight gate: enabled."
                ;;
            gasoracle)
                (( NO_GAS_ORACLE )) && NO_GAS_ORACLE=0 || NO_GAS_ORACLE=1
                save_settings
                (( NO_GAS_ORACLE )) && warn "Gas oracle: DISABLED (price from the node)." || ok "Gas oracle: enabled."
                ;;
            reset)
                FUZZ_SECONDS=""; DETECTORS=""; FUND_ETH=""; NO_PREFLIGHT=0; NO_GAS_ORACLE=0
                save_settings; ok "Advanced settings reset to defaults."
                ;;
            back) return 0 ;;
        esac
        echo
        read -rp "  ➜ Continue ..." _ || true
    done
}

# ---------------------------------------------------------------------------
# Tools menu (Helper tools) -- launches the OTHER onchain_scripts/ tools
# that the wizard does not run: monitor, triage, materialize, dashboard,
# DEX scanner, chain-fixture generator. Every entry prints the exact command
# and, unless it is a long-running server/monitor, runs it after a confirm.
# ---------------------------------------------------------------------------
run_tool() { # run_tool <label> <cmd...>
    local label="$1"; shift
    echo
    gutb "Command:"
    printf '   %s\n' "$*"
    local ans
    read -rp "  ➜ Run this command? (yes/no) [Enter = no]: " ans || true
    if [[ "$ans" == "yes" ]]; then
        ( cd "$SCRIPTS_DIR" && "$@" )
    else
        info "Skipped (the command is printed above)."
    fi
}

tools_menu() {
    while true; do
        new_page
        matrix_logo
        echo
        gutb "TOOLS"
        gutc "Helper tools in onchain_scripts/. Some are long-running (monitor, dashboard)."
        echo
        box_top
        box_line "  ${C_GREEN}◆ TOOLS ◆${C_R}"
        box_mid
        box_line "  ${C_DIM}All tools run from onchain_scripts/, with the chosen defaults.${C_R}"
        box_bot
        echo

        local -a opts=(
            "monitor|Monitor -- watch a live contract after deploy (outflow/new tx)"
            "triage|Triage -- break down the plans in work_dir into real surfaces"
            "materialize|Materialize -- control-leak surfaces, then open the dashboard"
            "dashboard|Dashboard -- local web control (default port 4114)"
            "dex|DEX arbitrage -- cross-DEX opportunity scanner"
            "fixture|Generate a 'chain' fixture for depth measurement"
            "back|Back to main menu"
        )
        MENU_DEFAULT_VAL="back"
        if ! menu "Choose a tool:" "${opts[@]}"; then
            [[ "$NAV_ACTION" == "quit" ]] && { quit_wizard; }
            return 0
        fi
        case "$REPLY_VAL" in
            monitor)
                local ch addr
                if ! prompt_nav "  ➜ Chain for monitor [${CHAIN:-sepolia}]: " "${CHAIN:-sepolia}"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                ch="$REPLY_VAL"
                if ! prompt_nav "  ➜ Contract address (0x...): " ""; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                addr="$REPLY_VAL"
                if [[ ! "$addr" =~ ^0x[0-9a-fA-F]{40}$ ]]; then err "  Invalid address."; continue; fi
                run_tool "monitor" "$PYTHON" monitor.py --chain "$ch" --address "$addr"
                ;;
            triage)
                local wd
                if ! prompt_nav "  ➜ Work dir (or a pattern, e.g. auto_work/*): " "auto_work/*"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                wd="$REPLY_VAL"
                # shellcheck disable=SC2086
                # (intentional glob expansion)
                ( cd "$SCRIPTS_DIR" && "$PYTHON" triage_findings.py $wd ) || err "  Triage failed (or there are no findings in $wd)."
                read -rp "  ➜ Continue ..." _ || true
                ;;
            materialize)
                local wd
                if ! prompt_nav "  ➜ Work dir (or a pattern, e.g. auto_work/*): " "auto_work/*"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                wd="$REPLY_VAL"
                # shellcheck disable=SC2086
                # (intentional glob expansion)
                ( cd "$SCRIPTS_DIR" && "$PYTHON" materialize_plan.py $wd ) || err "  Materialize failed (or there are no surfaces in $wd)."
                echo
                # Per the request, Materialize also opens the dashboard GUI so
                # the worklist can be inspected visually. NOTE (R3): the
                # dashboard is the same projection as the standalone Dashboard
                # entry -- it does NOT itself render the materialize worklist
                # (dashboard_server.py has no materialize view); the worklist
                # is the terminal output printed just above.
                local ans
                read -rp "  ➜ Open the dashboard GUI in the browser? (yes/no) [Enter = no]: " ans || true
                if [[ "$ans" == "yes" ]]; then
                    info "The dashboard runs until you stop it with Ctrl-C."
                    ( cd "$SCRIPTS_DIR" && bash server_run.sh 4114 )
                    read -rp "  ➜ Continue ..." _ || true
                fi
                ;;
            dashboard)
                local port
                if ! prompt_nav "  ➜ Port for the dashboard [4114]: " "4114"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                port="$REPLY_VAL"
                info "The dashboard runs until you stop it with Ctrl-C. The browser opens by itself."
                ( cd "$SCRIPTS_DIR" && bash server_run.sh "$port" )
                read -rp "  ➜ Continue ..." _ || true
                ;;
            dex)
                run_tool "dex" "$PYTHON" dex_arbitrage_scanner.py --chain "${CHAIN:-eth}"
                ;;
            fixture)
                local depth dir
                if ! prompt_nav "  ➜ Depth (number of steps, e.g. 4): " "4"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                depth="$REPLY_VAL"
                if ! prompt_nav "  ➜ Output directory [work_dir/chain_fixture]: " "work_dir/chain_fixture"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                dir="$REPLY_VAL"
                run_tool "fixture" "$PYTHON" gen_chain_fixture.py "$depth" "$dir"
                ;;
            back) return 0 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Doctor (full environment report), on its own page
# ---------------------------------------------------------------------------
show_doctor_page() {
    new_page
    matrix_logo
    echo
    CHECK_FULL=1
    check_env
    CHECK_FULL=0
    echo
    read -rp "  ➜ Enter to return to the main menu ..." _ || true
}

# ---------------------------------------------------------------------------
# Help page
# ---------------------------------------------------------------------------
show_help_page() {
    new_page
    matrix_logo
    echo
    box_top
    box_line "  ${C_GREEN}${C_B}◆ HELP ◆${C_R}"
    box_mid
    gutb "What ForkSploit does"
    gut "It finds a real, runnable exploit in a smart contract and -- with clear"
    gut "proof -- executes it, then sweeps the recovered funds to the recovery wallet."
    gut ""
    gutb "The wizard asks exactly three roles before anything signs:"
    gut "  · WHO funds it    -- private-key file (pays all the gas),"
    gut "  · WHAT is audited -- a 0x… address or a path to .sol/.bin (comma-separated for many),"
    gut "  · WHERE funds go  -- recovery wallet (0x…, 40 hex chars)."
    gut "You also pick the chain (testnet/mainnet) and the RPC."
    gut ""
    gutb "Steps (1/7 … 7/7)"
    gut "  1/7 CHAIN      -- pick the network (two-level submenu)."
    gut "  2/7 RPC        -- the default or your own RPC endpoint."
    gut "  3/7 WHO FUNDS  -- path to the private-key file."
    gut "  4/7 TARGETS    -- one or more addresses/paths."
    gut "  5/7 RECOVERY   -- where the funds are swept to."
    gut "  6/7 WALLET POLICY -- lock funding + recovery for this chain."
    gut "  7/7 MAINNET    -- explicit confirmation if the chain is not a testnet."
    gut ""
    gutb "Navigation"
    gut "  In the wizard: 'back' (previous step), 'main menu' (back to the menu),"
    gut "  'exit' (abort). In the menus you pick a row by number or by name;"
    gut "  'q' aborts, 'back'/'main menu' return."
    gut ""
    gutc "A wrong answer never causes an exit -- the script re-asks or steps back."
    box_bot
    echo
    read -rp "  ➜ Enter to return to the main menu ..." _ || true
}

# ---------------------------------------------------------------------------
# Which pipeline runs (auto for one target, batch for many)
# ---------------------------------------------------------------------------
choose_pipeline() {
    IFS=',' read -ra TARGET_PARTS <<< "$TARGETS_INPUT"
    IS_LIST_FILE=0
    if [[ ${#TARGET_PARTS[@]} -eq 1 && -f "$TARGETS_INPUT" && "$TARGETS_INPUT" != *.sol && "$TARGETS_INPUT" != *.bin ]]; then
        IS_LIST_FILE=1
    fi
    if [[ ${#TARGET_PARTS[@]} -gt 1 || $IS_LIST_FILE -eq 1 ]]; then
        PIPELINE_LABEL="batch_pipeline.py"
        PIPELINE_MODE="batch_pipeline.py  (multiple targets)"
    else
        PIPELINE_LABEL="auto_pipeline.py"
        PIPELINE_MODE="auto_pipeline.py  (single target)"
    fi
}

# ---------------------------------------------------------------------------
# Wizard steps. Each returns: 0 advance (NEXT_STEP set), 1 back (NEXT_STEP set),
# 2 quit, 3 main menu (leave the wizard and go back to the main menu).
# ---------------------------------------------------------------------------
CHAIN_LIST=""
load_chains() {
    CHAIN_LIST="$(py_help list_chains)"
}

# Chains of one kind ("testnet"/"mainnet") as "slug|title" lines.
chains_of_kind() {
    local want="$1" line c rest title tag
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        c="${line%%|*}"; rest="${line#*|}"
        title="${rest%%|*}"; tag="${rest##*|}"
        [[ "$tag" == "$want" ]] && printf '%s|%s\n' "$c" "$title"
    done <<< "$CHAIN_LIST"
}

step_chain() {
    NEXT_STEP=2
    local line c title kind kindname candidate shown
    while true; do
        # Page 1 -- pick the kind of network (a submenu opens on page 2).
        gutb "1/7 · CHAIN"
        gutc "The network the whole run takes place on."
        local -a gopts=(
            "testnet|Test networks   ${C_DIM}(safe to try)${C_R}"
            "mainnet|Main networks   ${C_DIM}(real value)${C_R}"
        )
        MENU_DEFAULT_VAL="testnet"
        if ! menu "Choose the network kind:" "${gopts[@]}"; then
            [[ "$NAV_ACTION" == "quit" ]] && return 2
            [[ "$NAV_ACTION" == "main_menu" ]] && return 3
            NEXT_STEP=1; return 1
        fi
        kind="$REPLY_VAL"
        if [[ "$kind" == "testnet" ]]; then kindname="Test networks"; else kindname="Main networks"; fi

        # Page 2 -- the chains of that kind, on a fresh page.
        while true; do
            new_page
            local -a copts=()
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                c="${line%%|*}"; title="${line#*|}"
                copts+=("$c|$title")
            done < <(chains_of_kind "$kind")
            gutb "1/7 · CHAIN › $kindname"
            MENU_DEFAULT_VAL="sepolia"
            if ! menu "Choose the chain:" "${copts[@]}"; then
                [[ "$NAV_ACTION" == "quit" ]] && return 2
                [[ "$NAV_ACTION" == "main_menu" ]] && return 3
                break                     # 'back' -> back to page 1 (kind)
            fi
            candidate="$REPLY_VAL"
            shown="$(py_help banner "$candidate")"
            echo
            bold "  Selected chain: $shown"
            while true; do                # confirm by re-typing the chain name
                if ! prompt_nav "  ➜ Retype the chain name to confirm ('$candidate'): " ""; then
                    [[ "$NAV_ACTION" == "quit" ]] && return 2
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 3
                    continue 2            # 'back' -> back to page 2 (chain list)
                fi
                if [[ "$REPLY_VAL" == "$candidate" ]]; then
                    CHAIN="$candidate"; return 0
                fi
                err "  '$candidate' and '$REPLY_VAL' do not match -- try again (or 'back'/'main menu')."
            done
        done
    done
}

step_rpc() {
    NEXT_STEP=3
    gutb "2/7 · RPC"
    local current
    if ! current="$(py_help rpc "$CHAIN" 2>&1)"; then
        err "ERROR: the chain '$CHAIN' is not known to ForkSploit."
        NEXT_STEP=1; return 1
    fi
    gut "Current RPC for '$CHAIN': ${C_CYN}${current}${C_R}"
    gutc "Leave the default or enter your own. Your own RPC is SAVED for all future runs on this chain."

    # Draw input frame
    echo
    box_top
    box_line ""
    box_line "  ${C_GREEN}◆ ENTER THE RPC URL ◆${C_R}"
    box_mid
    input_field "Current RPC" "$current"
    box_line ""
    box_bot

    if ! prompt_nav "  ➜ RPC URL (Enter = keep the one above): " ""; then
        [[ "$NAV_ACTION" == "quit" ]] && return 2
        [[ "$NAV_ACTION" == "main_menu" ]] && return 3
        NEXT_STEP=1; return 1
    fi
    if [[ -n "$REPLY_VAL" ]]; then
        py_help set_rpc "$CHAIN" "$REPLY_VAL"
        ok "Saved as the default RPC for '$CHAIN': $REPLY_VAL"
    else
        info "Kept: $current"
    fi
    return 0
}

step_key() {
    NEXT_STEP=4
    gutb "3/7 · WHO FUNDS IT"
    gutc "Private-key file of the wallet that PAYS all the gas (deploy, funding, exploit execution)."

    echo
    box_top
    box_line ""
    box_line "  ${C_GREEN}◆ ENTER THE KEY PATH ◆${C_R}"
    box_mid
    input_field "Default path" "$DEFAULT_KEY"
    box_line ""
    box_bot

    local kf
    if ! prompt_nav "  ➜ Path to the key file [$DEFAULT_KEY]: " "$DEFAULT_KEY"; then
        [[ "$NAV_ACTION" == "quit" ]] && return 2
        [[ "$NAV_ACTION" == "main_menu" ]] && return 3
        NEXT_STEP=2; return 1
    fi
    kf="$REPLY_VAL"
    if [[ ! -f "$kf" ]]; then
        err "  File '$kf' does not exist -- try again (or 'back'/'main menu')."
        return 1
    fi
    local wallet
    if ! wallet="$(py_help wallet_from_key "$kf" 2>&1)"; then
        err "  '$kf' does not contain a valid private key."
        err "  $(printf '%s' "$wallet" | tail -1)"
        return 1
    fi
    KEY_FILE="$kf"
    FUNDING_WALLET="$wallet"
    ok "Funding wallet: ${C_CYN}${FUNDING_WALLET}${C_R}"
    return 0
}

step_targets() {
    NEXT_STEP=5
    gutb "4/7 · WHAT IS AUDITED"
    gut "Enter ONE of:"
    gut "  · a single 0x... address or a path to .sol/.bin (to deploy),"
    gut "  · several targets, comma-separated (0xAAA...,0xBBB...,path/To.sol),"
    gut "  · a path to a list file (one contract per line)."

    echo
    box_top
    box_line ""
    box_line "  ${C_GREEN}◆ ENTER THE TARGET(S) ◆${C_R}"
    box_mid
    box_line ""
    box_line "  ${C_DIM}0x... or a path to a .sol/.bin file${C_R}"
    box_line "  ${C_DIM}Several targets: comma-separated${C_R}"
    box_line "  ${C_DIM}A list file${C_R}"
    box_line ""
    box_bot

    local ans
    while true; do
        if ! prompt_nav "  ➜ Target(s): " ""; then
            [[ "$NAV_ACTION" == "quit" ]] && return 2
            [[ "$NAV_ACTION" == "main_menu" ]] && return 3
            NEXT_STEP=3; return 1
        fi
        ans="$REPLY_VAL"
        [[ -n "$ans" ]] && break
        err "  Without a target there is nothing to audit -- try again."
    done
    TARGETS_INPUT="$ans"
    return 0
}

step_recovery() {
    NEXT_STEP=6
    gutb "5/7 · WHERE THE FUNDS GO"
    gutc "Recovery wallet: where ALL recovered funds (ETH and ERC20) are swept when the steps finish."

    echo
    box_top
    box_line ""
    box_line "  ${C_GREEN}◆ ENTER THE RECOVERY WALLET ◆${C_R}"
    box_mid
    box_line ""
    box_line "  ${C_DIM}Format: 0x + 40 hex chars${C_R}"
    box_line "  ${C_DIM}Example: 0x1234567890abcdef1234567890abcdef12345678${C_R}"
    box_line ""
    box_bot

    local ans
    while true; do
        if ! prompt_nav "  ➜ Recovery wallet (0x...): " ""; then
            [[ "$NAV_ACTION" == "quit" ]] && return 2
            [[ "$NAV_ACTION" == "main_menu" ]] && return 3
            NEXT_STEP=4; return 1
        fi
        ans="$REPLY_VAL"
        if [[ "$ans" =~ ^0x[0-9a-fA-F]{40}$ ]]; then break; fi
        err "  '$ans' is not a valid address (expected 0x + 40 hex chars) -- try again."
    done
    RECOVERY_WALLET="$ans"
    return 0
}

step_policy() {
    NEXT_STEP=7
    gutb "6/7 · WALLET POLICY"
    local out
    out="$("$PYTHON" "$SCRIPTS_DIR/wallet_policy.py" show --chain "$CHAIN" 2>&1)"
    if echo "$out" | grep -q "no policy registered"; then
        gutc "No wallet policy is registered yet for chain '$CHAIN'."
        gut "I will lock exactly these two wallets for ALL future runs on '$CHAIN':"
        gut "  funding_wallet  = ${C_CYN}${FUNDING_WALLET}${C_R}"
        gut "  recovery_wallet = ${C_CYN}${RECOVERY_WALLET}${C_R}"
        local ans
        if ! prompt_nav "  ➜ Confirm registration (yes/no): " ""; then
            [[ "$NAV_ACTION" == "quit" ]] && return 2
            [[ "$NAV_ACTION" == "main_menu" ]] && return 3
            NEXT_STEP=5; return 1
        fi
        ans="$REPLY_VAL"
        if [[ "$ans" != "yes" ]]; then
            err "  Cannot continue without a registered policy -- fix the wallets."
            NEXT_STEP=5; return 1
        fi
        local reg
        if ! reg="$("$PYTHON" "$SCRIPTS_DIR/wallet_policy.py" register \
            --chain "$CHAIN" --confirm-chain "$CHAIN" \
            --funding-wallet "$FUNDING_WALLET" --recovery-wallet "$RECOVERY_WALLET" --confirm 2>&1)"; then
            err "ERROR registering the wallet policy:"
            echo "$reg" >&2
            NEXT_STEP=5; return 1
        fi
        printf '%s\n' "$reg" | gut_block "    "
        ok "Wallet policy registered."
    else
        info "Wallet policy for '$CHAIN' is already registered:"
        printf '%s\n' "$out" | gut_block "    "
        gutc "If the wallets do not match the registered ones, the pipeline will refuse before signing anything."
    fi
    return 0
}

step_mainnet() {
    NEXT_STEP=8
    CONFIRM_MAINNET_FLAG=()
    local is_testnet
    is_testnet="$(py_help is_testnet "$CHAIN")"
    if [[ "$is_testnet" == "no" ]]; then
        gutb "7/7 · MAINNET CONFIRMATION"
        gut "  ${C_RED}${C_B}'$CHAIN' is NOT a testnet -- this is a real chain with real value.${C_R}"

        echo
        box_top
        box_line ""
        box_line "  ${C_RED}${C_B}◆ MAINNET CONFIRMATION ◆${C_R}"
        box_mid
        box_line "  ${C_RED}⚠ $CHAIN - Real value! ⚠${C_R}"
        box_line ""
        box_bot

        local ans
        while true; do
            if ! prompt_nav "  ➜ Confirm continuing on '$CHAIN' (yes/no): " ""; then
                [[ "$NAV_ACTION" == "quit" ]] && return 2
                [[ "$NAV_ACTION" == "main_menu" ]] && return 3
                NEXT_STEP=6; return 1
            fi
            case "$REPLY_VAL" in
                da|yes) break ;;
                ne|no) err "  Aborted on '$CHAIN' -- choose another chain."; NEXT_STEP=1; return 1 ;;
                *) err "  Enter 'yes' or 'no'." ;;
            esac
        done
        CONFIRM_MAINNET_FLAG=("--confirm-mainnet")
    else
        gutb "7/7 · MAINNET CONFIRMATION"
        info "  '$CHAIN' is a testnet -- no extra confirmation needed."
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Final summary + confirmation
# ---------------------------------------------------------------------------
summary() {
    local shown; shown="$(py_help banner "$CHAIN")"
    choose_pipeline

    echo
    box_top
    box_line "  ${C_B}RUN SUMMARY -- review before anything signs${C_R}"
    box_mid
    box_line "  Chain       : ${C_CYN}${shown}${C_R}"
    box_line "  RPC         : $(py_help rpc "$CHAIN")"
    box_line "  Funds from  : ${C_CYN}${FUNDING_WALLET}${C_R}"
    box_line "  Key         : ${KEY_FILE}"
    box_line "  Target(s)   : ${TARGETS_INPUT}"
    box_line "  Recovery    : ${C_CYN}${RECOVERY_WALLET}${C_R}"
    if (( ${#CONFIRM_MAINNET_FLAG[@]} > 0 )); then
        box_line "  Mainnet     : ${C_RED}YES -- real value${C_R}"
    else
        box_line "  Mainnet     : no (testnet)"
    fi
    box_line "  Running     : ${PIPELINE_MODE}"
    box_line "  Advanced    : $(advanced_summary)"
    box_bot
    echo
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
load_chains
load_settings

# run_wizard -- the 7-step run, driven from the main menu. Returns 0 when the
# pipeline was started (or dry-run printed), 1 when the user quit.
run_wizard() {
    reset_run_state
    local rc
    while (( STEP <= 7 )); do
        NEXT_STEP=$STEP
        case "$STEP" in
            1) step_chain    ;;
            2) step_rpc      ;;
            3) step_key      ;;
            4) step_targets  ;;
            5) step_recovery ;;
            6) step_policy   ;;
            7) step_mainnet  ;;
        esac
        rc=$?
        case "$rc" in
            0) STEP="$NEXT_STEP" ;;
            2) quit_wizard ;;
            3) return 1 ;;              # back to the main menu
            1) STEP="$NEXT_STEP"; (( STEP < 1 )) && STEP=1 ;;
        esac
        echo
    done

    summary
    if ! prompt_nav "  ➜ Start the pipeline with the settings above? (yes/no) [Enter = yes]: " "yes"; then
        [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
        warn "Aborted before starting."
        return 1
    fi
    if [[ "$REPLY_VAL" != "yes" && "$REPLY_VAL" != "da" ]]; then
        warn "Aborted before starting."
        return 1
    fi

    # -- Choose auto_pipeline.py (one target) or batch_pipeline.py (many) -----
    choose_pipeline
    build_advanced_flags
    if [[ $PIPELINE_LABEL == "batch_pipeline.py" ]]; then
        if [[ $IS_LIST_FILE -eq 1 ]]; then
            TARGETS_FILE="$TARGETS_INPUT"
        else
            TARGETS_FILE="$(mktemp "${TMPDIR:-/tmp}/forksploit_targets.XXXXXX")"
            trap 'rm -f "$TARGETS_FILE"' EXIT
            printf '%s\n' "${TARGET_PARTS[@]}" > "$TARGETS_FILE"
        fi
        RUN_CMD=("$PYTHON" batch_pipeline.py
            --targets "$TARGETS_FILE"
            --recovery-wallet "$RECOVERY_WALLET"
            --key "$KEY_FILE"
            --chain "$CHAIN"
            "${CONFIRM_MAINNET_FLAG[@]}"
            "${ADVANCED_FLAGS[@]}")
    else
        RUN_CMD=("$PYTHON" auto_pipeline.py
            --target "$TARGETS_INPUT"
            --recovery-wallet "$RECOVERY_WALLET"
            --key "$KEY_FILE"
            --chain "$CHAIN"
            "${CONFIRM_MAINNET_FLAG[@]}"
            "${ADVANCED_FLAGS[@]}")
    fi

    bold "-> Running $PIPELINE_LABEL"
    printf '   %s\n' "${RUN_CMD[*]}"
    if (( DRY_RUN )); then
        echo
        info "--dry-run: the command is ready, but I did NOT run it."
        return 0
    fi
    echo
    cd "$SCRIPTS_DIR" || { err "ERROR: cannot enter $SCRIPTS_DIR."; exit 1; }
    exec "${RUN_CMD[@]}"
}

matrix_logo
echo

check_env || exit 1
if (( DOCTOR_ONLY )); then
    echo
    bold "Doctor: the environment is ready."
    exit 0
fi

while true; do
    main_menu
    case "$MAIN_CHOICE" in
        wizard)
            run_wizard
            if (( DRY_RUN )); then
                # A dry run is a test/CI path: exit once the command is printed.
                exit 0
            fi
            ;;
        settings) settings_menu ;;
        advanced) advanced_menu ;;
        tools)    tools_menu ;;
        doctor)   show_doctor_page ;;
        help)     show_help_page ;;
        quit)     quit_wizard ;;
    esac
done

