#!/usr/bin/env bash
# forksploit.sh -- the one interactive entry point for running ForkSploit's
# full register -> fund -> fuzz -> exploit -> recover pipeline.
#
# UPGRADED v2.0 - Matrix Theme (črna, zelena, temno siva)
# - Logo "ForkSploit" je vedno prikazan na vrhu vsakega zaslona
# - Glavni meni s svojimi podmeniji (nov tek / nastavitve / doctor / pomoč)
# - Okvirčki za polja za vnos podatkov
# - Navigacija: nazaj (en korak), glavni meni, izhod
#
# What this script does, in order, before it touches anything:
#   1. PREFLIGHT ("doctor"): detect the OS, verify the build/runtime
#      prerequisites (Rust toolchain, z3 + pkg-config + clang/cmake, python3
#      + the onchain_scripts requirements, the built binary), and -- only
#      with your explicit confirmation -- install whatever is missing and
#      build the release binary. Nothing is installed silently.
#   2. MAIN MENU: a persistent menu with submenus -- Nov tek (the wizard),
#      Nastavitve (default key / per-chain RPC), Preveri okolje (full
#      doctor report), Pomoč (what the tool does), izhod (quit).
#   3. WIZARD: ask the three roles the whole run commits to -- WHO funds
#      (private-key file), WHAT is audited (one or more contracts), WHERE
#      recovered funds go (recovery wallet) -- plus the chain and RPC, with
#      a final read-back summary you confirm before anything signs.
#   4. EXEC: hand off to auto_pipeline.py (one target) or batch_pipeline.py
#      (many), exactly as the old script did.
#
# Navigation: every question accepts "nazaj" (redo the previous step),
# "glavni meni" (return to main menu), and "izhod" (abort cleanly).
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
        -h|--help) sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'neznana zastavica: %s (poskusi --help)\n' "$1" >&2; exit 2 ;;
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
# Persisted advanced settings (Nastavitve -> Napredne nastavitve)
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
    [[ -z "$s" ]] && s="privzete (brez dodatnih zastavic)"
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
    print("da" if args[0] in TESTNET_CHAINS else "ne")
elif fn == "list_chains":
    from chains import DEFAULT_RPC, TESTNET_CHAINS, chain_banner, chain_title
    tests = sorted(c for c in DEFAULT_RPC if c in TESTNET_CHAINS)
    mains = sorted(c for c in DEFAULT_RPC if c not in TESTNET_CHAINS)
    for c in tests + mains:
        tag = "testnet" if c in TESTNET_CHAINS else "mainnet"
        print(f"{c}|{chain_title(c)}|{chain_banner(c)}|{tag}")
else:
    sys.exit("neznana pomožna funkcija: " + fn)
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
        record warn "$(warn_s "$(printf '%-22s %s' "$desc" "${C_YEL}manjka${C_R}")")"
    fi
}

check_env() {
    MISSING_PKGS=(); PKG_OK=(); CHECK_LINES=()
    detect_os

    box_top
    box_line "  ${C_B}PREDLETNO PREVERJANJE OKOLJA${C_R} ${C_DIM}(doctor)${C_R}"
    box_mid
    box_line "  Sistem : ${C_CYN}${OS_NAME}${C_R} ${C_DIM}($(uname -m))${C_R}"
    if [[ -n "$PKG_MGR" ]]; then
        box_line "  Paketi : ${C_CYN}${PKG_MGR}${C_R}"
    else
        box_line "  Paketi : ${C_YEL}neznan upravljalnik -- namestitve ne bom izvajal sam${C_R}"
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
        record warn "$(warn_s "$(printf '%-22s %s' "cargo (Rust)" "manjka -- namestitev prek rustup")")"
    fi
    if command -v rustup >/dev/null 2>&1; then
        record ok "$(ok_s "$(printf '%-22s %s' "rustup" "ok")")"
    else
        rust_ok=0
        record warn "$(warn_s "$(printf '%-22s %s' "rustup" "manjka")")"
    fi

    # Python requirements (special: installed via pip).
    local deps_ok=1
    if have_python_deps; then
        record ok "$(ok_s "$(printf '%-22s %s' "python odvisnosti" "web3, fastapi, uvicorn, ...")")"
    else
        deps_ok=0
        record warn "$(warn_s "$(printf '%-22s %s' "python odvisnosti" "manjkajo -- glej onchain_scripts/requirements.txt")")"
    fi

    # Optional (never blocks a run).
    if command -v anvil >/dev/null 2>&1; then
        record ok "$(ok_s "$(printf '%-22s %s' "anvil (opcijsko)" "ok -- pre-flight fork simulacija bo na voljo")")"
    else
        record info "$(info_s "$(printf '%-22s %s' "anvil (opcijsko)" "ni nameščen -- pre-flight fork simulacija bo preskočena")")"
    fi
    if command -v solc >/dev/null 2>&1 || [[ -x "$HOME/.svm/0.8.24/solc-0.8.24" ]]; then
        record ok "$(ok_s "$(printf '%-22s %s' "solc (opcijsko)" "ok")")"
    else
        record info "$(info_s "$(printf '%-22s %s' "solc (opcijsko)" "ni nameščen -- potreben le za .sol cilje")")"
    fi

    # Built binary.
    local bin_ok=0
    if [[ -x "$BIN" ]]; then
        bin_ok=1
        record ok "$(ok_s "$(printf '%-22s %s' "binarij" "$BIN")")"
    else
        record warn "$(warn_s "$(printf '%-22s %s' "binarij" "$BIN ni zgrajen")")"
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
            ok "Okolje je pripravljeno (vse, kar je potrebno, je na mestu)."
        else
            info "$n_warn stvar(i) manjka -- glej zgoraj (opcijske vrstice '·' niso težava)."
        fi
    fi

    # Install missing system packages (one confirmation for all).
    if (( ${#MISSING_PKGS[@]} > 0 )); then
        echo
        if [[ -n "$PKG_MGR" ]]; then
            local cmdline; cmdline="$(pkg_install_cmdline "${MISSING_PKGS[@]}")" || cmdline=""
            if [[ -n "$cmdline" ]]; then
                bold "Manjka ${#MISSING_PKGS[@]} sistemskih odvisnosti. Namestim jih z:"
                echo "    $cmdline"
                if (( NO_INSTALL )); then
                    info "Preskočeno (--no-install). Namesti ročno: $cmdline"
                else
                    local ans
                    read -rp "  ➜ Namestim zdaj? (da/ne) [Enter = ne]: " ans
                    if [[ "$ans" == "da" ]]; then
                        if pkg_install_run "${MISSING_PKGS[@]}"; then
                            ok "Sistemske odvisnosti nameščene."
                            MISSING_PKGS=()
                        else
                            err "Namestitev ni uspela -- namesti ročno: $cmdline"
                        fi
                    else
                        info "Preskočeno. Namesti ročno: $cmdline"
                    fi
                fi
            fi
        else
            warn "Ne poznam upravljalnika paketov za ta sistem. Namesti ročno (glej README.md, razdelek Namestitev)."
        fi
    fi

    # Rust toolchain install offer.
    if (( rust_ok == 0 )); then
        echo
        bold "Rust orodja manjkajo. Uradni namestitveni ukaz:"
        echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
        if (( NO_INSTALL )); then
            info "Preskočeno (--no-install). Namesti ročno z zgornjim ukazom."
        else
            local ans
            read -rp "  ➜ Zaženem uradni rustup namestitveni program zdaj? (da/ne) [Enter = ne]: " ans
            if [[ "$ans" == "da" ]]; then
                if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; then
                    # shellcheck disable=SC1091
                    [[ -f "$HOME/.cargo/env" ]] && . "$HOME/.cargo/env"
                    command -v cargo >/dev/null 2>&1 && ok "Rust nameščen." || warn "Rust nameščen, a 'cargo' še ni na PATH -- odpri novo lupino."
                else
                    err "Namestitev Rust-a ni uspela."
                fi
            else
                info "Preskočeno. Namesti ročno z zgornjim ukazom."
            fi
        fi
    fi

    # Python requirements install offer.
    if (( deps_ok == 0 )); then
        echo
        bold "Python odvisnosti manjkajo. Predlagani ukaz:"
        echo "    $PYTHON -m pip install -r $REQ_FILE"
        if (( NO_INSTALL )); then
            info "Preskočeno (--no-install)."
        else
            local ans
            read -rp "  ➜ Namestim jih zdaj? (da/ne) [Enter = ne]: " ans
            if [[ "$ans" == "da" ]]; then
                if "$PYTHON" -m pip install -r "$REQ_FILE"; then
                    ok "Python odvisnosti nameščene."
                else
                    err "pip namestitev ni uspela (morda 'externally-managed-environment')."
                    info "Poskusi: python3 -m venv .venv && .venv/bin/pip install -r $REQ_FILE"
                fi
            else
                info "Preskočeno."
            fi
        fi
    fi

    # Build the release binary if it is missing and cargo is available.
    if (( bin_ok == 0 )) && command -v cargo >/dev/null 2>&1; then
        echo
        bold "Binarij še ni zgrajen. Zgradim ga z:"
        echo "    cargo build --release"
        if (( NO_INSTALL )); then
            info "Preskočeno (--no-install). Zgradi ročno: cargo build --release"
        else
            local ans
            read -rp "  ➜ Zgradim zdaj? (traja lahko več minut) (da/ne) [Enter = da]: " ans
            if [[ -z "$ans" || "$ans" == "da" ]]; then
                info "Gradim ... (to lahko traja dlje časa)"
                if (cd "$REPO_ROOT" && cargo build --release); then
                    ok "Zgrajeno: $BIN"
                    bin_ok=1
                else
                    err "Gradnja ni uspela -- odpravi napake zgoraj in poskusi znova."
                fi
            else
                info "Preskočeno."
            fi
        fi
    fi

    echo
    if [[ ! -x "$BIN" ]]; then
        err "Binarij '$BIN' še vedno manjka -- brez njega pipeline ne more teči."
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
    local __hint=" ${C_DIM}(nazaj = prejšnji · glavni meni = MM · izhod = EXIT)${C_R}"
    if ! read -rp "${__prompt}${__hint}" __input; then
        NAV_ACTION="quit"; return 1
    fi
    if [[ -z "$__input" && -n "$__default" ]]; then
        __input="$__default"
    fi
    case "$__input" in
        nazaj) NAV_ACTION="back"; return 1 ;;
        glavni\ meni|MM) NAV_ACTION="main_menu"; return 1 ;;
        izhod|EXIT) NAV_ACTION="quit"; return 1 ;;
        *) NAV_ACTION=""; REPLY_VAL="$__input"; return 0 ;;
    esac
}

# menu [--root] <title> <opt...> -- numbered selection; each opt is
# "value|label". An opt whose value is "#" is a non-selectable section header
# (printed as a dim line; it does not consume a number). Entries are laid out
# in a compact multi-column grid, so a long list never becomes a single-column
# wall.
#
# Navigation is by WORD only -- 'nazaj'/'glavni meni'/'izhod' (aliases 0, MM,
# q). Numbers belong to the entries alone: an earlier version also bound 1/2/3
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

    # Draw navigation bar with frame. The root menu has no 'glavni meni'
    # (it *is* the main menu) and no 'nazaj' (nowhere to go back to).
    echo
    input_field_top "NAVIGACIJA"
    if (( __root )); then
        input_field "Nazaj (korak)" "ni -- glavni meni"
        input_field "Glavni meni" "že si tukaj"
        input_field "Izhod" "izhod"
    else
        input_field "Nazaj (korak)" "nazaj"
        input_field "Glavni meni" "glavni meni"
        input_field "Izhod" "izhod"
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
        if ! read -rp "  ➜ Izberi [1-$n] (Enter = $__def): " __in; then
            NAV_ACTION="quit"; return 1
        fi
        [[ -z "$__in" ]] && __in=$__def
        case "$__in" in
            0|nazaj)
                if (( __root )); then
                    err "  V glavnem meniju ni 'nazaj' -- izberi vrstico ali 'izhod'."
                    continue
                fi
                NAV_ACTION="back"; return 1 ;;
            glavni\ meni|MM)
                if (( __root )); then
                    err "  Že si v glavnem meniju -- izberi vrstico ali 'izhod'."
                    continue
                fi
                NAV_ACTION="main_menu"; return 1 ;;
            izhod|EXIT|q|Q) NAV_ACTION="quit"; return 1 ;;
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
        err "  Neveljavna izbira -- vnesi številko 1-$n, ime, 'nazaj', 'glavni meni' ali 'izhod'."
    done
}

quit_wizard() {
    echo
    bold "Prekinjeno na zahtevo uporabnika."
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
        "#|${C_DIM}Pregled in izvedba${C_R}"
        "wizard|Nov tek -- čarovnik (veriga → RPC → ključ → cilji → recovery → potrditev)"
        "#|${C_DIM}Nastavitve in pomoč${C_R}"
        "settings|Nastavitve (privzeti ključ, RPC po verigi)"
        "doctor|Preveri okolje (doctor) -- kaj je na voljo, kaj manjka"
        "help|Pomoč -- kaj ForkSploit počne in kaj pomenijo koraki"
        "#|${C_DIM}Napredno in orodja${C_R}"
        "advanced|Napredne nastavitve teka (fuzzing, financiranje, pre-flight)"
        "tools|Orodja -- monitor, triage, materialize, dashboard, DEX, fixture"
    )
    MENU_DEFAULT_VAL="wizard"
    while true; do
        new_page
        matrix_logo
        echo
        if menu --root "GLAVNI MENI" "${opts[@]}"; then
            MAIN_CHOICE="$REPLY_VAL"; return 0
        fi
        [[ "$NAV_ACTION" == "quit" ]] && { MAIN_CHOICE="quit"; return 0; }
        # --root rejects 'nazaj'/'glavni meni', so nothing else can land here.
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
        gutb "NASTAVITVE"
        gutc "Trajne privzete vrednosti, shranjene med teki."
        echo
        box_top
        box_line "  ${C_GREEN}◆ NASTAVITVE ◆${C_R}"
        box_mid
        input_field "Privzeti ključ" "$DEFAULT_KEY"
        input_field "RPC (veriga)" "${CHAIN:-ni izbrana}"
        box_bot
        echo

        local -a opts=(
            "key|Nastavi privzeti ključ (pot do datoteke)"
            "rpc|Nastavi RPC za verigo"
            "back|Nazaj v glavni meni"
        )
        MENU_DEFAULT_VAL="back"
        if ! menu "Izberi nastavitev:" "${opts[@]}"; then
            [[ "$NAV_ACTION" == "quit" ]] && { quit_wizard; }
            return 0                     # 'nazaj'/'glavni meni' -> main menu
        fi
        case "$REPLY_VAL" in
            key)
                local kf
                if ! prompt_nav "  ➜ Pot do datoteke s ključem [$DEFAULT_KEY]: " "$DEFAULT_KEY"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                kf="$REPLY_VAL"
                if [[ ! -f "$kf" ]]; then
                    err "  Datoteka '$kf' ne obstaja."
                    continue
                fi
                local wallet
                if ! wallet="$(py_help wallet_from_key "$kf" 2>&1)"; then
                    err "  '$kf' ne vsebuje veljavnega privatnega ključa."
                    continue
                fi
                DEFAULT_KEY="$kf"
                ok "Privzeti ključ nastavljen: ${C_CYN}${wallet}${C_R}  (${kf})"
                ;;
            rpc)
                local ch
                if ! prompt_nav "  ➜ Veriga (npr. sepolia, eth, etc) [${CHAIN:-sepolia}]: " "${CHAIN:-sepolia}"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                ch="$REPLY_VAL"
                local cur
                if ! cur="$(py_help rpc "$ch" 2>&1)"; then
                    err "  Veriga '$ch' ni znana ForkSploit-u."
                    continue
                fi
                gut "  Trenutni RPC za '$ch': ${C_CYN}${cur}${C_R}"
                local url
                if ! prompt_nav "  ➜ Nov RPC URL (Enter = obdrži): " ""; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                url="$REPLY_VAL"
                if [[ -z "$url" ]]; then
                    info "  Obdržan: $cur"
                elif py_help set_rpc "$ch" "$url"; then
                    ok "  Shranjen RPC za '$ch': $url"
                else
                    err "  Shranjevanje RPC-ja ni uspelo."
                fi
                ;;
            back) return 0 ;;
        esac
        echo
        read -rp "  ➜ Enter za nadaljevanje ..." _ || true
    done
}

# ---------------------------------------------------------------------------
# Advanced run settings (Nastavitve -> Napredne nastavitve)
# ---------------------------------------------------------------------------
# Exposes only REAL auto_pipeline.py / batch_pipeline.py flags. Values are
# persisted in $SETTINGS_FILE; an empty value means "unset". Each editor
# validates its input and re-asks on a bad value (never a hard exit).
advanced_menu() {
    while true; do
        new_page
        matrix_logo
        echo
        gutb "NAPREDNE NASTAVITVE TEKA"
        gutc "Veljajo za vsak zagon iz čarovnika. Prazno = privzeto (zastavica se izpusti)."
        echo
        box_top
        box_line "  ${C_GREEN}◆ NAPREDNE NASTAVITVE ◆${C_R}"
        box_mid
        input_field "Fuzz trajanje" "${FUZZ_SECONDS:+${FUZZ_SECONDS}s}"
        input_field "Detektorji" "${DETECTORS:-privzeto (all)}"
        input_field "Financiranje" "${FUND_ETH:+${FUND_ETH} ETH}"
        input_field "Pre-flight vrata" "$( (( NO_PREFLIGHT )) && echo 'IZKLOPLJENA' || echo 'vklopljena (privzeto)' )"
        input_field "Gas oracle" "$( (( NO_GAS_ORACLE )) && echo 'IZKLOPLJEN' || echo 'vklopljen (privzeto)' )"
        box_bot
        echo

        local -a opts=(
            "fuzz|Nastavi trajanje fuzzinga (sekunde, npr. 300)"
            "det|Nastavi detektorje (all / high_confidence / seznam)"
            "fund|Nastavi začetno financiranje cilja (ETH, npr. 0.01)"
            "preflight|Preklopi pre-flight vrata izplativosti (vklop/izklop)"
            "gasoracle|Preklopi gas-fee oracle (vklop/izklop)"
            "reset|Ponastavi vse napredne nastavitve na privzete"
            "back|Nazaj v glavni meni"
        )
        MENU_DEFAULT_VAL="back"
        if ! menu "Izberi nastavitev:" "${opts[@]}"; then
            [[ "$NAV_ACTION" == "quit" ]] && { quit_wizard; }
            return 0
        fi
        case "$REPLY_VAL" in
            fuzz)
                local v
                if ! prompt_nav "  ➜ Fuzz trajanje v sekundah (Enter = privzeto/počisti): " "$FUZZ_SECONDS"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                v="$REPLY_VAL"
                if [[ -z "$v" ]]; then FUZZ_SECONDS=""
                elif [[ "$v" =~ ^[0-9]+$ ]] && (( v > 0 )); then FUZZ_SECONDS="$v"
                else err "  '$v' ni pozitivno celo število sekund -- poskusi znova."; continue; fi
                save_settings; ok "Shranjeno."
                ;;
            det)
                local v
                if ! prompt_nav "  ➜ Detektorji (all / high_confidence / npr. reentrancy,erc20): " "$DETECTORS"; then
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
                else err "  Neveljaven vnos -- uporabi 'all', 'high_confidence' ali imena, ločena z vejico."; continue; fi
                save_settings; ok "Shranjeno."
                ;;
            fund)
                local v
                if ! prompt_nav "  ➜ Začetno financiranje cilja v ETH (Enter = brez): " "$FUND_ETH"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                v="$REPLY_VAL"
                if [[ -z "$v" ]]; then FUND_ETH=""
                elif [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]]; then FUND_ETH="$v"
                else err "  '$v' ni veljavno število (npr. 0.01) -- poskusi znova."; continue; fi
                save_settings; ok "Shranjeno."
                ;;
            preflight)
                (( NO_PREFLIGHT )) && NO_PREFLIGHT=0 || NO_PREFLIGHT=1
                save_settings
                (( NO_PREFLIGHT )) && warn "Pre-flight vrata: IZKLOPLJENA (teče vsak plan za res)." || ok "Pre-flight vrata: vklopljena."
                ;;
            gasoracle)
                (( NO_GAS_ORACLE )) && NO_GAS_ORACLE=0 || NO_GAS_ORACLE=1
                save_settings
                (( NO_GAS_ORACLE )) && warn "Gas oracle: IZKLOPLJEN (cena iz vozlišča)." || ok "Gas oracle: vklopljen."
                ;;
            reset)
                FUZZ_SECONDS=""; DETECTORS=""; FUND_ETH=""; NO_PREFLIGHT=0; NO_GAS_ORACLE=0
                save_settings; ok "Napredne nastavitve ponastavljene na privzete."
                ;;
            back) return 0 ;;
        esac
        echo
        read -rp "  ➜ Nadaljevanje ..." _ || true
    done
}

# ---------------------------------------------------------------------------
# Tools menu (Pomožna orodja) -- launches the OTHER onchain_scripts/ tools
# that the wizard does not run: monitor, triage, materialize, dashboard,
# DEX scanner, chain-fixture generator. Every entry prints the exact command
# and, unless it is a long-running server/monitor, runs it after a confirm.
# ---------------------------------------------------------------------------
run_tool() { # run_tool <label> <cmd...>
    local label="$1"; shift
    echo
    gutb "Ukaz:"
    printf '   %s\n' "$*"
    local ans
    read -rp "  ➜ Zaženi ta ukaz? (da/ne) [Enter = ne]: " ans || true
    if [[ "$ans" == "da" ]]; then
        ( cd "$SCRIPTS_DIR" && "$@" )
    else
        info "Preskočeno (ukaz je izpisan zgoraj)."
    fi
}

tools_menu() {
    while true; do
        new_page
        matrix_logo
        echo
        gutb "ORODJA"
        gutc "Pomožna orodja onchain_scripts/. Nekatera so dolgotrajna (monitor, dashboard)."
        echo
        box_top
        box_line "  ${C_GREEN}◆ ORODJA ◆${C_R}"
        box_mid
        box_line "  ${C_DIM}Vsa orodja tečejo iz onchain_scripts/, z izbranimi privzetki.${C_R}"
        box_bot
        echo

        local -a opts=(
            "monitor|Monitor -- nadzor žive pogodbe po deployu (odliv/nova tx)"
            "triage|Triage -- razčleni plane v work_dir na resnične površine"
            "materialize|Materialize -- control-leak površine, nato odpri dashboard"
            "dashboard|Dashboard -- lokalni web nadzor (privzeto port 4114)"
            "dex|DEX arbitraža -- skener cross-DEX priložnosti"
            "fixture|Generiraj 'chain' fixture za merjenje globine"
            "back|Nazaj v glavni meni"
        )
        MENU_DEFAULT_VAL="back"
        if ! menu "Izberi orodje:" "${opts[@]}"; then
            [[ "$NAV_ACTION" == "quit" ]] && { quit_wizard; }
            return 0
        fi
        case "$REPLY_VAL" in
            monitor)
                local ch addr
                if ! prompt_nav "  ➜ Veriga za monitor [${CHAIN:-sepolia}]: " "${CHAIN:-sepolia}"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 0
                    continue
                fi
                ch="$REPLY_VAL"
                if ! prompt_nav "  ➜ Naslov pogodbe (0x...): " ""; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                addr="$REPLY_VAL"
                if [[ ! "$addr" =~ ^0x[0-9a-fA-F]{40}$ ]]; then err "  Neveljaven naslov."; continue; fi
                run_tool "monitor" "$PYTHON" monitor.py --chain "$ch" --address "$addr"
                ;;
            triage)
                local wd
                if ! prompt_nav "  ➜ Work dir (ali vzorec, npr. auto_work/*): " "auto_work/*"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                wd="$REPLY_VAL"
                # shellcheck disable=SC2086
                # (intentional glob expansion)
                ( cd "$SCRIPTS_DIR" && "$PYTHON" triage_findings.py $wd ) || err "  Triage ni uspel (ali ni najdb v $wd)."
                read -rp "  ➜ Nadaljevanje ..." _ || true
                ;;
            materialize)
                local wd
                if ! prompt_nav "  ➜ Work dir (ali vzorec, npr. auto_work/*): " "auto_work/*"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                wd="$REPLY_VAL"
                # shellcheck disable=SC2086
                # (intentional glob expansion)
                ( cd "$SCRIPTS_DIR" && "$PYTHON" materialize_plan.py $wd ) || err "  Materialize ni uspel (ali ni površin v $wd)."
                echo
                # Per the request, Materialize also opens the dashboard GUI so
                # the worklist can be inspected visually. NOTE (R3): the
                # dashboard is the same projection as the standalone Dashboard
                # entry -- it does NOT itself render the materialize worklist
                # (dashboard_server.py has no materialize view); the worklist
                # is the terminal output printed just above.
                local ans
                read -rp "  ➜ Odprem dashboard GUI v brskalniku? (da/ne) [Enter = ne]: " ans || true
                if [[ "$ans" == "da" ]]; then
                    info "Dashboard teče, dokler ga ne prekineš s Ctrl-C."
                    ( cd "$SCRIPTS_DIR" && bash server_run.sh 4114 )
                    read -rp "  ➜ Nadaljevanje ..." _ || true
                fi
                ;;
            dashboard)
                local port
                if ! prompt_nav "  ➜ Port za dashboard [4114]: " "4114"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                port="$REPLY_VAL"
                info "Dashboard teče, dokler ga ne prekineš s Ctrl-C. Brskalnik se odpre sam."
                ( cd "$SCRIPTS_DIR" && bash server_run.sh "$port" )
                read -rp "  ➜ Nadaljevanje ..." _ || true
                ;;
            dex)
                run_tool "dex" "$PYTHON" dex_arbitrage_scanner.py --chain "${CHAIN:-eth}"
                ;;
            fixture)
                local depth dir
                if ! prompt_nav "  ➜ Globina (št. korakov, npr. 4): " "4"; then
                    [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
                    continue
                fi
                depth="$REPLY_VAL"
                if ! prompt_nav "  ➜ Izhodna mapa [work_dir/chain_fixture]: " "work_dir/chain_fixture"; then
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
    read -rp "  ➜ Enter za vrnitev v glavni meni ..." _ || true
}

# ---------------------------------------------------------------------------
# Help page
# ---------------------------------------------------------------------------
show_help_page() {
    new_page
    matrix_logo
    echo
    box_top
    box_line "  ${C_GREEN}${C_B}◆ POMOČ ◆${C_R}"
    box_mid
    gutb "Kaj ForkSploit počne"
    gut "Poišče resničen, izvedljiv exploit na pametni pogodbi in ga -- z jasnim"
    gut "dokazom -- izvede, nato pobrana sredstva pobere na recovery denarnico."
    gut ""
    gutb "Čarovnik vpraša natanko tri vloge, preden karkoli podpiše:"
    gut "  · KDO financira  -- datoteka s privatnim ključem (plača ves gas),"
    gut "  · KAJ se pregleduje -- naslov 0x… ali pot do .sol/.bin (več z vejico),"
    gut "  · KAM gredo sredstva -- recovery denarnica (0x…, 40 hex znakov)."
    gut "Poleg tega izbereš verigo (testnet/mainnet) in RPC."
    gut ""
    gutb "Koraki (1/7 … 7/7)"
    gut "  1/7 VERIGA     -- izberi omrežje (dvonivojski podmeni)."
    gut "  2/7 RPC        -- privzeti ali svoj RPC endpoint."
    gut "  3/7 KDO FINANCIRA -- pot do datoteke s privatnim ključem."
    gut "  4/7 CILJI      -- en ali več naslovov/poti."
    gut "  5/7 RECOVERY   -- kam se poberejo sredstva."
    gut "  6/7 WALLET POLICY -- zakleni funding + recovery za to verigo."
    gut "  7/7 MAINNET    -- izrecna potrditev, če veriga ni testnet."
    gut ""
    gutb "Pomikanje"
    gut "  V čarovniku: 'nazaj' (prejšnji korak), 'glavni meni' (nazaj v meni),"
    gut "  'izhod' (prekini). V menijih izbereš vrstico s številko ali imenom;"
    gut "  'q' prekine, 'nazaj'/'glavni meni' se vrneta."
    gut ""
    gutc "Napačen vnos nikoli ne vrže izhoda -- skript znova vpraša ali vrne korak."
    box_bot
    echo
    read -rp "  ➜ Enter za vrnitev v glavni meni ..." _ || true
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
        PIPELINE_MODE="batch_pipeline.py  (več ciljev)"
    else
        PIPELINE_LABEL="auto_pipeline.py"
        PIPELINE_MODE="auto_pipeline.py  (en cilj)"
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
        gutb "1/7 · VERIGA"
        gutc "Omrežje, na katerem teče celoten tek."
        local -a gopts=(
            "testnet|Testna omrežja   ${C_DIM}(varna za preizkus)${C_R}"
            "mainnet|Glavna omrežja   ${C_DIM}(resnična vrednost)${C_R}"
        )
        MENU_DEFAULT_VAL="testnet"
        if ! menu "Izberi vrsto omrežja:" "${gopts[@]}"; then
            [[ "$NAV_ACTION" == "quit" ]] && return 2
            [[ "$NAV_ACTION" == "main_menu" ]] && return 3
            NEXT_STEP=1; return 1
        fi
        kind="$REPLY_VAL"
        if [[ "$kind" == "testnet" ]]; then kindname="Testna omrežja"; else kindname="Glavna omrežja"; fi

        # Page 2 -- the chains of that kind, on a fresh page.
        while true; do
            new_page
            local -a copts=()
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                c="${line%%|*}"; title="${line#*|}"
                copts+=("$c|$title")
            done < <(chains_of_kind "$kind")
            gutb "1/7 · VERIGA › $kindname"
            MENU_DEFAULT_VAL="sepolia"
            if ! menu "Izberi verigo:" "${copts[@]}"; then
                [[ "$NAV_ACTION" == "quit" ]] && return 2
                [[ "$NAV_ACTION" == "main_menu" ]] && return 3
                break                     # 'nazaj' -> back to page 1 (kind)
            fi
            candidate="$REPLY_VAL"
            shown="$(py_help banner "$candidate")"
            echo
            bold "  Izbrana veriga: $shown"
            while true; do                # confirm by re-typing the chain name
                if ! prompt_nav "  ➜ Ponovi ime verige, da potrdiš ('$candidate'): " ""; then
                    [[ "$NAV_ACTION" == "quit" ]] && return 2
                    [[ "$NAV_ACTION" == "main_menu" ]] && return 3
                    continue 2            # 'nazaj' -> back to page 2 (chain list)
                fi
                if [[ "$REPLY_VAL" == "$candidate" ]]; then
                    CHAIN="$candidate"; return 0
                fi
                err "  '$candidate' in '$REPLY_VAL' se ne ujemata -- poskusi znova (ali 'nazaj'/'glavni meni')."
            done
        done
    done
}

step_rpc() {
    NEXT_STEP=3
    gutb "2/7 · RPC"
    local current
    if ! current="$(py_help rpc "$CHAIN" 2>&1)"; then
        err "NAPAKA: veriga '$CHAIN' ni znana ForkSploit-u."
        NEXT_STEP=1; return 1
    fi
    gut "Trenutni RPC za '$CHAIN': ${C_CYN}${current}${C_R}"
    gutc "Pusti privzetega ali vnesi svoj. Svoj RPC se SHRANI za vse prihodnje teke na tej verigi."

    # Draw input frame
    echo
    box_top
    box_line ""
    box_line "  ${C_GREEN}◆ VNESI RPC URL ◆${C_R}"
    box_mid
    input_field "Trenutni RPC" "$current"
    box_line ""
    box_bot

    if ! prompt_nav "  ➜ RPC URL (Enter = obdrži zgornjega): " ""; then
        [[ "$NAV_ACTION" == "quit" ]] && return 2
        [[ "$NAV_ACTION" == "main_menu" ]] && return 3
        NEXT_STEP=1; return 1
    fi
    if [[ -n "$REPLY_VAL" ]]; then
        py_help set_rpc "$CHAIN" "$REPLY_VAL"
        ok "Shranjen kot privzeti RPC za '$CHAIN': $REPLY_VAL"
    else
        info "Obdržan: $current"
    fi
    return 0
}

step_key() {
    NEXT_STEP=4
    gutb "3/7 · KDO FINANCIRA"
    gutc "Datoteka s privatnim ključem denarnice, ki PLAČA ves gas (deploy, financiranje, izvedbo exploitov)."

    echo
    box_top
    box_line ""
    box_line "  ${C_GREEN}◆ VNESI POT DO KLJUČA ◆${C_R}"
    box_mid
    input_field "Privzeta pot" "$DEFAULT_KEY"
    box_line ""
    box_bot

    local kf
    if ! prompt_nav "  ➜ Pot do datoteke s ključem [$DEFAULT_KEY]: " "$DEFAULT_KEY"; then
        [[ "$NAV_ACTION" == "quit" ]] && return 2
        [[ "$NAV_ACTION" == "main_menu" ]] && return 3
        NEXT_STEP=2; return 1
    fi
    kf="$REPLY_VAL"
    if [[ ! -f "$kf" ]]; then
        err "  Datoteka '$kf' ne obstaja -- poskusi znova (ali 'nazaj'/'glavni meni')."
        return 1
    fi
    local wallet
    if ! wallet="$(py_help wallet_from_key "$kf" 2>&1)"; then
        err "  '$kf' ne vsebuje veljavnega privatnega ključa."
        err "  $(printf '%s' "$wallet" | tail -1)"
        return 1
    fi
    KEY_FILE="$kf"
    FUNDING_WALLET="$wallet"
    ok "Financirajoča denarnica: ${C_CYN}${FUNDING_WALLET}${C_R}"
    return 0
}

step_targets() {
    NEXT_STEP=5
    gutb "4/7 · KAJ SE PREGLEDUJE"
    gut "Vnesi ENO od:"
    gut "  · en naslov 0x... ali pot do .sol/.bin (za deploy),"
    gut "  · več ciljev, ločenih z vejico (0xAAA...,0xBBB...,path/To.sol),"
    gut "  · pot do datoteke s seznamom (ena pogodba na vrstico)."

    echo
    box_top
    box_line ""
    box_line "  ${C_GREEN}◆ VNESI CILJ(I) ◆${C_R}"
    box_mid
    box_line ""
    box_line "  ${C_DIM}0x... ali pot do .sol/.bin datoteke${C_R}"
    box_line "  ${C_DIM}Več ciljev: ločenih z vejico${C_R}"
    box_line "  ${C_DIM}Datoteka s seznamom${C_R}"
    box_line ""
    box_bot

    local ans
    while true; do
        if ! prompt_nav "  ➜ Cilj(i): " ""; then
            [[ "$NAV_ACTION" == "quit" ]] && return 2
            [[ "$NAV_ACTION" == "main_menu" ]] && return 3
            NEXT_STEP=3; return 1
        fi
        ans="$REPLY_VAL"
        [[ -n "$ans" ]] && break
        err "  Brez cilja ni kaj pregledovati -- poskusi znova."
    done
    TARGETS_INPUT="$ans"
    return 0
}

step_recovery() {
    NEXT_STEP=6
    gutb "5/7 · KAM GREDO SREDSTVA"
    gutc "Recovery denarnica: kam se poberejo VSA najdena sredstva (ETH in ERC20), ko se koraki končajo."

    echo
    box_top
    box_line ""
    box_line "  ${C_GREEN}◆ VNESI RECOVERY DENARNICO ◆${C_R}"
    box_mid
    box_line ""
    box_line "  ${C_DIM}Format: 0x + 40 hex znakov${C_R}"
    box_line "  ${C_DIM}Primer: 0x1234567890abcdef1234567890abcdef12345678${C_R}"
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
        err "  '$ans' ni veljaven naslov (pričakovano 0x + 40 hex znakov) -- poskusi znova."
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
        gutc "Za verigo '$CHAIN' še ni registriranega wallet policy-ja."
        gut "Zaklenil bom natanko ti dve denarnici za VSE prihodnje teke na '$CHAIN':"
        gut "  funding_wallet  = ${C_CYN}${FUNDING_WALLET}${C_R}"
        gut "  recovery_wallet = ${C_CYN}${RECOVERY_WALLET}${C_R}"
        local ans
        if ! prompt_nav "  ➜ Potrdi registracijo (da/ne): " ""; then
            [[ "$NAV_ACTION" == "quit" ]] && return 2
            [[ "$NAV_ACTION" == "main_menu" ]] && return 3
            NEXT_STEP=5; return 1
        fi
        ans="$REPLY_VAL"
        if [[ "$ans" != "da" ]]; then
            err "  Brez registriranega policy-ja se ne nadaljuje -- popravi denarnici."
            NEXT_STEP=5; return 1
        fi
        local reg
        if ! reg="$("$PYTHON" "$SCRIPTS_DIR/wallet_policy.py" register \
            --chain "$CHAIN" --confirm-chain "$CHAIN" \
            --funding-wallet "$FUNDING_WALLET" --recovery-wallet "$RECOVERY_WALLET" --confirm 2>&1)"; then
            err "NAPAKA pri registraciji wallet policy-ja:"
            echo "$reg" >&2
            NEXT_STEP=5; return 1
        fi
        printf '%s\n' "$reg" | gut_block "    "
        ok "Wallet policy registriran."
    else
        info "Wallet policy za '$CHAIN' je že registriran:"
        printf '%s\n' "$out" | gut_block "    "
        gutc "Če se denarnici ne ujemata z registriranima, bo pipeline to zavrnil, preden karkoli podpiše."
    fi
    return 0
}

step_mainnet() {
    NEXT_STEP=8
    CONFIRM_MAINNET_FLAG=()
    local is_testnet
    is_testnet="$(py_help is_testnet "$CHAIN")"
    if [[ "$is_testnet" == "ne" ]]; then
        gutb "7/7 · MAINNET POTRDITEV"
        gut "  ${C_RED}${C_B}'$CHAIN' NI testnet -- to je resnična veriga z resnično vrednostjo.${C_R}"

        echo
        box_top
        box_line ""
        box_line "  ${C_RED}${C_B}◆ POTRDITEV MAINNET ◆${C_R}"
        box_mid
        box_line "  ${C_RED}⚠ $CHAIN - Resnična vrednost! ⚠${C_R}"
        box_line ""
        box_bot

        local ans
        while true; do
            if ! prompt_nav "  ➜ Potrdi nadaljevanje na '$CHAIN' (da/ne): " ""; then
                [[ "$NAV_ACTION" == "quit" ]] && return 2
                [[ "$NAV_ACTION" == "main_menu" ]] && return 3
                NEXT_STEP=6; return 1
            fi
            case "$REPLY_VAL" in
                da) break ;;
                ne) err "  Prekinjeno na '$CHAIN' -- izberi drugo verigo."; NEXT_STEP=1; return 1 ;;
                *) err "  Vnesi 'da' ali 'ne'." ;;
            esac
        done
        CONFIRM_MAINNET_FLAG=("--confirm-mainnet")
    else
        gutb "7/7 · MAINNET POTRDITEV"
        info "  '$CHAIN' je testnet -- dodatna potrditev ni potrebna."
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
    box_line "  ${C_B}POVZETEK TEKA -- preveri, preden karkoli podpiše${C_R}"
    box_mid
    box_line "  Veriga      : ${C_CYN}${shown}${C_R}"
    box_line "  RPC         : $(py_help rpc "$CHAIN")"
    box_line "  Financira   : ${C_CYN}${FUNDING_WALLET}${C_R}"
    box_line "  Ključ       : ${KEY_FILE}"
    box_line "  Cilj(i)     : ${TARGETS_INPUT}"
    box_line "  Recovery    : ${C_CYN}${RECOVERY_WALLET}${C_R}"
    if (( ${#CONFIRM_MAINNET_FLAG[@]} > 0 )); then
        box_line "  Mainnet     : ${C_RED}DA -- resnična vrednost${C_R}"
    else
        box_line "  Mainnet     : ne (testnet)"
    fi
    box_line "  Poganjam    : ${PIPELINE_MODE}"
    box_line "  Napredno    : $(advanced_summary)"
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
    if ! prompt_nav "  ➜ Zaženi pipeline z zgornjimi nastavitvami? (da/ne) [Enter = da]: " "da"; then
        [[ "$NAV_ACTION" == "quit" ]] && quit_wizard
        warn "Prekinjeno pred zagonom."
        return 1
    fi
    if [[ "$REPLY_VAL" != "da" ]]; then
        warn "Prekinjeno pred zagonom."
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

    bold "-> Poganjam $PIPELINE_LABEL"
    printf '   %s\n' "${RUN_CMD[*]}"
    if (( DRY_RUN )); then
        echo
        info "--dry-run: ukaz je pripravljen, a ga NISEM zagnal."
        return 0
    fi
    echo
    cd "$SCRIPTS_DIR" || { err "NAPAKA: ne morem priti v $SCRIPTS_DIR."; exit 1; }
    exec "${RUN_CMD[@]}"
}

matrix_logo
echo

check_env || exit 1
if (( DOCTOR_ONLY )); then
    echo
    bold "Doctor: okolje je pripravljeno."
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

