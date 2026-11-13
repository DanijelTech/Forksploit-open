#!/usr/bin/env bash
# Author: DanyTech
# ForkSploit bootstrap -- rebuild the ENTIRE environment with a single command.
# Verified 2026-11-07: z3 4.13.3 + Rust nightly + cargo build --release = EXIT 0.
# Run in a PERSISTENT /workspace (survives a sandbox recycle).
# Usage:  bash /workspace/bootstrap_forklsploit.sh
set -u
ROOT=/workspace
REPO=$ROOT/ForkSploit
AUDIT=$ROOT/audit
LOG=$AUDIT/bootstrap.log
mkdir -p "$AUDIT"
exec > >(tee -a "$LOG") 2>&1
echo "==================== BOOTSTRAP $(date -u +%FT%TZ) ===================="

echo "[1/6] z3 + build tools (VERIFIED: apt-get update is required)"
if [ ! -f /usr/include/z3.h ]; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq z3 libz3-dev build-essential pkg-config clang || echo "  apt FAIL"
fi
echo "  z3: $(z3 --version 2>/dev/null || echo NONE)"

echo "[2/6] Rust nightly (the repo uses the nightly rust-toolchain)"
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
echo "  $(cargo --version 2>/dev/null || echo 'cargo NONE')"

echo "[3/6] Foundry (anvil/forge/cast)"
if ! command -v anvil >/dev/null 2>&1; then
  curl -sL https://foundry.paradigm.xyz | bash
  export PATH="$PATH:$HOME/.foundry/bin"
  foundryup
fi
export PATH="$PATH:$HOME/.foundry/bin"
echo "  $(anvil --version 2>/dev/null | head -1 || echo 'anvil NONE')"

echo "[4/6] Python dependencies"
pip install -q pyevmasm requests web3 eth-account 2>/dev/null && echo "  pip OK"

echo "[5/6] ForkSploit repo"
if [ -d "$REPO/.git" ]; then
  (cd "$REPO" && git fetch -q origin && git checkout -q main && git pull -q --ff-only origin main)
else
  git clone -q "https://${GITHUB_TOKEN}@github.com/DanijelTech/ForkSploit.git" "$REPO"
fi
(cd "$REPO" && git --no-pager log --oneline -1)

echo "[6/6] cargo build --release (z3 link)"
(cd "$REPO" && . "$HOME/.cargo/env" && cargo build --release 2>&1 | tail -3)
[ -x "$REPO/target/release/forksploit" ] && echo "  BINARY OK: $REPO/target/release/forksploit" || echo "  BUILD FAIL"

echo "==================== DONE ===================="
echo "Audit:  $AUDIT  (AUDIT_STATUS.md, DAOETC_reconstructed.sol, probe*.py)"
echo "Fork:   anvil --fork-url https://etc.etcdesktop.com --chain-id 61 --gas-limit 8000000 --hardfork shanghai"
echo "Fuzzer: $REPO/target/release/forksploit evm --help"
