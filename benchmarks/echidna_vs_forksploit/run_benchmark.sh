#!/usr/bin/env bash
# Author: DanyTech
# Reproducible Echidna-vs-ForkSploit benchmark on the SAME real contract:
# CyberScratchLottery 0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee (ETC Mordor).
#
# Both tools run against the identical deployed bytecode/ABI. ForkSploit reads
# the real on-chain contract in Address mode; Echidna runs its property harness
# that only wraps the real contract (no game logic is reimplemented).
#
# Prereqs: foundry (anvil/cast), echidna, solc 0.8.24, built ./target/release/forksploit
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
RPC_REMOTE="${RPC_REMOTE:-https://rpc.mordor.etccooperative.org}"
ANVIL_PORT="${ANVIL_PORT:-18545}"
TARGET=0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee
BUDGET="${BUDGET:-120}"

echo "[1/4] start anvil fork of Mordor ($RPC_REMOTE) on :$ANVIL_PORT"
anvil --fork-url "$RPC_REMOTE" --hardfork shanghai --port "$ANVIL_PORT" --chain-id 63 >/tmp/anvil_bench.log 2>&1 &
ANVIL_PID=$!
sleep 6
BLOCK=$(cast block-number --rpc-url "http://localhost:$ANVIL_PORT")

echo "[2/4] ForkSploit (Address mode) ${BUDGET}s"
rm -rf /tmp/fs_bench
timeout "$BUDGET" ./target/release/forksploit evm -t "$TARGET" -c mordor \
  -u "http://localhost:$ANVIL_PORT" -b "$BLOCK" -f --run-forever \
  -w /tmp/fs_bench > /tmp/fs_bench.log 2>&1
echo "  ForkSploit findings:"
grep -oE '\[[A-Za-z /0-9]+\] \(sim-[a-z]+\)' /tmp/fs_bench.log | sort | uniq -c

echo "[3/4] Echidna (property harness) ${BUDGET}s"
( cd "$HERE/target" && timeout "$BUDGET" echidna LotteryEchidna.sol --contract LotteryEchidna \
    --test-mode property --test-limit 5000000 > /tmp/echidna_bench.log 2>&1 )
echo "  Echidna results:"
grep -E 'echidna_.*(failed|passing)' /tmp/echidna_bench.log

echo "[4/4] stop anvil"
kill "$ANVIL_PID" 2>/dev/null
echo "Logs: /tmp/fs_bench.log /tmp/echidna_bench.log"
