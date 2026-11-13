#!/usr/bin/env bash
# proof_w1_w2_w3.sh -- reproducible proof (R1) that AttackWallet's W1/W2/W3
# fixes actually hold, against a throwaway local anvil node. No forge-std,
# no mocks: the REAL compiled AttackWallet is deployed and exercised.
#
#   W1: execute() with a step that reverts must REVERT the whole tx
#       (previously it returned success=false and the outer tx succeeded).
#   W2: executeBatch() runs a sequence atomically and reverts entirely on a
#       failing step (the earlier steps' effects are rolled back).
#   W3: sweep() must reach a CONTRACT recipient that needs >2300 gas
#       (previously .transfer() forwarded only 2300 and reverted).
#
# Usage: ./proof_w1_w2_w3.sh [rpc_url]
set -u
RPC="${1:-http://127.0.0.1:8547}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SOLC="${SOLC:-solc}"
CAST="${CAST:-cast}"

pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }

echo "=== compiling AttackWallet.sol + harness ==="
OUT="$(mktemp -d)"
"$SOLC" "$HERE/AttackWallet.sol" "$HERE/demo/W1W2W3Harness.sol" --bin --overwrite -o "$OUT" >/dev/null || { echo "compile failed"; exit 2; }
AW_BIN="$(cat "$OUT/AttackWallet.bin")"
REV_BIN="$(cat "$OUT/Reverter.bin")"
RECV_BIN="$(cat "$OUT/StorageReceiver.bin")"
CNT_BIN="$(cat "$OUT/Counter.bin")"

KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # anvil acct 0
OWNER=$("$CAST" wallet address --private-key $KEY)
echo "owner=$OWNER rpc=$RPC"

send() { "$CAST" send --rpc-url "$RPC" --private-key $KEY "$@" >/dev/null 2>&1; }
# Deploy via cast, returning the created address (cast prints
# `contractAddress  <addr>` in the receipt it emits on stdout).
deploy() {
  "$CAST" send --rpc-url "$RPC" --private-key $KEY --create "0x$1" 2>/dev/null \
    | awk '/^contractAddress/ {print $2}'
}

AW=$(deploy "$AW_BIN")
REV=$(deploy "$REV_BIN")
RECV=$(deploy "$RECV_BIN")
CNT=$(deploy "$CNT_BIN")
echo "AttackWallet=$AW Reverter=$REV Receiver=$RECV Counter=$CNT"
send "$AW" "setSafeWallet(address)" "$RECV"

# ---------------------------------------------------------------- W1
echo "=== W1: execute() with a reverting step must REVERT the tx ==="
BOOM=$("$CAST" calldata "boom()")
# Simulate AS the owner (cast call defaults to a random sender -> onlyOwner
# would revert and the test would pass vacuously).
if "$CAST" call --rpc-url "$RPC" --from "$OWNER" "$AW" "execute(address,bytes,uint256)" "$REV" "$BOOM" 0 >/dev/null 2>&1; then
  bad "W1: execute() did NOT revert on a failing step (silent failure is back)"
else
  ok "W1: execute() reverts when its step reverts"
fi
# And the CONTROL: the same call with a NON-reverting step must SUCCEED, so
# the PASS above is not just "everything reverts".
BUMP0=$("$CAST" calldata "bump()")
if "$CAST" call --rpc-url "$RPC" --from "$OWNER" "$AW" "execute(address,bytes,uint256)" "$CNT" "$BUMP0" 0 >/dev/null 2>&1; then
  ok "W1 control: execute() succeeds on a good step (so the revert above is the step's)"
else
  bad "W1 control: execute() reverted even on a good step -- test is not meaningful"
fi

# ---------------------------------------------------------------- W2
echo "=== W2: executeBatch() is atomic; a failing step rolls back earlier ones ==="
BUMP=$("$CAST" calldata "bump()")
# batch: bump() then boom() -> must revert, Counter.count stays 0
if "$CAST" call --rpc-url "$RPC" --from "$OWNER" "$AW" "executeBatch(address[],bytes[],uint256[])" "[$CNT,$REV]" "[$BUMP,$BOOM]" "[0,0]" >/dev/null 2>&1; then
  bad "W2: executeBatch() did NOT revert on a failing step"
else
  ok "W2: executeBatch() reverts when a step fails"
fi
COUNT=$("$CAST" call --rpc-url "$RPC" "$CNT" "count()(uint256)")
if [ "$COUNT" = "0" ]; then ok "W2: earlier step's effect was rolled back (count=0)"; else bad "W2: count=$COUNT (expected 0 -- not atomic)"; fi
# batch: bump() then bump() -> succeeds, count becomes 2
"$CAST" send --rpc-url "$RPC" --private-key $KEY "$AW" "executeBatch(address[],bytes[],uint256[])" "[$CNT,$CNT]" "[$BUMP,$BUMP]" "[0,0]" >/dev/null 2>&1
COUNT=$("$CAST" call --rpc-url "$RPC" "$CNT" "count()(uint256)")
if [ "$COUNT" = "2" ]; then ok "W2: a fully-successful batch applies every step (count=2)"; else bad "W2: count=$COUNT (expected 2)"; fi

# ---------------------------------------------------------------- W3
echo "=== W3: sweep() must reach a CONTRACT recipient needing >2300 gas ==="
send "$AW" --value 1ether   # fund AttackWallet
BAL_BEFORE=$("$CAST" balance "$RECV" --rpc-url "$RPC")
# sweep() is onlyOwner, so simulate AS the owner (cast call defaults to a
# random sender, which would revert "not owner" and prove nothing).
if "$CAST" call --rpc-url "$RPC" --from "$OWNER" "$AW" "sweep()" >/dev/null 2>&1; then
  ok "W3: sweep() succeeded (contract recipient reachable)"
else
  bad "W3: sweep() reverted to a contract recipient (2300-gas limit is back)"
fi
# confirm on-chain by actually sending and checking the recipient got paid + its storage wrote
send "$AW" --value 1ether
"$CAST" send --rpc-url "$RPC" --private-key $KEY "$AW" "sweep()" >/dev/null 2>&1
BAL_AFTER=$("$CAST" balance "$RECV" --rpc-url "$RPC")
HITS=$("$CAST" call --rpc-url "$RPC" "$RECV" "hits()(uint256)")
if [ "$BAL_AFTER" -gt "$BAL_BEFORE" ] && [ "$HITS" != "0" ]; then
  ok "W3: recipient received ETH and its receive() wrote storage (hits=$HITS)"
else
  bad "W3: recipient balance=$BAL_AFTER hits=$HITS (expected both to move)"
fi

echo
echo "=== RESULT: $pass passed, $fail failed ==="
rm -rf "$OUT"
[ "$fail" -eq 0 ]
