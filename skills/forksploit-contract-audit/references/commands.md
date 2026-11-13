# Command reference for a ForkSploit controlled review

A collection of the exact commands used through `../SKILL.md`, for quick copying
during work. All paths are relative to the ForkSploit repository root unless stated
otherwise. Replace the `<...>` placeholders with real values — never leave them
literally in a command.

## Node verification (PHASE 1)

```bash
# Chain ID (0x1 = ETH mainnet, 0x3d = ETC mainnet)
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
  <RPC_URL>

# Current block (check that it moves)
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  <RPC_URL>
```

## Verifying a local node in Docker (PHASE 1, if the user is unsure about the port)

```bash
# Shows the actual host-mapped port (the PORTS column) -- an internal port
# inside the container (e.g. 8545/tcp without the "0.0.0.0:...->" prefix) is NOT
# reachable from outside
docker ps
```

## Setting up a fork (PHASE 2)

```bash
# Start a fork on a separate port (8555), NOT 8545 (avoid a collision)
# --hardfork shanghai is MANDATORY for ETC (and probably other pre-Cancun chains) --
# without it EVERY eth_call on the fork fails with "Excess blob gas not set."
anvil --fork-url <VERIFIED_REAL_RPC_URL> --port 8555 --hardfork shanghai &

# Confirm the fork sees the target's real code
cast code <TARGET_ADDRESS> --rpc-url http://127.0.0.1:8555

# Confirm eth_call actually works (expect an ordinary EVM revert, NOT an RPC error)
cast call <TARGET_ADDRESS> "owner()(address)" --rpc-url http://127.0.0.1:8555
```

## Finding verified source code for a real, already-deployed target (before PHASE 4)

```bash
# Free, no API key. Replace "etc" with the appropriate chain's Blockscout instance.
curl -s "https://etc.blockscout.com/api/v2/smart-contracts/<TARGET_ADDRESS>" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('is_verified:', d.get('is_verified')); open('target_source.sol','w').write(d.get('source_code','')); json.dump(d.get('abi'), open('target_abi.json','w'))"
```

## Verifying ACTUAL ownership of funds (PHASE 4a, for pooled/staking contracts)

```bash
# Replace "stakes"/"mana" with the actual getter function of THIS contract (balanceOf,
# deposits, etc. -- check the ABI/source from the previous step)
cast call <TARGET_ADDRESS> "stakes(address)(uint256)" <WALLET_FROM_PHASE_0> --rpc-url http://127.0.0.1:8555
cast call <TARGET_ADDRESS> "mana(address)(uint256)" <WALLET_FROM_PHASE_0> --rpc-url http://127.0.0.1:8555
```

## RPC override (PHASE 3 and PHASE 7)

Run from the `onchain_scripts/` directory (or with `PYTHONPATH` set to it).

```bash
# Set the override to the FORK (safe exploration)
python3 -c "from chains import set_rpc_override; set_rpc_override('eth', 'http://127.0.0.1:8555')"

# Set the override to the REAL node (only after PHASE 6!)
python3 -c "from chains import set_rpc_override; set_rpc_override('eth', '<REAL_URL>')"

# Clear the override (PHASE 9, always at the end)
python3 -c "from chains import clear_rpc_override; clear_rpc_override('eth')"

# Check where the override currently points
python3 -c "from chains import get_rpc_url; print(get_rpc_url('eth'))"
```

Replace `'eth'` with `'etc'` for Ethereum Classic.

## The main cycle (PHASE 3 and PHASE 7)

```bash
python3 onchain_scripts/auto_pipeline.py \
  --target <TARGET_ADDRESS_OR_PATH_TO_.bin> \
  --recovery-wallet <RECOVERY_WALLET> \
  --key <PATH_TO_KEY_FILE> \
  --chain <eth|etc> \
  --confirm-mainnet \
  --fund-eth 0.01 \
  --fuzz-seconds 300 \
  --detectors all
```

Notes:
- `--confirm-mainnet` is MANDATORY for `eth`/`etc` even on a fork (see SKILL.md PHASE 3).
- `--key` in PHASE 3 (fork) = a test/throwaway key. `--key` in PHASE 7 (real node) =
  the user's real key, supplied freshly at that moment.
- `--fuzz-seconds 300` is a reasonable start; for more complex contracts it can take
  longer (see the `--detectors`/`--concolic` options directly in
  `./target/release/forksploit evm --help`, if `auto_pipeline.py` finds nothing in 300s).

## Direct ForkSploit launch (if `auto_pipeline.py` is not suitable, e.g. analysis only
## without exploit execution)

```bash
./target/release/forksploit evm \
  -t <TARGET_ADDRESS> \
  -c <eth|etc> \
  -u <FORK_OR_REAL_NODE_RPC_URL> \
  -f --run-forever \
  -d all \
  -w <WORK_DIR>
```

Output: `<WORK_DIR>/vulnerabilities/*.t.sol` (a proof for EVERY finding),
`*.plan.json` (a structured exploit plan), `*Exploit.s.sol` (ONLY for `(sim-confirmed)`
bug types — see `src/evm/solution/mod.rs`'s `is_confirmed_exploitable_bug`).
`(sim-confirmed)`/`(sim-review)` are ONLY simulation labels (see `src/evm/oracle.rs`) —
NEVER equate them with real on-chain confirmation (`PLAN_CONFIRMED` in
`auto_pipeline.py`, PHASE 7/8).

## Checking balances (PHASE 5 and PHASE 8)

```bash
cast balance <RECOVERY_WALLET> --rpc-url <FORK_OR_REAL_NODE_RPC_URL>
```

Always compare BEFORE and AFTER — record the value BEFORE running PHASE 3/7, not only
afterwards.

## Manually running a generated exploit script (if needed outside `auto_pipeline.py`)

```bash
forge script <PATH_TO_XExploit.s.sol> \
  --tc <ContractName>ExploitRunner \
  --rpc-url <FORK_OR_REAL_NODE_RPC_URL> \
  --private-key <KEY> \
  --broadcast
```
