#!/usr/bin/env python3
"""Confirmation engine for LLM-proposed attack hypotheses.

This is the part the human (not the LLM) is required to build and fully
control: given a hypothesis (a sequence of {actor, contract, function,
args, value} steps proposed by an LLM), it deploys FRESH instances of the
target contracts on the already-running local Anvil fork, executes the
steps for real via `cast send`, and decides CONFIRMED (the attacker's own
token balance is provably higher after the sequence than before it) or
REFUTED (it reverted, or balance did not increase) purely from on-chain
balance deltas. The LLM never gets to declare its own hypothesis a
success -- only real balance numbers do.

Usage:
    python3 confirm_engine.py hypothesis.json
"""
import json
import os
import subprocess
import sys

RPC = "http://127.0.0.1:8560"
CONTRACTS_DIR = os.path.join(os.path.dirname(__file__), "contracts")

ATTACKER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ATTACKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
VICTIM_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
VICTIM = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

INITIAL_MINT = 1000 * 10**18

ACTORS = {
    "attacker": (ATTACKER, ATTACKER_KEY),
    "victim": (VICTIM, VICTIM_KEY),
}


def _env():
    env = os.environ.copy()
    foundry_bin = os.path.expanduser("~/.foundry/bin")
    env["PATH"] = foundry_bin + ":" + env.get("PATH", "")
    return env


def cast(*args, check=True):
    cmd = ["cast"] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, env=_env())
    if check and result.returncode != 0:
        raise RuntimeError(
            f"cast {' '.join(args)} failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout.strip(), result.returncode


def read_bytecode(name):
    with open(os.path.join(CONTRACTS_DIR, f"{name}.bin")) as f:
        return f.read().strip()


def deploy_fresh():
    """Deploy brand-new SimpleToken + CustomVault instances, deployed by
    the attacker key (deployment itself grants no advantage here -- the
    vault's logic is the same regardless of who deploys it)."""
    token_bytecode = read_bytecode("SimpleToken")
    out, _ = cast(
        "send", "--rpc-url", RPC, "--private-key", ATTACKER_KEY,
        "--create", "0x" + token_bytecode, "--json",
    )
    token_addr = json.loads(out)["contractAddress"]

    vault_bytecode = read_bytecode("CustomVault")
    ctor_args, _ = cast("abi-encode", "constructor(address)", token_addr)
    ctor_args = ctor_args.strip()[2:]  # drop 0x
    out, _ = cast(
        "send", "--rpc-url", RPC, "--private-key", ATTACKER_KEY,
        "--create", "0x" + vault_bytecode + ctor_args, "--json",
    )
    vault_addr = json.loads(out)["contractAddress"]
    return token_addr, vault_addr


def mint(token_addr, to_addr, amount):
    cast(
        "send", token_addr, "mint(address,uint256)", to_addr, str(amount),
        "--rpc-url", RPC, "--private-key", ATTACKER_KEY,
    )


def balance_of(token_addr, addr):
    out, _ = cast("call", token_addr, "balanceOf(address)(uint256)", addr, "--rpc-url", RPC)
    return int(out.split()[0])


def resolve_placeholder(value, token_addr, vault_addr):
    if not isinstance(value, str):
        return value
    return (
        value
        .replace("<token>", token_addr)
        .replace("<vault>", vault_addr)
        .replace("<attacker>", ATTACKER)
        .replace("<victim>", VICTIM)
    )


def execute_step(step, token_addr, vault_addr):
    actor = step["actor"]
    if actor not in ACTORS:
        raise ValueError(f"unknown actor '{actor}' (must be 'attacker' or 'victim')")
    _, key = ACTORS[actor]

    contract = step["contract"]
    target = {"token": token_addr, "vault": vault_addr}.get(contract)
    if target is None:
        raise ValueError(f"unknown contract '{contract}' (must be 'token' or 'vault')")

    func_sig = step["function"]
    args = [resolve_placeholder(a, token_addr, vault_addr) for a in step.get("args", [])]
    value = str(step.get("value", "0"))

    cast_args = ["send", target, func_sig] + [str(a) for a in args] + [
        "--rpc-url", RPC, "--private-key", key, "--value", value,
    ]
    _, rc = cast(*cast_args, check=False)
    return rc == 0


def run_hypothesis(hypothesis):
    token_addr, vault_addr = deploy_fresh()
    mint(token_addr, ATTACKER, INITIAL_MINT)
    mint(token_addr, VICTIM, INITIAL_MINT)

    attacker_before = balance_of(token_addr, ATTACKER)

    log = []
    for i, step in enumerate(hypothesis["steps"]):
        ok = execute_step(step, token_addr, vault_addr)
        log.append({"step": i, "ok": ok, **step})
        if not ok:
            log[-1]["note"] = "reverted or failed -- stopping sequence"
            break

    attacker_after = balance_of(token_addr, ATTACKER)
    victim_after = balance_of(token_addr, VICTIM)
    profit = attacker_after - attacker_before

    verdict = "CONFIRMED" if profit > 0 and all(s["ok"] for s in log) else "REFUTED"

    return {
        "verdict": verdict,
        "attacker_token_balance_before": attacker_before,
        "attacker_token_balance_after": attacker_after,
        "attacker_profit_wei": profit,
        "victim_token_balance_after": victim_after,
        "token_addr": token_addr,
        "vault_addr": vault_addr,
        "steps_executed": log,
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 confirm_engine.py hypothesis.json", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1]) as f:
        hypothesis = json.load(f)
    result = run_hypothesis(hypothesis)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["verdict"] == "CONFIRMED" else 1)


if __name__ == "__main__":
    main()
