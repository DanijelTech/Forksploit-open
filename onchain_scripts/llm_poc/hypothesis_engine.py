#!/usr/bin/env python3
"""LLM hypothesis-generation layer.

This component ONLY proposes a hypothesis -- a strict-JSON sequence of
attack steps -- by asking a local LLM (Hermes' llama-server, OpenAI-
compatible endpoint) to read contract source and think about what an
attacker could do. It has NO authority to decide whether the hypothesis
is correct; that is confirm_engine.py's job, executed afterwards against
a real local Anvil fork. "LLM proposes, simulator disposes."

Usage:
    python3 hypothesis_engine.py > hypothesis_llm.json
"""
import json
import os
import re
import sys
import urllib.request

HERMES_URL = "http://localhost:18081/v1/chat/completions"
MODEL = "HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive"
CONTRACTS_DIR = os.path.join(os.path.dirname(__file__), "contracts")

SYSTEM_PROMPT = """You are a smart-contract security researcher proposing a concrete, \
testable attack hypothesis. You do NOT get to decide if you are right -- a separate \
simulation engine will execute your exact steps against a real local blockchain fork \
and measure real token balance deltas. Be precise and concrete, not vague.

You MUST answer with ONLY a single JSON object (no prose outside it), in this exact \
schema:
{
  "description": "one sentence describing the attack",
  "steps": [
    {"actor": "attacker" | "victim", "contract": "token" | "vault",
     "function": "<exact Solidity function signature, e.g. deposit(uint256)>",
     "args": ["<arg1>", "<arg2>", ...], "value": "<wei amount as string, usually 0>"}
  ]
}

Rules:
- There are exactly two actors available: "attacker" and "victim". Both start with \
1000 * 10^18 token units of the asset token, and 0 vault shares.
- Addresses: use the literal placeholders "<vault>", "<token>", "<attacker>", "<victim>" \
in args where an address is needed -- the real deployed addresses are substituted later.
- Token transfers that move tokens INTO the vault via the vault's own deposit function \
require an ERC20 approve(vault, amount) step first from the same actor, because the \
vault calls transferFrom.
- All uint256 amounts are given in the token's base units (18 decimals), as plain \
decimal strings, e.g. "500000000000000000000" for 500 tokens.
- Output ONLY the JSON object. No markdown fences, no explanation before or after.
"""


def build_user_prompt():
    with open(os.path.join(CONTRACTS_DIR, "CustomVault.sol")) as f:
        vault_src = f.read()
    with open(os.path.join(CONTRACTS_DIR, "SimpleToken.sol")) as f:
        token_src = f.read()
    return f"""Here is the asset token contract (name "token" in your steps):

```solidity
{token_src}
```

Here is the vault contract (name "vault" in your steps) that the token is deposited \
into:

```solidity
{vault_src}
```

Find a concrete sequence of calls, available to the "attacker" actor (optionally also \
using the "victim" actor, if the attack requires a second real depositor to extract \
value from), that makes the attacker end up with MORE tokens than they started with, \
without the vault's owner ever giving them anything for free. Propose your best single \
hypothesis as the required JSON object."""


def call_hermes(max_tokens=4000, temperature=0.2):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt()},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    req = urllib.request.Request(
        HERMES_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read())
    return body["choices"][0]["message"]


def extract_json(content):
    """The model may wrap JSON in markdown fences or add stray text around it --
    pull out the first balanced {...} block."""
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if fence:
        content = fence.group(1)
    else:
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1:
            raise ValueError(f"no JSON object found in model output:\n{content}")
        content = content[start:end + 1]
    return json.loads(content)


def call_hermes_messages(messages, max_tokens=4000, temperature=0.2):
    payload = {
        "model": MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    req = urllib.request.Request(
        HERMES_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read())
    return body["choices"][0]["message"]


def parse_message(message):
    content = message.get("content", "") or ""
    reasoning = message.get("reasoning_content", "") or ""
    if not content.strip():
        raise RuntimeError(
            "model returned empty content (only reasoning) -- increase max_tokens.\n"
            f"reasoning_content was: {reasoning[:2000]}"
        )
    hypothesis = extract_json(content)
    if "steps" not in hypothesis or not isinstance(hypothesis["steps"], list):
        raise ValueError(f"malformed hypothesis, missing 'steps' list: {hypothesis}")
    return hypothesis, reasoning


def generate_hypothesis():
    """First-shot hypothesis, no prior feedback."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_prompt()},
    ]
    message = call_hermes_messages(messages)
    return parse_message(message)


def refine_hypothesis(messages, previous_hypothesis, confirm_result):
    """Feed the simulation engine's real REFUTED verdict back to the model
    and ask it to revise. This is in-context refinement for THIS run only --
    nothing is written back into model weights or any persistent store. Any
    "growing library of confirmed techniques" lives in
    skills/forksploit-contract-audit/references/confirmed-techniques.md as a
    plain readable log, never as implicit model learning."""
    feedback = f"""Your previous hypothesis was executed for real on a local blockchain \
fork. The simulation engine's verdict was: {confirm_result['verdict']}.
Attacker token balance before: {confirm_result['attacker_token_balance_before']}
Attacker token balance after: {confirm_result['attacker_token_balance_after']}
Profit: {confirm_result['attacker_profit_wei']}

Your hypothesis was WRONG (no real profit). Think about what real-world precondition \
is missing -- for a donation/inflation attack to extract value, there usually needs to \
be ANOTHER party whose deposit gets diluted by your inflated share price. You have a \
"victim" actor available for exactly this. Propose a REVISED hypothesis as the same \
strict JSON object, fixing this gap."""
    messages = messages + [
        {"role": "assistant", "content": json.dumps(previous_hypothesis)},
        {"role": "user", "content": feedback},
    ]
    message = call_hermes_messages(messages)
    hypothesis, reasoning = parse_message(message)
    return hypothesis, reasoning, messages


def main():
    hypothesis, reasoning = generate_hypothesis()
    if reasoning:
        print(f"[reasoning, {len(reasoning)} chars, not executed]", file=sys.stderr)
    print(json.dumps(hypothesis, indent=2))


if __name__ == "__main__":
    main()
