#!/usr/bin/env python3
"""The full LLM-hypothesis / simulation-confirmation loop.

"LLM proposes, ForkSploit's simulation engine confirms or refutes -- never
the reverse." Hermes (hypothesis_engine.py) proposes a concrete attack; this
script hands it, unmodified, to confirm_engine.py, which executes it for
real against a local Anvil fork and returns a verdict backed by actual
token balance deltas. If REFUTED, the real verdict is fed back to Hermes
for in-context revision (NOT model training -- nothing persists past this
process) for up to --max-rounds attempts.

Usage:
    python3 run_loop.py [--max-rounds N]
"""
import argparse
import json
import sys

import confirm_engine
import hypothesis_engine


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-rounds", type=int, default=3)
    args = parser.parse_args()

    print(f"=== Round 1: first-shot hypothesis ===", file=sys.stderr)
    hypothesis, reasoning = hypothesis_engine.generate_hypothesis()
    messages = [
        {"role": "system", "content": hypothesis_engine.SYSTEM_PROMPT},
        {"role": "user", "content": hypothesis_engine.build_user_prompt()},
    ]

    for round_num in range(1, args.max_rounds + 1):
        print(f"--- round {round_num}: hypothesis ---", file=sys.stderr)
        print(json.dumps(hypothesis, indent=2), file=sys.stderr)

        result = confirm_engine.run_hypothesis(hypothesis)
        print(f"--- round {round_num}: verdict = {result['verdict']} "
              f"(profit = {result['attacker_profit_wei']}) ---", file=sys.stderr)

        if result["verdict"] == "CONFIRMED":
            print(json.dumps({
                "final_verdict": "CONFIRMED",
                "rounds_needed": round_num,
                "hypothesis": hypothesis,
                "confirm_result": result,
            }, indent=2))
            sys.exit(0)

        if round_num == args.max_rounds:
            break

        print(f"=== Round {round_num + 1}: refining after REFUTED ===", file=sys.stderr)
        hypothesis, reasoning, messages = hypothesis_engine.refine_hypothesis(
            messages, hypothesis, result
        )

    print(json.dumps({
        "final_verdict": "REFUTED",
        "rounds_needed": args.max_rounds,
        "hypothesis": hypothesis,
        "confirm_result": result,
    }, indent=2))
    sys.exit(1)


if __name__ == "__main__":
    main()
