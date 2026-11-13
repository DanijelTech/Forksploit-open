#!/usr/bin/env python3
# Author: DanyTech
"""triage_findings.py -- collapse thousands of fuzzer plans into the handful
of REAL vulnerable surfaces behind them, and say, per surface, exactly what
stands between it and a runnable exploit.

The fuzzer is right to be noisy: a single bug on a single target routinely
produces thousands of plans (one ETC mainnet run turned 1022 "Stale Guard
Counter" hits into 1945 plans). But a plan is not a finding -- most are
near-duplicates of the same surface, and the ones that matter are the ones
that describe a real, exploitable capability. This script answers the two
questions a human actually has after a run:

  1. WHAT DID WE REALLY FIND?  -> distinct (target, bug_types, selectors)
     surfaces, with a count of how many duplicate plans collapsed into each.
  2. WHAT IS STOPPING EACH ONE FROM BEING A RUNNABLE EXPLOIT? -> a viability
     tier, derived from the plan's own fuzzer-stamped metadata:
       RUNNABLE              -- confirmed + replayable + single caller: this
                                pipeline can execute it as-is.
       NEEDS_MATERIALIZATION -- confirmed, but discovered with a faked call
                                return (control leak). The exploit depends on
                                a call returning a value the real chain will
                                never produce on its own; to run it for real,
                                that call must be replaced with a real state
                                change (e.g. an oracle price must be moved by
                                a real swap, not faked). The exact leaked
                                step (contract + fn_selector) is reported --
                                that is the concrete target for the work.
       NEEDS_MULTI_SENDER    -- confirmed, but the trace needs more than one
                                msg.sender; execute_plan drives everything
                                from one signer, so it reverts by construction.
       HEURISTIC_ONLY        -- Review-tier: no oracle ever observed real
                                fund movement. Honest evidence, not a bug to
                                exploit; never send it (see the pre-flight
                                gate's confirmed_exploitable rule).
       AMOUNT_UNREALISTIC    -- RUNNABLE except the trace's own value is so
                                large the signer could never fund it.

Usage:
    python3 onchain_scripts/triage_findings.py <work_dir_or_auto_work> [...]
    python3 onchain_scripts/triage_findings.py --json onchain_scripts/auto_work/*

No network, no chain, no wallet: pure analysis of what the fuzzer already
wrote to disk.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import strategy_layer  # noqa: E402

UINT32_MAX = 0xFFFFFFFF

# Viability tiers, most-actionable first. A surface is reported under the
# FIRST tier it qualifies for, so RUNNABLE always wins.
RUNNABLE = "RUNNABLE"
NEEDS_MATERIALIZATION = "NEEDS_MATERIALIZATION"
NEEDS_MULTI_SENDER = "NEEDS_MULTI_SENDER"
AMOUNT_UNREALISTIC = "AMOUNT_UNREALISTIC"
HEURISTIC_ONLY = "HEURISTIC_ONLY"

TIER_ORDER = [
    RUNNABLE,
    NEEDS_MATERIALIZATION,
    NEEDS_MULTI_SENDER,
    AMOUNT_UNREALISTIC,
    HEURISTIC_ONLY,
]

TIER_BLURB = {
    RUNNABLE: "confirmed + replayable + single caller -- executable as-is",
    NEEDS_MATERIALIZATION: "confirmed, but depends on a faked call return (control leak) -- replace the leaked call with a real state change",
    NEEDS_MULTI_SENDER: "confirmed, but the trace needs more than one msg.sender -- one-signer replay reverts",
    AMOUNT_UNREALISTIC: "runnable in shape, but the trace's own value is too large for any real signer to fund",
    HEURISTIC_ONLY: "Review-tier heuristic -- no oracle observed real fund movement (evidence, not an exploit)",
}


def _leaked_steps(plan: dict) -> list[dict]:
    """Steps whose discovery used host.rs's control-leak (a faked/intercepted
    call return). `call_leak == u32::MAX` means the step ran normally."""
    out = []
    for i, step in enumerate(plan.get("steps") or []):
        leak = step.get("call_leak")
        if leak is None:
            continue
        if int(leak) != UINT32_MAX:
            out.append({
                "index": i,
                "contract": step.get("contract"),
                "fn_selector": step.get("fn_selector"),
                "caller": step.get("caller"),
            })
    return out


def _selectors(finding: dict) -> tuple:
    """The distinct function selectors across a finding's steps -- the shape
    of the surface, used to tell two genuinely different surfaces apart."""
    sel = set()
    for step in finding["plan"].get("steps") or []:
        s = step.get("fn_selector")
        if s:
            sel.add(s.lower())
    return tuple(sorted(sel))


def surface_key(finding: dict) -> tuple:
    """Identity of the REAL vulnerable surface a plan describes. Two plans
    with the same target, same bug classes, same call shape and same leak
    profile are the same surface -- everything else is fuzzer noise."""
    plan = finding["plan"]
    return (
        str(plan.get("target") or "").lower(),
        str(plan.get("chain") or "").lower(),
        tuple(sorted(finding.get("bug_types") or [])),
        str(plan.get("kind") or ""),
        _selectors(finding),
        tuple(s["fn_selector"] for s in _leaked_steps(plan)),
        int(finding.get("distinct_callers", 1) or 1),
    )


def classify(finding: dict) -> tuple[str, str]:
    """Returns (tier, human detail) for one finding. See the module doc for
    what each tier means."""
    plan = finding["plan"]
    if not finding.get("confirmed_exploitable", True) and plan.get("kind") != "reentrancy":
        return HEURISTIC_ONLY, "bug_types are all Review-tier; no observed fund movement"

    leaked = _leaked_steps(plan)
    if leaked:
        where = ", ".join(
            f"step {s['index']} {s['contract']}.{s['fn_selector']}" for s in leaked
        )
        return NEEDS_MATERIALIZATION, f"faked call return at {where}"

    if int(finding.get("distinct_callers", 1) or 1) > 1:
        return NEEDS_MULTI_SENDER, f"trace spans {finding.get('distinct_callers')} distinct callers"

    if not finding.get("atomic_replayable", True):
        # Replayability false without a per-step leak recorded (older plans
        # predate the per-step field): still not replayable, still needs work.
        return NEEDS_MATERIALIZATION, "trace depends on a control leak (per-step detail unavailable)"

    return RUNNABLE, "no blocker found in the plan's own metadata"


def triage(work_dirs: list[Path]) -> dict:
    surfaces: dict[tuple, dict] = {}
    total_plans = 0
    for work in work_dirs:
        try:
            findings = strategy_layer.load_findings(work)
        except Exception:
            continue
        for finding in findings:
            total_plans += 1
            key = surface_key(finding)
            tier, detail = classify(finding)
            entry = surfaces.get(key)
            if entry is None:
                plan = finding["plan"]
                surfaces[key] = {
                    "target": plan.get("target"),
                    "chain": plan.get("chain"),
                    "bug_types": sorted(finding.get("bug_types") or []),
                    "kind": plan.get("kind"),
                    "selectors": list(_selectors(finding)),
                    "tier": tier,
                    "detail": detail,
                    "leaked_steps": _leaked_steps(plan),
                    "duplicate_plans": 0,
                    "example_plan": finding.get("plan_path"),
                }
            else:
                # A surface seen at more than one tier keeps the most
                # actionable one (RUNNABLE beats NEEDS_MATERIALIZATION ...).
                if TIER_ORDER.index(tier) < TIER_ORDER.index(entry["tier"]):
                    entry["tier"] = tier
                    entry["detail"] = detail
                    entry["leaked_steps"] = _leaked_steps(finding["plan"])
            surfaces[key]["duplicate_plans"] += 1

    by_tier: dict[str, list] = defaultdict(list)
    for entry in surfaces.values():
        by_tier[entry["tier"]].append(entry)
    return {
        "total_plans": total_plans,
        "distinct_surfaces": len(surfaces),
        "by_tier": {t: sorted(by_tier.get(t, []), key=lambda e: -e["duplicate_plans"]) for t in TIER_ORDER},
    }


def print_report(report: dict) -> None:
    total = report["total_plans"]
    distinct = report["distinct_surfaces"]
    print("=" * 78)
    print(f"FORKSPLOIT TRIAGE -- {total} plan(s) collapsed into {distinct} distinct surface(s)")
    print("=" * 78)
    if total and distinct:
        print(f"  (each surface below stands for ~{total // max(distinct, 1)} near-duplicate plan(s))\n")

    for tier in TIER_ORDER:
        entries = report["by_tier"].get(tier) or []
        if not entries:
            continue
        print(f"--- {tier} ({len(entries)} surface(s)) -- {TIER_BLURB[tier]}")
        for e in entries:
            bugs = ", ".join(e["bug_types"]) or "?"
            print(f"  [{e['duplicate_plans']:5} plan(s)] {e['target']} ({e['chain']}) kind={e['kind']} -- {bugs}")
            print(f"          {e['detail']}")
            if e["leaked_steps"]:
                for s in e["leaked_steps"]:
                    print(f"          -> leaked: {s['contract']}.{s['fn_selector']} (step {s['index']})")
            if e["selectors"]:
                print(f"          selectors: {', '.join(e['selectors'])}")
            print(f"          example: {e['example_plan']}")
        print()

    runnable = report["by_tier"].get(RUNNABLE) or []
    materialize = report["by_tier"].get(NEEDS_MATERIALIZATION) or []
    print("=" * 78)
    print("WHAT TO DO NEXT")
    print("=" * 78)
    if runnable:
        print(f"  {len(runnable)} surface(s) are RUNNABLE -- run them as-is (the pre-flight")
        print("  gate will still skip any that the fork proves unprofitable).")
    else:
        print("  0 surfaces are runnable as-is.")
    if materialize:
        print(f"\n  {len(materialize)} surface(s) need MATERIALIZATION -- each is a real,")
        print("  confirmed bug whose exploit currently depends on a faked call return.")
        print("  The fix is per-surface: replace the leaked call listed above with a")
        print("  real state change (e.g. move an oracle price with a real swap), then")
        print("  re-run. These are the concrete targets for that work.")
    heur = report["by_tier"].get(HEURISTIC_ONLY) or []
    if heur:
        print(f"\n  {len(heur)} surface(s) are HEURISTIC-ONLY -- correctly never sent;")
        print("  they stay in vuln_info.jsonl as evidence.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("work_dirs", nargs="+", help="work dir(s), e.g. onchain_scripts/auto_work/*")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of the report")
    args = ap.parse_args()

    dirs = []
    for w in args.work_dirs:
        p = Path(w)
        if not p.exists():
            print(f"warning: {p} does not exist, skipping", file=sys.stderr)
            continue
        dirs.append(p)
    if not dirs:
        print("error: no valid work dir given", file=sys.stderr)
        return 1

    report = triage(dirs)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
