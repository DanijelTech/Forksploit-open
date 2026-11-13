#!/usr/bin/env python3
"""materialize_plan.py -- turn every NEEDS_MATERIALIZATION surface into a
concrete, per-call materialization worklist.

`triage_findings.py` answers "which surfaces are real, and what blocks each
one". For the surfaces blocked by a control leak (a faked call return during
discovery) it names the exact leaked step. This module takes that one step
further and answers the only question left before the exploit can be built:

    WHAT IS THAT LEAKED CALL, AND WHAT REAL STATE CHANGE REPLACES IT?

A control leak means the fuzzer proved the bug under the assumption that some
call returns a value the real chain will not produce on its own. The exploit
is real, but it needs a prefix -- a real transaction sequence that MAKES that
call return what the exploit needs. That prefix is the materialization
recipe, and its shape depends entirely on what the leaked call IS:

  TOKEN_BALANCE / TOKEN_APPROVE  -> the leak stood in for "the attacker holds
      / has approved enough tokens". Materialize by actually acquiring them
      (a real swap, a whale transfer, or -- if the attacker has no such path
      -- this surface is NEEDS_FUNDING and stays unproven).
  TOKEN_TRANSFER                 -> the leak stood in for the attacker's own
      transfer succeeding. Materialize by doing the transfer for real.
  NATIVE_WRAP / NATIVE_UNWRAP    -> a wrapped-native deposit/withdraw was
      faked. Materialize with a real deposit/withdraw.
  PRICE_ORACLE                   -> the leak stood in for a price read. This
      is the classic case: materialize with a real swap/flash-loan prefix that
      MOVES the price the oracle reads.
  SIGNATURE                      -> a signature check was faked. Materialize
      by producing a real signature (or, if none can exist, NEEDS_PRIVILEGE).
  AUTH_GUARD                     -> the leak stood in for an access-control
      check passing. There is no real state change that grants it -- report
      NEEDS_PRIVILEGE and never send it.
  REENTRANCY_CALLBACK            -> the leak is a callback into the attacker
      during execution. Materialization is a CALLBACK recipe, not a state
      change: the plan generator must be able to replay a DIFFERENT call in
      the callback window (see the Rust `armCallback`/`repeat_step` gap).

The output is a worklist grouped by leak class: for each class, the recipe,
whether it is materializable at all, and every surface (with its example
plan) it unblocks. That is the honest, ordered plan for closing the gap --
not a promise that every surface is exploitable.

Usage:
    python3 onchain_scripts/materialize_plan.py onchain_scripts/auto_work/*
    python3 onchain_scripts/materialize_plan.py --json onchain_scripts/auto_work/*
    python3 onchain_scripts/materialize_plan.py --lookup onchain_scripts/auto_work/*

`--lookup` resolves unknown selectors against 4byte.directory (network); the
default is fully offline and classifies from the built-in table only.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import strategy_layer  # noqa: E402
import triage_findings as triage  # noqa: E402

UINT32_MAX = 0xFFFFFFFF

# --- leak classes -----------------------------------------------------------
# Materializable classes: a real prefix exists in principle.
TOKEN_BALANCE = "TOKEN_BALANCE"
TOKEN_APPROVE = "TOKEN_APPROVE"
TOKEN_TRANSFER = "TOKEN_TRANSFER"
NATIVE_WRAP = "NATIVE_WRAP"
NATIVE_UNWRAP = "NATIVE_UNWRAP"
PRICE_ORACLE = "PRICE_ORACLE"
SIGNATURE = "SIGNATURE"
STORAGE_READ = "STORAGE_READ"
EXTERNAL_CALL = "EXTERNAL_CALL"
# Not materializable as a state change: needs privilege or a generator change.
AUTH_GUARD = "AUTH_GUARD"
REENTRANCY_CALLBACK = "REENTRANCY_CALLBACK"
UNKNOWN = "UNKNOWN"

# class -> (recipe, materializable)
RECIPES = {
    TOKEN_BALANCE: (
        "acquire the tokens the guard reads (real swap, or a funded whale) so "
        "the leaked balanceOf returns a large enough value",
        True,
    ),
    TOKEN_APPROVE: (
        "really approve the spender before the exploit (a second tx is fine if "
        "the trace is not strictly atomic)",
        True,
    ),
    TOKEN_TRANSFER: (
        "perform the transfer the leak faked -- a real ERC-20 transfer of the "
        "attacker's own tokens",
        True,
    ),
    NATIVE_WRAP: (
        "really deposit native value for the wrapped token the guard reads",
        True,
    ),
    NATIVE_UNWRAP: (
        "really withdraw the wrapped token the leak faked",
        True,
    ),
    PRICE_ORACLE: (
        "PREFIX with a real swap/flash-loan that MOVES the price the oracle "
        "reads; the exploit then runs against the moved price, not a faked one",
        True,
    ),
    SIGNATURE: (
        "produce a real (v,r,s) that recovers to the expected signer -- e.g. "
        "ecrecover(0) if the check never rejects address(0), or a malleable/"
        "replayable signature if the nonce is missing",
        True,
    ),
    STORAGE_READ: (
        "make the storage the guard reads hold the value the leak faked "
        "(usually a prior state-changing call on the same contract)",
        True,
    ),
    EXTERNAL_CALL: (
        "replace the faked external call with the real call it stood in for "
        "(a real contract at the expected address, returning the needed value)",
        True,
    ),
    AUTH_GUARD: (
        "NO real state change grants this -- the leak stood in for an "
        "access-control check. Report NEEDS_PRIVILEGE and never send it",
        False,
    ),
    REENTRANCY_CALLBACK: (
        "not a state change: the plan generator must replay a DIFFERENT call "
        "in the callback window (Rust armCallback/repeat_step extension)",
        False,
    ),
    UNKNOWN: (
        "unclassified -- resolve the selector (4byte) and add it to the table",
        False,
    ),
}

# --- selector knowledge base ------------------------------------------------
# Seeded with the well-known selectors seen in real runs. Extend freely; the
# table is the only thing standing between UNKNOWN and a real recipe.
SELECTOR_CLASS = {
    # ERC-20 / ERC-721 views
    "0x70a08231": TOKEN_BALANCE,   # balanceOf(address)
    "0x18160ddd": STORAGE_READ,    # totalSupply()
    "0xdd62ed3e": TOKEN_APPROVE,   # allowance(address,address)
    # ERC-20 mutators
    "0xa9059cbb": TOKEN_TRANSFER,  # transfer(address,uint256)
    "0x23b872dd": TOKEN_TRANSFER,  # transferFrom(address,address,uint256)
    "0x095ea7b3": TOKEN_APPROVE,   # approve(address,uint256)
    # wrapped native
    "0xd0e30db0": NATIVE_WRAP,     # deposit()
    "0x2e1a7d4d": NATIVE_UNWRAP,   # withdraw(uint256)
    "0xf3fef3a3": NATIVE_UNWRAP,   # withdraw(address,uint256)
    # oracles
    "0x50d25bcd": PRICE_ORACLE,    # latestAnswer()
    "0xfeaf968c": PRICE_ORACLE,    # latestRoundData()
    "0x0902f1ac": PRICE_ORACLE,    # getReserves()
    "0x3850c7bd": PRICE_ORACLE,    # slot0()
    "0x0e8f9b23": PRICE_ORACLE,    # getPrice()
    "0x9dc29fac": PRICE_ORACLE,    # peek()
    # signatures
    "0x1626ba7e": SIGNATURE,       # isValidSignature(bytes32,bytes)
    "0xe3ce9714": SIGNATURE,       # proxyWithdraw(address,uint256,uint8,bytes32,bytes32)
    # access control (leak here is a privilege, not a state change)
    "0x8da5cb5b": AUTH_GUARD,      # owner()
    "0x893d20e8": AUTH_GUARD,      # getOwner()
    "0x2f54bf6e": AUTH_GUARD,      # isOwner(address)
    "0x7065cb48": AUTH_GUARD,      # addOwner(address)
    "0x173825d9": AUTH_GUARD,      # removeOwner(address)
    "0xba51a6df": AUTH_GUARD,      # changeRequirement(uint256)
    "0xb20d30a9": AUTH_GUARD,      # setDailyLimit(uint256)
    "0x5c52c2f5": AUTH_GUARD,      # resetSpentToday()
    "0xa6f9dae1": AUTH_GUARD,      # changeOwner(address)
    "0x1554611f": AUTH_GUARD,      # escapeHatch()
    "0x3e2640d6": AUTH_GUARD,      # extendClosingTime(uint256)
    "0xc01c1ca3": AUTH_GUARD,      # claimRemaining()
    "0x797af627": AUTH_GUARD,      # confirm(bytes32)
    "0xb75c7dc6": AUTH_GUARD,      # revoke(bytes32)
    "0xc2cf7326": AUTH_GUARD,      # hasConfirmed(bytes32,address)
    # reads the fuzzer used as guards
    "0xf1736d86": STORAGE_READ,    # m_dailyLimit()
    "0x02ef6c86": STORAGE_READ,    # calculateWithdraw(address)
    "0x7e3ef7cd": TOKEN_BALANCE,   # getMyBalance(address)
}


def classify_selector(selector: str | None) -> str:
    if not selector:
        return UNKNOWN
    return SELECTOR_CLASS.get(selector.lower(), UNKNOWN)


def leaked_steps(plan: dict) -> list[dict]:
    """The steps whose discovery used a faked call return (see
    triage_findings._leaked_steps); `call_leak == u32::MAX` ran normally."""
    out = []
    for i, step in enumerate(plan.get("steps") or []):
        leak = step.get("call_leak")
        if leak is None or int(leak) == UINT32_MAX:
            continue
        out.append({
            "index": i,
            "contract": step.get("contract"),
            "fn_selector": step.get("fn_selector"),
        })
    return out


def is_callback_leak(step: dict, plan: dict) -> bool:
    """A leak into a contract OTHER than the target, or a leak whose selector
    differs from the surrounding target calls, is the reentrancy-callback
    shape (the Rust armCallback gap), not a plain state-read leak."""
    target = str(plan.get("target") or "").lower()
    c = str(step.get("contract") or "").lower()
    if c and target and c != target:
        return True
    return False


def worklist(work_dirs: list[Path]) -> dict:
    """Group every leaked step across every work dir by (class, selector),
    and attach the surfaces each one blocks.

    Only findings that triage classifies NEEDS_MATERIALIZATION are counted.
    A Review-tier heuristic (e.g. "Stale Guard Counter") that happens to
    carry a per-step `call_leak` is NOT a materializable exploit -- triage
    already ranks it HEURISTIC_ONLY, and counting its leaks here would
    inflate the worklist with hundreds of surfaces nobody can or should
    act on. The materialization worklist is exactly the NEEDS_MATERIALIZATION
    tier, broken down by what each leaked call is."""
    groups: dict[tuple, dict] = {}
    total_plans = 0
    total_surfaces = 0
    for work in work_dirs:
        try:
            findings = strategy_layer.load_findings(work)
        except Exception:
            continue
        seen_surface_keys: set = set()
        for finding in findings:
            total_plans += 1
            key = triage.surface_key(finding)
            if key in seen_surface_keys:
                continue
            seen_surface_keys.add(key)
            if triage.classify(finding)[0] != triage.NEEDS_MATERIALIZATION:
                continue
            total_surfaces += 1
            plan = finding["plan"]
            for step in leaked_steps(plan):
                cls = (
                    REENTRANCY_CALLBACK
                    if is_callback_leak(step, plan)
                    else classify_selector(step.get("fn_selector"))
                )
                gkey = (cls, str(step.get("fn_selector") or "").lower())
                g = groups.get(gkey)
                if g is None:
                    recipe, materializable = RECIPES[cls]
                    g = groups[gkey] = {
                        "leak_class": cls,
                        "selector": step.get("fn_selector"),
                        "recipe": recipe,
                        "materializable": materializable,
                        "surfaces": [],
                        "plan_count": 0,
                        "bug_types": set(),
                    }
                g["plan_count"] += 1
                g["bug_types"].update(finding.get("bug_types") or [])
                g["surfaces"].append({
                    "target": plan.get("target"),
                    "chain": plan.get("chain"),
                    "bug_types": sorted(finding.get("bug_types") or []),
                    "step": step["index"],
                    "example_plan": finding.get("plan_path"),
                })

    ordered = sorted(
        groups.values(),
        key=lambda g: (not g["materializable"], g["leak_class"], -g["plan_count"]),
    )
    for g in ordered:
        g["surface_count"] = len(g["surfaces"])
        g["bug_types"] = sorted(g["bug_types"])
    return {
        "total_plans": total_plans,
        "distinct_surfaces": total_surfaces,
        "groups": ordered,
    }


def print_worklist(report: dict) -> None:
    groups = report["groups"]
    total_leaks = sum(g["plan_count"] for g in groups)
    mat = [g for g in groups if g["materializable"]]
    blocked = [g for g in groups if not g["materializable"]]
    print("=" * 78)
    print(f"MATERIALIZATION WORKLIST -- {total_leaks} leaked call(s) across "
          f"{len(groups)} distinct selector(s)")
    print(f"  from {report['distinct_surfaces']} NEEDS_MATERIALIZATION surface(s) "
          f"/ {report['total_plans']} plan(s)")
    print("=" * 78)
    if not groups:
        print("  no control-leak surfaces found -- nothing to materialize.")
        return

    def _dump(title, items):
        if not items:
            return
        print(f"\n--- {title} ({len(items)}) " + "-" * max(0, 60 - len(title)))
        for g in items:
            bugs = ", ".join(g.get("bug_types") or []) or "?"
            print(f"\n  [{g['plan_count']:4} leak(s), {g['surface_count']} surface(s)] "
                  f"{g['leak_class']}  {g['selector']}  -- {bugs}")
            if g.get("resolved_signature"):
                print(f"      resolved: {g['resolved_signature']}")
            print(f"      recipe: {g['recipe']}")
            seen = set()
            for s in g["surfaces"]:
                sk = (s["target"], s["bug_types"][0] if s["bug_types"] else "", s["step"])
                if sk in seen:
                    continue
                seen.add(sk)
                sb = ", ".join(s["bug_types"]) or "?"
                print(f"      - {s['target']} ({s['chain']}) step {s['step']} -- {sb}")

    _dump("MATERIALIZABLE -- a real prefix can replace the leak", mat)
    _dump("NOT MATERIALIZABLE -- no state change grants this", blocked)

    print("\n" + "=" * 78)
    print("NEXT")
    print("=" * 78)
    print(f"  {len(mat)} leak class(es) can be materialized with a real prefix; "
          f"{len(blocked)} cannot.")
    if any(g["leak_class"] == AUTH_GUARD for g in blocked):
        print("  AUTH_GUARD leaks mean the fuzzer faked an access-control check passing:")
        print("  that is NEEDS_PRIVILEGE -- no prefix grants it, do not send it.")
    if any(g["leak_class"] == REENTRANCY_CALLBACK for g in blocked):
        print("  REENTRANCY_CALLBACK leaks need a generator change (replay a DIFFERENT")
        print("  call in the callback window), not a state change -- see the Rust")
        print("  armCallback/repeat_step gap.")
    print("\n  A materialized surface is still only PROVEN when a real tx moves real")
    print("  value on a fork -- until then it stays evidence, exactly as before.")


def lookup_selector(selector: str, timeout: float = 8.0) -> str | None:
    """Resolve a selector to a text signature via 4byte.directory. Network,
    best-effort: any failure returns None and never raises, so --lookup can
    enrich the report without ever breaking an offline run."""
    if not selector:
        return None
    import urllib.parse
    import urllib.request
    url = "https://www.4byte.directory/api/v1/signatures/?" + urllib.parse.urlencode(
        {"hex_signature": selector}
    )
    req = urllib.request.Request(url, headers={"User-Agent": "ForkSploit/materialize_plan"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return None
    results = data.get("results") or []
    if not results:
        return None
    # 4byte returns oldest-first; the first is the most likely canonical name.
    return results[0].get("text_signature")


def apply_lookup(report: dict) -> list[dict]:
    """Fill UNKNOWN groups' recipes with a real 4byte signature, in place.
    Returns the list of (selector, signature) that were resolved, so the
    caller can print what changed. UNKNOWN groups whose selector cannot be
    resolved stay UNKNOWN -- never guessed."""
    resolved = []
    for g in report["groups"]:
        if g["leak_class"] != UNKNOWN:
            continue
        sig = lookup_selector(g["selector"])
        if not sig:
            continue
        g["resolved_signature"] = sig
        g["recipe"] = f"unclassified locally; 4byte says '{sig}' -- classify it and add to SELECTOR_CLASS"
        resolved.append({"selector": g["selector"], "signature": sig})
    return resolved


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("work_dirs", nargs="+", help="work dir(s), e.g. onchain_scripts/auto_work/*")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--lookup", action="store_true",
                    help="resolve UNKNOWN selectors against 4byte.directory (network)")
    args = ap.parse_args()

    dirs = [Path(w) for w in args.work_dirs if Path(w).exists()]
    if not dirs:
        print("error: no valid work dir given", file=sys.stderr)
        return 1

    report = worklist(dirs)
    resolved = apply_lookup(report) if args.lookup else []
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_worklist(report)
        if args.lookup:
            if resolved:
                print("\nResolved via 4byte.directory:")
                for r in resolved:
                    print(f"  {r['selector']} -> {r['signature']}")
            else:
                print("\n--lookup: no UNKNOWN selectors needed resolving (or lookup failed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
