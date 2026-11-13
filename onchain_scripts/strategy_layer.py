#!/usr/bin/env python3
"""strategy_layer.py -- orders findings sensibly, and composes ONE coherent,
fully-executable plan out of the many independent plans the Rust layer emits
for a target.

Why this exists: `auto_pipeline.py`/`batch_pipeline.py` discover every
`*.plan.json` for a target and execute each one completely independently, in
plain lexicographic filename order -- there is no concept anywhere in this
codebase of one finding's result feeding into another. Many real compound
exploits need several steps no single oracle connects: e.g. (1) forge a
signature via an unchecked `ecrecover(0)`, which flips `authorized[caller]`,
then (2) call a separately-found `withdraw()` that requires that flag, then
(3) drain a token the withdraw left in the attacker's hands. Oracle A's own
plan stops after the forging call; oracle B's own plan, replayed alone from
real, unmodified chain state, reverts. Neither finding alone proves the
compound attack is real -- but replaying A's steps, then B's, then C's as one
ordered sequence from the same AttackWallet caller might.

This module never duplicates `execute_plan()`'s own safety/gas/mainnet logic
-- it only ASSEMBLES a synthetic, merged plan dict with the same schema
`execute_plan()` already knows how to run, and the caller
(`auto_pipeline.py`/`batch_pipeline.py`) is the one that actually invokes
`execute_plan()` with it. This module deliberately does NOT import
`auto_pipeline`/`batch_pipeline` (avoids a circular import, and keeps the
classification/composition logic usable from either script identically).

Composition (superseding the previous "pairs of flat plans only" scope):
  - N-way, not just pairs: every capability-unlocking finding is ordered in
    front of every objective finding, then the whole group is flattened into
    ONE step sequence.
  - `kind == "reentrancy"` plans participate. Their arm/disarm slot is tied
    to the LAST step of their own `steps`, so a reentrancy plan is only ever
    placed LAST in a composed sequence (nothing may follow a step whose
    callback is armed) -- and at most one reentrancy plan per composition.
  - `needs_funding` plans participate. Their funding is handled by
    `execute_plan()`'s existing flashloan path (or the caller's own funding
    step); composition does not need to reason about it beyond keeping the
    funding-dependent steps together.
  - Argument-level data threading: address arguments that reference a
    different actor in an objective step are rewritten to the composed
    caller (AttackWallet) identity, and `approve` steps are ordered ahead of
    the `transferFrom` they authorize. This covers the "B's calldata needs
    the actor A set up" shape, not just "A changed state B reads".
  - The Rust layer now stamps each plan with `bug_types`, `distinct_callers`,
    `atomic_replayable`, `full_trace_steps`, per-step `caller`/`fn_selector`
    -- so this module reads those directly instead of re-deriving them from
    the sibling `.t.sol`, and can prefer richer/multi-step traces.
"""
import json
import re
from pathlib import Path
from typing import Callable

# Classification is driven entirely by the bug_type taxonomy the oracles
# already produce (see src/evm/oracle.rs's classify_confidence and
# skills/forksploit-contract-audit/references/zmogljivosti.md section 3) --
# no new semantic understanding of what any function does, just a second
# axis on top of the EXISTING, already-reviewed tier classification.
#
# UNLOCK: grants/proves some capability or bypass, but doesn't by itself
# represent fund/value movement.
UNLOCK_BUG_TYPES = frozenset({
    "Unauthorized Owner Change",
    "Unauthorized Pause Toggle",
    "Unauthorized Proxy Upgrade",
    "Arbitrary Call",
    "Delegatecall Injection",
    "Delegatecall Target From Calldata",
    "Delegatecall Target From Calldata (Unconfirmed)",
    "Unchecked ecrecover(0)",
    "Arbitrary Storage Write",
    "Initializer Front-Running",
    "Proxy Reinitialization",
    "Proxy Storage Collision",
    "Reentrancy",
    "Signature Malleability",
    "Signature Replay",
    "Storage Collision",
    "Tx.Origin Phishing Bypass",
    "Curve Virtual Price Decrease",
    "TWAP Manipulation Precondition",
    "Read-Only Reentrancy",
    "Token Accounting Mismatch",
    # Genuinely ambiguous (see SKILL.md) -- tried in both roles rather
    # than an arbitrary single pick.
    "ERC4626 Share Inflation",
    "Integer Overflow",
    "Forced Native Value Accounting",
})

# OBJECTIVE: already represents fund/value movement or a direct
# profit/loss by itself.
OBJECTIVE_BUG_TYPES = frozenset({
    "Unauthorized ERC20 Transfer",
    "Unauthorized ERC1155 Transfer",
    "Unauthorized NFT Transfer",
    "Fund Loss",
    "Insolvent: Promised Native Value Exceeds Real Balance",
    "ERC4626 Rounding Favors User",
    "Selfdestruct",
    "Validation-Independent Payment",
    "TWAP Manipulation (Profit Confirmed)",
    "Curve Virtual Price Decrease (Profit Confirmed)",
    "Imbalanced Uniswap Pair",
    # Same ambiguous set as above, intentionally duplicated.
    "ERC4626 Share Inflation",
    "Integer Overflow",
    "Forced Native Value Accounting",
})

# Matches lines like "[Reentrancy] (confirmed): ..." or
# "[Delegatecall Target From Calldata] (sim-confirmed): ..." in a
# generated .t.sol's "================ Description ================"
# block -- tolerant of both the pre- and post-2026-11-02 confidence-tier
# label spelling (see oracle.rs's ConfidenceTier::as_str() rename). Used
# ONLY as a fallback for plans produced before the Rust schema carried
# `bug_types` directly.
_CONFIRMED_BUG_TYPE_RE = re.compile(r"^\[(.+?)\]\s*\((?:sim-)?confirmed\):", re.MULTILINE)

_CONTRACT_NAME_SUFFIX_RE = re.compile(r"_(\d+)$")

# ERC20 selectors the argument-threading step understands, so it can order an
# approval ahead of the transfer it authorizes and rewrite a foreign `from`.
_APPROVE_SELECTORS = frozenset({"0x095ea7b3", "0xa22cb465"})  # approve(address,uint256), setApprovalForAll
_TRANSFER_FROM_SELECTORS = frozenset({"0x23b872dd"})  # transferFrom(address,address,uint256)


def _bug_types_from_t_sol(vulnerabilities_dir: Path, contract_name: str) -> set:
    """Fallback path: reads the matching `{contract_name}.t.sol`'s
    Description block and returns every bug_type logged there at
    (sim-)confirmed tier. Only used when a plan.json predates the schema
    change that made `bug_types` a first-class plan field."""
    t_sol_path = vulnerabilities_dir / f"{contract_name}.t.sol"
    if not t_sol_path.exists():
        return set()
    try:
        text = t_sol_path.read_text()
    except OSError:
        return set()
    return set(_CONFIRMED_BUG_TYPE_RE.findall(text))


def load_findings(work_dir: Path) -> list[dict]:
    """Loads every `*.plan.json` under `work_dir/vulnerabilities/` plus its
    bug_type set, kind, funding flag, and the Rust-stamped composition
    metadata -- the input to `ordering_key` and the composition builders.
    Returns `[]` if there is no vulnerabilities dir (mirrors the existing
    `plan_files` glob convention in auto_pipeline.py/batch_pipeline.py)."""
    vulnerabilities_dir = work_dir / "vulnerabilities"
    if not vulnerabilities_dir.exists():
        return []
    findings = []
    for plan_path in sorted(vulnerabilities_dir.glob("*.plan.json")):
        try:
            plan = json.loads(plan_path.read_text())
        except (OSError, ValueError):
            continue
        contract_name = plan["contract_name"]
        # Prefer the plan's own bug_types (authoritative, written by the
        # generator that also wrote the .t.sol); fall back to parsing the
        # .t.sol only for older plans.
        bug_types = set(plan.get("bug_types") or ())
        if not bug_types:
            bug_types = _bug_types_from_t_sol(vulnerabilities_dir, contract_name)
        findings.append({
            "contract_name": contract_name,
            "plan_path": plan_path,
            "plan": plan,
            "bug_types": bug_types,
            "kind": plan.get("kind"),
            "needs_funding": bool(plan.get("needs_funding")),
            "atomic_replayable": bool(plan.get("atomic_replayable", True)),
            "distinct_callers": int(plan.get("distinct_callers", 1) or 1),
            "step_count": int(plan.get("step_count", len(plan.get("steps", []))) or 0),
            # Whether any bug_type is Confirmed-tier (a directly observed
            # violation), as opposed to a Review-tier heuristic. The Rust
            # layer emits a plan.json for BOTH and leaves the standalone-vs-
            # evidence-only decision to the Python side (see mod.rs); the
            # pre-flight gate reads this to skip heuristic-only plans that
            # have no real extraction step to replay.
            "confirmed_exploitable": bool(plan.get("confirmed_exploitable", True)),
        })
    return findings


def ordering_key(finding: dict):
    """Sort key for the EXISTING independent-execution loop: unlock-class
    findings first, then genuinely ambiguous ones, then objective-class,
    then anything unclassified/informational -- with a numeric (not
    lexicographic) tiebreak on the finding's own BUG_COUNTER suffix, so
    "_10" doesn't sort before "_2". Also prefers multi-step traces over
    single-step ones within a tier, so the richest evidence is tried
    first. Replaces the plain `sorted(plan_files)` filename sort; does not
    itself attempt any chaining."""
    bug_types = finding["bug_types"]
    is_unlock = bool(bug_types & UNLOCK_BUG_TYPES)
    is_objective = bool(bug_types & OBJECTIVE_BUG_TYPES)
    if is_unlock and not is_objective:
        tier = 0
    elif is_unlock and is_objective:
        tier = 1
    elif is_objective:
        tier = 2
    else:
        tier = 3
    m = _CONTRACT_NAME_SUFFIX_RE.search(finding["contract_name"])
    numeric_suffix = int(m.group(1)) if m else 0
    # Richer traces first within a tier (negated so more steps sorts earlier).
    return (tier, -finding.get("step_count", 0), numeric_suffix, finding["contract_name"])


def _steps_of(finding: dict) -> list[dict]:
    """The step list to compose from: prefer the UNMINIMIZED
    `full_trace_steps` (the minimizer strips the earlier state-setting
    calls a compound exploit needs), falling back to the minimized
    `steps` for older plans."""
    plan = finding["plan"]
    full = plan.get("full_trace_steps")
    if full:
        return [dict(s) for s in full]
    return [dict(s) for s in plan.get("steps", [])]


def _is_chainable(finding: dict) -> bool:
    """Every plan kind is now composable. `reentrancy` plans are allowed
    but must end up last (see `compose_plan`). A plan whose discovery
    relied on a faked/intercepted return value (`atomic_replayable` False)
    cannot be reproduced by AttackWallet, so it is excluded as a
    composition member -- it stays honest standalone evidence only."""
    if not finding.get("atomic_replayable", True):
        return False
    return finding.get("kind") in ("flat", "reentrancy")


def _step_key(step: dict) -> tuple:
    """Identity of a step for de-duplication across composed plans: two
    plans found on the same target routinely share an identical setup call
    (e.g. the same `approve`), and replaying it twice is at best wasteful,
    at worst a revert (a second `approve` to the same value is fine, but a
    second `mint`/`initialize` is not)."""
    return (
        str(step.get("contract", "")).lower(),
        str(step.get("calldata", "")).lower(),
        str(step.get("value", "")),
        str(step.get("caller", "")).lower(),
    )


def _dedup_steps(steps: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for step in steps:
        key = _step_key(step)
        if key in seen:
            continue
        seen.add(key)
        out.append(step)
    return out


# W5: dependency-aware ordering. A step that CREATES state must run before a
# step that CONSUMES it. Rather than a general symbolic planner (out of scope
# and easy to get subtly wrong), this is a small, explicit, testable rule set
# keyed on the 4-byte selector families the fuzzer actually records:
#
#   approve(spender, amount)      -> creates an ALLOWANCE the later
#   transferFrom(from, to, amount)   transferFrom spends, on the same token
#   deposit()                     -> creates a BALANCE the later
#   withdraw(uint256)/redeem(...)    withdraw/redeem burns, on the same contract
#
# Matching is by the called contract (`step["contract"]`), so an approve on a
# token only orders before a transferFrom on THAT token. Anything not in the
# rule set keeps its original relative order (a stable topological sort).
# `_APPROVE_SELECTORS`/`_TRANSFER_FROM_SELECTORS` are defined once, near the
# top of this module.
_DEPOSIT_SELECTORS = frozenset({"0xd0e30db0"})  # deposit() (WETH-style)
_WITHDRAW_SELECTORS = frozenset({"0x2e1a7d4d", "0xba087652"})  # withdraw(uint256), redeem(uint256,address,address)


def order_steps_by_dependencies(steps: list[dict]) -> tuple[list[dict], list[str]]:
    """W5: stable topological re-order so a prerequisite step runs before the
    step that depends on it. Returns `(ordered_steps, notes)`; `notes` names
    the detected edges (for the run log) and any cycle that forced a
    fall-back. A cycle is reported, never silently reordered into something
    wrong -- the original order is kept in that case."""
    if len(steps) < 2:
        return list(steps), []

    def sel(s: dict) -> str:
        return str(s.get("fn_selector", "")).lower()

    def ctr(s: dict) -> str:
        return str(s.get("contract", "")).lower()

    edges: set[tuple[int, int]] = set()  # (prerequisite_idx, dependent_idx)

    def add_edges(producers: list[int], consumers: list[int], label: str) -> None:
        for p in producers:
            for c in consumers:
                if p != c and ctr(steps[p]) == ctr(steps[c]):
                    if (p, c) not in edges:
                        edges.add((p, c))
                        notes.append(f"step {p} before step {c}: {label}")

    notes: list[str] = []
    approves = [i for i, s in enumerate(steps) if sel(s) in _APPROVE_SELECTORS]
    transfers = [i for i, s in enumerate(steps) if sel(s) in _TRANSFER_FROM_SELECTORS]
    add_edges(approves, transfers, "approve creates the allowance transferFrom spends")
    deposits = [i for i, s in enumerate(steps) if sel(s) in _DEPOSIT_SELECTORS]
    withdrawals = [i for i, s in enumerate(steps) if sel(s) in _WITHDRAW_SELECTORS]
    add_edges(deposits, withdrawals, "deposit/mint creates the balance withdraw/redeem burns")

    if not edges:
        return list(steps), notes

    # Stable Kahn topological sort: always take the lowest original index that
    # has no unsatisfied prerequisite, so unrelated steps keep their order.
    indeg = {i: 0 for i in range(len(steps))}
    adj: dict[int, list[int]] = {i: [] for i in range(len(steps))}
    for (a, b) in edges:
        adj[a].append(b)
        indeg[b] += 1
    ordered_idx: list[int] = []
    remaining = set(range(len(steps)))
    while remaining:
        ready = sorted(i for i in remaining if indeg[i] == 0)
        if not ready:
            # Cycle: fall back to the original order, and say so.
            notes.append("dependency cycle detected -- keeping the original step order")
            return list(steps), notes
        pick = ready[0]
        remaining.discard(pick)
        ordered_idx.append(pick)
        for nxt in adj[pick]:
            indeg[nxt] -= 1
    return [steps[i] for i in ordered_idx], notes


def _thread_address_arguments(steps: list[dict], composed_caller: str | None) -> list[dict]:
    """Best-effort argument-level data threading (W5 removed the old
    approve-before-transferFrom reorder from here -- ordering is now handled
    by `order_steps_by_dependencies`, which composes correctly with it).

    One concrete, verifiable rewrite -- no guessing about semantics: if a
    `transferFrom(from, to, amount)` step names a `from` that is NOT the
    composed caller, rewrite `from` to the composed caller. This is exactly
    the multi-caller flattening problem the Rust layer's `distinct_callers`
    metadata flags: plan A minted tokens to actor X, plan B transfers from X
    -- but AttackWallet is one identity, so X must become that identity for
    the composed sequence to hold. A no-op when there is nothing to change,
    and a `composed_caller` of None (caller unknown) skips it.
    """
    if not steps:
        return steps

    def _selector(step: dict) -> str:
        return str(step.get("fn_selector", "")).lower()

    # transferFrom(from, to, amount) -- from is the first 32-byte word after
    # the selector.
    if composed_caller:
        caller_word = composed_caller.lower()[2:].rjust(64, "0")
        for step in steps:
            if _selector(step) not in _TRANSFER_FROM_SELECTORS:
                continue
            data = str(step.get("calldata", ""))
            if len(data) < 10 + 64:
                continue
            from_word = data[10:10 + 64]
            if from_word.lower() == caller_word:
                continue
            step["calldata"] = data[:10] + caller_word + data[10 + 64:]
            step["_threaded_from"] = True
    return steps


def compose_plan(findings: list[dict], composed_caller: str | None = None) -> dict:
    """Composes ONE coherent, fully-executable plan from an ordered list of
    findings.

    Ordering: every unlock-class finding's steps first (in the given
    order), then unclassified ones, then objective-class findings' steps --
    so the capability/state change happens before the extraction that
    depends on it. A `reentrancy`-kind finding is always placed LAST,
    because its arm/disarm slot is tied to the final step of its own
    `steps` and nothing may run after an armed callback. At most one
    reentrancy plan is honored per composition (a second would need a
    second arm slot the schema does not have); any extra is folded in as a
    plain flat replay.

    Steps are de-duplicated, address arguments are threaded to the composed
    caller, and `approve`s are ordered ahead of the `transferFrom`s they
    authorize. The result has the exact schema `execute_plan()` consumes
    (src/evm/solution/script_generator.rs's ExploitPlan).
    """
    if not findings:
        raise ValueError("compose_plan needs at least one finding")

    unlocks = [f for f in findings if f["bug_types"] & UNLOCK_BUG_TYPES]
    objectives = [f for f in findings if f["bug_types"] & OBJECTIVE_BUG_TYPES]
    # Anything neither unlock nor objective still participates -- an
    # unclassified finding may still be the step that sets up state -- so
    # it goes between unlock and objective.
    neutral = [f for f in findings if f not in unlocks and f not in objectives]

    reentrancy = [f for f in findings if f.get("kind") == "reentrancy"]
    reentrancy_kept = reentrancy[-1] if reentrancy else None

    def _ordered(group):
        # Preserve the caller's order within each group, but never let a
        # reentrancy finding appear anywhere except last overall.
        return [f for f in group if f is not reentrancy_kept]

    steps: list[dict] = []
    for finding in _ordered(unlocks) + _ordered(neutral) + _ordered(objectives):
        steps.extend(_steps_of(finding))
    if reentrancy_kept is not None:
        steps.extend(_steps_of(reentrancy_kept))

    steps = _dedup_steps(steps)
    # W5: order prerequisites before their dependents (approve -> transferFrom,
    # deposit -> withdraw), stably; then thread address arguments to the
    # composed caller. The dependency pass subsumes the old ad-hoc
    # "approve before transferFrom" shuffle.
    steps, dep_notes = order_steps_by_dependencies(steps)
    steps = _thread_address_arguments(steps, composed_caller)

    total_value = 0
    for step in steps:
        try:
            total_value += int(step.get("value") or 0)
        except (TypeError, ValueError):
            pass

    repeat_step = None
    kind = "flat"
    if reentrancy_kept is not None:
        kind = "reentrancy"
        repeat_step = reentrancy_kept["plan"].get("repeat_step")

    return {
        "contract_name": "+".join(f["contract_name"] for f in findings),
        "kind": kind,
        "needs_funding": any(f.get("needs_funding") for f in findings) or total_value > 0,
        "total_value": str(total_value),
        "steps": steps,
        "repeat_step": repeat_step,
        "composed_from": [f["contract_name"] for f in findings],
        # A composition is only "evidence of real fund movement" if at least
        # one member is Confirmed-tier. A group built entirely from Review-
        # tier heuristics has no observed extraction step, so the pre-flight
        # gate may skip it -- same rule as a standalone plan.
        "confirmed_exploitable": any(f.get("confirmed_exploitable", True) for f in findings),
    }


def _unpack_result(result: tuple) -> tuple:
    """Normalises whatever the caller's `execute_plan` returns into the
    4-tuple (status, recovery_delta_wei, gas_spent_wei, net_profit_wei).

    `execute_plan` returns four values now (it reports NET profit, see its
    own doc), but a 2-tuple is still accepted so this module stays usable
    with any caller that hasn't adopted the gas fields yet -- the missing
    gas/net fields simply default to 0 rather than crashing composition."""
    if len(result) >= 4:
        return result[0], result[1], result[2], result[3]
    status, delta = result[0], result[1]
    return status, delta, 0, 0


def build_composition_candidates(findings: list[dict], max_attempts: int = 12) -> list[list[dict]]:
    """Builds candidate GROUPS of findings to compose, richest first.

    - If there are both unlock-class and objective-class findings, each
      objective is offered a group of ALL unlock findings plus itself --
      N-way, not the old unlock/objective pair.
    - When no unlock-class finding exists, each objective is tried on its
      own (so it still gets executed), and objective+objective groups are
      offered (some exploits are two value-moving steps in sequence).
    - Capped at `max_attempts` groups so a target with many findings can't
      blow up the number of real on-chain attempts this adds.
    """
    chainable = [f for f in findings if _is_chainable(f)]
    unlocks = [f for f in chainable if f["bug_types"] & UNLOCK_BUG_TYPES]
    objectives = [f for f in chainable if f["bug_types"] & OBJECTIVE_BUG_TYPES]

    groups: list[list[dict]] = []
    if unlocks and objectives:
        for objective in objectives:
            groups.append(list(unlocks) + [objective])
            if len(groups) >= max_attempts:
                return groups
    if objectives:
        for objective in objectives:
            groups.append([objective])
            if len(groups) >= max_attempts:
                return groups
        for i, first in enumerate(objectives):
            for second in objectives[i + 1:]:
                groups.append([first, second])
                if len(groups) >= max_attempts:
                    return groups
    elif chainable:
        # Only neutral/unclassified findings: still compose them together
        # rather than dropping them.
        groups.append(list(chainable))
    return groups[:max_attempts]


def run_chain_attempts(
    execute_plan_fn: Callable,
    w3,
    acct,
    nonce_box: dict,
    attack_wallet: str,
    findings: list[dict],
    already_confirmed_contract_names: set,
    recovery_wallet: str,
    tee,
    chain: str = "sepolia",
    max_attempts: int = 12,
) -> list[dict]:
    """Tries every composition candidate via the CALLER's own `execute_plan`
    function (passed in, never imported here, so this module stays
    decoupled from auto_pipeline.py/batch_pipeline.py and introduces no
    circular import). Skips any group whose objective half already
    confirmed on its own in the independent pass -- no point spending a
    real composed attempt proving something the independent run already
    proved. Returns one result dict per attempt with the SAME
    `status`/`recovery_delta_wei` shape `execute_plan()` itself returns,
    plus which findings were composed, so the caller can log/report it as
    a distinct, materially stronger compound finding rather than
    conflating it with an ordinary single-bug PLAN_CONFIRMED."""
    groups = build_composition_candidates(findings, max_attempts=max_attempts)
    results = []
    for group in groups:
        # Skip a group when its last (objective) member already confirmed
        # alone in the independent pass.
        if group and group[-1]["contract_name"] in already_confirmed_contract_names:
            continue
        try:
            merged_plan = compose_plan(group, composed_caller=attack_wallet)
        except ValueError:
            continue
        names = [f["contract_name"] for f in group]
        tee.log(
            f"[strategy] Trying composition of {len(group)} plan(s): "
            + " -> ".join(
                f"{f['contract_name']} ({', '.join(sorted(f['bug_types'])) or 'unknown'})"
                for f in group
            )
        )
        try:
            raw_result = execute_plan_fn(w3, acct, nonce_box, attack_wallet, merged_plan, recovery_wallet, tee, chain=chain)
            status, recovery_delta_wei, gas_spent_wei, net_profit_wei = _unpack_result(raw_result)
            # `_unpack_result`'s 4-tuple contract is deliberately unchanged
            # (existing callers and tests depend on it); the 5th element
            # (gas UNITS, for the structured proof) is read here directly,
            # defaulting to 0 for an older 4-/2-tuple caller.
            _raw = tuple(raw_result)
            gas_units = _raw[4] if len(_raw) >= 5 else 0
        except Exception as e:
            # One composed attempt raising must not abort the remaining
            # ones -- same reasoning as the independent pass in
            # auto_pipeline.main(). Report it as inconclusive and go on.
            tee.log(
                f"[strategy] composition {names} raised {type(e).__name__}: {e} -- "
                "treating as INCONCLUSIVE, continuing with the remaining attempts.",
                alert=True,
            )
            status, recovery_delta_wei, gas_spent_wei, net_profit_wei = "inconclusive", 0, 0, 0
            gas_units = 0
        results.append({
            "unlock_contract_name": names[0] if names else "",
            "objective_contract_name": names[-1] if names else "",
            "composed_contract_names": names,
            "merged_contract_name": merged_plan["contract_name"],
            "status": status,
            "recovery_delta_wei": recovery_delta_wei,
            "gas_spent_wei": gas_spent_wei,
            "gas_units": gas_units,
            "net_profit_wei": net_profit_wei,
            # FAZA 1.2: the gate stamps these onto the composed plan when it
            # measures the gas footprint (a composition carries no fuzzer
            # metadata), so the report can show the composed plan's own gas
            # reality exactly like a standalone one.
            "gas_estimate": merged_plan.get("gas_estimate"),
            "fits_block_gas_limit": merged_plan.get("fits_block_gas_limit"),
            "gas_headroom_pct": merged_plan.get("gas_headroom_pct"),
            "block_gas_limit": merged_plan.get("block_gas_limit"),
        })
    return results
