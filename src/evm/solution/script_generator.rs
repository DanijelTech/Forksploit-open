use std::fs::{self, File};

use handlebars::{handlebars_helper, Handlebars};
use serde::Serialize;
use tracing::error;

use super::{TemplateArgs, Tx};

/// One (target, calldata, value) step of a structured exploit plan -- the
/// same information the Solidity exploit templates render into source,
/// but kept as plain data so `onchain_scripts/auto_pipeline.py` can drive
/// the reusable `AttackWallet` contract directly instead of generating,
/// compiling, and deploying a bespoke exploit contract per bug found. See
/// that script's module docstring and
/// `onchain_scripts/contracts/AttackWallet.sol`.
#[derive(Serialize, Clone)]
struct PlanStep<'a> {
    contract: &'a str,
    calldata: &'a str,
    value: &'a str,
    /// The `msg.sender` this step was recorded with. Kept in the plan (it
    /// used to be dropped) so the Python layer can tell a single-identity
    /// trace from a multi-caller one, and can thread an earlier step's
    /// real on-chain result into a later step's calldata argument.
    caller: &'a str,
    /// The 4-byte function selector (hex, `0x`-prefixed) this step calls,
    /// so the Python layer can reason about step roles (an owner-setter
    /// that unlocks a later withdraw, an approve before a transferFrom, a
    /// repeated selector for a reentrancy arm) without re-decoding the
    /// calldata itself.
    fn_selector: &'a str,
    /// Set when this step is a raw ERC20-interface call (transfer/
    /// transferFrom/mint/burn/skim/approve) made directly on a token
    /// contract rather than through the buy/sell swap-router path -- see
    /// `super::erc20_token_touched`'s own doc comment for why
    /// `onchain_scripts/auto_pipeline.py` needs this to know which token
    /// to check/sweep off AttackWallet after the plan completes.
    stolen_asset: Option<&'a str>,
    /// u32::MAX when this step ran to completion normally; any other value
    /// means this step's discovery used host.rs's control-leak mechanism
    /// (an intercepted call with a fuzzer-injected fake return value, see
    /// `Tx::call_leak`). `atomic_replayable` on the plan is false when ANY
    /// step carries a non-neutral value -- AttackWallet cannot fake a
    /// return value on the real chain, so such a plan is honest evidence
    /// but not a runnable atomic exploit.
    call_leak: u32,
}

impl<'a> From<&'a Tx> for PlanStep<'a> {
    fn from(tx: &'a Tx) -> Self {
        Self {
            contract: &tx.contract,
            calldata: &tx.calldata,
            value: &tx.value,
            caller: &tx.caller,
            fn_selector: &tx.fn_selector,
            stolen_asset: super::erc20_token_touched(tx),
            call_leak: tx.call_leak,
        }
    }
}

/// Everything the Python layer needs to decide how a plan can be merged
/// with another, WITHOUT re-deriving it from the generated `.t.sol`.
///
/// The previous schema carried only `contract_name`/`kind`/`needs_funding`/
/// `total_value`/`steps`/`repeat_step` -- so `strategy_layer.py` had to
/// read the sibling `.t.sol`'s Description block just to learn which
/// bug_types fired, could not tell a single-identity trace from a
/// multi-caller one, and could not know that a plan's discovery leaned on
/// a faked return value (making it un-replayable on-chain). All of that is
/// now first-class plan data.
///
/// One impersonated caller in a plan's trace: which caller address was an
/// identity the fuzzer read out of target storage, and where it read it
/// from. See `PlanMeta::owner_impersonation_detail`.
#[derive(Serialize)]
struct ImpersonatedCaller {
    /// The checksummed caller address that impersonated a stored identity.
    caller: String,
    /// The checksummed contract whose storage the address was read from.
    harvested_from_contract: String,
    /// The storage slot key (0x-padded 32-byte hex) it was read from.
    harvested_from_slot: String,
}

#[derive(Serialize)]
struct PlanMeta<'a> {
    /// Every bug_type the finding's Description block lists (see
    /// `super::parse_bug_report`). A trace can trip more than one oracle,
    /// so this is a list, not a single value.
    bug_types: Vec<String>,
    /// "sim-confirmed" when at least one bug_type is Confirmed-tier,
    /// "sim-review" otherwise -- mirrors `oracle.rs`'s `ConfidenceTier`.
    confidence: &'a str,
    /// Whether any bug_type is in `is_confirmed_exploitable_bug`'s list
    /// (i.e. the trace is a directly observed violation, not a heuristic).
    confirmed_exploitable: bool,
    /// True when no step's discovery relied on a faked/intercepted call
    /// return -- only then can AttackWallet replay this plan soundly
    /// on-chain. See `PlanStep::call_leak`.
    atomic_replayable: bool,
    /// True when `trace_depends_on_control_leak` held for the trace.
    requires_control_leak: bool,
    /// Distinct top-level `msg.sender` addresses in `steps`, and their
    /// list. `has_multiple_distinct_callers` is `distinct_callers > 1`.
    distinct_callers: usize,
    callers: Vec<String>,
    /// True when EVERY caller in this trace is an address the fuzzer
    /// harvested out of the TARGET's own storage (see
    /// `crate::evm::host::HARVESTED_STORAGE_ADDRESSES`) -- i.e. the finding
    /// was produced by impersonating an identity the contract itself
    /// stored, overwhelmingly its `owner`/admin/multisig, rather than a
    /// genuine external attacker.
    ///
    /// This is the honest, machine-readable form of the false positive
    /// observed live on ETC target 0x9f5304...: `escapeHatch()` is
    /// `require(msg.sender == owner)`, and the fuzzer satisfied it simply
    /// by becoming the owner address it read from slot 0 -- reported as
    /// "Fund Loss". It is NOT an exploit, and AttackWallet cannot replay
    /// it as one either (the Python layer has no owner key). Plans flagged
    /// here should be treated as evidence only, never attempted on-chain.
    owner_impersonation: bool,
    /// Structured provenance behind `owner_impersonation`: WHO was
    /// impersonated, on WHICH contract, out of WHICH storage slot. A bare
    /// boolean told a reader that a plan was a false positive but not why,
    /// which made the report unactionable. Empty exactly when
    /// `owner_impersonation` is false.
    owner_impersonation_detail: Vec<ImpersonatedCaller>,
    /// PHASE 3.2: the SEMANTIC owner-gated test, stricter than
    /// `owner_impersonation`. True only when some step calls a contract AS
    /// an identity harvested from THAT SAME contract's own storage --
    /// exactly the `require(msg.sender == owner)` shape satisfied by
    /// impersonation. `owner_impersonation` is true for an address
    /// harvested from ANY target; this is true only for the contract's own
    /// stored privileged identity, which is what actually proves the
    /// privileged-party shape rather than merely suggesting it.
    owner_gated: bool,
    /// The (caller, contract, slot) behind `owner_gated`, one entry per
    /// step that satisfied the semantic test. Empty exactly when
    /// `owner_gated` is false.
    owner_gated_detail: Vec<ImpersonatedCaller>,
    /// Number of entries in `steps` -- lets the Python layer prefer
    /// richer, multi-step findings when assembling a merged plan.
    step_count: usize,
    target: &'a str,
    chain: &'a str,
}

#[derive(Serialize)]
struct ExploitPlan<'a> {
    contract_name: &'a str,
    kind: &'a str,
    needs_funding: bool,
    total_value: &'a str,
    /// The minimized proof -- the smallest sequence that re-triggers the
    /// oracle. Always present.
    steps: Vec<PlanStep<'a>>,
    /// The UNMINIMIZED trace the finding was discovered on, when the
    /// caller had it (see `generate_test_with_full_trace`). This is what
    /// the Python layer merges into a coherent multi-step plan: the
    /// minimizer deliberately strips earlier state-setting calls (approve,
    /// ownership flip, ...) that a compound exploit needs, so `steps`
    /// alone often has nothing to chain. Falls back to `steps` when no
    /// full trace was supplied, so a consumer can always read this field.
    full_trace_steps: Vec<PlanStep<'a>>,
    /// Only set for `kind == "reentrancy"`: the call that must be armed
    /// via `AttackWallet.armCallback()` immediately before executing the
    /// last entry of `steps` (the trigger), so the reentrant callback
    /// replays it for real instead of relying on a generated contract's
    /// own hardcoded `receive()`.
    repeat_step: Option<PlanStep<'a>>,
    #[serde(flatten)]
    meta: PlanMeta<'a>,
}

fn write_plan(output_dir: &str, contract_name: &str, plan: &ExploitPlan) {
    let path = format!("{}/{}.plan.json", output_dir, contract_name);
    let file = match File::create(&path) {
        Ok(f) => f,
        Err(_) => {
            error!("write_plan error: failed to create output file {:?}.", path);
            return;
        }
    };
    if let Err(e) = serde_json::to_writer_pretty(file, plan) {
        error!("write_plan error: failed to serialize plan to {:?}: {:?}", path, e);
    }
}

/// Builds the `PlanMeta` shared by every plan generator. `trace` is the
/// SAME step list the plan serializes, so `step_count`/`distinct_callers`
/// always agree with what `steps` actually contains.
fn build_plan_meta<'a>(args: &'a TemplateArgs, trace: &[Tx]) -> PlanMeta<'a> {
    let bug_types = super::parse_bug_report(&args.solution);
    let requires_control_leak = super::trace_depends_on_control_leak(trace);
    // PHASE 2.3 (TASK_SPEC.md): the acceptance criterion is that a
    // `sim-confirmed` plan NEVER rests on control leak. Injecting a faked
    // return value is only ever allowed as `sim-review` research -- so a
    // trace whose discovery needed one is downgraded here, regardless of
    // how strong its bug_type is. The bug_type is still listed (it is real
    // evidence of a violated invariant), but the CONFIDENCE claim is
    // withheld: the same call would not reproduce without the injected
    // return, so calling it "confirmed" would overstate what was observed.
    let confidence = if requires_control_leak {
        "sim-review"
    } else if bug_types.iter().any(|b| super::is_confirmed_bug_type(b)) {
        "sim-confirmed"
    } else {
        "sim-review"
    };
    let mut callers: Vec<String> = trace.iter().map(|tx| tx.caller.clone()).collect();
    callers.sort();
    callers.dedup();
    // ANY caller being a storage-harvested identity means the trace relied
    // on an identity the target itself stored -- see the field's own doc.
    // Deliberately `any`, not `all`: the live false positive had TWO
    // callers (a generic fuzzer address plus the target's owner multisig),
    // and the owner was the one that actually satisfied
    // `require(msg.sender == owner)` -- an `all` test would have missed
    // exactly the case this flag exists for.
    let owner_impersonation = callers.iter().any(|c| crate::evm::host::is_harvested_storage_address(c));
    // Structured provenance for each harvested caller -- the report should
    // name WHO/WHICH CONTRACT/WHICH SLOT, not just "this is a false
    // positive". A harvested address whose (contract, slot) origin was not
    // recorded falls back to explicit "unknown" markers rather than being
    // dropped, so the entry count always matches the impersonated callers.
    let owner_impersonation_detail: Vec<ImpersonatedCaller> = callers
        .iter()
        .filter(|c| crate::evm::host::is_harvested_storage_address(c))
        .map(|c| {
            let (contract, slot) = crate::evm::host::harvested_address_origin(c)
                .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));
            ImpersonatedCaller {
                caller: c.clone(),
                harvested_from_contract: contract,
                harvested_from_slot: slot,
            }
        })
        .collect();
    // PHASE 3.2: the semantic owner-gated test. Per STEP (caller, contract),
    // ask whether the caller is an identity THAT contract harvested from its
    // OWN storage -- i.e. the trace calls the contract as its stored owner.
    // This is strictly narrower than `owner_impersonation` (which only needs
    // the address to come from SOME target's storage), so it is the honest
    // signal that the `require(msg.sender == owner)` shape was exercised.
    let owner_gated_detail: Vec<ImpersonatedCaller> = trace
        .iter()
        .filter(|tx| crate::evm::host::is_harvested_sender_for(&tx.contract, &tx.caller))
        .map(|tx| {
            let (contract, slot) = crate::evm::host::harvested_address_origin(&tx.caller)
                .unwrap_or_else(|| (tx.contract.clone(), "unknown".to_string()));
            ImpersonatedCaller {
                caller: tx.caller.clone(),
                harvested_from_contract: contract,
                harvested_from_slot: slot,
            }
        })
        .collect();
    let owner_gated = !owner_gated_detail.is_empty();
    PlanMeta {
        confirmed_exploitable: super::is_confirmed_exploitable_bug(&args.solution),
        confidence,
        requires_control_leak,
        // A step that needed an intercepted, fuzzer-faked return value
        // cannot be reproduced by AttackWallet, which only ever makes
        // real calls -- so the plan is honest evidence but not atomic.
        atomic_replayable: !requires_control_leak,
        distinct_callers: callers.len(),
        callers,
        owner_impersonation,
        owner_impersonation_detail,
        owner_gated,
        owner_gated_detail,
        step_count: trace.len(),
        bug_types,
        target: &args.target,
        chain: &args.chain,
    }
}

/// Emit the structured JSON plan for a flat (non-reentrancy) fund-extraction
/// exploit, alongside the Solidity script `generate_script` produces.
pub fn generate_exploit_plan(args: &TemplateArgs, full_trace: Option<&[Tx]>) {
    let steps: Vec<PlanStep> = args.trace.iter().map(PlanStep::from).collect();
    let full_trace_steps: Vec<PlanStep> = match full_trace {
        Some(ft) if !ft.is_empty() => ft.iter().map(PlanStep::from).collect(),
        _ => steps.clone(),
    };
    // Metadata reflects the FULL trace when we have it: that is the
    // sequence the Python layer will actually merge, so its
    // distinct_callers/step_count must describe that sequence, not the
    // minimized one.
    let meta_source: &[Tx] = match full_trace {
        Some(ft) if !ft.is_empty() => ft,
        _ => &args.trace,
    };
    let meta = build_plan_meta(args, meta_source);
    let plan = ExploitPlan {
        contract_name: &args.contract_name,
        kind: "flat",
        needs_funding: args.needs_funding,
        total_value: &args.total_value,
        steps,
        full_trace_steps,
        repeat_step: None,
        meta,
    };
    write_plan(&args.output_dir, &args.contract_name, &plan);
}

/// Emit the structured JSON plan for a reentrancy exploit, alongside the
/// Solidity script `generate_reentrancy_script` produces.
pub fn generate_reentrancy_exploit_plan(
    args: &TemplateArgs,
    setup: &[&Tx],
    repeat_tx: &Tx,
    full_trace: Option<&[Tx]>,
) {
    let total_value: u128 = setup
        .iter()
        .filter_map(|tx| crate::evm::utils::parse_pretty_wei(&tx.value))
        .sum();
    let total_value_str = total_value.to_string();
    let mut all: Vec<Tx> = setup.iter().map(|tx| (*tx).clone()).collect();
    all.push(repeat_tx.clone());
    let meta = build_plan_meta(args, &all);
    let steps: Vec<PlanStep> = setup.iter().map(|tx| PlanStep::from(*tx)).collect();
    let full_trace_steps: Vec<PlanStep> = match full_trace {
        Some(ft) if !ft.is_empty() => ft.iter().map(PlanStep::from).collect(),
        _ => steps.clone(),
    };
    let plan = ExploitPlan {
        contract_name: &args.contract_name,
        kind: "reentrancy",
        needs_funding: total_value > 0,
        total_value: &total_value_str,
        steps,
        full_trace_steps,
        repeat_step: Some(PlanStep::from(repeat_tx)),
        meta,
    };
    write_plan(&args.output_dir, &args.contract_name, &plan);
}

/// Template for the atomic `forge script` exploit PoC (as opposed to
/// `foundry_test.hbs`, which produces a `forge test` reproduction).
const SCRIPT_TEMPLATE: &str = include_str!("foundry_script.hbs");

/// Template for the atomic reentrancy exploit PoC (see
/// `split_reentrant_trace` in `mod.rs` for how the setup/repeat calls are
/// derived from the trace).
const REENTRANCY_SCRIPT_TEMPLATE: &str = include_str!("foundry_script_reentrancy.hbs");

handlebars_helper!(is_deposit: |ty: String| ty == "deposit");
handlebars_helper!(is_buy: |ty: String| ty == "buy");
handlebars_helper!(is_withdraw: |ty: String| ty == "withdraw");
handlebars_helper!(is_sell: |ty: String| ty == "sell");

/// Generate an atomic Foundry exploit script for a fund-extraction bug.
///
/// Unlike the `forge test` reproduction (which uses `vm.prank`/`vm.deal` to
/// simulate multiple callers and funding -- test-only cheatcodes that don't
/// exist outside Foundry's test/simulation environment), this emits:
///   - `{contract_name}Exploit`: a plain contract whose `attack()` replays the
///     whole call sequence from its own identity (`address(this)`), so it can
///     actually be deployed and run on a real network.
///   - `{contract_name}ExploitRunner is Script`: a `forge script` that deploys
///     the exploit contract, funds it with the ETH the attack needs, and calls
///     `attack()`, all inside one `vm.startBroadcast()`/ `vm.stopBroadcast()`
///     block -- i.e. one atomic broadcast transaction, so there's no window
///     between steps for anyone to front-run.
pub fn generate_script(args: &TemplateArgs) {
    let mut handlebars = Handlebars::new();
    if handlebars
        .register_template_string("foundry_script", SCRIPT_TEMPLATE)
        .is_err()
    {
        error!("generate_script error: failed to register template file.");
        return;
    }

    handlebars.register_helper("is_deposit", Box::new(is_deposit));
    handlebars.register_helper("is_buy", Box::new(is_buy));
    handlebars.register_helper("is_withdraw", Box::new(is_withdraw));
    handlebars.register_helper("is_sell", Box::new(is_sell));

    if fs::create_dir_all(&args.output_dir).is_err() {
        error!(
            "generate_script error: failed to create output dir {:?}.",
            args.output_dir
        );
        return;
    }

    let path = format!("{}/{}Exploit.s.sol", args.output_dir, args.contract_name);
    let output = match File::create(&path) {
        Ok(f) => f,
        Err(_) => {
            error!("generate_script error: failed to create output file {:?}.", path);
            return;
        }
    };

    if let Err(e) = handlebars.render_to_write("foundry_script", args, output) {
        error!("generate_script error: failed to render template: {:?}", e);
    }
}

#[derive(Serialize)]
struct ReentrancyScriptArgs<'a> {
    contract_name: &'a str,
    solution: &'a str,
    router: &'a str,
    interface: &'a std::collections::HashSet<String>,
    include_interface: bool,
    setup_calls: &'a [&'a Tx],
    repeat_tx: &'a Tx,
    needs_funding: bool,
    total_value: String,
    is_onchain: bool,
    target: &'a str,
    chain: &'a str,
    block_number: &'a str,
    etherscan_keyname: &'a str,
}

/// Generate an atomic Foundry exploit script for a reentrancy bug, whose
/// shape is fundamentally different from `generate_script`'s flat replay:
/// `attack()` triggers the vulnerable call once, and `receive()` -- invoked
/// when that call sends this contract ETH mid-execution -- repeats it,
/// reproducing the real call-stack reentrancy instead of a flattened
/// sequence of independent calls (which a `vm.prank`-based `forge test`
/// reproduction can fake but a real broadcast transaction cannot).
///
/// `setup` and `repeat_tx` come from `split_reentrant_trace` in `mod.rs`:
/// `setup` is every call the attacking caller makes, in order, including
/// one copy of the repeated call (the trigger); `repeat_tx` is that same
/// repeated call's own `Tx`, rendered again inside `receive()`.
pub fn generate_reentrancy_script(args: &TemplateArgs, setup: &[&Tx], repeat_tx: &Tx) {
    let mut handlebars = Handlebars::new();
    if handlebars
        .register_template_string("foundry_script_reentrancy", REENTRANCY_SCRIPT_TEMPLATE)
        .is_err()
    {
        error!("generate_reentrancy_script error: failed to register template file.");
        return;
    }

    handlebars.register_helper("is_deposit", Box::new(is_deposit));
    handlebars.register_helper("is_buy", Box::new(is_buy));
    handlebars.register_helper("is_withdraw", Box::new(is_withdraw));
    handlebars.register_helper("is_sell", Box::new(is_sell));

    if fs::create_dir_all(&args.output_dir).is_err() {
        error!(
            "generate_reentrancy_script error: failed to create output dir {:?}.",
            args.output_dir
        );
        return;
    }

    // Funding is computed from just the attacking caller's own calls
    // (`setup`), not `args.total_value` -- that figure covers the whole
    // original multi-caller trace, which can include other callers' calls
    // that `split_reentrant_trace` deliberately drops.
    let total_value: u128 = setup
        .iter()
        .filter_map(|tx| crate::evm::utils::parse_pretty_wei(&tx.value))
        .sum();
    let needs_funding = total_value > 0;

    let ctx = ReentrancyScriptArgs {
        contract_name: &args.contract_name,
        solution: &args.solution,
        router: &args.router,
        interface: &args.interface,
        include_interface: args.include_interface,
        setup_calls: setup,
        repeat_tx,
        needs_funding,
        total_value: total_value.to_string(),
        is_onchain: args.is_onchain,
        target: &args.target,
        chain: &args.chain,
        block_number: &args.block_number,
        etherscan_keyname: &args.etherscan_keyname,
    };

    let path = format!("{}/{}ReentrancyExploit.s.sol", args.output_dir, args.contract_name);
    let output = match File::create(&path) {
        Ok(f) => f,
        Err(_) => {
            error!(
                "generate_reentrancy_script error: failed to create output file {:?}.",
                path
            );
            return;
        }
    };

    if let Err(e) = handlebars.render_to_write("foundry_script_reentrancy", &ctx, output) {
        error!("generate_reentrancy_script error: failed to render template: {:?}", e);
    }
}

#[cfg(test)]
mod plan_meta_confidence_tests {
    use super::*;
    use crate::evm::solution::{TemplateArgs, Tx};

    fn args_for(solution: &str) -> TemplateArgs {
        TemplateArgs {
            solution: solution.to_string(),
            ..Default::default()
        }
    }

    /// PHASE 2.3 acceptance criterion (TASK_SPEC.md): a
    /// `sim-confirmed` plan must NEVER rest on control leak. A trace whose
    /// discovery used an intercepted, fuzzer-injected fake return value has
    /// to be downgraded to `sim-review`, even when its bug_type is
    /// Confirmed-tier -- because the same call would not reproduce on-chain
    /// without the injected return, so "confirmed" would overstate what was
    /// actually observed. This is the regression test for the
    /// `build_plan_meta` fix.
    #[test]
    fn control_leak_trace_is_never_sim_confirmed() {
        let args = args_for("[Fund Loss] (sim-confirmed): drained the vault");

        // Baseline: the SAME Confirmed-tier bug_type with no control leak
        // is sim-confirmed -- this guards the test against passing
        // vacuously (e.g. if `parse_bug_report`/`is_confirmed_bug_type`
        // silently stopped recognising the bug_type).
        let clean = vec![Tx {
            call_leak: u32::MAX,
            ..Default::default()
        }];
        let clean_meta = build_plan_meta(&args, &clean);
        assert!(
            clean_meta.bug_types.iter().any(|b| b == "Fund Loss"),
            "bug_type must be parsed for the test to be meaningful"
        );
        assert_eq!(clean_meta.confidence, "sim-confirmed");
        assert!(!clean_meta.requires_control_leak);
        assert!(clean_meta.atomic_replayable);

        // The same trace, but its discovery needed control leak (any value
        // other than CALL_UNTIL's neutral u32::MAX default).
        let leaked = vec![Tx {
            call_leak: 3,
            ..Default::default()
        }];
        let leaked_meta = build_plan_meta(&args, &leaked);
        assert!(
            leaked_meta.requires_control_leak,
            "a non-neutral call_leak must be flagged as control-leak dependent"
        );
        assert_ne!(
            leaked_meta.confidence, "sim-confirmed",
            "a control-leak-dependent trace must never be sim-confirmed (PHASE 2.3)"
        );
        assert_eq!(leaked_meta.confidence, "sim-review");
        assert!(
            !leaked_meta.atomic_replayable,
            "a control-leak-dependent trace is not atomic-replayable"
        );
        // The bug_type is still listed as honest evidence -- only the
        // CONFIDENCE claim is withheld.
        assert!(leaked_meta.bug_types.iter().any(|b| b == "Fund Loss"));
    }
}

