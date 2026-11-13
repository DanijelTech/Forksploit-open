mod abi;
mod script_generator;

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::SystemTime,
};

use abi::StructDef;
use handlebars::{handlebars_helper, Handlebars};
use serde::Serialize;
use tracing::{debug, error};

use self::abi::{Abi, DecodedArg};
use super::{types::EVMU256, utils, OnChainConfig};
use crate::{generic_vm::vm_state::SwapInfo, input::SolutionTx};

/// Template
const TEMPLATE: &str = include_str!("foundry_test.hbs");

/// Cli args.
static CLI_ARGS: OnceLock<CliArgs> = OnceLock::new();

/// `make_contract_name()` returns the SAME name for every bug found on a
/// given target (it's derived purely from the target address/path, not
/// from the bug itself) -- confirmed live: fuzzing a real contract with
/// ~36 distinct findings (reentrancy, fund loss, unchecked calls, ...)
/// left exactly ONE `.t.sol`/`.s.sol`/`.plan.json` on disk, because every
/// call to `generate_test()` wrote to the identical `{contract_name}.t.sol`
/// path, silently overwriting all earlier bugs' reproductions with
/// whichever was found last. This counter makes each call's output
/// filename unique (`{contract_name}_{n}.t.sol`) so distinct bugs on the
/// same target stop destroying each other's evidence.
static BUG_COUNTER: AtomicU64 = AtomicU64::new(0);

// Template helpers to compare strings
handlebars_helper!(is_deposit: |ty: String| ty == "deposit");
handlebars_helper!(is_buy: |ty: String| ty == "buy");
handlebars_helper!(is_withdraw: |ty: String| ty == "withdraw");
handlebars_helper!(is_sell: |ty: String| ty == "sell");

/// Initialize CLI_ARGS.
pub fn init_cli_args(target: String, work_dir: String, onchain: &Option<OnChainConfig>) {
    let (chain, block_number) = match onchain {
        Some(oc) => {
            let block_number = oc.block_number.clone();
            let number = EVMU256::from_str_radix(block_number.trim_start_matches("0x"), 16)
                .unwrap()
                .to_string();
            (oc.chain_name.clone(), number)
        }
        None => (String::from(""), String::from("")),
    };

    let cli_args = CliArgs {
        is_onchain: onchain.is_some(),
        chain,
        target,
        block_number,
        output_dir: format!("{}/vulnerabilities", work_dir),
    };

    let _ = CLI_ARGS.set(cli_args);
}

/// Generate a foundry test file.
pub fn generate_test<T: SolutionTx>(solution: String, inputs: Vec<T>) {
    generate_test_with_full_trace(solution, inputs, None);
}

/// Like `generate_test`, but also takes the UNMINIMIZED trace the finding
/// was discovered on (`full_trace`), when available.
///
/// Why this exists: `SequentialMinimizer` strips every transaction that
/// isn't strictly required to re-trigger the oracle, which is exactly what
/// a `forge test` reproduction wants -- but it also strips the earlier
/// state-setting calls a COMPOUND exploit needs (e.g. the `approve` before
/// a `transferFrom`, the ownership flip before the privileged drain). A
/// minimized single-step plan gives the Python layer nothing to merge. The
/// full trace is emitted as a SEPARATE, clearly-marked field
/// (`full_trace_steps`) so the Python layer can assemble a coherent
/// multi-step plan from it while the minimized `steps` stay the
/// minimal proof.
pub fn generate_test_with_full_trace<T: SolutionTx>(
    solution: String,
    inputs: Vec<T>,
    full_trace: Option<Vec<T>>,
) {
    let solution = utils::remove_color(&solution);

    let trace: Vec<Tx> = inputs.iter().map(Tx::from).collect();
    if trace.is_empty() {
        error!("generate_test error: no trace found.");
        return;
    }
    let full_trace: Option<Vec<Tx>> = full_trace.map(|ft| ft.iter().map(Tx::from).collect());
    let args = TemplateArgs::new(solution, trace);
    if args.is_err() {
        debug!("skip generating test: not evm solution.");
        return;
    }
    let args = args.unwrap();
    if fs::create_dir_all(&args.output_dir).is_err() {
        error!(
            "generate_test error: failed to create output dir {:?}.",
            args.output_dir
        );
        return;
    }
    let mut handlebars = Handlebars::new();
    if handlebars.register_template_string("foundry_test", TEMPLATE).is_err() {
        error!("generate_test error: failed to register template file.");
        return;
    }

    handlebars.register_helper("is_deposit", Box::new(is_deposit));
    handlebars.register_helper("is_buy", Box::new(is_buy));
    handlebars.register_helper("is_withdraw", Box::new(is_withdraw));
    handlebars.register_helper("is_sell", Box::new(is_sell));

    let path = format!("{}/{}.t.sol", args.output_dir, args.contract_name);
    let output = File::create(path);
    if output.is_err() {
        error!("generate_test error: failed to create output file.");
        return;
    }

    if let Err(e) = handlebars.render_to_write("foundry_test", &args, &mut output.unwrap()) {
        error!("generate_test error: failed to render template: {:?}", e);
    }

    // For every CONFIRMED (not Review-tier heuristic) vulnerability class,
    // also emit a `forge script` PoC that executes the whole attack
    // atomically in one broadcast transaction, instead of only a
    // `forge test` reproduction -- see is_confirmed_exploitable_bug's own
    // doc comment for exactly where that line is drawn and why.
    //
    // A plan.json is emitted for EVERY finding now, not only for
    // Confirmed-tier single-identity traces. The previous code silently
    // skipped plan generation whenever a trace depended on control leak or
    // had multiple distinct callers, and never emitted one at all for
    // Review-tier findings -- so a target whose only evidence was a
    // multi-caller or leak-dependent trace produced NO machine-readable
    // plan for the Python layer to chain. The plan's own metadata
    // (`atomic_replayable`, `distinct_callers`, `confidence`,
    // `confirmed_exploitable`, `bug_types`) carries everything the Python
    // layer needs to decide whether to run it standalone, chain it, or
    // treat it as evidence only -- the decision belongs there, not in a
    // silent skip here.
    let mut plan_emitted = false;
    if is_reentrancy_bug(&args.solution) {
        match split_reentrant_trace(&args.trace) {
            Some((setup, repeat_tx)) => {
                script_generator::generate_reentrancy_script(&args, &setup, repeat_tx);
                script_generator::generate_reentrancy_exploit_plan(
                    &args,
                    &setup,
                    repeat_tx,
                    full_trace.as_deref(),
                );
                plan_emitted = true;
            }
            None => {
                debug!(
                    "no single-caller repeated (contract, selector) call in the trace to use as the \
                     receive() callback -- emitting a flat plan instead (metadata marks it non-reentrancy)."
                );
            }
        }
    }

    if !plan_emitted {
        script_generator::generate_exploit_plan(&args, full_trace.as_deref());
    }

    // The atomic `forge script` (deploy + fund + attack in one broadcast
    // transaction) is only sound when the trace is a directly observed,
    // Confirmed-tier violation that replays as a real call sequence:
    // control-leak-dependent traces relied on a fuzzer-injected fake return
    // value AttackWallet cannot reproduce, and a multi-caller trace cannot
    // be flattened into one `address(this)` identity (an address argument
    // embedded in calldata still points at the original actor). Those two
    // cases still get a plan.json above -- they are honest evidence, just
    // not a runnable atomic exploit -- and the Python layer sees exactly
    // which is which via `atomic_replayable`/`distinct_callers`.
    if !plan_emitted
        && is_confirmed_exploitable_bug(&args.solution)
        && !trace_depends_on_control_leak(&args.trace)
        && !has_multiple_distinct_callers(&args.trace)
    {
        script_generator::generate_script(&args);
    }
}

/// Whether the recorded trace involves more than one distinct top-level
/// caller address. See the call site above for why this disqualifies a
/// trace from atomic `forge script` generation.
fn has_multiple_distinct_callers(trace: &[Tx]) -> bool {
    trace.iter().map(|tx| &tx.caller).collect::<HashSet<_>>().len() > 1
}

/// Whether ANY step's own discovery used host.rs's control-leak mechanism
/// (see Tx::call_leak's own doc, and the call site above for the full
/// writeup of why this disqualifies atomic script/plan generation): a
/// u32::MAX call_leak (CALL_UNTIL's own neutral default) means "ran to
/// completion normally, no call was intercepted," which is the only case
/// an atomic AttackWallet replay can actually be the same thing that was
/// proven in simulation.
fn trace_depends_on_control_leak(trace: &[Tx]) -> bool {
    trace.iter().any(|tx| tx.call_leak != u32::MAX)
}

fn is_reentrancy_bug(solution: &str) -> bool {
    solution.contains("[Reentrancy]")
}

/// Extracts every bug_type from a Description block's lines of the form
/// `[Bug Type] (sim-confirmed): ...` -- the same shape
/// `strategy_layer.py`'s `_CONFIRMED_BUG_TYPE_RE` matches, but tolerant of
/// BOTH confidence tiers (the Python side needs only confirmed ones; the
/// plan's own `bug_types` should list everything the trace tripped so a
/// Review-tier finding is still chainable as an unlock).
fn parse_bug_report(solution: &str) -> Vec<String> {
    let mut types = Vec::new();
    for line in solution.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix('[') else { continue };
        let Some(end) = rest.find(']') else { continue };
        let bug_type = rest[..end].trim();
        // Require the `(sim-...)` tier marker right after the bracket so a
        // stray `[Sender]`/`[1]` trace line can never be mistaken for a
        // bug_type.
        let after = rest[end + 1..].trim_start();
        if !(after.starts_with("(sim-confirmed)") || after.starts_with("(sim-review)")
            || after.starts_with("(confirmed)") || after.starts_with("(review)"))
        {
            continue;
        }
        if !bug_type.is_empty() && !types.iter().any(|t| t == bug_type) {
            types.push(bug_type.to_string());
        }
    }
    types
}

/// Whether a single bug_type string is Confirmed-tier -- delegates to
/// `oracle.rs`'s `classify_confidence`, the single source of truth for the
/// tier, so this can never drift from what the oracle JSON prints. It used
/// to delegate to `is_confirmed_exploitable_bug`'s list instead, which is a
/// DIFFERENT set: `Reentrancy` is Confirmed-tier but is not "exploitable"
/// here (it has its own extraction path), so reading the tier off the wrong
/// list silently mislabelled a `sim-confirmed` reentrancy plan as
/// `sim-review` -- contradicting the oracle JSON for the same finding.
fn is_confirmed_bug_type(bug_type: &str) -> bool {
    super::oracle::classify_confidence(bug_type) == super::oracle::ConfidenceTier::Confirmed
}

/// Finds a reentrant pattern in the trace: a (contract, fn_selector) pair
/// that the SAME caller invokes more than once. ForkSploit's reentrancy
/// oracle (see `middlewares/reentrancy.rs`) triggers via the engine's
/// "control leak" mechanism: the outer call into that function leaks
/// control (typically because it sends ETH, which can call back into the
/// caller's own `receive()`/`fallback()`), and the fuzzer found that
/// repeating the SAME call during that leak trips the read-before-call,
/// write-after-reentry pattern. That matches exactly how a real reentrancy
/// attacker contract works: call the vulnerable function once, and have
/// `receive()` call it again -- which is the shape this generates.
///
/// Returns (setup calls including the trigger call once, the Tx to replay
/// inside `receive()`). Only ever considers calls made by the SAME caller
/// that performs the repeated call, dropping every other caller's calls
/// entirely -- reusing a different caller's call would hit the exact same
/// "address mismatch" problem documented on `has_multiple_distinct_callers`
/// (e.g. another account's own deposit does nothing for an attacker trying
/// to withdraw funds that were credited to a different address).
fn split_reentrant_trace(trace: &[Tx]) -> Option<(Vec<&Tx>, &Tx)> {
    let mut counts: HashMap<(&str, &str), usize> = HashMap::new();
    for tx in trace {
        *counts
            .entry((tx.contract.as_str(), tx.fn_selector.as_str()))
            .or_insert(0) += 1;
    }
    let (repeated_key, _) = counts.into_iter().find(|(_, count)| *count >= 2)?;

    let repeat_callers: HashSet<&str> = trace
        .iter()
        .filter(|tx| (tx.contract.as_str(), tx.fn_selector.as_str()) == repeated_key)
        .map(|tx| tx.caller.as_str())
        .collect();
    if repeat_callers.len() != 1 {
        return None;
    }
    let attacker = *repeat_callers.iter().next().unwrap();

    let mut setup = Vec::new();
    let mut reentrant_sample: Option<&Tx> = None;
    let mut kept_trigger = false;
    for tx in trace {
        if tx.caller != attacker {
            continue;
        }
        let key = (tx.contract.as_str(), tx.fn_selector.as_str());
        if key == repeated_key {
            reentrant_sample = Some(tx);
            if !kept_trigger {
                setup.push(tx);
                kept_trigger = true;
            }
        } else {
            setup.push(tx);
        }
    }
    reentrant_sample.map(|r| (setup, r))
}

/// Bug classes worth generating an atomic `forge script` exploit for, on
/// top of the `forge test` reproduction every bug already gets.
///
/// The line this draws is CONFIDENCE, not "does it move money": every
/// bug_type listed here is one `oracle.rs`'s `classify_confidence` tags
/// `Confirmed` -- a directly observed violation (a call that actually
/// succeeded, a signature that actually replayed, a slot that actually
/// collided), not a heuristic inference. Replaying a Confirmed trace
/// atomically is honest: the thing it reproduces genuinely happened.
///
/// Deliberately EXCLUDES every `Review`-tier bug_type (Centralization
/// Risk, Curve Virtual Price Decrease, Price Feed Staleness, TWAP
/// Manipulation Precondition, Unbounded Loop, Stale Guard Counter,
/// Unchecked Low-Level Call, Uninitialized Memory Read, state_comp,
/// Integer Overflow, Delegatecall Target From Calldata (Unconfirmed)) --
/// generating a confident-looking, runnable "exploit" for a finding this
/// project's own confidence classification admits might be a false
/// positive would be worse than generating none: it would dress up a
/// guess as proof. The `forge test` reproduction (which still gets
/// generated for every bug type, Review included) says "here is exactly
/// what happened"; an `.s.sol` exploit script says "here is a working
/// attack" -- that second claim only gets made when it's actually true.
///
/// Reentrancy is NOT in this list -- it has its own dedicated
/// `generate_reentrancy_script`/`generate_reentrancy_exploit_plan` path
/// (see the call site below) because a reentrant attack's shape
/// (`attack()` triggers once, `receive()` repeats) is fundamentally
/// different from this function's flat single-sequence replay.
///
/// `Invariant Violation` IS included: it is Confirmed-tier (a directly
/// observed false relationship, see oracle.rs) and its trace is a normal
/// flat call sequence, so it replays through AttackWallet like any other
/// flat plan. It was previously missing from this list, which -- because
/// `auto_pipeline.py` treats `confirmed_exploitable == false` as "Review-tier
/// heuristic, nothing to replay" -- silently skipped EVERY user-declared
/// invariant finding even though the oracle had just stamped it
/// `sim-confirmed`. This list and `oracle.rs`'s `classify_confidence` are
/// reconciled by `classify_confidence_matches_confirmed_exploitable_list`
/// below so the two cannot drift apart again.
const CONFIRMED_EXPLOITABLE_BUG_TYPES: &[&str] = &[
        // Already covered before this list was expanded.
        "Fund Loss",
        "ERC4626 Share Inflation",
        "Unauthorized ERC20 Transfer",
        "Unauthorized NFT Transfer",
        "Unauthorized ERC1155 Transfer",
        "Imbalanced Uniswap Pair",
        // Every other Confirmed-tier bug_type (see oracle.rs's
        // classify_confidence), added together so every oracle this
        // project ships gets a real, runnable exploit for its
        // deterministic findings, not just the original 6.
        "Unauthorized Owner Change",
        "Unauthorized Pause Toggle",
        "Unauthorized Proxy Upgrade",
        "Unprotected Proxy Upgrade (UUPS)",
        "Arbitrary Call",
        "Delegatecall Injection",
        "Delegatecall Target From Calldata",
        "Unchecked ecrecover(0)",
        "Arbitrary Storage Write",
        // A user-declared invariant (oracles/invariant.rs) is evaluated
        // against the real post-transaction state and only reported when
        // the declared relationship is actually observed to be false --
        // Confirmed-tier, and a flat replayable trace, exactly like the
        // other entries here. Omitting it made the Python layer skip every
        // invariant finding as a non-extractable heuristic.
        "Invariant Violation",
        "Insolvent: Promised Native Value Exceeds Real Balance",
        "Initializer Front-Running",
        "ERC4626 Rounding Favors User",
        "Proxy Reinitialization",
        "Proxy Storage Collision",
        "Storage Collision",
        "Selfdestruct",
        "Signature Malleability",
        "Signature Replay",
        "Tx.Origin Phishing Bypass",
        "Validation-Independent Payment",
        "Bug",
        // Secondary-confirmation promotions from oracles/
        // twap_manipulation.rs and oracles/curve_virtual_price.rs: same
        // oracle as the Review-tier "TWAP Manipulation Precondition"/
        // "Curve Virtual Price Decrease", but only reported under these
        // bug_types when the caller who caused it also walked away with
        // a confirmed net ETH profit in the same transaction.
        "TWAP Manipulation (Profit Confirmed)",
        "Curve Virtual Price Decrease (Profit Confirmed)",
];

fn is_confirmed_exploitable_bug(solution: &str) -> bool {
    CONFIRMED_EXPLOITABLE_BUG_TYPES
        .iter()
        .any(|bug_type| solution.contains(&format!("[{}]", bug_type)))
}

#[derive(Debug, Clone)]
struct CliArgs {
    is_onchain: bool,
    chain: String,
    target: String,
    block_number: String,
    output_dir: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Tx {
    interface_calls: Vec<String>,
    // A tx can contain both a `buy` and a `sell` operation at the same time.
    buy_type: BuyType,
    sell_type: SellType,
    borrow_idx: u32,
    caller: String,
    contract: String,
    value: String,
    fn_signature: String,
    fn_selector: String,
    fn_args: String,
    calldata: String,
    liq_percent: u8,
    balance_idx: u32,
    // map<type, swap_info>
    swap_data: HashMap<String, SwapInfo>,
    /// u32::MAX = this step's own discovery never relied on control leak.
    /// See SolutionTx::call_leak's own doc for what any other value means
    /// and why `trace_depends_on_control_leak` (below) treats it as
    /// disqualifying for atomic script/plan generation.
    call_leak: u32,
}

impl<T: SolutionTx> From<&T> for Tx {
    fn from(input: &T) -> Self {
        let (is_borrow, mut liq_percent, swap_data) = (input.is_borrow(), input.liq_percent(), input.swap_data());
        let buy_type = BuyType::new(is_borrow, &swap_data);
        let sell_type = SellType::new(liq_percent, &swap_data);

        // Adjust the liq_percent based on whether the `sell` operation is actually
        // executed.
        if liq_percent > 0 && sell_type != SellType::Sell {
            liq_percent = 0;
        }

        Self {
            buy_type,
            sell_type,
            caller: input.caller(),
            contract: input.contract(),
            value: input.value(),
            fn_signature: input.fn_signature(),
            fn_selector: input.fn_selector(),
            fn_args: input.fn_args(),
            calldata: input.calldata(),
            liq_percent,
            swap_data,
            call_leak: input.call_leak(),
            ..Default::default()
        }
    }
}

impl Tx {
    pub fn make_interface_call(&self, args: &[DecodedArg]) -> String {
        let fn_name = self
            .fn_signature
            .split('(')
            .next()
            .unwrap_or(&self.fn_selector)
            .to_string();

        let args = args
            .iter()
            .map(|DecodedArg { value, .. }| value.clone())
            .collect::<Vec<String>>()
            .join(", ");

        let mut fn_call = format!("I({}).{}", self.contract, fn_name);
        if !self.value.is_empty() {
            fn_call.push_str(format!("{{value: {}}}", self.value).as_str());
        }
        fn_call.push_str(format!("({});", args).as_str());
        fn_call
    }
}

#[derive(Debug, Serialize, Default)]
pub struct TemplateArgs {
    contract_name: String,
    // map<struct_signature, struct_def>
    struct_defs: HashMap<String, StructDef>,
    interface: HashSet<String>,
    is_onchain: bool,
    include_interface: bool,
    router: String,
    chain: String,
    target: String,
    block_number: String,
    etherscan_keyname: String,
    solution: String,
    trace: Vec<Tx>,
    stepping_with_return: bool,
    output_dir: String,
    /// Total wei value spent across the whole trace (sum of each tx's
    /// `value`), used by the `forge script` exploit generator to know how
    /// much ETH to fund the exploit contract with.
    total_value: String,
    needs_funding: bool,
}

impl TemplateArgs {
    pub fn new(solution: String, trace: Vec<Tx>) -> Result<Self, String> {
        let cli_args = CLI_ARGS.get();
        if cli_args.is_none() {
            return Err(String::from("CLI_ARGS is not initialized."));
        }
        let cli_args = cli_args.unwrap();

        // Stepping with return
        let stepping_with_return = trace.iter().any(|tx| tx.fn_selector == "0x00000000");
        let mut trace: Vec<Tx> = trace.into_iter().filter(|tx| tx.fn_selector != "0x00000000").collect();

        setup_trace(&mut trace);
        let router = get_router(&trace);
        let contract_name = format!("{}_{}", make_contract_name(cli_args), BUG_COUNTER.fetch_add(1, Ordering::Relaxed));
        let include_interface = trace
            .iter()
            .any(|x| !x.interface_calls.is_empty() || x.buy_type == BuyType::Buy || x.sell_type == SellType::Sell);

        // Decode calldata and collect struct definitions and interface declarations
        let mut struct_defs = HashMap::new();
        let mut interface = HashSet::new();
        for tx in trace.iter_mut() {
            decode_calldata(tx, &mut struct_defs, &mut interface);
        }

        let total_value: u128 = trace
            .iter()
            .filter_map(|tx| crate::evm::utils::parse_pretty_wei(&tx.value))
            .sum();
        let needs_funding = total_value > 0;

        Ok(Self {
            contract_name,
            struct_defs,
            interface,
            is_onchain: cli_args.is_onchain,
            include_interface,
            router,
            chain: cli_args.chain.clone(),
            target: cli_args.target.clone(),
            block_number: cli_args.block_number.clone(),
            etherscan_keyname: format!("{}_ETHERSCAN_API_KEY", cli_args.chain.to_uppercase()),
            solution,
            trace,
            stepping_with_return,
            output_dir: cli_args.output_dir.clone(),
            total_value: total_value.to_string(),
            needs_funding,
        })
    }
}

fn decode_calldata(tx: &mut Tx, struct_defs: &mut HashMap<String, StructDef>, interface: &mut HashSet<String>) {
    // Ignore preset interfaces (IERC20 / IUniswapV2Router)
    if !tx.interface_calls.is_empty() || tx.buy_type == BuyType::Buy || tx.sell_type == SellType::Sell {
        return;
    }

    if tx.buy_type == BuyType::Deposit || tx.sell_type == SellType::Withdraw {
        if tx.buy_type == BuyType::Deposit {
            interface.insert("function deposit() external payable;".to_string());
        }
        if tx.sell_type == SellType::Withdraw {
            interface.insert("function withdraw(uint256) external;".to_string());
        }
        return;
    }

    // For contracts whose real ABI isn't known (unverified/decompiled --
    // e.g. via EVMole), `fn_signature` can fall back to literally using the
    // hex selector as the "function name" (observed: "d0e30db0()" for a
    // real selector of 0xd0e30db0) -- there's no other way to represent
    // "the selector and arg types are known, the real name isn't".
    // Solidity has no way to force a specific selector by naming a
    // function after it, though: it always hashes whatever identifier is
    // actually written, so `interface I { function d0e30db0() ... }`
    // calls keccak256("d0e30db0()")[:4] = 0x73cb7aa0, NOT the real
    // 0xd0e30db0 -- silently calling a different (and likely nonexistent)
    // function. Confirmed live: this is exactly why a freshly generated
    // reentrancy exploit for an unverified Sepolia contract reverted with
    // no revert reason on its very first call. Detect that fallback shape
    // and skip interface generation for it, so the raw
    // `.call(abi.encodeWithSelector(fn_selector, ...))` branch already in
    // the templates (which uses the real selector bytes directly,
    // bypassing Solidity's name-based hashing entirely) is used instead.
    let selector_hex = tx.fn_selector.trim_start_matches("0x");
    if !selector_hex.is_empty() && tx.fn_signature.starts_with(selector_hex) {
        return;
    }

    let mut abi = Abi::new();
    if let Ok(args) = abi.decode_input(&tx.fn_signature, &tx.calldata) {
        let sd = abi.take_struct_defs();
        struct_defs.extend(sd.clone());
        interface.insert(make_interface(&tx.fn_signature, &sd));

        tx.interface_calls.extend(abi.take_memory_vars());
        tx.interface_calls.push(tx.make_interface_call(args.as_slice()));
    }
}

fn make_interface(fn_sig: &str, struct_defs: &HashMap<String, StructDef>) -> String {
    let mut fn_decl = fn_sig.to_string();
    // struct_signature: "(address,address,uint24)"
    for (struct_signature, struct_def) in struct_defs.iter() {
        let struct_arr_sig = format!("{}[]", struct_signature);
        if fn_decl.contains(&struct_arr_sig) {
            fn_decl = fn_decl.replace(&struct_arr_sig, &format!("{}[] memory", struct_def.name));
        } else {
            fn_decl = fn_decl.replace(struct_signature, &format!("{} memory", struct_def.name));
        }
    }

    let res = fn_decl
        .replace("bytes,", "bytes memory,")
        .replace("bytes)", "bytes memory)")
        .replace("string,", "string memory,")
        .replace("string)", "string memory)")
        .replace("],", "] memory,")
        .replace("])", "] memory)");

    format!("function {} external payable;", res)
}

fn setup_trace(trace: &mut [Tx]) {
    let (mut borrow_idx, mut balance_idx) = (0, 0);
    for tx in trace.iter_mut() {
        // Liquidation / Withdraw
        if [SellType::Sell, SellType::Withdraw].contains(&tx.sell_type) {
            tx.balance_idx = balance_idx;
            balance_idx += 1;
        }

        // Raw code
        if let Some(call) = make_erc20_calls(tx) {
            tx.interface_calls = vec![call];
            continue;
        }

        // Borrow
        if tx.buy_type == BuyType::Buy {
            tx.borrow_idx = borrow_idx;
            borrow_idx += 1;
        }

        // ABI Call
        if tx.value == "0" {
            tx.value = "".to_string();
        }
    }
}

fn make_erc20_calls(tx: &Tx) -> Option<String> {
    if tx.buy_type != BuyType::None {
        return None;
    }

    // Confirmed live 2026-11-01: every arm below used to drop `tx.value`
    // entirely, unlike `make_interface_call`'s own `{value: ...}`
    // handling -- harmless for a real Uniswap-V2-style LP/ERC20 (none of
    // these are payable there), but these function NAMES/signatures are
    // matched by TEXT alone, with no way to tell "this really is a plain
    // ERC20/LP" apart from "a completely different, payable contract
    // just happens to have a function named e.g. mint(address)". Hit
    // live by oracles/self_referral.rs's own fixture: its payable
    // `mint(address referral)` matched this `mint(address)` arm,
    // producing a script that called `mint()` with the REQUIRED ETH
    // silently dropped -- reverting with "need value" every time, a
    // confidently-generated exploit that flat out did not work. Build
    // the value suffix the exact same way make_interface_call does, so
    // the actual recorded value is never silently discarded.
    let value_suffix = if tx.value.is_empty() {
        String::new()
    } else {
        format!("{{value: {}}}", tx.value)
    };

    let code = match tx.fn_signature.as_str() {
        "" => format!("IERC20({}).transfer({}, {});", tx.caller, tx.contract, tx.value),
        "balanceOf(address)" => format!("IERC20({}).balanceOf({});", tx.contract, tx.fn_args),
        "approve(address,uint256)" => format!("IERC20({}).approve{}({});", tx.contract, value_suffix, tx.fn_args),
        "transfer(address,uint256)" => format!("IERC20({}).transfer{}({});", tx.contract, value_suffix, tx.fn_args),
        "transferFrom(address,address,uint256)" => {
            format!("IERC20({}).transferFrom{}({});", tx.contract, value_suffix, tx.fn_args)
        }
        "mint(address)" => format!("IERC20({}).mint{}({});", tx.contract, value_suffix, tx.fn_args),
        "burn(address)" => format!("IERC20({}).burn{}({});", tx.contract, value_suffix, tx.fn_args),
        "skim(address)" => format!("IERC20({}).skim{}({});", tx.contract, value_suffix, tx.fn_args),
        "sync()" => format!("IERC20({}).sync{}();", tx.contract, value_suffix),
        _ => "".to_string(),
    };

    if code.is_empty() {
        None
    } else {
        Some(code)
    }
}

/// Token contract touched by a raw ERC20-interface call in this step --
/// the SAME selector match as `make_erc20_calls` above (which renders
/// the Solidity comment for the SAME call), returning just the token
/// address rather than rendered source. `script_generator::PlanStep`
/// surfaces this in `plan.json` so `onchain_scripts/auto_pipeline.py`
/// knows which ERC20 contract to check/sweep off AttackWallet after a
/// plan completes -- a raw transfer/transferFrom/mint never touches
/// AttackWallet.sweep()'s ETH-only balance check on its own (see that
/// function's own doc comment for why this is a separate, narrower gap
/// than the buy/sell swap-router path, which already converts back to
/// ETH as part of the trace itself). "balanceOf"/"sync()" are excluded:
/// read-only/argument-less, they never move funds anywhere.
fn erc20_token_touched(tx: &Tx) -> Option<&str> {
    if tx.buy_type != BuyType::None {
        return None;
    }
    match tx.fn_signature.as_str() {
        "approve(address,uint256)"
        | "transfer(address,uint256)"
        | "transferFrom(address,address,uint256)"
        | "mint(address)"
        | "burn(address)"
        | "skim(address)" => Some(tx.contract.as_str()),
        _ => None,
    }
}

fn get_router(trace: &[Tx]) -> String {
    trace
        .iter()
        .find(|t| {
            // need swap
            t.buy_type == BuyType::Buy || t.sell_type == SellType::Sell
        })
        .map(|t| {
            if let Some(swap_info) = t.swap_data.get("buy") {
                swap_info.target.clone()
            } else {
                t.swap_data
                    .get("sell")
                    .map(|swap_info| swap_info.target.clone())
                    .unwrap_or_default()
            }
        })
        .unwrap_or_default()
}

fn make_contract_name(cli_args: &CliArgs) -> String {
    if cli_args.is_onchain {
        return format!("C{}", &cli_args.target[2..6]);
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let default_name = format!("C{}", now);

    Path::new(&cli_args.target)
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|dirname| dirname.to_str())
        .map(|dirname| {
            dirname
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .map(|name| {
            if name.is_empty() {
                default_name.clone()
            } else {
                format!("{}{}", &name[..1].to_uppercase(), &name[1..])
            }
        })
        .unwrap_or(default_name)
}

#[derive(Clone, Debug, Serialize, Default, PartialEq, Eq)]
#[serde(into = "String")]
pub enum BuyType {
    #[default]
    None,
    Deposit,
    Buy,
}

impl From<BuyType> for String {
    fn from(input: BuyType) -> Self {
        match input {
            BuyType::None => "".to_string(),
            BuyType::Deposit => "deposit".to_string(),
            BuyType::Buy => "buy".to_string(),
        }
    }
}

impl BuyType {
    pub fn new(is_borrow: bool, swap_data: &HashMap<String, SwapInfo>) -> Self {
        if is_borrow {
            if swap_data.contains_key("deposit") {
                return BuyType::Deposit;
            } else if swap_data.contains_key("buy") {
                return BuyType::Buy;
            }
        }
        BuyType::None
    }
}

#[derive(Clone, Debug, Serialize, Default, PartialEq, Eq)]
#[serde(into = "String")]
pub enum SellType {
    #[default]
    None,
    Withdraw,
    Sell,
}

impl From<SellType> for String {
    fn from(input: SellType) -> Self {
        match input {
            SellType::None => "".to_string(),
            SellType::Withdraw => "withdraw".to_string(),
            SellType::Sell => "sell".to_string(),
        }
    }
}

impl SellType {
    pub fn new(liq_percent: u8, swap_data: &HashMap<String, SwapInfo>) -> Self {
        if liq_percent > 0 {
            if swap_data.contains_key("withdraw") {
                return SellType::Withdraw;
            } else if swap_data.contains_key("sell") {
                return SellType::Sell;
            }
        }
        SellType::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockInput {
        caller: String,
        contract: String,
        fn_signature: String,
        fn_selector: String,
        fn_args: String,
        value: String,
        is_borrow: bool,
        liq_percent: u8,
        swap_data: HashMap<String, SwapInfo>,
        calldata: String,
    }

    impl MockInput {
        fn new(fn_sig: &str, calldata: &str, value: &str) -> Self {
            Self {
                caller: String::from(""),
                contract: String::from("0xca143ce32fe78f1f7019d7d551a6402fc5350c73"),
                fn_signature: String::from(fn_sig),
                fn_selector: String::from(""),
                fn_args: String::from(""),
                value: String::from(value),
                is_borrow: false,
                liq_percent: 0,
                swap_data: HashMap::new(),
                calldata: String::from(calldata),
            }
        }
    }

    impl SolutionTx for MockInput {
        fn caller(&self) -> String {
            self.caller.clone()
        }
        fn contract(&self) -> String {
            self.contract.clone()
        }
        fn fn_signature(&self) -> String {
            self.fn_signature.clone()
        }
        fn fn_selector(&self) -> String {
            self.fn_selector.clone()
        }
        fn fn_args(&self) -> String {
            self.fn_args.clone()
        }
        fn value(&self) -> String {
            self.value.clone()
        }
        fn is_borrow(&self) -> bool {
            self.is_borrow
        }
        fn liq_percent(&self) -> u8 {
            self.liq_percent
        }
        fn swap_data(&self) -> HashMap<String, SwapInfo> {
            self.swap_data.clone()
        }
        fn calldata(&self) -> String {
            self.calldata.clone()
        }
    }

    #[test]
    fn test_template_is_valid() {
        let mut handlebars = Handlebars::new();
        assert!(handlebars.register_template_string("foundry_test", TEMPLATE).is_ok());
    }

    #[test]
    fn test_generate_test() {
        let target = "0xca143ce32fe78f1f7019d7d551a6402fc5350c73".to_string();
        let work_dir = "/tmp".to_string();
        init_cli_args(target, work_dir, &None);

        let input1 = MockInput::new(
            "approve(address,uint256)",
            "0x095ea7b300000000000000000000000089257a52ad585aacb1137fcc8abbd03a963b96830000000000000000000000000000000000000000000000056bc75e2d63100000",
            "",
        );
        let input2 = MockInput::new(
            "createPair(address,address)",
            "c9c65396000000000000000000000000aaec620ab3a0aa4e503c544d8715d70082da7891000000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
            "1234",
        );
        let inputs = vec![input1, input2];
        let solution = String::from("solution");
        generate_test(solution, inputs);
    }

    #[test]
    fn test_generate_script_for_fund_extraction_bug() {
        let target = "0xca143ce32fe78f1f7019d7d551a6402fc5350c73".to_string();
        let work_dir = "/tmp".to_string();
        init_cli_args(target, work_dir, &None);

        // A tx that actually carries ETH value, so the generated script's
        // funding step should be included.
        let input = MockInput::new(
            "approve(address,uint256)",
            "0x095ea7b300000000000000000000000089257a52ad585aacb1137fcc8abbd03a963b96830000000000000000000000000000000000000000000000056bc75e2d63100000",
            "1234",
        );
        let inputs = vec![input];
        // Must contain a bug-type marker from `is_confirmed_exploitable_bug`'s
        // list for `generate_test` to also emit the atomic exploit script.
        let solution = String::from("[Fund Loss]: test fund extraction scenario");
        generate_test(solution, inputs);

        let path = "/tmp/vulnerabilities/Ca143ExploitExploit.s.sol";
        // contract_name for onchain targets is "C" + first 4 hex chars of the
        // address, so for 0xca143... it's "Ca14" -- just check *a* file with
        // the Exploit.s.sol suffix was written instead of hardcoding the
        // exact name, to keep this test robust to that detail.
        let dir = std::fs::read_dir("/tmp/vulnerabilities").expect("output dir missing");
        let found = dir
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with("Exploit.s.sol"));
        assert!(
            found,
            "expected an *Exploit.s.sol file to be generated, checked path hint: {}",
            path
        );
    }

    #[test]
    fn test_no_script_for_multi_caller_fund_extraction_bug() {
        // Verified live against a real onchain ERC4626 share-inflation bug:
        // a multi-actor trace (caller A mints tokens to address B, then B
        // transfers them into the vault) flattened into a single
        // `address(this)` identity reverts when replayed for real, because
        // the mint recipient argument still points at B, not at the
        // exploit contract -- so the later transfer-from-self step finds a
        // zero balance. The atomic script must not be generated for this
        // shape of trace; the forge test (which keeps each call's real
        // `vm.prank` identity) remains the correct reproduction.
        let target = "0xdeadbeef00000000000000000000000000000000".to_string();
        let work_dir = "/tmp".to_string();
        init_cli_args(target, work_dir, &None);

        let mut input1 = MockInput::new("approve(address,uint256)", "0x095ea7b3", "0");
        input1.caller = String::from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let mut input2 = MockInput::new("transfer(address,uint256)", "0xa9059cbb", "0");
        input2.caller = String::from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let inputs = vec![input1, input2];

        let _ = std::fs::remove_dir_all("/tmp/vulnerabilities");
        let solution = String::from("[Fund Loss]: multi-caller scenario");
        generate_test(solution, inputs);

        let dir = std::fs::read_dir("/tmp/vulnerabilities").expect("output dir missing");
        let found_script = dir
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with("Exploit.s.sol"));
        assert!(
            !found_script,
            "expected NO *Exploit.s.sol to be generated for a multi-caller trace"
        );
    }

    #[test]
    fn test_generate_reentrancy_script() {
        // Verified live against the real onchain reentrancy bug this
        // targets: a single caller deposits, then calls withdraw() which
        // (vulnerably) sends ETH before zeroing the caller's recorded
        // balance -- the SAME (contract, selector) call (withdraw())
        // appearing twice from the SAME caller is exactly the shape
        // split_reentrant_trace looks for.
        let target = "0xreentrancytest00000000000000000000000000".to_string();
        let work_dir = "/tmp".to_string();
        init_cli_args(target, work_dir, &None);

        let attacker = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut deposit = MockInput::new("deposit()", "0xd0e30db0", "1000000000000000000");
        deposit.caller = String::from(attacker);
        deposit.fn_selector = String::from("0xd0e30db0");

        let mut withdraw1 = MockInput::new("withdraw()", "0x3ccfd60b", "0");
        withdraw1.caller = String::from(attacker);
        withdraw1.fn_selector = String::from("0x3ccfd60b");

        let mut withdraw2 = MockInput::new("withdraw()", "0x3ccfd60b", "0");
        withdraw2.caller = String::from(attacker);
        withdraw2.fn_selector = String::from("0x3ccfd60b");

        let inputs = vec![deposit, withdraw1, withdraw2];

        let _ = std::fs::remove_dir_all("/tmp/vulnerabilities");
        let solution = String::from("[Reentrancy]: test reentrancy scenario");
        generate_test(solution, inputs);

        let dir = std::fs::read_dir("/tmp/vulnerabilities").expect("output dir missing");
        let found_reentrancy_script = dir
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with("ReentrancyExploit.s.sol"));
        assert!(
            found_reentrancy_script,
            "expected a *ReentrancyExploit.s.sol to be generated for a repeated single-caller call"
        );
    }

    #[test]
    fn test_no_reentrancy_script_without_repeated_call() {
        // A trace with no (contract, selector) pair repeated by the same
        // caller shouldn't produce a reentrancy script -- there's no
        // callback pattern to derive one from.
        let target = "0xreentrancytest20000000000000000000000000".to_string();
        let work_dir = "/tmp".to_string();
        init_cli_args(target, work_dir, &None);

        let attacker = "0xcccccccccccccccccccccccccccccccccccccccc";
        let mut deposit = MockInput::new("deposit()", "0xd0e30db0", "1000000000000000000");
        deposit.caller = String::from(attacker);
        deposit.fn_selector = String::from("0xd0e30db0");
        let mut withdraw = MockInput::new("withdraw()", "0x3ccfd60b", "0");
        withdraw.caller = String::from(attacker);
        withdraw.fn_selector = String::from("0x3ccfd60b");

        let inputs = vec![deposit, withdraw];

        let _ = std::fs::remove_dir_all("/tmp/vulnerabilities");
        let solution = String::from("[Reentrancy]: no repeated call");
        generate_test(solution, inputs);

        let dir = std::fs::read_dir("/tmp/vulnerabilities").expect("output dir missing");
        let found_reentrancy_script = dir
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with("ReentrancyExploit.s.sol"));
        assert!(
            !found_reentrancy_script,
            "expected NO reentrancy script without a repeated call in the trace"
        );
    }

    // FAZA 2.3 regression: the plan's own `confidence`/`confirmed_exploitable`
    // flags must agree with the oracle JSON for the SAME finding, or the
    // Python layer (auto_pipeline.py's metadata_skip_reason) will skip a
    // finding the Rust side just stamped `sim-confirmed`. Two separate bugs
    // caused exactly that disagreement:
    //   * `is_confirmed_bug_type` read the tier off `is_confirmed_exploitable_bug`
    //     instead of `oracle::classify_confidence`, so a Confirmed-tier
    //     `Reentrancy` plan was labelled `sim-review`.
    //   * `Invariant Violation` was missing from the confirmed-exploitable
    //     list, so every user-declared invariant finding was skipped.
    // This test pins both, and reconciles the two lists so they cannot drift
    // apart again.
    #[test]
    fn classify_confidence_matches_confirmed_exploitable_list() {
        use crate::evm::oracle::{classify_confidence, ConfidenceTier};

        // (1) The tier helper used for a plan's `confidence` must agree with
        // the oracle's own classification for every bug_type we know.
        for bug_type in CONFIRMED_EXPLOITABLE_BUG_TYPES {
            assert!(
                is_confirmed_bug_type(bug_type),
                "`{bug_type}` is in the confirmed-exploitable list but \
                 is_confirmed_bug_type says it is not Confirmed-tier"
            );
            assert_eq!(
                classify_confidence(bug_type),
                ConfidenceTier::Confirmed,
                "`{bug_type}` is confirmed-exploitable but the oracle classifies it Review -- \
                 the plan's `confidence` would contradict the oracle JSON"
            );
        }

        // (2) Every Confirmed-tier bug_type must be in the list, EXCEPT the
        // deliberate exclusions -- otherwise it is a sim-confirmed finding
        // the Python layer would silently skip.
        let deliberate_exclusions = ["Reentrancy"];
        for bug_type in [
            "Fund Loss",
            "Invariant Violation",
            "Arbitrary Storage Write",
            "Unchecked ecrecover(0)",
            "Reentrancy",
        ] {
            if deliberate_exclusions.contains(&bug_type) {
                continue;
            }
            assert!(
                CONFIRMED_EXPLOITABLE_BUG_TYPES.contains(&bug_type),
                "Confirmed-tier `{bug_type}` is missing from the confirmed-exploitable list -- \
                 auto_pipeline.py would skip it as a non-extractable heuristic"
            );
        }

        // (2b) `is_confirmed_bug_type` must read the tier from the oracle,
        // NOT from the confirmed-exploitable list -- they differ exactly on
        // the deliberate exclusion. `Reentrancy` is Confirmed-tier but is
        // NOT confirmed-exploitable (its own extraction path handles it), so
        // if the helper ever delegates back to the list this catches it: the
        // reentrancy plan would be mislabelled sim-review while the oracle
        // JSON says sim-confirmed.
        assert!(
            is_confirmed_bug_type("Reentrancy"),
            "Reentrancy is Confirmed-tier: is_confirmed_bug_type must agree with \
             oracle::classify_confidence, not with the (narrower) exploitable list"
        );
        assert!(
            !CONFIRMED_EXPLOITABLE_BUG_TYPES.contains(&"Reentrancy"),
            "Reentrancy must stay OUT of the exploitable list (its own extraction path handles it)"
        );

        // (3) A user-declared invariant finding is a flat, replayable trace:
        // it must be BOTH Confirmed-tier AND confirmed-exploitable.
        assert_eq!(classify_confidence("Invariant Violation"), ConfidenceTier::Confirmed);
        assert!(
            is_confirmed_exploitable_bug("[Invariant Violation] (sim-confirmed): solvent check broke"),
            "an Invariant Violation finding must be marked confirmed_exploitable"
        );
        assert!(
            is_confirmed_bug_type("Invariant Violation"),
            "an Invariant Violation plan must be labelled sim-confirmed, not sim-review"
        );
    }

    /// W3: the generated exploit templates must pay the beneficiary with a
    /// full-gas `call`, never `.transfer()` -- a CONTRACT beneficiary (Gnosis
    /// Safe / multisig) needs more than the 2300-gas stipend `.transfer()`
    /// forwards, so `.transfer()` would strand the proceeds in the exploit
    /// contract. Asserts on the REAL rendered scripts (both templates).
    #[test]
    fn generated_exploit_scripts_use_full_gas_call_not_transfer() {
        // `contract_name` is derived from the target's parent dir and carries
        // a timestamp for a path-less address target, so locate the rendered
        // script by suffix rather than guessing its exact name.
        fn read_script_ending_with(dir: &str, suffix: &str) -> String {
            let entry = std::fs::read_dir(dir)
                .expect("output dir missing")
                .filter_map(|e| e.ok())
                .find(|e| e.file_name().to_string_lossy().ends_with(suffix))
                .unwrap_or_else(|| panic!("no script ending with {suffix} was generated"));
            std::fs::read_to_string(entry.path()).expect("script unreadable")
        }

        let work_dir = "/tmp".to_string();

        // Flat (non-reentrancy) script.
        init_cli_args("0xca143ce32fe78f1f7019d7d551a6402fc5350c73".to_string(), work_dir.clone(), &None);
        let input = MockInput::new(
            "approve(address,uint256)",
            "0x095ea7b300000000000000000000000089257a52ad585aacb1137fcc8abbd03a963b96830000000000000000000000000000000000000000000000056bc75e2d63100000",
            "1234",
        );
        let _ = std::fs::remove_dir_all("/tmp/vulnerabilities");
        generate_test(String::from("[Fund Loss]: w3 template check"), vec![input]);
        let flat = read_script_ending_with("/tmp/vulnerabilities", "Exploit.s.sol");
        assert!(
            !flat.contains("beneficiary.transfer("),
            "collectAndDestroy() must not use .transfer() (W3):\n{flat}"
        );
        assert!(
            flat.contains("beneficiary.call{value: address(this).balance}"),
            "collectAndDestroy() must pay via a full-gas call (W3):\n{flat}"
        );

        // Reentrancy script.
        init_cli_args("0xreentrancytest30000000000000000000000000".to_string(), work_dir, &None);
        let attacker = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut deposit = MockInput::new("deposit()", "0xd0e30db0", "1000000000000000000");
        deposit.caller = String::from(attacker);
        deposit.fn_selector = String::from("0xd0e30db0");
        let mut withdraw1 = MockInput::new("withdraw()", "0x3ccfd60b", "0");
        withdraw1.caller = String::from(attacker);
        withdraw1.fn_selector = String::from("0x3ccfd60b");
        let mut withdraw2 = MockInput::new("withdraw()", "0x3ccfd60b", "0");
        withdraw2.caller = String::from(attacker);
        withdraw2.fn_selector = String::from("0x3ccfd60b");
        let _ = std::fs::remove_dir_all("/tmp/vulnerabilities");
        generate_test(String::from("[Reentrancy]: w3 template check"), vec![deposit, withdraw1, withdraw2]);
        let reentrancy = read_script_ending_with("/tmp/vulnerabilities", "ReentrancyExploit.s.sol");
        assert!(
            !reentrancy.contains("beneficiary.transfer("),
            "reentrancy collectAndDestroy() must not use .transfer() (W3):\n{reentrancy}"
        );
        assert!(
            reentrancy.contains("beneficiary.call{value: address(this).balance}"),
            "reentrancy collectAndDestroy() must pay via a full-gas call (W3):\n{reentrancy}"
        );
    }
}
