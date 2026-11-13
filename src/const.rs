pub const DEBUG_PRINT_PERCENT: usize = 8000;

/// Hard ceiling on concurrent concolic (Z3) solvers for the WHOLE campaign,
/// never per-job. The historical default was "number of CPUs", which launched
/// one solver per core; on a many-core host that oversubscribed the machine
/// (each Z3 solver is CPU- and memory-hungry) and froze it. A small fixed
/// ceiling keeps the concolic pool genuinely parallel while staying bounded.
pub const MAX_CONCOLIC_THREADS: usize = 2;

/// The effective global concolic cap: at most [`MAX_CONCOLIC_THREADS`], and
/// never more than the machine can actually run (`min(2, cores)`), so a
/// single-core box does not oversubscribe itself with the default.
pub fn max_concolic_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(MAX_CONCOLIC_THREADS)
}

pub const INFANT_STATE_INITIAL_VOTES: usize = 3; // used in fuzzer.rs when infant is added to states
pub const CORPUS_INITIAL_VOTES: usize = 3; // used in fuzzer.rs when infant is added to states
/// used in libafl scheduled mutator (this is at max 1 << MAX_STACK_POW ==
/// 2^MAX_STACK_POW)
pub const MAX_STACK_POW: usize = 7;
/// Widened from 10: a compound exploit routinely needs several distinct
/// argument/slot mutations to line up in ONE input (an amount, a recipient,
/// a slot index, a flag) -- 10 attempts routinely exhausted before a valid
/// multi-argument combination was found, so the mutator fell back to
/// MutationResult::Skipped and the input was dropped. Higher is pure
/// search-breadth, bounded by MUTATION_RETRIES below.
pub const MAX_HAVOC_ATTEMPTS: usize = 32;
pub const KNOWN_STATE_MAX_SIZE: usize = 1000;
pub const KNOWN_STATE_SKIP_SIZE: usize = 500;

// src/fuzzer.rs
/// The maximum number of inputs (or VMState) to keep in the corpus before
/// pruning. Widened from 500: a target with several interacting subsystems
/// (proxy + implementation + token + oracle) needs a much larger corpus to
/// retain the intermediate states each subsystem's exploration produces;
/// pruning at 500 discarded exactly those deep, multi-call intermediate
/// states before they could be extended into a compound exploit.
pub const DROP_THRESHOLD: usize = 4000;
/// The number of inputs (or VMState) to prune each time the corpus is pruned
/// (widened in step with DROP_THRESHOLD so the corpus keeps the same
/// headroom ratio, just at a larger absolute size).
pub const PRUNE_AMT: usize = 1000;
/// If inputs (or VMState) has not been visited this many times, it will be
/// ignored during pruning
pub const VISIT_IGNORE_THRESHOLD: usize = 2;

// src/state.rs
/// Amount of accounts and contracts that can be caller during fuzzing.
/// We will generate random addresses for these accounts and contracts.
/// Widened from 2: access-control / multisig / role-separated logic needs
/// more than two distinct identities to reach (owner vs operator vs user vs
/// attacker), and a two-address pool structurally cannot express "a third,
/// unauthorized caller tries the privileged path".
pub const ACCOUNT_AMT: u8 = 8;
/// Amount of accounts and contracts that can be caller during fuzzing.
/// We will generate random addresses for these accounts and contracts.
/// Widened from 2 for the same reason as ACCOUNT_AMT -- contract-vs-contract
/// interactions (a router calling a pool calling a token) need more than two
/// distinct contract identities in play.
pub const CONTRACT_AMT: u8 = 8;
/// Maximum size of the input data. Widened from 20: a dynamic array argument
/// (a recipient list, a batch of calls, a path through a router) is encoded
/// with its length as the first word, and a cap of 20 bytes could not even
/// encode a 2-element array plus its own length word, so any array-shaped
/// argument was permanently unreachable.
pub const MAX_INPUT_SIZE: usize = 64;

// src/abi.rs
/// Sample will be used to generate a random value with max value
pub const SAMPLE_MAX: u64 = 100;
/// Maximum value of the mutate choice. Related to [SAMPLE_MAX]
pub const MUTATE_CHOICE_MAX: u64 = 80;
/// Exclusive lower bound of the "expand" band: `MUTATE_CHOICE_MAX + 1`, so the
/// `0..=MUTATE_CHOICE_MAX` and expand arms form a partition with no shared
/// endpoint.
pub const MUTATE_CHOICE_MAX_EXCLUSIVE: u64 = MUTATE_CHOICE_MAX + 1;
/// Maximum value of the expand choice. Related to [SAMPLE_MAX]
pub const EXPAND_CHOICE_MAX: u64 = 90;
/// Exclusive lower bound of the "shrink" band: `EXPAND_CHOICE_MAX + 1`.
pub const EXPAND_CHOICE_MAX_EXCLUSIVE: u64 = EXPAND_CHOICE_MAX + 1;
/// Maximum value of the random address choice. Related to [SAMPLE_MAX]
pub const RANDOM_ADDRESS_CHOICE: u64 = 90;
/// Chance (out of [SAMPLE_MAX]) that a fixed-size tuple/array arg with 2+
/// address slots (e.g. `createPair(tokenA, tokenB)`) gets ALL its address
/// slots set together in one mutation, instead of the default one-slot-
/// at-a-time behavior. Kept well below [RANDOM_ADDRESS_CHOICE] so "one
/// correct + one deliberately wrong address" (a real bug pattern too)
/// stays reachable, not dominated.
pub const MULTI_ADDR_CHOICE: u64 = 35;

// src/evm/corpus_initializer.rs
/// If there are more than 1/UNKNOWN_SIGS_DIVISOR unknown sigs, we will
/// decompile with EVMole
pub const UNKNOWN_SIGS_DIVISOR: usize = 30;

// src/evm/mutator.rs
/// Sample will be used to generate a random value with max value
pub const MUTATOR_SAMPLE_MAX: u64 = 100;
/// Related to [MUTATOR_SAMPLE_MAX]
pub const EXPLOIT_PRESET_CHOICE: u64 = 20;
/// Related to [MUTATOR_SAMPLE_MAX]
pub const ABI_MUTATE_CHOICE: u64 = 96;
/// Related to [MUTATOR_SAMPLE_MAX]
pub const HAVOC_CHOICE: u64 = 60;
/// Maximum number of iterations to try to find a valid havoc mutation
pub const HAVOC_MAX_ITERS: u64 = 10;
/// Related to [MUTATOR_SAMPLE_MAX]
pub const MUTATE_CALLER_CHOICE: u64 = 20;
/// Related to [MUTATOR_SAMPLE_MAX]
pub const TURN_TO_STEP_CHOICE: u64 = 60;
/// Related to [MUTATOR_SAMPLE_MAX]
pub const RANDOMNESS_CHOICE: u64 = 33;
/// Related to [MUTATOR_SAMPLE_MAX]
pub const LIQUIDATE_CHOICE: u64 = 5;
/// Exclusive lower bound of the randomness band: `LIQUIDATE_CHOICE + 1`, so the
/// `0..=LIQUIDATE_CHOICE` and randomness arms do not share an endpoint.
pub const LIQUIDATE_CHOICE_EXCLUSIVE: u64 = LIQUIDATE_CHOICE + 1;
/// Related to [MUTATOR_SAMPLE_MAX]
pub const LIQ_PERCENT_CHOICE: u64 = 80;
pub const LIQ_PERCENT: u64 = 10;
/// Related to [MUTATOR_SAMPLE_MAX] and [LIQUIDATE_CHOICE]
pub const RANDOMNESS_CHOICE_2: u64 = 6;
/// Maximum number of retries to try to find a valid mutation
pub const MUTATION_RETRIES: usize = 20;

// src/evm/scheduler.rs
pub const POWER_MULTIPLIER: f64 = 32.0;
pub const MAX_POWER: f64 = 3200.0;
pub const MIN_POWER: f64 = 32.0;
