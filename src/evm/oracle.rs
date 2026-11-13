use crate::evm::input::ConciseEVMInput;
use crate::{evm::srcmap::RawSourceMapInfo, fuzzer::ORACLE_OUTPUT};

/// How much independent judgment a finding needs before acting on it.
///
/// This is a SIMULATION-level judgment only -- revm, with no gas
/// metering and no real mempool/block-limit/front-running dynamics (see
/// this crate's own CLAUDE.md). `as_str()` deliberately returns
/// "sim-confirmed"/"sim-review", never the bare "confirmed"/"review" it
/// used to: this string is printed verbatim to the terminal and baked
/// into generated `.t.sol`/`Exploit.s.sol` file headers
/// (`src/fuzzer.rs`), which `onchain_scripts/auto_pipeline.py` then
/// pipes, unfiltered, into the SAME log file as its own
/// PLAN_CONFIRMED/"CONFIRMED:" lines -- a REAL, deterministic signal
/// requiring an actual on-chain balance increase (`execute_plan()` in
/// that file). Confirmed live 2026-11-02 against real ETC mainnet (plan
/// C9f53_2): a trace this tier calls "Confirmed" can still be physically
/// unexecutable on the real chain (exceeded the real block.gasLimit;
/// revm never metered it). Reusing the bare word "confirmed" for both
/// meanings is exactly the kind of ambiguity that let a client-facing
/// report conflate "the pattern is real in simulation" with "the money
/// actually moved" -- the "sim-" prefix makes that impossible even if
/// someone greps the combined log for "CONFIRMED" (uppercase) without
/// reading the surrounding text.
///
/// `Confirmed`: the same deterministic signal this project's own
/// `--detectors high_confidence` preset (`OracleType::from_strs`,
/// src/evm/mod.rs) already trusts enough to include by default -- a
/// directly observed violation (an unauthorized call that actually
/// succeeded, a storage slot that actually collided, a signature that
/// actually replayed), not an inference about what an observation might
/// imply. Still only ever established inside the simulated fuzzing VM,
/// never on a real chain -- see the prefix note above.
///
/// `Review`: a heuristic signal excluded from `high_confidence` for a
/// known false-positive risk (e.g. a legitimately-constant admin flag
/// looking like a dead counter, a dispatcher subtraction looking like
/// unchecked arithmetic). Worth a human look, not a certain bug -- the
/// same framing `unbounded_loop.rs`/`stale_guard.rs`/
/// `centralization_risk.rs` already use in their own doc comments, now
/// surfaced in the JSON/terminal output instead of staying buried in
/// source comments only visible to someone reading the Rust code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfidenceTier {
    Confirmed,
    Review,
}

impl ConfidenceTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfidenceTier::Confirmed => "sim-confirmed",
            ConfidenceTier::Review => "sim-review",
        }
    }
}

/// Classifies a finding by its `bug_type` string, deliberately NOT a
/// parameter every one of the ~35 `EVMBugResult::new`/`new_simple` call
/// sites across src/evm/oracles/*.rs would need to pass. For most oracles
/// this mirrors `OracleType::from_strs`'s `high_confidence` list exactly
/// (src/evm/mod.rs) -- that list already encodes which oracles are
/// trusted enough to be on by default vs excluded for false-positive
/// risk. A few oracles (twap_manipulation.rs, curve_virtual_price.rs) are
/// finer-grained than that: the SAME oracle emits a Review-tier bug_type
/// for its base signal and a DIFFERENT, Confirmed-tier bug_type only when
/// a second, stronger signal also held in the same call -- `OracleType`
/// gates whether the oracle runs at all, not which of its own possible
/// outputs counts as confirmed, so those two bug_types are intentionally
/// NOT mirrored 1:1 against a single OracleType entry. If an oracle's own
/// confidence classification ever changes, update the matching list
/// (`high_confidence` for a whole-oracle promotion, just this list for a
/// bug_type-level split) the same way.
/// Downgrades a Confirmed-tier finding to Review when the trace that produced
/// it depended on host.rs's control leak (a faked/intercepted call return).
/// `call_leak == u32::MAX` is CALL_UNTIL's neutral default and means the call
/// ran normally; any other value means the violated state was only reachable
/// because a call return was injected, so claiming `sim-confirmed` would
/// overstate what was actually observed (FAZA 2.3, TASK_SPEC.md).
fn effective_confidence(base: ConfidenceTier, call_leak: u32) -> ConfidenceTier {
    if call_leak != u32::MAX {
        ConfidenceTier::Review
    } else {
        base
    }
}

pub(crate) fn classify_confidence(bug_type: &str) -> ConfidenceTier {
    match bug_type {
        "Unauthorized Owner Change"
        | "Unauthorized Pause Toggle"
        | "Unauthorized Proxy Upgrade"
        | "Unprotected Proxy Upgrade (UUPS)"
        | "Arbitrary Call"
        | "Unauthorized ERC20 Transfer"
        | "Delegatecall Injection"
        | "Delegatecall Target From Calldata"
        | "Unchecked ecrecover(0)"
        | "Arbitrary Storage Write"
        | "Fund Loss"
        | "ERC4626 Share Inflation"
        | "Insolvent: Promised Native Value Exceeds Real Balance"
        // A user-declared invariant is evaluated against the real
        // post-transaction state and only reported when the declared
        // relationship is actually observed to be false -- a directly
        // observed violation, the same standard as the other entries here,
        // not an inference. The user wrote the invariant, so its own
        // relevance is their call; our claim is only "this held state
        // broke it".
        | "Invariant Violation"
        | "Initializer Front-Running"
        | "Unauthorized ERC1155 Transfer"
        | "Unauthorized NFT Transfer"
        | "ERC4626 Rounding Favors User"
        | "Proxy Reinitialization"
        | "Proxy Storage Collision"
        | "Reentrancy"
        | "Selfdestruct"
        | "Signature Malleability"
        | "Signature Replay"
        | "Storage Collision"
        | "Tx.Origin Phishing Bypass"
        | "Bug"
        | "Imbalanced Uniswap Pair"
        // Promoted from Review (see the matching high_confidence addition
        // in src/evm/mod.rs's OracleType::from_strs): this oracle only
        // reports after empirically observing BOTH outcomes of the same
        // guard, each with a confirmed payment -- not a single-shot guess.
        | "Validation-Independent Payment"
        // These two are the SAME oracles as the Review-tier "TWAP
        // Manipulation Precondition"/"Curve Virtual Price Decrease"
        // below, but reported under a different bug_type specifically
        // when a SECOND signal also held: the caller who caused the
        // precondition/decrease also walked away from the same
        // transaction with a net ETH balance increase -- real, demonstrated
        // profit, not just the underlying anomaly. See
        // oracles/twap_manipulation.rs and oracles/curve_virtual_price.rs.
        | "TWAP Manipulation (Profit Confirmed)"
        | "Curve Virtual Price Decrease (Profit Confirmed)" => ConfidenceTier::Confirmed,
        // Everything else (Centralization Risk, the base "Curve Virtual
        // Price Decrease" and "TWAP Manipulation Precondition" bug_types
        // -- i.e. without a confirmed profit, see above -- Price Feed
        // Staleness, Unbounded Loop, Stale Guard Counter, Unchecked
        // Low-Level Call, Uninitialized Memory Read, state_comp, Integer
        // Overflow -- the last of which isn't even gated by an
        // OracleType, it's always-on -- and anything not yet listed
        // above) defaults to Review. The safer direction to be wrong in
        // is understating confidence, not overstating it.
        _ => ConfidenceTier::Review,
    }
}

pub struct EVMBugResult {
    pub bug_type: String,
    pub bug_info: String,
    pub input: ConciseEVMInput,
    pub issue_source: Option<String>,
    pub sourcemap: Option<RawSourceMapInfo>,
    pub bug_idx: u64,
    pub confidence: ConfidenceTier,
}

impl EVMBugResult {
    pub fn to_value(&self) -> serde_json::Value {
        // FAZA 2.3 (TASK_SPEC.md): the acceptance criterion is that
        // a `sim-confirmed` finding NEVER rests on control leak. The plan
        // generator already enforces this (`build_plan_meta`), but this JSON
        // is also printed verbatim and re-parsed (`parse_bug_report`), so the
        // tier has to be consistent at the oracle level too -- otherwise the
        // report would claim `sim-confirmed` for a trace that only reached
        // the violated state because host.rs injected a faked call return.
        let confidence = effective_confidence(self.confidence, self.input.call_leak);
        serde_json::json!({
            "bug_type": self.bug_type,
            "bug_info": self.bug_info,
            "input": self.input,
            "sourcemap": self.sourcemap,
            "issue_source": self.issue_source,
            "bug_idx": self.bug_idx,
            "confidence": confidence.as_str(),
            // Every finding, regardless of confidence tier, carries an
            // actually-replayable transaction trace (`input` above,
            // ConciseEVMInput) -- not a static-analysis guess. This
            // field states that fact explicitly for anything consuming
            // this JSON, rather than leaving it implicit.
            "evidence": "replayable_transaction_trace",
        })
    }

    pub fn new(
        bug_type: String,
        bug_idx: u64,
        bug_info: String,
        input: ConciseEVMInput,
        sourcemap: Option<RawSourceMapInfo>,
        issue_source: Option<String>,
    ) -> Self {
        let confidence = classify_confidence(&bug_type);
        Self {
            bug_type,
            bug_info,
            input,
            sourcemap,
            issue_source,
            bug_idx,
            confidence,
        }
    }

    pub fn new_simple(bug_type: String, bug_idx: u64, bug_info: String, input: ConciseEVMInput) -> Self {
        let confidence = classify_confidence(&bug_type);
        Self {
            bug_type,
            bug_info,
            input,
            issue_source: None,
            sourcemap: None,
            bug_idx,
            confidence,
        }
    }

    pub fn push_to_output(&self) {
        ORACLE_OUTPUT.lock().unwrap().push(self.to_value());
    }
}

#[cfg(test)]
mod effective_confidence_tests {
    use super::*;

    /// A clean trace (call_leak == u32::MAX) keeps the bug_type's own tier.
    #[test]
    fn clean_trace_keeps_confirmed() {
        assert_eq!(
            effective_confidence(ConfidenceTier::Confirmed, u32::MAX),
            ConfidenceTier::Confirmed
        );
    }

    /// FAZA 2.3: a control-leak trace is never `sim-confirmed`, regardless of
    /// how strong the bug_type is.
    #[test]
    fn control_leak_trace_is_downgraded() {
        assert_eq!(
            effective_confidence(ConfidenceTier::Confirmed, 3),
            ConfidenceTier::Review
        );
    }

    /// A Review-tier finding stays Review either way (never upgraded).
    #[test]
    fn review_is_never_upgraded() {
        assert_eq!(
            effective_confidence(ConfidenceTier::Review, u32::MAX),
            ConfidenceTier::Review
        );
        assert_eq!(
            effective_confidence(ConfidenceTier::Review, 7),
            ConfidenceTier::Review
        );
    }
}
