use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    env,
    fmt::Debug,
    fs::OpenOptions,
    hash::{Hash, Hasher},
    io::Write,
    marker::PhantomData,
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Duration,
};
// Used only by the `dump_file!`/`dump_txn!` expansions and the vulnerability
// dump, all gated on `print_txn_corpus`.
#[cfg(feature = "print_txn_corpus")]
use std::{fs::File, path::Path, sync::atomic::AtomicUsize};

use itertools::Itertools;
use libafl::{
    fuzzer::Fuzzer,
    mark_feature_time,
    prelude::{
        Corpus,
        CorpusId,
        Event,
        EventConfig,
        EventManager,
        Executor,
        Feedback,
        HasObservers,
        HasRand,
        ObserversTuple,
        Testcase,
        UsesInput,
    },
    schedulers::{RemovableScheduler, Scheduler},
    stages::StagesTuple,
    start_timer,
    state::{HasCorpus, HasExecutions, HasLastReportTime, HasMetadata, HasSolutions, State, UsesState},
    Error,
    Evaluator,
    ExecuteInputResult,
};
use libafl_bolts::current_time;
use serde::{de::DeserializeOwned, Serialize};
#[cfg(feature = "print_txn_corpus")]
use tracing::error;
#[cfg(feature = "print_txn_corpus")]
use tracing::info;

use crate::{
    evm::{host::JMP_MAP, solution, utils::prettify_concise_inputs},
    feedback::CmpMetadata,
    generic_vm::{vm_executor::MAP_SIZE, vm_state::VMStateT},
    input::{ConciseSerde, SolutionTx, VMInputT},
    minimizer::SequentialMinimizer,
    oracle::BugMetadata,
    r#const::INFANT_STATE_INITIAL_VOTES,
    scheduler::HasReportCorpus,
    state::{HasCurrentInputIdx, HasExecutionResult, HasInfantStateState, HasItyState, InfantStateState},
};

pub static RUN_FOREVER: AtomicBool = AtomicBool::new(false);
pub static ORACLE_OUTPUT: Mutex<Vec<serde_json::Value>> = Mutex::new(vec![]);

/// A filesystem-safe, length-bounded base name for a finding's dump files.
///
/// The dump file is named after every `bug_idx` a single execution tripped,
/// comma-joined (see the vulnerability dump below). With `--run-forever` one
/// input can trip a huge number of oracle hits -- a per-pc heuristic like
/// Stale Guard Counter fires on every matching pc -- so the joined string can
/// blow past the filesystem's 255-byte NAME_MAX, and the old
/// `File::create(...).unwrap()` then panicked, killing the whole fuzzer
/// (confirmed live on ETC: "File name too long" ~3s into a run, well before
/// the fuzz budget). Bound the name: keep the readable ids when they fit,
/// otherwise keep a short prefix plus a stable content hash, so a file is
/// still written (never a panic) and distinct findings stay distinct.
#[cfg(feature = "print_txn_corpus")]
fn vuln_file_base(bug_idxs: &str) -> String {
    const MAX: usize = 120;
    if bug_idxs.len() <= MAX {
        return bug_idxs.to_string();
    }
    let mut h = DefaultHasher::new();
    bug_idxs.hash(&mut h);
    // bug_idxs is ASCII (decimal u64 ids joined by ','), so this slice is a
    // valid char boundary.
    format!("{}_h{:016x}", &bug_idxs[..MAX], h.finish())
}

/// A fuzzer that implements ForkSploit logic using LibAFL's [`Fuzzer`] trait
///
/// CS: The scheduler for the input corpus
/// IS: The scheduler for the infant state corpus
/// F: The feedback for the input corpus (e.g., coverage map)
/// IF: The feedback for the infant state corpus (e.g., comparison, etc.)
/// I: The VM input type
/// OF: The objective for the input corpus (e.g., oracles)
/// S: The fuzzer state type
/// VS: The VM state type
/// Addr: The address type (e.g., H160)
/// Loc: The call target location type (e.g., H160)
#[allow(clippy::type_complexity)]
#[derive(Debug)]
pub struct ForkSploitFuzzer<VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI, SM>
where
    CS: Scheduler<State = S>,
    IS: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>> + HasReportCorpus<InfantStateState<Loc, Addr, VS, CI>>,
    F: Feedback<S>,
    IF: Feedback<S>,
    IFR: Feedback<S>,
    I: VMInputT<VS, Loc, Addr, CI>,
    OF: Feedback<S>,
    S: State + HasCorpus + HasRand + HasMetadata + UsesInput<Input = I>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// The scheduler for the input corpus
    scheduler: CS,
    /// The feedback for the input corpus (e.g., coverage map)
    feedback: F,
    /// The feedback for the input state and execution result in infant state
    /// corpus (e.g., comparison, etc.)
    infant_feedback: IF,
    /// The feedback for the resultant state to be inserted into infant state
    /// corpus (e.g., dataflow, etc.)
    infant_result_feedback: IFR,
    /// The scheduler for the infant state corpus
    infant_scheduler: IS,
    /// The objective for the input corpus (e.g., oracles)
    objective: OF,
    /// Map from hash of a testcase can do (e.g., coverage map) to the (testcase
    /// idx, fav factor) Used to minimize the corpus
    minimizer_map: HashMap<u64, (usize, f64)>,
    sequential_minimizer: SM,
    phantom: PhantomData<(I, S, OT, VS, Loc, Addr, Out, CI, SM)>,
    /// work dir path
    work_dir: String,
}

impl<VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI, SM>
    ForkSploitFuzzer<VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI, SM>
where
    CS: Scheduler<State = S>,
    IS: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>> + HasReportCorpus<InfantStateState<Loc, Addr, VS, CI>>,
    F: Feedback<S>,
    IF: Feedback<S>,
    IFR: Feedback<S>,
    I: VMInputT<VS, Loc, Addr, CI>,
    OF: Feedback<S>,
    S: State + HasCorpus + HasRand + HasMetadata + UsesInput<Input = I>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Creates a new ForkSploitFuzzer
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scheduler: CS,
        infant_scheduler: IS,
        feedback: F,
        infant_feedback: IF,
        infant_result_feedback: IFR,
        objective: OF,
        sequential_minimizer: SM,
        work_dir: String,
    ) -> Self {
        Self {
            scheduler,
            feedback,
            infant_feedback,
            infant_result_feedback,
            infant_scheduler,
            objective,
            work_dir,
            minimizer_map: Default::default(),
            sequential_minimizer,
            phantom: PhantomData,
        }
    }

    /// Called every time a new testcase is added to the corpus
    /// Setup the minimizer map
    pub fn on_add_corpus(&mut self, input: &I, coverage: &[u8; MAP_SIZE], testcase_idx: usize) {
        let mut hasher = DefaultHasher::new();
        coverage.hash(&mut hasher);
        let hash = hasher.finish();
        self.minimizer_map.insert(hash, (testcase_idx, input.fav_factor()));
    }

    /// Called every time a testcase is replaced for the corpus
    /// Update the minimizer map
    pub fn on_replace_corpus(&mut self, (hash, new_fav_factor, _): (u64, f64, usize), new_testcase_idx: usize) {
        let res = self.minimizer_map.get_mut(&hash).unwrap();
        res.0 = new_testcase_idx;
        res.1 = new_fav_factor;
    }

    /// Determine if a testcase should be replaced based on the minimizer map
    /// If the new testcase has a higher fav factor or any better comparison
    /// results, replace the old one
    /// Returns None if the testcase should not be replaced
    /// Returns Some((hash, new_fav_factor, testcase_idx)) if
    /// the testcase should be replaced
    pub fn should_replace(&self, input: &I, coverage: &[u8; MAP_SIZE], state: &S) -> Option<(u64, f64, usize)> {
        let mut hasher = DefaultHasher::new();
        coverage.hash(&mut hasher);
        let hash = hasher.finish();
        // if the coverage is same
        if let Some((testcase_idx, fav_factor)) = self.minimizer_map.get(&hash) {
            let new_fav_factor = input.fav_factor();
            // if the new testcase has a higher fav factor, replace the old one
            if new_fav_factor > *fav_factor {
                return Some((hash, new_fav_factor, *testcase_idx));
            }

            // check if the testcase had a better comparison result
            if let Some(metadata) = state.metadata_map().get::<CmpMetadata>() {
                if metadata.cmp_interesting {
                    return Some((hash, new_fav_factor, *testcase_idx));
                }
            }
        }
        None
    }
}

impl<VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI, SM> UsesState
    for ForkSploitFuzzer<VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI, SM>
where
    CS: Scheduler<State = S>,
    IS: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>> + HasReportCorpus<InfantStateState<Loc, Addr, VS, CI>>,
    F: Feedback<S>,
    IF: Feedback<S>,
    IFR: Feedback<S>,
    I: VMInputT<VS, Loc, Addr, CI>,
    OF: Feedback<S>,
    S: State + HasCorpus + HasRand + HasMetadata + UsesInput<Input = I>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    type State = S;
}

/// Implement fuzzer trait for ForkSploitFuzzer
impl<VS, Loc, Addr, Out, CS, IS, E, EM, F, IF, IFR, I, OF, S, ST, OT, CI, SM> Fuzzer<E, EM, ST>
    for ForkSploitFuzzer<VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI, SM>
where
    CS: Scheduler<State = S>,
    IS: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>> + HasReportCorpus<InfantStateState<Loc, Addr, VS, CI>>,
    E: Executor<EM, Self, State = S>,
    EM: EventManager<E, Self, State = S>,
    F: Feedback<S>,
    IF: Feedback<S>,
    IFR: Feedback<S>,
    I: VMInputT<VS, Loc, Addr, CI>,
    OF: Feedback<S>,
    S: State
        + HasExecutions
        + HasMetadata
        + HasCurrentInputIdx
        + HasRand
        + HasCorpus
        + HasLastReportTime
        + UsesInput<Input = I>,
    ST: StagesTuple<E, EM, S, Self>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Fuzz one input
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut EM::State,
        manager: &mut EM,
    ) -> Result<CorpusId, libafl::Error> {
        let idx = self.scheduler.next(state)?;
        state.set_current_input_idx(idx.into());

        // TODO: if the idx input is a concolic input returned by the solver
        // we should not perform all stages.

        stages
            .perform_all(self, executor, state, manager, idx)
            .expect("perform_all failed");
        manager.process(self, state, executor)?;
        Ok(idx)
    }

    /// Fuzz loop
    fn fuzz_loop(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut EM::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        // now report stats to manager every 1 sec
        let reporting_interval = Duration::from_millis(
            env::var("REPORTING_INTERVAL")
                .unwrap_or("1000".to_string())
                .parse::<u64>()
                .unwrap(),
        );
        loop {
            self.fuzz_one(stages, executor, state, manager)?;
            manager.maybe_report_progress(state, reporting_interval)?;
        }
    }
}

#[cfg(feature = "print_txn_corpus")]
pub static DUMP_FILE_COUNT: AtomicUsize = AtomicUsize::new(0);

pub static REPLAY: AtomicBool = AtomicBool::new(false);

#[macro_export]
macro_rules! dump_file {
    ($state: expr, $corpus_path: expr, $print: expr) => {{
        if !REPLAY.load(::std::sync::atomic::Ordering::Relaxed) {
            let count = DUMP_FILE_COUNT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed) + 1;

            let tx_trace = $state.get_execution_result().new_state.trace.clone();
            let txn_text = tx_trace.to_string($state);
            let txn_text_replayable = tx_trace.to_file_str($state);

            let data = format!(
                "Reverted? {} \n Txn:\n{}",
                $state.get_execution_result().reverted,
                txn_text
            );
            if $print {
                info!("============= New Corpus Item =============");
                info!("{}", data);
                info!("==========================================");
            }

            // write to file
            let path = Path::new($corpus_path.as_str());
            if !path.exists() {
                std::fs::create_dir_all(path).unwrap();
            }
            let mut file = File::create(format!("{}/{}", $corpus_path, count)).unwrap();
            file.write_all(data.as_bytes()).unwrap();

            let mut replayable_file = File::create(format!("{}/{}_replayable", $corpus_path, count)).unwrap();
            replayable_file.write_all(txn_text_replayable.as_bytes()).unwrap();
        }
    }};
}

#[macro_export]
macro_rules! dump_txn {
    ($corpus_path: expr, $input: expr) => {{
        if !REPLAY.load(::std::sync::atomic::Ordering::Relaxed) {
            let count = DUMP_FILE_COUNT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed) + 1;
            // write to file
            let path = Path::new($corpus_path.as_str());
            if !path.exists() {
                std::fs::create_dir_all(path).unwrap();
            }

            let concise_input = ConciseEVMInput::from_input($input, &EVMExecutionResult::empty_result());

            let txn_text = concise_input.serialize_string();
            let txn_text_replayable = String::from_utf8(concise_input.serialize_concise()).unwrap();

            let mut file = File::create(format!("{}/{}_seed", $corpus_path, count)).unwrap();
            file.write_all(txn_text.as_bytes()).unwrap();

            let mut replayable_file =
                File::create(format!("{}/{}_seed_replayable", $corpus_path, count)).unwrap();
            replayable_file.write_all(txn_text_replayable.as_bytes()).unwrap();
        }
    }};
}

// implement evaluator trait for ForkSploitFuzzer
impl<VS, Loc, Addr, Out, E, EM, I, S, CS, IS, F, IF, IFR, OF, OT, CI, SM> Evaluator<E, EM>
    for ForkSploitFuzzer<VS, Loc, Addr, Out, CS, IS, F, IF, IFR, I, OF, S, OT, CI, SM>
where
    CS: Scheduler<State = S> + RemovableScheduler,
    IS: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>> + HasReportCorpus<InfantStateState<Loc, Addr, VS, CI>>,
    F: Feedback<S>,
    IF: Feedback<S>,
    IFR: Feedback<S>,
    E: Executor<EM, Self, State = S> + HasObservers<Observers = OT>,
    OT: ObserversTuple<S> + serde::Serialize + serde::de::DeserializeOwned,
    EM: EventManager<E, Self, State = S>,
    I: VMInputT<VS, Loc, Addr, CI>,
    OF: Feedback<S>,
    S: State
        + HasCorpus
        + HasSolutions
        + HasInfantStateState<Loc, Addr, VS, CI>
        + HasItyState<Loc, Addr, VS, CI>
        + HasExecutionResult<Loc, Addr, VS, Out, CI>
        + HasExecutions
        + HasMetadata
        + HasRand
        + HasLastReportTime
        + UsesInput<Input = I>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default + Into<Vec<u8>> + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + SolutionTx,
    SM: SequentialMinimizer<S, E, Loc, Addr, CI, OF>,
{
    /// Evaluate input (execution + feedback + objectives)
    fn evaluate_input_events(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, &input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        // execute the input
        start_timer!(state);
        let exitkind = executor.run_target(self, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);
        *state.executions_mut() += 1;

        start_timer!(state);
        executor.observers_mut().post_exec_all(state, &input, &exitkind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        let observers = executor.observers();

        let _concise_input = input.get_concise(state.get_execution_result());

        let reverted = state.get_execution_result().reverted;

        // get new stage first
        let is_infant_interesting = self
            .infant_feedback
            .is_interesting(state, manager, &input, observers, &exitkind)?;

        let is_solution = self
            .objective
            .is_interesting(state, manager, &input, observers, &exitkind)?;

        // add the trace of the new state
        #[cfg(any(feature = "print_infant_corpus", feature = "print_txn_corpus"))]
        {
            state.get_execution_result_mut().new_state.trace.from_idx = Some(input.get_state_idx());
            state.get_execution_result_mut().new_state.trace.derived_time =
                input.get_staged_state().trace.derived_time + 1;
            state
                .get_execution_result_mut()
                .new_state
                .trace
                .add_input(_concise_input);
        }

        // add the new VM state to infant state corpus if it is interesting
        let mut state_idx = input.get_state_idx();
        if is_infant_interesting && !reverted {
            state_idx = state.add_infant_state(
                &state.get_execution_result().new_state.clone(),
                &mut self.infant_scheduler,
                input.get_state_idx(),
            );

            if self
                .infant_result_feedback
                .is_interesting(state, manager, &input, observers, &exitkind)?
            {
                self.infant_scheduler.sponsor_state(
                    state.get_infant_state_state(),
                    state_idx,
                    INFANT_STATE_INITIAL_VOTES,
                )
            }
        }

        let mut res = ExecuteInputResult::None;
        if is_solution && !reverted {
            res = ExecuteInputResult::Solution;
        } else {
            let is_corpus = self
                .feedback
                .is_interesting(state, manager, &input, observers, &exitkind)?;

            if is_corpus {
                res = ExecuteInputResult::Corpus;

                // Debugging prints
                #[cfg(feature = "print_txn_corpus")]
                {
                    let corpus_dir = format!("{}/corpus", self.work_dir.as_str()).to_string();
                    dump_file!(state, corpus_dir, true);
                }
            }
        }

        let mut corpus_idx = CorpusId::from(0usize);
        if res == ExecuteInputResult::Corpus || res == ExecuteInputResult::Solution {
            // Add the input to the main corpus
            let mut testcase = Testcase::new(input.clone());
            self.feedback.append_metadata(state, observers, &mut testcase)?;
            corpus_idx = state.corpus_mut().add(testcase)?;
            self.infant_scheduler
                .report_corpus(state.get_infant_state_state(), state_idx);
            self.scheduler.on_add(state, corpus_idx)?;
            self.on_add_corpus(&input, unsafe { JMP_MAP.get() }, corpus_idx.into());
        }

        let final_res = match res {
            // not interesting input, just check whether we should replace it due to better fav factor
            ExecuteInputResult::None => {
                self.objective.discard_metadata(state, &input)?;
                match self.should_replace(&input, unsafe { JMP_MAP.get() }, state) {
                    Some((hash, new_fav_factor, old_testcase_idx)) => {
                        let testcase = Testcase::new(input.clone());
                        let prev = state.corpus_mut().replace(old_testcase_idx.into(), testcase)?;
                        self.infant_scheduler
                            .report_corpus(state.get_infant_state_state(), state_idx);
                        self.scheduler.on_replace(state, old_testcase_idx.into(), &prev)?;
                        self.on_replace_corpus((hash, new_fav_factor, old_testcase_idx), old_testcase_idx);

                        Ok((res, Some(old_testcase_idx.into())))
                    }
                    None => {
                        self.feedback.discard_metadata(state, &input)?;
                        Ok((res, None))
                    }
                }
            }
            // if the input is interesting, we need to add it to the input corpus
            ExecuteInputResult::Corpus => {
                // Not a solution
                self.objective.discard_metadata(state, &input)?;

                // Fire the event for CLI
                if send_events {
                    // TODO set None for fast targets
                    let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        manager.serialize_observers(observers)?
                    };
                    manager.fire(
                        state,
                        Event::NewTestcase {
                            input,
                            observers_buf,
                            exit_kind: exitkind,
                            corpus_size: state.corpus().count(),
                            client_config: manager.configuration(),
                            time: current_time(),
                            executions: *state.executions(),
                            forward_id: None,
                        },
                    )?;
                }
                Ok((res, Some(corpus_idx)))
            }
            // find the solution
            ExecuteInputResult::Solution => {
                state
                    .metadata_map_mut()
                    .get_mut::<BugMetadata>()
                    .unwrap()
                    .register_corpus_idx(corpus_idx.into());

                let full_trace_inputs = {
                    let trace = state.get_execution_result().new_state.trace.clone();
                    trace.get_concise_inputs(state)
                };
                let minimized = self.sequential_minimizer.minimize(
                    state,
                    executor,
                    &state.get_execution_result().new_state.trace.clone(),
                    &mut self.objective,
                    corpus_idx.into(),
                );
                let txn_text = prettify_concise_inputs(&minimized);
                let _txn_json = minimized
                    .iter()
                    .map(|ci| String::from_utf8(ci.serialize_concise()).expect("utf-8 failed"))
                    .join("\n");

                println!("\n\n\n😊😊 Found vulnerabilities! \n\n");
                let oracle_output = ORACLE_OUTPUT.lock().unwrap();
                let cur_report =
                    format!(
                    "================ Description ================\n{}\n================ Trace ================\n{}\n",
                    oracle_output.iter().map(|v| {
                        format!(
                            "[{}] ({}): {}",
                            v["bug_type"].as_str().unwrap(),
                            v["confidence"].as_str().unwrap_or("sim-confirmed"),
                            v["bug_info"].as_str().unwrap()
                        )
                     }).join("\n"),
                    txn_text
                );
                println!("{}", cur_report);

                solution::generate_test_with_full_trace(
                    cur_report.clone(),
                    minimized,
                    Some(full_trace_inputs),
                );

                let vuln_file = format!("{}/vuln_info.jsonl", self.work_dir.as_str());
                let mut f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(vuln_file)
                    .expect("Unable to open file");
                let joined = oracle_output
                    .iter()
                    .map(|v| serde_json::to_string(v).expect("failed to json"))
                    .join("\n");
                f.write_all(joined.as_bytes()).expect("Unable to write data");
                f.write_all(b"\n").expect("Unable to write data");

                #[cfg(feature = "print_txn_corpus")]
                {
                    let vulns_dir = format!("{}/vulnerabilities", self.work_dir.as_str());

                    if !REPLAY.load(Ordering::Relaxed) {
                        let bug_idxs = oracle_output.iter().map(|v| v["bug_idx"].as_u64().unwrap()).join(",");
                        // Bound the name: one input can trip thousands of
                        // oracle hits (a per-pc heuristic), and the raw
                        // joined id string can exceed the filesystem's
                        // 255-byte NAME_MAX -- which used to panic here and
                        // kill the whole run. See vuln_file_base.
                        let base = vuln_file_base(&bug_idxs);
                        let data = format!(
                            "Reverted? {} \n Txn: {}",
                            state.get_execution_result().reverted,
                            txn_text
                        );
                        // write to file
                        let path = Path::new(vulns_dir.as_str());
                        if !path.exists() {
                            std::fs::create_dir_all(path).unwrap();
                        }
                        // Dump failures must never take down the fuzzer (a
                        // read-only/full disk, a name collision) -- log and
                        // continue, like the rest of the corpus writes.
                        if let Err(e) = File::create(format!("{}/{}", vulns_dir, base))
                            .and_then(|mut file| file.write_all(data.as_bytes()))
                        {
                            error!("failed to dump finding {}: {e}", base);
                        }
                        if let Err(e) = File::create(format!("{}/{}_replayable", vulns_dir, base))
                            .and_then(|mut replayable_file| replayable_file.write_all(_txn_json.as_bytes()))
                        {
                            error!("failed to dump replayable finding {}: {e}", base);
                        }
                    }
                    // dump_file!(state, vulns_dir, false);
                }
                drop(oracle_output);

                if !RUN_FOREVER.load(Ordering::Relaxed) {
                    exit(0);
                }

                // With --run-forever, execution continues past this point
                // instead of exiting -- this early `return` bypassed the
                // ORACLE_OUTPUT.clear() below for every bug found this way,
                // so every SUBSEQUENT finding's report (and the
                // is_reentrancy_bug/is_fund_extraction_bug checks that
                // decide which exploit script to generate from it) kept
                // accumulating every earlier finding's oracle entries too.
                // A second, unrelated bug found later in the same run could
                // get mislabeled with an earlier bug's type, or generate
                // the wrong kind of exploit script for it.
                ORACLE_OUTPUT.lock().unwrap().clear();
                return Ok((res, None));
            }
        };
        ORACLE_OUTPUT.lock().unwrap().clear();
        final_res
    }

    /// Adds an input to the corpus unconditionally, even if the feedback
    /// doesn't consider it "interesting" -- same contract as libafl's own
    /// `StdFuzzer::add_input`. Not exercised by this project's own fuzzing
    /// loop (which always goes through `evaluate_input_events`), but still
    /// part of the `Evaluator` trait's public contract, so it needs a real
    /// implementation rather than a panic if anything (this crate or a
    /// future libafl version) ever calls it directly.
    fn add_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
    ) -> Result<CorpusId, Error> {
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, &input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        start_timer!(state);
        let exitkind = executor.run_target(self, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);
        *state.executions_mut() += 1;

        start_timer!(state);
        executor.observers_mut().post_exec_all(state, &input, &exitkind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        let observers = executor.observers();
        let mut testcase = Testcase::new(input.clone());

        let is_solution = self.objective.is_interesting(state, manager, &input, observers, &exitkind)?;
        if is_solution {
            self.objective.append_metadata(state, observers, &mut testcase)?;
            let idx = state.solutions_mut().add(testcase)?;
            manager.fire(
                state,
                Event::Objective {
                    objective_size: state.solutions().count(),
                },
            )?;
            return Ok(idx);
        }
        self.objective.discard_metadata(state, &input)?;

        // Some Feedback impls collect data in is_interesting that
        // append_metadata later relies on -- must still call it even
        // though we're adding this input to the corpus unconditionally.
        let _ = self.feedback.is_interesting(state, manager, &input, observers, &exitkind)?;

        self.feedback.append_metadata(state, observers, &mut testcase)?;
        let idx = state.corpus_mut().add(testcase)?;
        self.scheduler.on_add(state, idx)?;

        let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
            None
        } else {
            manager.serialize_observers(observers)?
        };
        manager.fire(
            state,
            Event::NewTestcase {
                input,
                observers_buf,
                exit_kind: exitkind,
                corpus_size: state.corpus().count(),
                client_config: manager.configuration(),
                time: current_time(),
                executions: *state.executions(),
                forward_id: None,
            },
        )?;

        Ok(idx)
    }
}

#[cfg(all(test, feature = "print_txn_corpus"))]
mod vuln_file_base_tests {
    use super::vuln_file_base;

    /// X1 regression: a very long joined id list must yield a short,
    /// filesystem-valid base name -- never the >255-byte string that made
    /// `File::create` panic with "File name too long" and killed the run.
    #[test]
    fn long_id_list_is_bounded_and_valid() {
        let short = "1,2,3";
        assert_eq!(vuln_file_base(short), short, "a short id list is kept verbatim");

        // 500 ids -> well over NAME_MAX as a raw string.
        let long = (0..500).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        assert!(long.len() > 255, "precondition: the raw list is over NAME_MAX");
        let base = vuln_file_base(&long);
        assert!(base.len() <= 140, "bounded name, got {} bytes", base.len());
        assert!(!base.contains('/'), "no path separators in the base name");
        // Deterministic, and distinct inputs give distinct names.
        assert_eq!(base, vuln_file_base(&long));
        let other = (0..500).map(|i| (i + 1).to_string()).collect::<Vec<_>>().join(",");
        assert_ne!(base, vuln_file_base(&other));
    }
}
