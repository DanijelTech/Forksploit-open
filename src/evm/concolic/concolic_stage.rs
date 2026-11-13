use std::{cell::RefCell, fmt::Debug, ops::Deref, rc::Rc, sync::atomic::Ordering};

use libafl::{
    corpus::{Corpus, Testcase},
    events::{EventFirer, ProgressReporter},
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::Input,
    prelude::{CorpusId, HasMetadata, ObserversTuple, Stage, UsesInput},
    state::{HasCorpus, State, UsesState},
    Error,
    Evaluator,
};
use libafl_bolts::{impl_serdeany, Named};
use revm_primitives::HashSet;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::{
    evm::{
        concolic::concolic_host::{ConcolicHost, Field, Solution, ALL_SOLUTIONS, ALL_WORKER_THREADS},
        host::CONCOLIC_NO_CONTROL_LEAK,
        input::{EVMInput, EVMInputT},
        middlewares::middleware::MiddlewareType,
        types::{EVMFuzzExecutor, EVMFuzzState, EVMQueueExecutor},
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
};
pub struct ConcolicStage<OT> {
    pub enabled: bool,
    pub allow_symbolic_addresses: bool,
    pub known_state_input: HashSet<(usize, usize)>,
    pub vm_executor: Rc<RefCell<EVMQueueExecutor>>,
    pub phantom: std::marker::PhantomData<OT>,
    /// Max live Z3 solvers this stage's hosts may keep in the process-wide
    /// `ALL_WORKER_THREADS` pool. Already clamped to the campaign-wide cap
    /// (`max_concolic_threads()`), so it is `min(2, cores)` -- never
    /// `num_cpus`, never multiplied by `--jobs`.
    pub num_threads: usize,
}

impl<OT> UsesState for ConcolicStage<OT> {
    type State = EVMFuzzState;
}

impl<OT> ConcolicStage<OT> {
    pub fn new(
        enabled: bool,
        allow_symbolic_addresses: bool,
        vm_executor: Rc<RefCell<EVMQueueExecutor>>,
        num_threads: usize,
    ) -> Self {
        Self {
            enabled,
            allow_symbolic_addresses,
            known_state_input: HashSet::new(),
            vm_executor,
            phantom: std::marker::PhantomData,
            num_threads,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicPrioritizationMetadata {
    pub interesting_idx: Vec<usize>,
    pub solutions: Vec<(Solution, Rc<EVMInput>)>,
}

impl_serdeany!(ConcolicPrioritizationMetadata);

impl<EM, Z, OT> Stage<EVMFuzzExecutor<OT>, EM, Z> for ConcolicStage<OT>
where
    Z: Evaluator<EVMFuzzExecutor<OT>, EM, State = Self::State>,
    EM: ProgressReporter + UsesState<State = Self::State>,
    OT: ObserversTuple<Self::State>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut EVMFuzzExecutor<OT>,
        state: &mut Self::State,
        manager: &mut EM,
        _corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        if !state.metadata_map().contains::<ConcolicPrioritizationMetadata>() {
            // 0..state.corpus().count() is the range of indexes of the corpus
            let idxs = (0..state.corpus().count()).collect::<Vec<_>>();
            state.metadata_map_mut().insert(ConcolicPrioritizationMetadata {
                interesting_idx: idxs,
                solutions: vec![],
            });
        }

        // We just inserted the metadata above if missing, so it is present
        // here; use `if let` rather than `.unwrap()` so an unforeseen state
        // (e.g. metadata cleared by another stage mid-run) degrades to "no
        // concolic work this round" instead of aborting the fuzzer.
        let Some(meta) = state
            .metadata_map()
            .get::<ConcolicPrioritizationMetadata>()
            .cloned()
        else {
            error!("concolic: prioritization metadata missing, skipping this stage run");
            return Ok(());
        };

        let total = meta.interesting_idx.len();
        let mut done = 0usize;
        for idx in &meta.interesting_idx {
            done += 1;
            // One line per corpus entry. Concolic work for each entry runs on
            // the bounded worker pool (`ConcolicStage::num_threads` solvers,
            // at most `min(2, cores)` -- see `max_concolic_threads()`); the
            // pool is drained before this loop advances, so these lines are
            // per-corpus-entry progress, not one per solver.
            info!(
                "concolic: testcase #{} ({}/{}) -- bounded pool of {} Z3 solver(s)",
                idx, done, total, self.num_threads
            );

            let Some(testcase) = state
                .corpus()
                .get((*idx).into())
                .ok()
                .and_then(|c| c.borrow().input().clone())
            else {
                // Corpus index with no loadable input (evicted/empty slot):
                // skip just this entry, never abort the whole stage.
                debug!("concolic: testcase #{} has no input, skipping", idx);
                continue;
            };

            if testcase.get_data_abi().is_none() || testcase.get_state().has_post_execution() {
                // borrow/step tx?
                continue;
            }

            // An uninitialized staged state carries an EMPTY world state
            // (raw corpus seeds are built with `StagedVMState::new_uninitialized`).
            // Running concolic against it is meaningless AND harmful: every
            // storage slot reads as 0, so `require(x == storage)`-style gates
            // pass with the zero input, and the emitted solution testcases
            // inherit that empty state. Those solutions are then evaluated
            // directly by `fuzzer.evaluate_input` (which, unlike the mutator,
            // does not swap in a real infant state), so the oracle observes a
            // post-state write that never happens on-chain. Confirmed live:
            // a "solved stays 0" invariant reported `sim-confirmed` from a
            // transaction that reverts with "gate" on real state.
            if !testcase.get_staged_state().initialized {
                debug!(
                    "concolic: testcase #{} has an uninitialized (empty) world state, skipping",
                    idx
                );
                continue;
            }

            let testcase_ref = Rc::new(testcase.clone());

            {
                let mut vm = self.vm_executor.deref().borrow_mut();
                vm.host.add_middlewares(Rc::new(RefCell::new(ConcolicHost::new(
                    testcase_ref.clone(),
                    self.num_threads,
                ))));
                // FAZA 2.4: no control leak while concolic runs. A faked call
                // return can make a branch reachable that the real callee
                // never would, so a concolic "solution" resting on it names a
                // transaction the chain cannot reproduce. Forcing the real
                // callee path here means every solution is only ever derived
                // from genuinely-executed code; the (deliberate) leak-based
                // exploration in the normal fuzzing loop is untouched.
                CONCOLIC_NO_CONTROL_LEAK.store(true, Ordering::Relaxed);
                vm.execute(&testcase_ref, state);
                CONCOLIC_NO_CONTROL_LEAK.store(false, Ordering::Relaxed);

                // Drain the worker pool to completion before reading
                // ALL_SOLUTIONS: every spawned solver is joined here, so all
                // its results are visible below and the pool is empty again
                // before the next testcase's host is created. A worker that
                // panicked (an unexpected symbolic-expression shape is a real,
                // confirmed failure mode of this pipeline) is logged and
                // skipped -- never propagated into this (the main fuzzer)
                // thread, which would kill the whole run over one testcase.
                let mut worker_threads = ALL_WORKER_THREADS.lock().unwrap_or_else(|e| e.into_inner());
                while !worker_threads.is_empty() {
                    let curr_thread = worker_threads.remove(0);
                    if let Err(panic_payload) = curr_thread.join() {
                        let msg = panic_payload
                            .downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "<non-string panic payload>".to_string());
                        error!("Concolic worker thread panicked (skipping this solve, run continues): {msg}");
                    }
                }
                drop(worker_threads);

                let mut solutions = ALL_SOLUTIONS.lock().unwrap();
                if solutions.len() > 0 {
                    let meta = state
                        .metadata_map_mut()
                        .get_mut::<ConcolicPrioritizationMetadata>()
                        .expect("Failed to get metadata");
                    for solution in solutions.iter() {
                        meta.solutions.push((solution.clone(), testcase_ref.clone()));
                    }
                    solutions.clear();
                }
                drop(solutions);

                vm.host.remove_middlewares_by_ty(&MiddlewareType::Concolic);
            }
        }

        {
            let metadata = state
                .metadata_map_mut()
                .get_mut::<ConcolicPrioritizationMetadata>()
                .unwrap();
            metadata.interesting_idx.clear();

            let mut testcases = vec![];

            while let Some((solution, orig_testcase)) = metadata.solutions.pop() {
                debug!("We have a solution from concolic execution: {}", solution.to_string());
                let mut data_abi = orig_testcase.get_data_abi().expect("data abi");
                let mut new_testcase = (*orig_testcase).clone();

                // if cannot set_bytes AND no fields to modify, skip
                if data_abi.set_bytes(solution.input) {
                    // This can fail if e.g. solving for an array
                    new_testcase.data = Some(data_abi);
                } else if solution.fields.is_empty() {
                    continue;
                }

                for mod_fields in solution.fields {
                    match mod_fields {
                        Field::Caller => {
                            if self.allow_symbolic_addresses {
                                new_testcase.set_caller(solution.caller);
                            }
                        }
                        Field::CallDataValue => {
                            new_testcase.set_txn_value(solution.value);
                        }
                        Field::Origin => {
                            if self.allow_symbolic_addresses {
                                new_testcase.set_origin(solution.origin);
                            }
                        }
                    }
                }
                // debug!("new testcase: {:?}", new_testcase);
                testcases.push(new_testcase);
            }

            for testcase in testcases {
                fuzzer
                    .evaluate_input(state, executor, manager, testcase)
                    .expect("evaluate input");
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct ConcolicFeedbackWrapper<F: Named + Debug> {
    pub inner: F,
}

impl<F: Named + Debug> ConcolicFeedbackWrapper<F> {
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F: Named + Debug> Named for ConcolicFeedbackWrapper<F> {
    fn name(&self) -> &str {
        "ConcolicFeedbackWrapper"
    }
}

impl<I, S, F> Feedback<S> for ConcolicFeedbackWrapper<F>
where
    I: Input,
    F: Feedback<S> + Named + Debug,
    S: State + HasMetadata + HasCorpus + UsesInput<Input = I>,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        self.inner.is_interesting(state, manager, input, observers, exit_kind)
    }

    #[inline]
    #[allow(unused_variables)]
    fn append_metadata<OT>(
        &mut self,
        state: &mut S,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
    {
        if !state.metadata_map().contains::<ConcolicPrioritizationMetadata>() {
            // 0..state.corpus().count() is the range of indexes of the corpus
            let idxs = (0..state.corpus().count()).collect::<Vec<_>>();
            state.metadata_map_mut().insert(ConcolicPrioritizationMetadata {
                interesting_idx: idxs,
                solutions: vec![],
            });
        }

        let idx = state.corpus().count();
        let meta = state
            .metadata_map_mut()
            .get_mut::<ConcolicPrioritizationMetadata>()
            .unwrap();

        meta.interesting_idx.push(idx);

        self.inner.append_metadata(state, observers, testcase)
    }
}
