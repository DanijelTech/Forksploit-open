//! FAZA 6.2: multi-core fuzzing via process isolation.
//!
//! Why processes and not threads: `EVMFuzzState` is not `Send` -- the
//! compiler rejects `assert_send::<EVMFuzzState>()` because `StagedVMState`
//! and `EVMState` carry `Rc<RefCell<..>>`. On top of that, the coverage/cmp
//! maps (`COVERAGE`, `CMP_MAP`, `JMP_MAP`, ...) are process-global
//! `RacyCell`s whose `unsafe impl Sync` is sound *only* under the
//! single-threaded assumption documented in `src/sync_utils.rs`. In-process
//! worker threads would therefore be a genuine data race, not just a
//! borrow-checker nuisance.
//!
//! The sound way to use more than one core is one OS process per job, each
//! with its own fully isolated state and its own work dir. The parent
//! process only supervises and aggregates the workers' findings; it never
//! shares memory with them.

use std::{
    collections::HashSet,
    ffi::OsString,
    fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

use tracing::{error, info, warn};

/// Derive an independent, well-separated seed per job (splitmix64 finalizer)
/// so that N jobs explore genuinely different random streams from one base
/// seed. Job 0 does not simply get `base` -- that would make the campaign
/// reproduce a single-core run's first job and waste the seed space.
pub fn derive_job_seed(base: u64, job: usize) -> u64 {
    let mut z = base.wrapping_add((job as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Strip the flags the supervisor overrides (`--jobs`, `--seed`,
/// `--fuzz-seconds`, `-w`/`--work-dir`, in both `--flag value` and
/// `--flag=value`/`-wvalue` forms) from the inherited argv, so the child
/// receives exactly one value for each and clap cannot reject a duplicate.
pub fn filter_overridden_flags<I: IntoIterator<Item = OsString>>(args: I) -> Vec<OsString> {
    const SEPARATE: [&str; 5] = [
        "--jobs",
        "--seed",
        "--fuzz-seconds",
        "--work-dir",
        "--concolic-num-threads",
    ];
    const JOINED: [&str; 5] = [
        "--jobs=",
        "--seed=",
        "--fuzz-seconds=",
        "--work-dir=",
        "--concolic-num-threads=",
    ];
    let mut out = Vec::new();
    let mut iter = args.into_iter().peekable();
    while let Some(a) = iter.next() {
        let s = a.to_string_lossy();
        if SEPARATE.contains(&s.as_ref()) || s.as_ref() == "-w" {
            let _ = iter.next(); // drop the flag's value too
            continue;
        }
        if JOINED.iter().any(|p| s.starts_with(p)) {
            continue;
        }
        // Attached short form, e.g. `-wwork_dir`, but never `--...`.
        if s.starts_with("-w") && !s.starts_with("--") && s.len() > 2 {
            continue;
        }
        out.push(a);
    }
    out
}

fn file_content_hash(path: &Path) -> std::io::Result<u64> {
    let bytes = fs::read(path)?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    Ok(h.finish())
}

/// Copy every finding from each job's `vulnerabilities/` dir into
/// `parent_dir/vulnerabilities/`. Identical content found by more than one
/// job is copied once; a name clash with *different* content is preserved by
/// prefixing the newer file with `job<i>_` rather than silently overwriting
/// one job's finding with another's. Returns the number of files written.
pub fn merge_vulnerabilities(
    parent_dir: &Path,
    job_dirs: &[(usize, PathBuf)],
) -> std::io::Result<usize> {
    let dest = parent_dir.join("vulnerabilities");
    fs::create_dir_all(&dest)?;
    let mut seen: HashSet<u64> = HashSet::new();
    let mut written = 0usize;

    for (idx, job_dir) in job_dirs {
        let src = job_dir.join("vulnerabilities");
        let entries = match fs::read_dir(&src) {
            Ok(e) => e,
            Err(_) => continue, // job found nothing
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name() else { continue };
            let hash = match file_content_hash(&path) {
                Ok(h) => h,
                Err(e) => {
                    warn!("merge: cannot read {}: {e}", path.display());
                    continue;
                }
            };
            if !seen.insert(hash) {
                continue; // byte-identical to a finding already merged
            }
            let mut target = dest.join(name);
            if target.exists() {
                let prefixed = format!("job{}_", idx);
                let mut pname = OsString::from(prefixed);
                pname.push(name);
                target = dest.join(pname);
            }
            if let Err(e) = fs::copy(&path, &target) {
                warn!("merge: cannot copy {}: {e}", path.display());
            } else {
                written += 1;
            }
        }
    }
    Ok(written)
}

/// Per-job concolic (Z3) solver budget: the campaign-wide cap
/// (`max_concolic_threads()`) is SHARED across all jobs, never multiplied by
/// them. With `--jobs N` each worker gets `max(1, cap / N)`, so the whole
/// campaign's live Z3 solver count stays bounded by the cap instead of
/// `N * cap` (the oversubscription that froze hosts). A single job receives
/// the full cap. Note the floor of 1: beyond `cap` jobs the total is the job
/// count, which is inherent to process isolation -- each worker still solves
/// at most one branch at a time.
pub fn per_job_concolic_threads(jobs: usize) -> usize {
    let jobs = jobs.max(1);
    (crate::r#const::max_concolic_threads() / jobs).max(1)
}

fn spawn_job(
    base_args: &[OsString],
    job_dir: &Path,
    seed: u64,
    concolic_threads: usize,
) -> std::io::Result<Child> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.args(base_args);
    cmd.arg("--jobs").arg("1");
    cmd.arg("--seed").arg(seed.to_string());
    cmd.arg("--work-dir").arg(job_dir);
    cmd.arg("--concolic-num-threads")
        .arg(concolic_threads.to_string());
    // Belt-and-braces: even if the flag override above were somehow lost, a
    // worker can never re-enter supervisor mode and fork-bomb.
    cmd.env("FORKSPLOIT_JOB", "1");
    // Keep each worker's own output in its own log so N interleaved streams
    // don't corrupt the parent's stdout (which a caller may be parsing).
    let log = job_dir.join("fuzzer.log");
    fs::create_dir_all(job_dir)?;
    let out = fs::File::create(&log)?;
    let err = out.try_clone()?;
    cmd.stdout(out).stderr(err);
    cmd.spawn()
}

/// Clamp a requested job count to what the machine can actually run: never
/// more than the number of available cores. Each fuzzing job is ~one fully
/// busy core (plus up to one concolic solver per job under `--concolic`), so
/// `--jobs` above the core count oversubscribes the host -- the same failure
/// class as the historical `num_cpus` concolic default that froze a 15-core
/// box, just via the process count instead of the solver count. A request
/// above the core count is reduced, and `run_supervisor` warns about it.
pub fn clamp_jobs_to_cores(jobs: usize) -> usize {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    jobs.max(1).min(cores)
}

/// Run `jobs` isolated worker processes, bound the whole campaign to
/// `fuzz_seconds` (0 = unlimited), then aggregate every worker's findings
/// into `work_dir/vulnerabilities/`. Returns the process exit code for the
/// parent (0 on success, 1 if every worker failed to even start).
///
/// `jobs` is clamped to the available core count (see [`clamp_jobs_to_cores`]).
pub fn run_supervisor(jobs: usize, fuzz_seconds: u64, work_dir: &Path, base_seed: u64) -> i32 {
    let jobs = {
        let clamped = clamp_jobs_to_cores(jobs);
        if clamped != jobs {
            warn!(
                "multicore: --jobs {jobs} clamped to {clamped} (available cores); more workers than \
                 cores would oversubscribe the host and can freeze it"
            );
        }
        clamped
    };
    if let Err(e) = fs::create_dir_all(work_dir) {
        error!("multicore: cannot create work dir {}: {e}", work_dir.display());
        return 1;
    }

    // A base seed of 0 means "pick one from the clock" in FuzzState::new, but
    // the supervisor must resolve it once so all workers are reproducible as
    // a group and provably distinct from each other.
    let base_seed = if base_seed == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x5EED)
    } else {
        base_seed
    };

    let base_args = filter_overridden_flags(std::env::args_os().skip(1));
    info!(
        "multicore: launching {jobs} isolated worker processes (base seed {base_seed}, budget {}s)",
        if fuzz_seconds == 0 {
            "unlimited".to_string()
        } else {
            fuzz_seconds.to_string()
        }
    );

    let mut job_dirs: Vec<(usize, PathBuf)> = Vec::with_capacity(jobs);
    let mut children: Vec<(usize, Child)> = Vec::with_capacity(jobs);
    let mut spawn_failures = 0usize;

    for job in 0..jobs {
        let job_dir = work_dir.join(format!("job_{job}"));
        let seed = derive_job_seed(base_seed, job);
        match spawn_job(&base_args, &job_dir, seed, per_job_concolic_threads(jobs)) {
            Ok(child) => {
                info!(
                    "multicore: job {job} -> {} (seed {seed}, log {}/fuzzer.log)",
                    job_dir.display(),
                    job_dir.display()
                );
                job_dirs.push((job, job_dir));
                children.push((job, child));
            }
            Err(e) => {
                error!("multicore: failed to spawn job {job}: {e}");
                spawn_failures += 1;
            }
        }
    }

    if children.is_empty() {
        error!("multicore: no worker processes could be started");
        return 1;
    }

    // Wait for completion, enforcing the wall-clock budget if one was given.
    let deadline = if fuzz_seconds == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_secs(fuzz_seconds))
    };
    let mut running: Vec<(usize, Child)> = children;
    loop {
        running.retain_mut(|(job, child)| match child.try_wait() {
            Ok(Some(status)) => {
                info!("multicore: job {job} exited with {status}");
                false
            }
            Ok(None) => true,
            Err(e) => {
                error!("multicore: job {job} wait error: {e}");
                false
            }
        });
        if running.is_empty() {
            break;
        }
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                warn!(
                    "multicore: budget reached, terminating {} still-running worker(s)",
                    running.len()
                );
                for (job, child) in running.iter_mut() {
                    if let Err(e) = child.kill() {
                        warn!("multicore: cannot kill job {job}: {e}");
                    }
                    let _ = child.wait();
                }
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    match merge_vulnerabilities(work_dir, &job_dirs) {
        Ok(n) => info!(
            "multicore: merged {n} finding file(s) into {}/vulnerabilities/",
            work_dir.display()
        ),
        Err(e) => error!("multicore: merge failed: {e}"),
    }

    if spawn_failures == jobs {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C1 regression: `--jobs` must never exceed the machine's core count.
    /// Each job is ~one busy core, so more workers than cores oversubscribe
    /// the host -- the freeze risk. The clamp is relative to the observed
    /// core count so it holds on any machine.
    #[test]
    fn jobs_are_clamped_to_core_count() {
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        assert_eq!(clamp_jobs_to_cores(0), 1, "0 (and anything below 1) means at least one job");
        assert_eq!(clamp_jobs_to_cores(1), 1);
        if cores >= 2 {
            assert_eq!(clamp_jobs_to_cores(2), 2);
        }
        assert_eq!(clamp_jobs_to_cores(cores), cores, "exactly the core count is allowed");
        for too_many in [cores + 1, cores + 100, usize::MAX] {
            assert_eq!(
                clamp_jobs_to_cores(too_many),
                cores,
                "a job count above the core count must be clamped (requested {too_many})"
            );
        }
    }

    #[test]
    fn job_seeds_are_distinct_and_stable() {
        let base = 1667840158231589000u64;
        let seeds: Vec<u64> = (0..8).map(|j| derive_job_seed(base, j)).collect();
        let uniq: HashSet<u64> = seeds.iter().copied().collect();
        assert_eq!(uniq.len(), seeds.len(), "job seeds must be unique");
        // Deterministic: same inputs -> same output.
        assert_eq!(derive_job_seed(base, 3), seeds[3]);
        // And not a trivial offset of the base.
        assert_ne!(seeds[0], base);
    }

    #[test]
    fn filter_strips_all_override_forms() {
        let input: Vec<OsString> = [
            "evm", "-t", "target", "--jobs", "4", "--seed=99", "-w", "old_dir", "--fuzz-seconds",
            "30", "--work-dir=other", "-wattached", "--run-forever", "-f",
            "--concolic-num-threads", "7", "--concolic-num-threads=9",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let out = filter_overridden_flags(input);
        let strs: Vec<String> = out.iter().map(|s| s.to_string_lossy().into_owned()).collect();
        assert_eq!(strs, vec!["evm", "-t", "target", "--run-forever", "-f"]);
    }

    #[test]
    fn per_job_concolic_threads_never_multiplies_the_cap() {
        // The freeze cause was cap * jobs solvers. For any job count up to the
        // cap the total stays <= cap (each job gets an even share); every job
        // keeps at least one solver. Above the cap the share floors at 1, so
        // the total is the job count, never the job count times the cap.
        let cap = crate::r#const::max_concolic_threads();
        for jobs in 1..=cap {
            let per_job = per_job_concolic_threads(jobs);
            assert!(per_job >= 1, "every job must get at least one solver");
            assert!(
                jobs * per_job <= cap,
                "jobs={jobs} per_job={per_job} must stay within the cap {cap}"
            );
        }
        for jobs in (cap + 1)..=16usize {
            assert_eq!(per_job_concolic_threads(jobs), 1);
        }
        assert_eq!(per_job_concolic_threads(1), cap);
        assert_eq!(per_job_concolic_threads(cap), 1);
        assert_eq!(per_job_concolic_threads(100), 1);
    }

    #[test]
    fn merge_dedups_identical_and_preserves_distinct_clashes() {
        let root = std::env::temp_dir().join(format!("fs_merge_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let job0 = root.join("job_0");
        let job1 = root.join("job_1");
        fs::create_dir_all(job0.join("vulnerabilities")).unwrap();
        fs::create_dir_all(job1.join("vulnerabilities")).unwrap();
        // Same name, identical content -> merged once.
        fs::write(job0.join("vulnerabilities/A.t.sol"), b"same").unwrap();
        fs::write(job1.join("vulnerabilities/A.t.sol"), b"same").unwrap();
        // Same name, different content -> both preserved.
        fs::write(job0.join("vulnerabilities/B.t.sol"), b"one").unwrap();
        fs::write(job1.join("vulnerabilities/B.t.sol"), b"two").unwrap();

        let dirs = vec![(0usize, job0.clone()), (1usize, job1.clone())];
        let n = merge_vulnerabilities(&root, &dirs).unwrap();
        assert_eq!(n, 3, "A once + B twice");
        let dest = root.join("vulnerabilities");
        assert!(dest.join("A.t.sol").exists());
        assert!(dest.join("B.t.sol").exists());
        assert!(dest.join("job1_B.t.sol").exists());
        let _ = fs::remove_dir_all(&root);
    }
}
