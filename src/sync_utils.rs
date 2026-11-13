use std::cell::UnsafeCell;

/// A global, mutable cell for state that the main fuzzing loop touches on
/// every instruction (coverage/cmp maps) or very frequently, where a `Mutex`
/// would add real per-instruction locking overhead for no actual benefit.
///
/// # Safety invariant
///
/// ForkSploit's main fuzzing loop is single-threaded: one process runs one
/// campaign on one thread (multi-core is done via process isolation, not
/// threads -- see `CLAUDE.md`). Every `RacyCell` in this codebase is written
/// and read only from that one thread. NOTE: the concolic (Z3) worker pool
/// does run real OS threads, but it deliberately never touches a `RacyCell`
/// -- a worker only receives cloned, `Send` data (`Vec<Box<Expr>>`) and builds
/// its Z3 objects from its own thread-local context. If a future change ever
/// had a second thread read or write one of these fields -- a multi-core
/// `Launcher`-based campaign, or handing a `RacyCell` to a concolic worker --
/// the field holding it must be redesigned (e.g. per-thread-local maps merged
/// at sync points, or a real `Mutex`), not just called from a second thread.
pub struct RacyCell<T>(UnsafeCell<T>);

unsafe impl<T> Sync for RacyCell<T> {}

impl<T> RacyCell<T> {
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// # Safety
    /// Caller must uphold the single-thread invariant documented on [`RacyCell`].
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }

    /// # Safety
    /// Caller must uphold the single-thread invariant documented on [`RacyCell`].
    pub unsafe fn get(&self) -> &T {
        unsafe { &*self.0.get() }
    }
}
