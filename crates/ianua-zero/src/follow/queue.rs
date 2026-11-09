//! The reloads waiting to run, each at most once.
//!
//! A reload asked for while the same one waits is folded into it, and one
//! asked for while the same one runs waits until that ends, so one target
//! is never read twice at once and a burst of changes to one tenant reads
//! it once or twice, not once per change. Should the queue reach its room,
//! everything waiting is folded into one full reload.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use ianua_domain::types::TenantId;
use tokio::sync::Notify;

use super::locked;

/// What one reload reads again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Target {
    /// Reloads routing and security state for the named isolation boundary.
    Tenant(TenantId),
    /// The served certificates.
    Certificates,
    /// Every tenant and the served certificates.
    Everything,
}

/// Why a reload runs, which decides what a failed read leaves served.
/// The later a cause is listed, the more it asks; two asks of one target
/// run once, for the stronger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Cause {
    /// The timer: nothing is known to have changed. A failed read keeps
    /// what was held.
    Routine,
    /// A heard change. A tenant it names whose read fails may be revoked,
    /// so it is withdrawn; the others keep what was held.
    Heard,
    /// Events went by unheard, so any tenant may be out of date. A failed
    /// read keeps what was held, and the tables count as stale until a
    /// full reload succeeds.
    Unheard,
}

#[derive(Debug, Default)]
struct Waiting {
    order: VecDeque<Target>,
    causes: HashMap<Target, Cause>,
    running: HashSet<Target>,
}

impl Waiting {
    /// Queues `target`, or folds it into the same target waiting.
    fn add(&mut self, target: Target, cause: Cause) {
        if let Some(waiting) = self.causes.get_mut(&target) {
            *waiting = (*waiting).max(cause);
            return;
        }
        self.order.push_back(target);
        self.causes.insert(target, cause);
    }

    /// Folds everything waiting into one full reload. Which changes were
    /// asked for is lost with them, so it runs as for events unheard.
    fn fold_into_everything(&mut self) {
        self.order.clear();
        self.causes.clear();
        self.add(Target::Everything, Cause::Unheard);
    }

    /// The first waiting target not running now, taken out to run.
    fn take(&mut self) -> Option<(Target, Cause)> {
        let at = self
            .order
            .iter()
            .position(|target| !self.running.contains(target))?;
        let target = self.order.remove(at)?;
        let cause = self.causes.remove(&target)?;
        self.running.insert(target);
        Some((target, cause))
    }
}

/// The reloads waiting to run.
#[derive(Debug)]
pub(super) struct ReloadQueue {
    waiting: Mutex<Waiting>,
    ready: Notify,
    room: usize,
}

impl ReloadQueue {
    /// A queue holding at most `room` reloads before it folds them into one
    /// full reload.
    pub(super) fn new(room: usize) -> Self {
        Self {
            waiting: Mutex::new(Waiting::default()),
            ready: Notify::new(),
            room: room.max(1),
        }
    }

    /// Asks for `target` to be read again, for `cause`.
    pub(super) fn ask(&self, target: Target, cause: Cause) {
        self.queue(target, cause);
        self.ready.notify_one();
    }

    fn queue(&self, target: Target, cause: Cause) {
        let mut waiting = locked(&self.waiting);
        if waiting.causes.len() >= self.room && !waiting.causes.contains_key(&target) {
            tracing::warn!("too many reloads waiting; reading everything again instead");
            waiting.fold_into_everything();
            return;
        }
        waiting.add(target, cause);
    }

    /// The next reload to run, waiting for one when none can run now. The
    /// caller hands it back through [`finish`](Self::finish) once it ran.
    pub(super) async fn next(&self) -> (Target, Cause) {
        loop {
            let ready = self.ready.notified();
            if let Some(next) = locked(&self.waiting).take() {
                return next;
            }
            ready.await;
        }
    }

    /// Marks `target` as run, so a reload of it asked for meanwhile may run.
    pub(super) fn finish(&self, target: Target) {
        locked(&self.waiting).running.remove(&target);
        self.ready.notify_one();
    }

    /// The reloads waiting, in order.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> Vec<(Target, Cause)> {
        let waiting = locked(&self.waiting);
        waiting
            .order
            .iter()
            .filter_map(|target| waiting.causes.get(target).map(|cause| (*target, *cause)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reload_asked_twice_runs_once_for_the_stronger_cause() {
        let queue = ReloadQueue::new(10);
        let acme = Target::Tenant(TenantId::new());

        queue.ask(acme, Cause::Routine);
        queue.ask(acme, Cause::Heard);

        assert_eq!(queue.waiting(), vec![(acme, Cause::Heard)]);
    }

    /// A second reload of a running tenant waits for the first to finish,
    /// while another tenant's queued reload can run in between.
    #[tokio::test]
    async fn a_running_target_is_not_handed_out_again() {
        let queue = ReloadQueue::new(10);
        let acme = Target::Tenant(TenantId::new());
        let globex = Target::Tenant(TenantId::new());
        queue.ask(acme, Cause::Heard);
        let (first, _) = queue.next().await;
        queue.ask(acme, Cause::Heard);
        queue.ask(globex, Cause::Heard);

        let (second, _) = queue.next().await;
        queue.finish(first);
        let (third, _) = queue.next().await;

        assert_eq!((first, second, third), (acme, globex, acme));
    }

    /// Asking for five tenant reloads with room for two leaves one full
    /// reload queued with the unheard-events cause.
    #[test]
    fn a_full_queue_folds_into_one_full_reload() {
        let queue = ReloadQueue::new(2);

        for _ in 0..5 {
            queue.ask(Target::Tenant(TenantId::new()), Cause::Heard);
        }

        assert_eq!(queue.waiting(), vec![(Target::Everything, Cause::Unheard)]);
    }
}
