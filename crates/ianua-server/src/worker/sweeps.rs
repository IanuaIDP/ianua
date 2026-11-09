//! The sweep scheduler: every sweep the app defines, each round run once
//! across every worker.
//!
//! Each worker asks on every tick which sweeps' rounds have come, through
//! the app's claim, and runs those it won. A claim is a row in the
//! database, first insert wins, so a round goes to one worker however many
//! tick, and a worker that restarts within a round does not run it again.
//! Each run is held to its sweep's period, so a run never reaches into the
//! next round, and a sweep still running here when its next round comes
//! lets that round go: every sweep looks at what is due now, so the next
//! round picks up what this one left.

mod expiries;
mod lifecycles;
mod platform;
mod upkeep;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::auditor::RequestAuditor;
use ianua_app::error::AppError;
use ianua_app::ports::scheduling::SweepClaims;
use ianua_app::use_case::Command;
use ianua_app::use_cases::scheduling::{ClaimDuePorts, ClaimDueUseCase, Sweep, sweeps};
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::scheduling::sweep::SweepName;
use ianua_domain::shared::clock;
use ianua_infra::postgres::scheduling::PgSweepClaims;
use time::OffsetDateTime;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::error::{PlatformError, ServerError};
use crate::worker::parts::Parts;

/// One sweep's use case, ready to run a round.
#[async_trait]
pub(super) trait SweepRun: Send + Sync {
    /// The full path of the use case it runs, as the app's list of sweeps
    /// names it.
    fn runs(&self) -> &'static str;

    /// Runs the round claimed at `now`, recording what it changes through
    /// `auditor`, and says what it came to, for the log.
    ///
    /// # Errors
    ///
    /// The [`AppError`] the use case failed with; the next round tries
    /// again.
    async fn run(&self, auditor: &RequestAuditor, now: OffsetDateTime) -> Result<String, AppError>;
}

/// What a sweep's use case takes, made from the moment its round was
/// claimed.
pub(super) trait SweepInput: Send {
    /// The input for the round claimed at `now`.
    fn at(now: OffsetDateTime) -> Self;
}

impl SweepInput for () {
    fn at(_now: OffsetDateTime) -> Self {}
}

impl SweepInput for OffsetDateTime {
    fn at(now: OffsetDateTime) -> Self {
        now
    }
}

/// A sweep's use case as a [`SweepRun`].
pub(super) struct Swept<U>(U);

impl<U> Swept<U>
where
    Self: SweepRun + 'static,
{
    /// `use_case`, ready to run its rounds.
    pub(super) fn of(use_case: U) -> Arc<dyn SweepRun> {
        Arc::new(Self(use_case))
    }
}

#[async_trait]
impl<U, T> SweepRun for Swept<U>
where
    U: Command<Caller = (), Output = Result<T, AppError>> + Send + Sync,
    U::Input: SweepInput,
    T: std::fmt::Debug + Send,
{
    fn runs(&self) -> &'static str {
        std::any::type_name::<U>()
    }

    async fn run(&self, auditor: &RequestAuditor, now: OffsetDateTime) -> Result<String, AppError> {
        let came_to = self.0.execute(&(), auditor, U::Input::at(now)).await?;
        Ok(format!("{came_to:?}"))
    }
}

/// Why the sweeps cannot be scheduled.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(super) enum ScheduleError {
    /// A sweep of the app has no runner, so it would never run.
    #[error("nothing runs the {0} sweep")]
    Unrun(String),
    /// Two runners run one use case.
    #[error("two runners run {0}")]
    Doubled(&'static str),
    /// A runner runs a use case no sweep names.
    #[error("{0} is run as a sweep, but the app names no sweep for it")]
    Unknown(&'static str),
}

/// One sweep with what runs it.
struct Bound {
    runner: Arc<dyn SweepRun>,
    period: Duration,
}

/// Each of `sweeps` with the one runner of its use case.
///
/// # Errors
///
/// [`ScheduleError`] when a sweep has no runner, or a runner is doubled or
/// runs no sweep.
fn bound(
    sweeps: &[Sweep],
    runners: Vec<Arc<dyn SweepRun>>,
) -> Result<HashMap<SweepName, Bound>, ScheduleError> {
    let mut by_use_case: HashMap<&'static str, Arc<dyn SweepRun>> = HashMap::new();
    for runner in runners {
        let runs = runner.runs();
        if by_use_case.insert(runs, runner).is_some() {
            return Err(ScheduleError::Doubled(runs));
        }
    }
    let mut bound = HashMap::with_capacity(sweeps.len());
    for sweep in sweeps {
        let Some(runner) = by_use_case.remove(sweep.runs()) else {
            return Err(ScheduleError::Unrun(sweep.name().to_string()));
        };
        let period = Duration::try_from(sweep.period().get()).unwrap_or(Duration::MAX);
        bound.insert(sweep.name().clone(), Bound { runner, period });
    }
    if let Some(unknown) = by_use_case.into_keys().next() {
        return Err(ScheduleError::Unknown(unknown));
    }
    Ok(bound)
}

/// Every runner the worker has.
///
/// # Errors
///
/// [`ServerError`] when a use case cannot be built.
fn runners(parts: &Parts<'_>) -> Result<Vec<Arc<dyn SweepRun>>, ServerError> {
    Ok([
        upkeep::runners(parts)?,
        lifecycles::runners(parts),
        expiries::runners(parts),
        platform::runners(parts)?,
    ]
    .concat())
}

/// Starts the scheduler of every sweep.
///
/// # Errors
///
/// [`ServerError`] when a sweep's use case cannot be built, or a sweep of
/// the app has no runner.
pub(super) fn start(parts: &Parts<'_>, shutdown: &Shutdown) -> Result<(), ServerError> {
    let sweeps = sweeps().map_err(PlatformError::of("the app's sweeps"))?;
    let bound = bound(&sweeps, runners(parts)?).map_err(PlatformError::of("the sweeps"))?;
    let claims: Arc<dyn SweepClaims> =
        Arc::new(PgSweepClaims::new(Arc::clone(&parts.platform.databases)));
    let scheduler = Scheduler {
        claims: ClaimDueUseCase::new(ClaimDuePorts { claims }, sweeps),
        bound,
        auditor: parts.system_auditor(),
        tick: parts.config.worker.sweeps.tick,
    };
    let stop = shutdown.clone();
    shutdown.spawn("the sweep scheduler", scheduler.run(stop));
    Ok(())
}

/// Claims the sweeps' rounds on each tick and runs those won.
struct Scheduler {
    claims: ClaimDueUseCase,
    bound: HashMap<SweepName, Bound>,
    auditor: RequestAuditor,
    tick: Duration,
}

impl Scheduler {
    /// Ticks until `shutdown` stops it, then waits for the runs in hand,
    /// for as long as the stop's grace allows.
    async fn run(self, shutdown: Shutdown) {
        let mut ticks = tokio::time::interval(self.tick);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut running = Runs::default();
        loop {
            tokio::select! {
                () = shutdown.stopping() => break,
                _ = ticks.tick() => self.round(&mut running, clock::now()).await,
                Some(ended) = running.tasks.join_next(), if !running.tasks.is_empty() => {
                    running.finish(ended);
                }
            }
        }
        while let Some(ended) = running.tasks.join_next().await {
            running.finish(ended);
        }
    }

    /// Claims the rounds due at `now` and starts each sweep won that is not
    /// still running here.
    async fn round(&self, running: &mut Runs, now: OffsetDateTime) {
        let won = match self.claims.execute(&(), &self.auditor, now).await {
            Ok(won) => won,
            Err(error) => {
                tracing::warn!(%error, "the sweeps' rounds could not be claimed; the next tick tries again");
                return;
            }
        };
        for name in won {
            let Some(bound) = self.bound.get(&name) else {
                continue;
            };
            if !running.names.insert(name.clone()) {
                tracing::warn!(sweep = %name, "a sweep's round came while its last one still ran here; the round is left");
                continue;
            }
            let run = Bound {
                runner: Arc::clone(&bound.runner),
                period: bound.period,
            };
            let auditor = self.auditor.clone();
            running.tasks.spawn(ran(name, run, auditor, now));
        }
    }
}

/// The sweeps running here, by name, and their tasks.
#[derive(Default)]
struct Runs {
    names: HashSet<SweepName>,
    tasks: JoinSet<SweepName>,
}

impl Runs {
    /// Forgets the run that ended, so its sweep's next round may run.
    fn finish(&mut self, ended: Result<SweepName, tokio::task::JoinError>) {
        match ended {
            Ok(name) => {
                self.names.remove(&name);
            }
            Err(error) => {
                tracing::error!(%error, "a sweep's run panicked");
                self.names.clear();
            }
        }
    }
}

/// Runs one round of `name`, held to its bound period, logs how it went, and
/// answers the name for the scheduler to forget it.
async fn ran(
    name: SweepName,
    run: Bound,
    auditor: RequestAuditor,
    now: OffsetDateTime,
) -> SweepName {
    match tokio::time::timeout(run.period, run.runner.run(&auditor, now)).await {
        Ok(Ok(came_to)) => tracing::debug!(sweep = %name, %came_to, "a sweep ran"),
        Ok(Err(error)) if error.is_server_error() => {
            tracing::error!(sweep = %name, %error, "a sweep failed; its next round tries again");
        }
        Ok(Err(error)) => {
            tracing::warn!(sweep = %name, %error, "a sweep was refused; its next round tries again");
        }
        Err(_) => tracing::warn!(
            sweep = %name,
            "a sweep ran past its period and was stopped; its next round goes on from what is due"
        ),
    }
    name
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use ianua_app::ports::shared::EventDispatcher;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::events::event::DomainEvent;

    use super::*;

    /// A dispatcher that keeps nothing: the tests' sweeps record nothing.
    struct Silent;

    #[async_trait]
    impl EventDispatcher for Silent {
        async fn dispatch(
            &self,
            _events: &[DomainEvent],
            _ctx: &AuditContext,
        ) -> Result<(), DomainError> {
            Ok(())
        }
    }

    /// A runner standing in for a sweep's use case, counting its runs.
    struct Counting {
        runs: &'static str,
        ran: Arc<AtomicU32>,
    }

    #[async_trait]
    impl SweepRun for Counting {
        fn runs(&self) -> &'static str {
            self.runs
        }

        async fn run(
            &self,
            _auditor: &RequestAuditor,
            _now: OffsetDateTime,
        ) -> Result<String, AppError> {
            self.ran.fetch_add(1, Ordering::SeqCst);
            Ok(String::new())
        }
    }

    /// Claims kept in memory, shared by every scheduler of a test, the
    /// first claim of a round winning it.
    #[derive(Default)]
    struct SharedClaims(Mutex<HashSet<(String, String)>>);

    #[async_trait]
    impl SweepClaims for SharedClaims {
        async fn claim(
            &self,
            sweep: &SweepName,
            round: ianua_domain::domains::scheduling::sweep::SweepRound,
        ) -> Result<bool, DomainError> {
            let mut held = self
                .0
                .lock()
                .map_err(|_| DomainError::infra_msg("poisoned"))?;
            Ok(held.insert((sweep.to_string(), format!("{round:?}"))))
        }
    }

    fn app_sweeps() -> Vec<Sweep> {
        sweeps().unwrap()
    }

    fn counting(sweeps: &[Sweep], ran: &Arc<AtomicU32>) -> Vec<Arc<dyn SweepRun>> {
        sweeps
            .iter()
            .map(|sweep| {
                Arc::new(Counting {
                    runs: sweep.runs(),
                    ran: Arc::clone(ran),
                }) as Arc<dyn SweepRun>
            })
            .collect()
    }

    fn scheduler(claims: Arc<dyn SweepClaims>, ran: &Arc<AtomicU32>) -> Scheduler {
        let sweeps = app_sweeps();
        Scheduler {
            bound: bound(&sweeps, counting(&sweeps, ran)).unwrap(),
            claims: ClaimDueUseCase::new(ClaimDuePorts { claims }, sweeps),
            auditor: RequestAuditor::system(Arc::new(Silent)),
            tick: Duration::from_secs(15),
        }
    }

    fn noon() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    async fn round_of(scheduler: &Scheduler) {
        let mut running = Runs::default();
        scheduler.round(&mut running, noon()).await;
        while let Some(ended) = running.tasks.join_next().await {
            running.finish(ended);
        }
    }

    /// A runner for each of the app's sweeps binds every one of them.
    #[test]
    fn a_runner_for_each_sweep_binds_them_all() {
        let sweeps = app_sweeps();
        let ran = Arc::new(AtomicU32::new(0));

        let bound = bound(&sweeps, counting(&sweeps, &ran)).unwrap();

        assert_eq!(bound.len(), sweeps.len());
    }

    /// Removing a runner makes schedule binding fail with the name of the
    /// sweep that would otherwise have no runner.
    #[test]
    fn a_sweep_without_a_runner_refuses_the_start() {
        let sweeps = app_sweeps();
        let ran = Arc::new(AtomicU32::new(0));
        let mut runners = counting(&sweeps, &ran);
        let left_out = runners.remove(0);

        let refused = bound(&sweeps, runners).err();

        assert!(matches!(
            refused,
            Some(ScheduleError::Unrun(name)) if sweeps[0].runs() == left_out.runs() && name == sweeps[0].name().to_string()
        ));
    }

    /// Adding a second runner for one use case makes schedule binding fail
    /// with a duplicate runner error.
    #[test]
    fn a_doubled_runner_refuses_the_start() {
        let sweeps = app_sweeps();
        let ran = Arc::new(AtomicU32::new(0));
        let mut runners = counting(&sweeps, &ran);
        runners.push(Arc::clone(&runners[0]));

        assert!(matches!(
            bound(&sweeps, runners),
            Err(ScheduleError::Doubled(_))
        ));
    }

    /// Two workers tick at the same moment over one claim store: every
    /// sweep's round runs once between them, not twice.
    #[tokio::test]
    async fn a_round_runs_once_across_two_schedulers() {
        let claims: Arc<dyn SweepClaims> = Arc::new(SharedClaims::default());
        let ran = Arc::new(AtomicU32::new(0));
        let first = scheduler(Arc::clone(&claims), &ran);
        let second = scheduler(claims, &ran);

        tokio::join!(round_of(&first), round_of(&second));

        let sweeps = u32::try_from(app_sweeps().len()).unwrap();
        assert_eq!(ran.load(Ordering::SeqCst), sweeps);
    }

    /// A sweep already marked as running keeps that marker and skips its
    /// new round while every other due sweep runs.
    #[tokio::test]
    async fn a_round_is_left_while_the_last_still_runs_here() {
        let ran = Arc::new(AtomicU32::new(0));
        let claims: Arc<dyn SweepClaims> = Arc::new(SharedClaims::default());
        let scheduler = scheduler(claims, &ran);
        let mut running = Runs::default();
        let name = app_sweeps()[0].name().clone();
        running.names.insert(name.clone());

        scheduler.round(&mut running, noon()).await;
        while let Some(ended) = running.tasks.join_next().await {
            running.finish(ended);
        }

        let sweeps = u32::try_from(app_sweeps().len()).unwrap();
        assert_eq!(ran.load(Ordering::SeqCst), sweeps - 1);
        assert!(running.names.contains(&name));
    }
}
