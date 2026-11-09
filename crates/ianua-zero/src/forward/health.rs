//! Asking each backend whether it is well, on the service's schedule.
//!
//! Every probed service has one task, started when the service appears,
//! restarted when its pool is rebuilt and stopped when it goes or stops
//! being probed, so a service created after start is probed like one that
//! was there before. Probes across every service share one bound on how
//! many are in flight, and each is held to its service's probe timeout. A
//! probe is sent like any request to a backend: through the screen, with
//! the service's own TLS, and never following a redirect.
//!
//! A backend is marked down after the service's number of failed probes in
//! a row, and up again after its number of passed ones.
//!
//! After each round the service's verdicts are reported through the app's
//! [`BackendHealthReports`], good for a few probe intervals, so the API
//! shows each backend's live health and shows "unknown" once this gateway
//! stops reporting. A report that cannot be made in time is logged and
//! dropped; probing and routing never wait on it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ianua_app::ports::routing::{
    BackendHealth, BackendHealthReports, BackendVerdict, ServiceHealthReport,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::routing::backend::health_check::ActiveHealthCheck;
use ianua_domain::types::{ServiceId, TenantId};
use tokio::sync::Semaphore;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use super::pool::{Member, Probed, ServicePool};
use super::settings::ProbeSettings;
use super::{locked, period, semaphore};

/// A service's pool, as one tenant's.
type PoolKey = (TenantId, ServiceId);

/// How many probe intervals a report stays good for: one missed round is
/// not a gateway gone.
const REPORT_INTERVALS: u32 = 3;

/// The longest one report may take to be kept.
const REPORT_TIMEOUT: Duration = Duration::from_secs(2);

/// The health-check task of every probed service.
pub(crate) struct HealthChecks {
    root: CancellationToken,
    probes: Arc<Semaphore>,
    reports: Arc<dyn BackendHealthReports>,
    running: Mutex<HashMap<PoolKey, Running>>,
}

/// A probe task, and the pool it probes.
struct Running {
    cancel: CancellationToken,
    pool: Arc<ServicePool>,
}

impl HealthChecks {
    /// Health checks that all stop when `root` is cancelled, holding probes
    /// in flight to `settings`, each round's verdicts reported to
    /// `reports`.
    #[must_use]
    pub(crate) fn new(
        root: CancellationToken,
        settings: ProbeSettings,
        reports: Arc<dyn BackendHealthReports>,
    ) -> Self {
        Self {
            root,
            probes: semaphore(settings.max_in_flight),
            reports,
            running: Mutex::new(HashMap::new()),
        }
    }

    /// How many services are being probed.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn running_count(&self) -> usize {
        locked(&self.running).len()
    }

    /// Brings one tenant's probes in line with `pools`: a pool that is gone,
    /// rebuilt or no longer probed has its task stopped, and a probed pool
    /// without one gets one. Other tenants' probes are left alone.
    pub(super) fn reconcile_tenant(
        &self,
        tenant_id: TenantId,
        pools: &[(ServiceId, Arc<ServicePool>)],
    ) {
        let mut running = locked(&self.running);
        stop_changed(&mut running, tenant_id, pools);
        self.start_missing(&mut running, tenant_id, pools);
    }

    /// Stops every probe of a tenant.
    pub(super) fn drop_tenant(&self, tenant_id: TenantId) {
        stop_changed(&mut locked(&self.running), tenant_id, &[]);
    }

    /// Starts a task for each probed pool of `tenant_id` that has none.
    fn start_missing(
        &self,
        running: &mut HashMap<PoolKey, Running>,
        tenant_id: TenantId,
        pools: &[(ServiceId, Arc<ServicePool>)],
    ) {
        for (service_id, pool) in pools {
            let key = (tenant_id, *service_id);
            if running.contains_key(&key) {
                continue;
            }
            let Some(check) = pool.active_check().cloned() else {
                continue;
            };
            let cancel = self.root.child_token();
            let probes = Arc::clone(&self.probes);
            let reporter = Reporter {
                tenant: ScopedTenant::for_background(tenant_id),
                service_id: *service_id,
                reports: Arc::clone(&self.reports),
                valid_for: check
                    .interval_secs()
                    .std_duration()
                    .saturating_mul(REPORT_INTERVALS),
            };
            tokio::spawn(watch(
                Arc::clone(pool),
                check,
                Watching { probes, reporter },
                cancel.clone(),
            ));
            let pool = Arc::clone(pool);
            running.insert(key, Running { cancel, pool });
        }
    }
}

/// Stops the tasks of `tenant_id` whose pool is not among `pools`, the
/// very same pool, still probed.
fn stop_changed(
    running: &mut HashMap<PoolKey, Running>,
    tenant_id: TenantId,
    pools: &[(ServiceId, Arc<ServicePool>)],
) {
    running.retain(|(tenant, service), current| {
        if *tenant != tenant_id {
            return true;
        }
        let kept = pools.iter().any(|(id, pool)| {
            id == service && Arc::ptr_eq(pool, &current.pool) && pool.active_check().is_some()
        });
        if !kept {
            current.cancel.cancel();
        }
        kept
    });
}

/// What a probe task shares with the others, and where it reports.
struct Watching {
    probes: Arc<Semaphore>,
    reporter: Reporter,
}

/// Where one service's verdicts are reported, and for how long each
/// report is good.
pub(super) struct Reporter {
    /// The tenant whose service it is.
    pub(super) tenant: ScopedTenant,
    /// The upstream identity whose backend verdicts these reports update.
    pub(super) service_id: ServiceId,
    /// Where its reports go.
    pub(super) reports: Arc<dyn BackendHealthReports>,
    /// How long each report is good for.
    pub(super) valid_for: Duration,
}

impl Reporter {
    /// Reports `members`' verdicts as `tally` holds them, giving up after
    /// [`REPORT_TIMEOUT`].
    pub(super) async fn report(&self, members: &[Arc<Member>], tally: &Tally) {
        let report = ServiceHealthReport {
            service_id: self.service_id,
            backends: members
                .iter()
                .map(|member| BackendHealth {
                    backend: member.url().clone(),
                    verdict: verdict_of(tally.verdict(member.url().as_str())),
                })
                .collect(),
            observed_at: ianua_domain::shared::clock::now(),
        };
        let kept = self.reports.report(&self.tenant, &report, self.valid_for);
        match tokio::time::timeout(REPORT_TIMEOUT, kept).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "backend health was not reported"),
            Err(_) => tracing::warn!("backend health was not reported in time"),
        }
    }
}

/// The verdict a report carries for `probed`.
fn verdict_of(probed: Probed) -> BackendVerdict {
    match probed {
        Probed::Up => BackendVerdict::Up,
        Probed::Down => BackendVerdict::Down,
    }
}

/// Probes `pool` on `check`'s schedule until `cancel` fires, reporting
/// after each round.
async fn watch(
    pool: Arc<ServicePool>,
    check: ActiveHealthCheck,
    watching: Watching,
    cancel: CancellationToken,
) {
    let mut tally = Tally::default();
    let mut ticks = tokio::time::interval(period(check.interval_secs().std_duration()));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let round = async {
            ticks.tick().await;
            probe_round(&pool, &check, &watching.probes, &mut tally).await;
            watching.reporter.report(&pool.members(), &tally).await;
        };
        tokio::select! {
            () = cancel.cancelled() => return,
            () = round => {}
        }
    }
}

/// Probes each backend now in `pool` once, and marks those whose run of
/// results crossed a threshold.
pub(super) async fn probe_round(
    pool: &ServicePool,
    check: &ActiveHealthCheck,
    probes: &Semaphore,
    tally: &mut Tally,
) {
    let members = pool.members();
    tally.keep_only(&members);
    for member in members.iter() {
        let Ok(_permit) = probes.acquire().await else {
            return;
        };
        let probed = pool.probe(member, check).await;
        let Some(verdict) = tally.record(member.url().as_str(), probed, check) else {
            continue;
        };
        member.set_probed(verdict);
        announce(member, verdict);
    }
}

/// Logs a backend going down or coming back.
fn announce(member: &Member, verdict: Probed) {
    match verdict {
        Probed::Up => {
            tracing::info!(backend = %member.url(), "a backend passed its health checks");
        }
        Probed::Down => {
            tracing::warn!(backend = %member.url(), "a backend failed its health checks");
        }
    }
}

/// Each backend's run of probe results.
#[derive(Default)]
pub(super) struct Tally {
    runs: HashMap<String, Run>,
}

impl Tally {
    /// Forgets the backends no longer in `members`.
    fn keep_only(&mut self, members: &[Arc<Member>]) {
        self.runs.retain(|url, _| {
            members
                .iter()
                .any(|member| member.url().as_str() == url.as_str())
        });
    }

    /// The verdict held for `url`: up until its checks say otherwise.
    fn verdict(&self, url: &str) -> Probed {
        self.runs.get(url).map_or(Probed::Up, |run| run.verdict)
    }

    /// Counts `probed` for `url`, answering with the new verdict when the
    /// run crossed a threshold.
    fn record(&mut self, url: &str, probed: Probed, check: &ActiveHealthCheck) -> Option<Probed> {
        self.runs
            .entry(url.to_owned())
            .or_default()
            .record(probed, check)
    }
}

/// One backend's current verdict and the results against it in a row.
struct Run {
    verdict: Probed,
    in_a_row: u32,
}

impl Default for Run {
    /// A backend starts up: nothing is known against it.
    fn default() -> Self {
        Self {
            verdict: Probed::Up,
            in_a_row: 0,
        }
    }
}

impl Run {
    /// Counts `probed`, answering with the new verdict when it changed.
    fn record(&mut self, probed: Probed, check: &ActiveHealthCheck) -> Option<Probed> {
        if probed == self.verdict {
            self.in_a_row = 0;
            return None;
        }
        self.in_a_row = self.in_a_row.saturating_add(1);
        let needed = match probed {
            Probed::Up => check.healthy_threshold(),
            Probed::Down => check.unhealthy_threshold(),
        };
        if self.in_a_row < needed {
            return None;
        }
        self.in_a_row = 0;
        self.verdict = probed;
        Some(probed)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::backend::health_check::ActiveHealthCheckParams;
    use ianua_domain::types::{Seconds, UrlPath};

    use super::*;

    fn check(healthy: u32, unhealthy: u32) -> ActiveHealthCheck {
        ActiveHealthCheck::new(ActiveHealthCheckParams {
            path: UrlPath::new("/healthz").unwrap(),
            interval_secs: Seconds::new(10),
            timeout_secs: Seconds::new(1),
            healthy_threshold: healthy,
            unhealthy_threshold: unhealthy,
            panic_threshold_percent: 0,
        })
        .unwrap()
    }

    #[test]
    fn a_backend_is_marked_down_after_its_failures_in_a_row() {
        let check = check(2, 3);
        let mut run = Run::default();

        assert_eq!(run.record(Probed::Down, &check), None);
        assert_eq!(run.record(Probed::Down, &check), None);
        assert_eq!(run.record(Probed::Down, &check), Some(Probed::Down));
    }

    #[test]
    fn a_backend_is_marked_up_after_its_passes_in_a_row() {
        let check = check(2, 1);
        let mut run = Run::default();
        run.record(Probed::Down, &check);

        assert_eq!(run.record(Probed::Up, &check), None);
        assert_eq!(run.record(Probed::Up, &check), Some(Probed::Up));
    }

    #[test]
    fn a_pass_breaks_a_run_of_failures() {
        let check = check(2, 3);
        let mut run = Run::default();

        run.record(Probed::Down, &check);
        run.record(Probed::Down, &check);
        run.record(Probed::Up, &check);

        assert_eq!(run.record(Probed::Down, &check), None);
    }

    #[test]
    fn a_healthy_backend_passing_changes_nothing() {
        let check = check(2, 3);
        let mut run = Run::default();

        assert_eq!(run.record(Probed::Up, &check), None);
        assert_eq!(run.record(Probed::Up, &check), None);
    }
}
