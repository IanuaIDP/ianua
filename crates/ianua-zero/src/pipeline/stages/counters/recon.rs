//! The ReconDetection stage: scoring a client on the shape of scanning, a
//! client whose requests mostly fail, that walks many distinct paths, or
//! that fails to sign in again and again, even while it stays under every
//! rate limit.
//!
//! Recon is scored per tenant, over the domain's recon window across the
//! tenant's pipelines, since a scan asks mostly for paths no route matches.
//! Every finished request is counted, refused or not, with the status it
//! ended on; the stage scores what the fleet counted in the current window
//! and slows or blocks the client.

use std::net::IpAddr;
use std::time::Duration;

use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::{ReconDetectionConfig, ReconWindow};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DenialStatus, Seconds, TenantId};

use super::keys::{FixedWindow, client_address};
use super::{CounterStages, passed, refused, unavailable, unknown_client};

/// How long a client recon scoring blocked stays flagged for the tenants
/// that refuse flagged addresses. A platform setting rather than a tenant's:
/// it protects tenants from each other, so no one tenant owns it.
const RECON_FLAG: Seconds = Seconds::new(3_600);

/// The longest prefix of a path remembered when counting distinct paths. A
/// path is chosen by the client and unbounded; a prefix answers the only
/// question asked of it, whether it differs from the others.
const TRACKED_PATH_LEN: usize = 256;

/// What the recon stage needs to know about a request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReconProbe<'a> {
    /// The path as the client sent it.
    pub path: &'a str,
    /// The tenant's recon window, from the domain's
    /// `Pipeline::recon_window_across`.
    pub window: ReconWindow,
}

/// A finished request, as recon counts it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReconOutcome<'a> {
    /// The tenant the request was for.
    pub tenant: TenantId,
    /// The client's address.
    pub client: IpAddr,
    /// The path as the client sent it.
    pub path: &'a str,
    /// The status the request ended on, whether the upstream or the gateway
    /// answered.
    pub status: u16,
    /// The tenant's recon window, from the domain's
    /// `Pipeline::recon_window_across`.
    pub window: ReconWindow,
}

/// The counters one client's window is scored on.
struct ReconKeys {
    total: String,
    refusals: String,
    auth_failures: String,
    paths: String,
}

impl ReconKeys {
    fn of(tenant: TenantId, client: IpAddr, window: ReconWindow) -> Self {
        let index = FixedWindow::at(window.seconds(), clock::now()).index();
        let key = |signal: &str| format!("recon:{tenant}:{client}:{index}:{signal}");
        Self {
            total: key("total"),
            refusals: key("refusals"),
            auth_failures: key("auth"),
            paths: key("paths"),
        }
    }
}

/// What the fleet counted for one client in the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Signals {
    total: u32,
    refusals: u32,
    auth_failures: u32,
    paths: u32,
}

/// What a client's window calls for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconVerdict {
    Clean,
    Tarpit,
    Block,
}

/// What a finished request's status says to recon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// Not found or forbidden: what probing for paths runs into.
    Refused,
    /// Not signed in: what guessing credentials runs into.
    AuthFailed,
    Other,
}

impl Ending {
    fn of(status: u16) -> Self {
        match status {
            403 | 404 => Self::Refused,
            401 => Self::AuthFailed,
            _ => Self::Other,
        }
    }
}

impl CounterStages {
    /// Scores the client on what the fleet counted in its current recon
    /// window, and slows the request or refuses it once enough signals
    /// tripped. A block also flags the client for the tenants that refuse
    /// flagged addresses.
    ///
    /// # Errors
    ///
    /// Never; the `Result` keeps the shape every stage has.
    pub(crate) async fn recon(
        &self,
        config: &ReconDetectionConfig,
        probe: ReconProbe<'_>,
        ctx: &PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let Some(client) = client_address(ctx) else {
            return Ok(unknown_client());
        };
        let keys = ReconKeys::of(ctx.tenant_id, client, probe.window);
        let length = probe.window.seconds();
        let Some(signals) = self.within(self.signals(&keys, probe.path, length)).await else {
            return Ok(unavailable());
        };
        match verdict(signals, config) {
            ReconVerdict::Clean => Ok(passed("no recon signal tripped")),
            ReconVerdict::Tarpit => Ok(self.tarpit(config).await),
            ReconVerdict::Block => {
                self.flag(client, RECON_FLAG).await;
                Ok(scanning())
            }
        }
    }

    /// Counts a finished request for recon scoring. A count that fails is
    /// logged: the request has already been answered.
    pub(crate) async fn record_recon(&self, outcome: ReconOutcome<'_>) {
        let keys = ReconKeys::of(outcome.tenant, outcome.client, outcome.window);
        let counted = self.count_outcome(&keys, &outcome);
        if self.within(counted).await.is_none() {
            tracing::warn!("a finished request was not counted for recon");
        }
    }

    /// Reads the client's counts, adding this request's path to its
    /// distinct paths.
    async fn signals(&self, keys: &ReconKeys, path: &str, length: Seconds) -> Option<Signals> {
        let paths = [tracked(path)];
        let (total, refusals, auth_failures, distinct) = tokio::join!(
            self.fleet.add(&keys.total, 0, length),
            self.fleet.add(&keys.refusals, 0, length),
            self.fleet.add(&keys.auth_failures, 0, length),
            self.fleet.add_distinct(&keys.paths, &paths, length),
        );
        Some(Signals {
            total: total?,
            refusals: refusals?,
            auth_failures: auth_failures?,
            paths: distinct?,
        })
    }

    async fn count_outcome(&self, keys: &ReconKeys, outcome: &ReconOutcome<'_>) -> Option<()> {
        let length = outcome.window.seconds();
        let paths = [tracked(outcome.path)];
        let (total, distinct, ending) = tokio::join!(
            self.fleet.count(&keys.total, length),
            self.fleet.add_distinct(&keys.paths, &paths, length),
            self.count_ending(keys, Ending::of(outcome.status), length),
        );
        total?;
        distinct?;
        ending
    }

    async fn count_ending(&self, keys: &ReconKeys, ending: Ending, length: Seconds) -> Option<()> {
        let key = match ending {
            Ending::Refused => &keys.refusals,
            Ending::AuthFailed => &keys.auth_failures,
            Ending::Other => return Some(()),
        };
        self.fleet.count(key, length).await.map(|_| ())
    }

    /// Holds the request for the configured delay before letting it on. At
    /// most a bounded number are held at once, so slowing scanners cannot
    /// tie up the gateway; past that the request is refused instead.
    async fn tarpit(&self, config: &ReconDetectionConfig) -> StageDecision {
        let Ok(_held) = self.tarpits.try_acquire() else {
            return refused(
                DenialStatus::TOO_MANY_REQUESTS,
                "automated scanning suspected",
            );
        };
        tokio::time::sleep(Duration::from_millis(u64::from(config.tarpit_delay_ms))).await;
        passed("slowed down: automated scanning suspected")
    }
}

fn scanning() -> StageDecision {
    refused(DenialStatus::FORBIDDEN, "automated scanning detected")
}

/// The part of a path recon remembers.
fn tracked(path: &str) -> String {
    let mut end = path.len().min(TRACKED_PATH_LEN);
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    path[..end].to_owned()
}

/// What `signals` call for under `config`.
fn verdict(signals: Signals, config: &ReconDetectionConfig) -> ReconVerdict {
    let tripped = tripped(signals, config);
    if tripped >= config.block_signal_count {
        return ReconVerdict::Block;
    }
    if tripped >= config.tarpit_signal_count {
        return ReconVerdict::Tarpit;
    }
    ReconVerdict::Clean
}

/// How many of the three signals tripped.
fn tripped(signals: Signals, config: &ReconDetectionConfig) -> u8 {
    let refusal_ratio = signals.total >= config.min_requests
        && f64::from(signals.refusals) / f64::from(signals.total.max(1))
            >= f64::from(config.error_ratio_threshold);
    let walked = signals.paths >= config.distinct_path_threshold;
    let guessed = signals.auth_failures >= config.auth_failure_threshold;
    [refusal_ratio, walked, guessed]
        .into_iter()
        .map(u8::from)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::super::fakes::{Rig, context, denial_status};
    use super::*;

    fn config() -> ReconDetectionConfig {
        ReconDetectionConfig {
            window_seconds: Seconds::new(3_600),
            min_requests: 4,
            error_ratio_threshold: 0.5,
            distinct_path_threshold: 50,
            auth_failure_threshold: 3,
            tarpit_signal_count: 1,
            block_signal_count: 2,
            tarpit_delay_ms: 2_000,
        }
    }

    fn window() -> ReconWindow {
        ReconWindow::new(Seconds::new(3_600)).unwrap()
    }

    fn probe(path: &str) -> ReconProbe<'_> {
        ReconProbe {
            path,
            window: window(),
        }
    }

    fn finished<'a>(ctx: &PipelineContext, path: &'a str, status: u16) -> ReconOutcome<'a> {
        ReconOutcome {
            tenant: ctx.tenant_id,
            client: client_address(ctx).unwrap(),
            path,
            status,
            window: window(),
        }
    }

    fn signals(total: u32, refusals: u32, auth_failures: u32, paths: u32) -> Signals {
        Signals {
            total,
            refusals,
            auth_failures,
            paths,
        }
    }

    /// A finished 404 is counted as a request, a refusal and a path, on the
    /// counters every instance shares.
    #[tokio::test]
    async fn a_finished_request_is_counted_on_the_shared_counters() {
        let rig = Rig::counting();
        let ctx = context();

        rig.stages()
            .record_recon(finished(&ctx, "/admin", 404))
            .await;

        assert_eq!(rig.fleet.total_under(":total"), 1);
        assert_eq!(rig.fleet.total_under(":refusals"), 1);
        assert_eq!(rig.fleet.total_under(":auth"), 0);
        assert_eq!(rig.fleet.distinct_under(":paths"), 1);
    }

    /// A client whose four requests were all refused and who failed to sign
    /// in three times tripped two signals, and is blocked.
    #[tokio::test]
    async fn a_scanner_is_blocked() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let ctx = context();
        for path in ["/a", "/b", "/c", "/d"] {
            stages.record_recon(finished(&ctx, path, 404)).await;
        }
        for _ in 0..3 {
            stages.record_recon(finished(&ctx, "/login", 401)).await;
        }

        let decision = stages.recon(&config(), probe("/e"), &ctx).await.unwrap();

        assert_eq!(denial_status(&decision), Some(403));
    }

    /// A client with one tripped signal is slowed down, then let on.
    #[tokio::test(start_paused = true)]
    async fn a_suspect_is_slowed_then_let_on() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let ctx = context();
        for path in ["/a", "/b", "/c", "/d"] {
            stages.record_recon(finished(&ctx, path, 404)).await;
        }
        let started = tokio::time::Instant::now();

        let decision = stages.recon(&config(), probe("/e"), &ctx).await.unwrap();

        assert!(!decision.is_terminal());
        assert!(started.elapsed() >= Duration::from_millis(2_000));
    }

    /// A client whose requests were answered is clean.
    #[tokio::test]
    async fn an_ordinary_client_passes() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let ctx = context();
        for path in ["/a", "/b", "/c", "/d"] {
            stages.record_recon(finished(&ctx, path, 200)).await;
        }

        let decision = stages.recon(&config(), probe("/e"), &ctx).await.unwrap();

        assert!(!decision.is_terminal());
    }

    /// Unavailable reconnaissance counters produce a 503 denial.
    #[tokio::test]
    async fn unreadable_counts_refuse() {
        let rig = Rig::unreachable();

        let decision = rig
            .stages()
            .recon(&config(), probe("/e"), &context())
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(503));
    }

    /// One refusal is not a ratio: below the minimum number of requests the
    /// refusal signal does not trip.
    #[test]
    fn too_few_requests_trip_no_refusal_signal() {
        assert_eq!(tripped(signals(1, 1, 0, 1), &config()), 0);
        assert_eq!(tripped(signals(4, 2, 0, 4), &config()), 1);
    }

    /// Each signal counts once, and enough of them block.
    #[test]
    fn every_signal_counts_toward_the_verdict() {
        let walked = verdict(signals(4, 0, 0, 50), &config());
        let caught = verdict(signals(4, 4, 3, 50), &config());
        let quiet = verdict(signals(4, 0, 0, 4), &config());

        assert_eq!(walked, ReconVerdict::Tarpit);
        assert_eq!(caught, ReconVerdict::Block);
        assert_eq!(quiet, ReconVerdict::Clean);
    }

    /// A path past the tracked length is cut to it, on a character
    /// boundary.
    #[test]
    fn a_long_path_is_cut_on_a_character_boundary() {
        let path = format!("/{}", "é".repeat(200));

        let kept = tracked(&path);

        assert!(kept.len() <= TRACKED_PATH_LEN);
        assert!(path.starts_with(&kept));
    }
}
