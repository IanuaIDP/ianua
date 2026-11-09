//! What a tenant's decoy and recon stages ask of a request before any route
//! is matched.
//!
//! A scanner asking for `/.env` matches no real route, so no pipeline has
//! been chosen yet. The decoys and the recon window are therefore read
//! across every running pipeline of the tenant, and the strictest answer
//! wins: the longest block, the widest window.

use crate::domains::proxy::pipeline::Pipeline;
use crate::domains::proxy::stages::stage::{DecoyLifetime, ReconWindow, StageKind};
use crate::isolation::scope::TenantScope;
use crate::types::CanonicalPath;

impl<T: TenantScope> Pipeline<T> {
    /// How long a client asking for `path` is blocked, when one of this
    /// pipeline's enabled decoy stages lists it. `None` when none does.
    ///
    /// Two decoy stages listing the same path answer with the longer block.
    #[must_use]
    pub fn decoy_lifetime(&self, path: &CanonicalPath) -> Option<DecoyLifetime> {
        self.active_stages()
            .into_iter()
            .filter_map(|stage| {
                let StageKind::HoneypotRoutes(config) = stage.kind() else {
                    return None;
                };
                config.catches(path).then(|| config.lifetime())
            })
            .max()
    }

    /// The recon scoring window of this pipeline's enabled recon stages.
    /// `None` when it has none.
    ///
    /// Two recon stages answer with the wider window, which gathers the most
    /// signals.
    #[must_use]
    pub fn recon_window(&self) -> Option<ReconWindow> {
        self.active_stages()
            .into_iter()
            .filter_map(|stage| {
                let StageKind::ReconDetection(config) = stage.kind() else {
                    return None;
                };
                Some(config.window())
            })
            .max()
    }

    /// How long a client asking for `path` is blocked, across `pipelines`.
    /// `None` when no running pipeline calls it a decoy.
    ///
    /// `pipelines` are every pipeline of one tenant. Only active ones count:
    /// a draft or switched-off pipeline serves no traffic, so its decoys are
    /// not yet, or no longer, set out. The longest block any of them asks
    /// for is the one applied.
    #[must_use]
    pub fn decoy_lifetime_across<'a>(
        pipelines: impl IntoIterator<Item = &'a Self>,
        path: &CanonicalPath,
    ) -> Option<DecoyLifetime>
    where
        T: 'a,
    {
        pipelines
            .into_iter()
            .filter(|pipeline| pipeline.status().is_active())
            .filter_map(|pipeline| pipeline.decoy_lifetime(path))
            .max()
    }

    /// The recon scoring window across `pipelines`. `None` when no running
    /// pipeline scores recon.
    ///
    /// `pipelines` are every pipeline of one tenant. Only active ones count.
    /// Recon is scored per tenant, since a request that matched no route
    /// belongs to no pipeline, and the widest window asked for is the one
    /// used.
    #[must_use]
    pub fn recon_window_across<'a>(
        pipelines: impl IntoIterator<Item = &'a Self>,
    ) -> Option<ReconWindow>
    where
        T: 'a,
    {
        pipelines
            .into_iter()
            .filter(|pipeline| pipeline.status().is_active())
            .filter_map(Self::recon_window)
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::proxy::fixtures::{running, stage, switched_off, with_status};
    use crate::domains::proxy::pipeline_status::PipelineStatus;
    use crate::domains::proxy::stages::stage::{HoneypotConfig, ReconDetectionConfig};
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::Seconds;

    fn path(raw: &str) -> CanonicalPath {
        CanonicalPath::new(raw).unwrap()
    }

    fn decoys(paths: &[&str], block_ttl_seconds: u32) -> StageKind {
        StageKind::HoneypotRoutes(HoneypotConfig {
            paths: paths.iter().map(|raw| path(raw)).collect(),
            block_ttl_seconds: Seconds::new(block_ttl_seconds),
        })
    }

    fn recon(window_seconds: u32) -> StageKind {
        StageKind::ReconDetection(ReconDetectionConfig {
            window_seconds: Seconds::new(window_seconds),
            min_requests: 10,
            error_ratio_threshold: 0.5,
            distinct_path_threshold: 50,
            auth_failure_threshold: 10,
            tarpit_signal_count: 1,
            block_signal_count: 3,
            tarpit_delay_ms: 2000,
        })
    }

    /// A valid block duration for comparison with the chosen decoy stage.
    fn lifetime(seconds: u32) -> DecoyLifetime {
        DecoyLifetime::new(Seconds::new(seconds)).unwrap()
    }

    /// A valid scoring window for comparison with the chosen recon stage.
    fn window(seconds: u32) -> ReconWindow {
        ReconWindow::new(Seconds::new(seconds)).unwrap()
    }

    /// A pipeline listing `/.env` as a decoy blocks a client asking for it
    /// for an hour. `/api/users` is no decoy.
    #[test]
    fn a_listed_path_is_a_decoy() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![stage(decoys(&["/.env"], 3600))]);

        assert_eq!(
            pipeline.decoy_lifetime(&path("/.env")),
            Some(lifetime(3600))
        );
        assert_eq!(pipeline.decoy_lifetime(&path("/api/users")), None);
    }

    /// Two decoy stages both list `/.env`, one blocking an hour and one a
    /// day. The day applies.
    #[test]
    fn two_decoy_stages_answer_with_the_longer_block() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![
            stage(decoys(&["/.env"], 3600)),
            stage(decoys(&["/.env"], 86_400)),
        ]);

        assert_eq!(
            pipeline.decoy_lifetime(&path("/.env")),
            Some(lifetime(86_400))
        );
    }

    /// A switched-off decoy stage catches nothing.
    #[test]
    fn a_switched_off_decoy_stage_catches_nothing() {
        let pipeline: Pipeline<ResolvedTenant> =
            running(vec![switched_off(decoys(&["/.env"], 3600))]);

        assert_eq!(pipeline.decoy_lifetime(&path("/.env")), None);
    }

    /// Across a tenant's pipelines, the longest block for `/.env` among the
    /// running ones applies. A draft one asking for a week does not count.
    #[test]
    fn across_pipelines_the_longest_running_block_applies() {
        let pipelines: Vec<Pipeline<ResolvedTenant>> = vec![
            running(vec![stage(decoys(&["/.env"], 3600))]),
            running(vec![stage(decoys(&["/.env", "/.git/config"], 7200))]),
            with_status(
                PipelineStatus::Draft,
                vec![stage(decoys(&["/.env"], 604_800))],
            ),
        ];

        assert_eq!(
            Pipeline::decoy_lifetime_across(&pipelines, &path("/.env")),
            Some(lifetime(7200))
        );
        assert_eq!(
            Pipeline::decoy_lifetime_across(&pipelines, &path("/robots.txt")),
            None
        );
    }

    /// A switched-off pipeline's decoys are no longer set out.
    #[test]
    fn a_disabled_pipeline_sets_out_no_decoys() {
        let pipelines: Vec<Pipeline<ResolvedTenant>> = vec![with_status(
            PipelineStatus::Disabled,
            vec![stage(decoys(&["/.env"], 3600))],
        )];

        assert_eq!(
            Pipeline::decoy_lifetime_across(&pipelines, &path("/.env")),
            None
        );
    }

    /// A pipeline with a one-minute recon stage scores over a minute. One
    /// with none scores nothing.
    #[test]
    fn a_recon_stage_sets_the_window() {
        let scoring: Pipeline<ResolvedTenant> = running(vec![stage(recon(60))]);
        let silent: Pipeline<ResolvedTenant> = running(Vec::new());

        assert_eq!(scoring.recon_window(), Some(window(60)));
        assert_eq!(silent.recon_window(), None);
    }

    /// Two recon stages in one pipeline, a minute and an hour. The hour
    /// applies.
    #[test]
    fn two_recon_stages_answer_with_the_wider_window() {
        let pipeline: Pipeline<ResolvedTenant> =
            running(vec![stage(recon(60)), stage(recon(3600))]);

        assert_eq!(pipeline.recon_window(), Some(window(3600)));
    }

    /// Across a tenant's pipelines, the widest running window applies. A
    /// switched-off pipeline and a switched-off stage do not count.
    #[test]
    fn across_pipelines_the_widest_running_window_applies() {
        let pipelines: Vec<Pipeline<ResolvedTenant>> = vec![
            running(vec![stage(recon(60))]),
            running(vec![switched_off(recon(86_400))]),
            with_status(PipelineStatus::Disabled, vec![stage(recon(43_200))]),
            running(vec![stage(recon(600))]),
        ];

        assert_eq!(Pipeline::recon_window_across(&pipelines), Some(window(600)));
    }

    /// A tenant with no running pipeline scores no recon.
    #[test]
    fn no_running_pipeline_scores_no_recon() {
        let pipelines: Vec<Pipeline<ResolvedTenant>> = Vec::new();

        assert_eq!(Pipeline::recon_window_across(&pipelines), None);
    }
}
