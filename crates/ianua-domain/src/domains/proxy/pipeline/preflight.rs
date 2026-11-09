//! A browser's CORS preflight, answered before any stage runs.
//!
//! A preflight is the `OPTIONS` a browser sends on its own before a
//! cross-origin request, to ask whether it may send it. It carries no
//! credential, so the Identity stage would refuse it on every route that
//! is not public, and the browser would then never send the real request.
//! It grants nothing either: it reaches no upstream and lets nothing
//! through. So it is answered from the route's Cors settings alone, and the
//! real request that follows still runs every stage.

use crate::domains::proxy::pipeline::Pipeline;
use crate::domains::proxy::stages::checks::cors::{CorsAnswer, CorsRefusal, CorsRequest};
use crate::domains::proxy::stages::decision::HeaderEntry;
use crate::domains::proxy::stages::stage::{CorsConfig, StageKind};
use crate::isolation::scope::TenantScope;

/// What a pipeline does with a request before its stages run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightRule {
    /// Run every stage: the request is no preflight, or the pipeline has
    /// no Cors stage to answer one from.
    RunStages,
    /// Answer the preflight with these headers and an empty
    /// [`PREFLIGHT_STATUS`](crate::domains::proxy::stages::checks::cors::PREFLIGHT_STATUS)
    /// answer, and run no stage.
    Answer(Vec<HeaderEntry>),
    /// Refuse the preflight, and run no stage.
    Refuse(CorsRefusal),
}

impl<T: TenantScope> Pipeline<T> {
    /// What this pipeline does with `request` before its stages run.
    ///
    /// A preflight on a pipeline with enabled Cors stages is answered from
    /// the first in run order, and only when every one of them allows it:
    /// the real request must pass each of them, so a preflight one would
    /// refuse is refused. Anything else runs every stage.
    #[must_use]
    pub fn preflight(&self, request: &CorsRequest<'_>) -> PreflightRule {
        if !request.is_preflight() {
            return PreflightRule::RunStages;
        }
        let mut answers = self.cors_settings().map(|config| config.answer(request));
        let Some(first) = answers.next() else {
            return PreflightRule::RunStages;
        };
        if let Some(Err(refusal)) = answers.find(Result::is_err) {
            return PreflightRule::Refuse(refusal);
        }
        match first {
            Ok(CorsAnswer::Preflight(headers)) => PreflightRule::Answer(headers),
            Ok(CorsAnswer::NotCrossOrigin | CorsAnswer::Allowed(_)) => PreflightRule::RunStages,
            Err(refusal) => PreflightRule::Refuse(refusal),
        }
    }

    /// The settings of each enabled Cors stage, in run order.
    fn cors_settings(&self) -> impl Iterator<Item = &CorsConfig> {
        self.active_stages().into_iter().filter_map(|stage| {
            let StageKind::Cors(config) = stage.kind() else {
                return None;
            };
            Some(config)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::proxy::fixtures::{running, stage, switched_off};
    use crate::domains::proxy::stages::checks::cors::{PreflightAsk, SentOrigin};
    use crate::domains::proxy::stages::stage::CorsCredentials;
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{Fact, HeaderName, HttpMethod, Origin, Seconds};

    fn cors(origin: &str, methods: &[HttpMethod]) -> StageKind {
        StageKind::Cors(CorsConfig {
            allowed_origins: vec![Origin::new(origin).unwrap()],
            allowed_methods: methods.to_vec(),
            allowed_headers: vec![HeaderName::new("Content-Type").unwrap()],
            exposed_headers: Vec::new(),
            max_age_secs: Seconds::new(600),
            allow_credentials: CorsCredentials::Withheld,
        })
    }

    fn app() -> StageKind {
        cors("https://app.acme.com", &[HttpMethod::Get, HttpMethod::Post])
    }

    fn preflight_for(method: &'static str) -> CorsRequest<'static> {
        CorsRequest {
            method: HttpMethod::Options,
            origin: SentOrigin::One("https://app.acme.com"),
            preflight: PreflightAsk::Asks {
                method: Fact::Known(method),
                headers: vec![Fact::Known("content-type")],
            },
        }
    }

    /// Ann's page on `app.acme.com` asks whether it may `POST`. The
    /// pipeline answers from its Cors stage, before Identity, which would
    /// refuse a request carrying no credential.
    #[test]
    fn a_preflight_is_answered_before_any_stage_runs() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![stage(app())]);

        let rule = pipeline.preflight(&preflight_for("POST"));

        let PreflightRule::Answer(headers) = rule else {
            panic!("the preflight is answered");
        };
        assert!(
            headers
                .iter()
                .any(|header| header.name().as_str() == "access-control-allow-methods")
        );
    }

    #[test]
    fn a_preflight_for_a_method_not_allowed_is_refused() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![stage(app())]);

        assert_eq!(
            pipeline.preflight(&preflight_for("DELETE")),
            PreflightRule::Refuse(CorsRefusal::Method)
        );
    }

    /// The real request after the preflight is no preflight: it runs every
    /// stage, Identity and Policy included.
    #[test]
    fn the_real_request_runs_every_stage() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![stage(app())]);
        let real = CorsRequest {
            method: HttpMethod::Post,
            origin: SentOrigin::One("https://app.acme.com"),
            preflight: PreflightAsk::NotAsked,
        };

        assert_eq!(pipeline.preflight(&real), PreflightRule::RunStages);
    }

    /// A preflight request is assigned to the normal stages when the pipeline
    /// has no CORS stage or its CORS stage is switched off.
    #[test]
    fn without_a_cors_stage_a_preflight_runs_every_stage() {
        let none: Pipeline<ResolvedTenant> = running(Vec::new());
        let off: Pipeline<ResolvedTenant> = running(vec![switched_off(app())]);

        assert_eq!(
            none.preflight(&preflight_for("POST")),
            PreflightRule::RunStages
        );
        assert_eq!(
            off.preflight(&preflight_for("POST")),
            PreflightRule::RunStages
        );
    }

    /// A GET-only CORS stage makes the pipeline refuse a POST preflight,
    /// even when another CORS stage permits POST.
    #[test]
    fn every_cors_stage_must_allow_the_preflight() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![
            stage(app()),
            stage(cors("https://app.acme.com", &[HttpMethod::Get])),
        ]);

        assert_eq!(
            pipeline.preflight(&preflight_for("POST")),
            PreflightRule::Refuse(CorsRefusal::Method)
        );
    }
}
