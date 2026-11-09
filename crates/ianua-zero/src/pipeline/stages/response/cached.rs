//! `Cache`, its lookup step: an answer kept for the same question and the
//! same caller, served without asking the upstream.
//!
//! The lookup files the question under the one [`CacheKey`] the store step
//! keeps answers under, so an answer is only ever found by the caller it was
//! kept for. A kept answer is put on the context as the response to serve,
//! like the `Terminate` stage's: the pipeline still has to grant the
//! request, and the stages after this one still run. A cache that cannot be
//! read, or does not answer in time, is a miss: not serving from the cache
//! is always safe.

use ianua_domain::domains::proxy::request::context::{
    PipelineContext, ReadyResponse, ResponseSource,
};
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::CacheConfig;
use ianua_domain::types::HttpMethod;

use super::cache::CacheKey;
use super::{Exchange, ResponseStages};

impl ResponseStages {
    /// Serves the answer kept for this question and caller, when there is
    /// one, by putting it on `ctx`. The request passes either way.
    pub(crate) async fn cache_lookup(
        &self,
        config: &CacheConfig,
        ctx: &mut PipelineContext,
        exchange: Exchange<'_>,
    ) -> StageDecision {
        if exchange.request.method() != HttpMethod::Get {
            return passed("only a GET is served from the cache");
        }
        let Some(key) = CacheKey::for_request(ctx, config.vary_by_user, exchange) else {
            return passed("the cache keeps nothing for this caller");
        };
        let kept = match self.within(self.cache.lookup(&key)).await {
            Ok(kept) => kept,
            Err(error) => {
                tracing::warn!(%error, "the cache could not be read; forwarding");
                return passed("the cache could not be read");
            }
        };
        let Some(kept) = kept else {
            return passed("nothing is cached for this question");
        };
        ctx.response = ResponseSource::Ready(ReadyResponse {
            status: kept.status,
            headers: kept.headers,
            body: kept.body,
        });
        passed("served from the cache")
    }
}

/// The request goes on, recorded as `reason`.
fn passed(reason: &str) -> StageDecision {
    StageDecision::Pass {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::proxy::{CachedAnswer, ResponseCache as _};
    use ianua_domain::domains::proxy::request::context::{Caller, UserSignIn, Verified};
    use ianua_domain::domains::proxy::stages::stage::CacheScope;
    use ianua_domain::types::{CorrelationId, Expiry, PipelineId, Seconds, UserId};

    use super::*;
    use crate::pipeline::stages::response::fixtures::{Fakes, admitted, context};

    fn config(scope: CacheScope) -> CacheConfig {
        CacheConfig {
            ttl_seconds: Seconds::new(60),
            vary_by_user: scope,
        }
    }

    fn signed_in_as(user_id: UserId, ctx: &mut PipelineContext) {
        ctx.authenticate(Verified {
            caller: Caller::User {
                user_id,
                sign_in: UserSignIn::Token,
            },
            expiry: Expiry::Never,
        })
        .unwrap();
    }

    /// Keeps `body` for Ann's `GET /orders` in `fakes`' cache.
    async fn kept_for(fakes: &Fakes, ctx: &PipelineContext, body: &[u8]) {
        let request = admitted("GET", "/orders");
        let key = CacheKey::for_request(
            ctx,
            CacheScope::PerUser,
            Exchange {
                request: &request,
                query: None,
            },
        )
        .unwrap();
        let answer = CachedAnswer {
            status: 200,
            headers: &[],
            body,
        };
        fakes
            .cache
            .store(&key, answer, Seconds::new(60))
            .await
            .unwrap();
    }

    /// Ann asks for her orders again within the minute. The answer kept for
    /// her is put on the context to serve, and the request goes on.
    #[tokio::test]
    async fn a_kept_answer_is_served() {
        let fakes = Fakes::default();
        let mut ctx = context();
        signed_in_as(UserId::new(), &mut ctx);
        kept_for(&fakes, &ctx, b"[1,2]").await;
        let request = admitted("GET", "/orders");

        let decision = fakes
            .stages()
            .cache_lookup(
                &config(CacheScope::PerUser),
                &mut ctx,
                Exchange {
                    request: &request,
                    query: None,
                },
            )
            .await;

        assert!(matches!(decision, StageDecision::Pass { .. }));
        let served = ctx.response.ready().map(|ready| ready.body.clone());
        assert_eq!(served, Some(b"[1,2]".to_vec()));
    }

    /// With Ann's orders cached, Sam's lookup of the same page leaves his
    /// response unset rather than serving her answer.
    #[tokio::test]
    async fn another_callers_answer_is_never_served() {
        let fakes = Fakes::default();
        let mut anns = context();
        signed_in_as(UserId::new(), &mut anns);
        kept_for(&fakes, &anns, b"[1,2]").await;
        let mut sams =
            PipelineContext::new(anns.tenant_id, PipelineId::new(), CorrelationId::new());
        signed_in_as(UserId::new(), &mut sams);
        let request = admitted("GET", "/orders");

        fakes
            .stages()
            .cache_lookup(
                &config(CacheScope::PerUser),
                &mut sams,
                Exchange {
                    request: &request,
                    query: None,
                },
            )
            .await;

        assert!(sams.response.ready().is_none());
    }
}
