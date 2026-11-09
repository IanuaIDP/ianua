//! `CanaryToken`, both ways: a request presenting one of the tenant's decoy
//! credentials is refused, and an answer that carries one is withheld, each
//! recorded.
//!
//! A decoy is never issued, so whoever presents one replays a stolen copy,
//! and an upstream rendering one exposes something it should never show: a
//! debug dump, an error page saying too much, an endpoint echoing secrets.
//! For a leaking answer the caller did nothing wrong; the leak is the
//! upstream's. Either way an administrator must find it on record.
//!
//! The request side reads the headers and the query, where a credential
//! travels, and never the body: the gateway decides on metadata. A refused
//! thief is told only the 401 any bad credential gets.
//!
//! The response side guards the answer, so an answer it cannot read
//! through is withheld too: one longer than the gateway reads, or one whose
//! bytes are compressed, could carry a decoy where the scan never looked.

use async_trait::async_trait;
use ianua_app::ports::proxy::{ResponseMeta, ResponseStageOutcome};
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::{CanaryToken, CanaryTokenConfig};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CorrelationId, DenialStatus, IpAddress, TenantId};

use super::body::{Encoding, encoding};
use super::{ResponseRead, ResponseStages, unchanged, withheld};
use crate::pipeline::facts::RequestFacts;

/// Records a canary token presented to the gateway or found in an
/// upstream's answer.
#[async_trait]
pub(crate) trait CanaryAlarm: Send + Sync {
    /// Records that an upstream of `tenant_id` rendered one of its canary
    /// tokens in the answer to `correlation_id`, which was withheld.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the leak cannot be recorded.
    async fn record_leak(
        &self,
        tenant_id: TenantId,
        correlation_id: CorrelationId,
    ) -> Result<(), DomainError>;

    /// Records that a client at `ip_address` presented one of
    /// `tenant_id`'s canary tokens on the request `correlation_id`, which
    /// was refused. The token itself is never recorded.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the presentation cannot be recorded.
    async fn record_presentation(
        &self,
        tenant_id: TenantId,
        ip_address: IpAddress,
        correlation_id: CorrelationId,
    ) -> Result<(), DomainError>;
}

/// What the scan found in an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scan {
    /// A decoy is in the answer.
    Leaked,
    /// The whole answer was read and holds no decoy.
    Clean,
    /// Part of the answer could not be read, so a decoy may be in it.
    Unread,
}

impl ResponseStages {
    /// Withholds an answer that carries one of the tenant's canary tokens,
    /// in a header or the body, and records the leak. An answer the scan
    /// cannot read whole is withheld too.
    ///
    /// # Errors
    ///
    /// Never: an answer that cannot be checked is withheld, and the answer
    /// stays withheld when the leak cannot be recorded.
    pub(crate) async fn canary_leak(
        &self,
        config: &CanaryTokenConfig,
        answer: ResponseRead<'_>,
    ) -> Result<ResponseStageOutcome, DomainError> {
        if config.tokens.is_empty() {
            return Ok(unchanged("no canary token is planted"));
        }
        match scan(&config.tokens, answer.meta, answer.body) {
            Scan::Clean => Ok(unchanged("no canary token in the answer")),
            Scan::Unread => Ok(withheld(
                "the answer could not be checked for canary tokens",
            )),
            Scan::Leaked => {
                self.record_leak(answer.context).await;
                Ok(withheld("a canary token leaked in the answer"))
            }
        }
    }

    /// Records the leak in `ctx`'s tenant. A leak that cannot be recorded
    /// is logged; the answer is withheld either way.
    async fn record_leak(&self, ctx: &PipelineContext) {
        let recorded = self
            .within(
                self.canary_alarm
                    .record_leak(ctx.tenant_id, ctx.correlation_id),
            )
            .await;
        if let Err(error) = recorded {
            tracing::error!(
                %error,
                correlation_id = %ctx.correlation_id,
                "a leaked canary token could not be recorded"
            );
        }
    }

    /// The request side: refuses a request that presents one of the
    /// tenant's canary tokens in a header or its query, and records it.
    ///
    /// # Errors
    ///
    /// Never: the request is refused whether or not the record is
    /// written.
    pub(crate) async fn canary_presented(
        &self,
        config: &CanaryTokenConfig,
        ctx: &PipelineContext,
        request: &RequestFacts,
    ) -> Result<StageDecision, DomainError> {
        if !presents(&config.tokens, request) {
            return Ok(StageDecision::Pass {
                reason: "no canary token presented".to_owned(),
            });
        }
        self.record_presented(ctx).await;
        Ok(StageDecision::Deny {
            status: DenialStatus::UNAUTHORIZED,
            reason: "canary_token_presented".to_owned(),
        })
    }

    /// Records the presentation in `ctx`'s tenant. One that cannot be
    /// recorded, or whose client address is unknown, is logged; the request
    /// is refused either way.
    async fn record_presented(&self, ctx: &PipelineContext) {
        let Some(address) = ctx.ip_address.known() else {
            tracing::error!(
                correlation_id = %ctx.correlation_id,
                "a canary token was presented from an unknown address and is not recorded"
            );
            return;
        };
        let recorded = self
            .within(self.canary_alarm.record_presentation(
                ctx.tenant_id,
                address.clone(),
                ctx.correlation_id,
            ))
            .await;
        if let Err(error) = recorded {
            tracing::error!(
                %error,
                correlation_id = %ctx.correlation_id,
                "a presented canary token could not be recorded"
            );
        }
    }
}

/// Whether a header value or the query of `request` holds any of `tokens`.
fn presents(tokens: &[CanaryToken], request: &RequestFacts) -> bool {
    let in_headers = request
        .headers
        .values()
        .any(|value| carries(value.as_bytes(), tokens));
    in_headers
        || request
            .query()
            .is_some_and(|query| carries(query.as_bytes(), tokens))
}

/// Whether a decoy is in the answer's headers or the bytes read of its
/// body, and whether the rest of it went unread.
fn scan(tokens: &[CanaryToken], response: &ResponseMeta, body: CapturedBody<'_>) -> Scan {
    let in_headers = response
        .headers
        .iter()
        .any(|entry| carries(entry.value().as_str().as_bytes(), tokens));
    if in_headers {
        return Scan::Leaked;
    }
    if encoding(response) == Encoding::Encoded {
        return Scan::Unread;
    }
    if carries(body.bytes, tokens) {
        return Scan::Leaked;
    }
    if !body.is_whole() {
        return Scan::Unread;
    }
    Scan::Clean
}

/// Whether `bytes` hold any of `tokens` anywhere.
fn carries(bytes: &[u8], tokens: &[CanaryToken]) -> bool {
    tokens.iter().any(|token| {
        let needle = token.as_str().as_bytes();
        !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
    })
}

#[cfg(test)]
pub(crate) mod fakes {
    use std::sync::Mutex;

    use super::*;

    /// An alarm that remembers the leaks and presentations it was told of,
    /// or cannot record any.
    #[derive(Default)]
    pub(crate) struct FakeAlarm {
        broken: bool,
        recorded: Mutex<Vec<(TenantId, CorrelationId)>>,
        presented: Mutex<Vec<(TenantId, IpAddress, CorrelationId)>>,
    }

    impl FakeAlarm {
        /// An alarm whose record cannot be written.
        pub(crate) fn broken() -> Self {
            Self {
                broken: true,
                ..Self::default()
            }
        }

        /// The leaks recorded so far.
        pub(crate) fn recorded(&self) -> Vec<(TenantId, CorrelationId)> {
            self.recorded.lock().unwrap().clone()
        }

        /// The presented tokens recorded so far.
        pub(crate) fn presented(&self) -> Vec<(TenantId, IpAddress, CorrelationId)> {
            self.presented.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CanaryAlarm for FakeAlarm {
        async fn record_leak(
            &self,
            tenant_id: TenantId,
            correlation_id: CorrelationId,
        ) -> Result<(), DomainError> {
            if self.broken {
                return Err(DomainError::infra_msg("the inbox is unreachable"));
            }
            self.recorded
                .lock()
                .unwrap()
                .push((tenant_id, correlation_id));
            Ok(())
        }

        async fn record_presentation(
            &self,
            tenant_id: TenantId,
            ip_address: IpAddress,
            correlation_id: CorrelationId,
        ) -> Result<(), DomainError> {
            if self.broken {
                return Err(DomainError::infra_msg("the inbox is unreachable"));
            }
            self.presented
                .lock()
                .unwrap()
                .push((tenant_id, ip_address, correlation_id));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::proxy::request::body::BodyExtent;
    use ianua_domain::types::Fact;

    use super::fakes::FakeAlarm;
    use super::*;
    use crate::pipeline::stages::response::fixtures::{
        Fakes, answer, context, is_unchanged, is_withheld, json, sent,
    };

    const DECOY: &str = "sk-decoy-0123456789abcdef";

    fn planted() -> CanaryTokenConfig {
        CanaryTokenConfig {
            tokens: vec![CanaryToken::new(DECOY).unwrap()],
        }
    }

    async fn check(
        fakes: &Fakes,
        ctx: &PipelineContext,
        response: &ResponseMeta,
        body: CapturedBody<'_>,
    ) -> ResponseStageOutcome {
        fakes
            .stages()
            .canary_leak(
                &planted(),
                ResponseRead {
                    context: ctx,
                    meta: response,
                    body,
                },
            )
            .await
            .unwrap()
    }

    /// A JSON body containing the planted decoy is withheld, with a leak
    /// recorded for the request's tenant and correlation ID.
    #[tokio::test]
    async fn a_canary_in_the_body_is_withheld_and_recorded() {
        let fakes = Fakes::default();
        let ctx = context();
        let body = format!("{{\"debug\":\"key={DECOY}\"}}");

        let outcome = check(
            &fakes,
            &ctx,
            &json(),
            CapturedBody::new(body.as_bytes(), BodyExtent::Whole),
        )
        .await;

        assert!(is_withheld(&outcome));
        assert_eq!(
            fakes.alarm.recorded(),
            [(ctx.tenant_id, ctx.correlation_id)]
        );
    }

    /// A decoy echoed in a response header is caught as well.
    #[tokio::test]
    async fn a_canary_in_a_header_is_withheld_and_recorded() {
        let fakes = Fakes::default();

        let outcome = check(
            &fakes,
            &context(),
            &answer(200, &[("x-echo", DECOY)]),
            CapturedBody::new(b"{}", BodyExtent::Whole),
        )
        .await;

        assert!(is_withheld(&outcome));
        assert_eq!(fakes.alarm.recorded().len(), 1);
    }

    /// A clean answer read whole is passed on, and nothing is recorded.
    #[tokio::test]
    async fn a_clean_answer_is_passed_on() {
        let fakes = Fakes::default();

        let outcome = check(
            &fakes,
            &context(),
            &json(),
            CapturedBody::new(b"{\"ok\":true}", BodyExtent::Whole),
        )
        .await;

        assert!(is_unchanged(&outcome));
        assert!(fakes.alarm.recorded().is_empty());
    }

    /// With a decoy configured, truncated and gzip-encoded answers are
    /// withheld because the scan cannot inspect their complete contents.
    #[tokio::test]
    async fn an_answer_the_scan_cannot_read_whole_is_withheld() {
        let fakes = Fakes::default();
        let ctx = context();

        let truncated = check(
            &fakes,
            &ctx,
            &json(),
            CapturedBody::new(b"{\"rows\":[", BodyExtent::Prefix),
        )
        .await;
        let compressed = check(
            &fakes,
            &ctx,
            &answer(200, &[("content-encoding", "gzip")]),
            CapturedBody::new(b"\x1f\x8b\x08", BodyExtent::Whole),
        )
        .await;

        assert!(is_withheld(&truncated));
        assert!(is_withheld(&compressed));
    }

    /// The leak cannot be recorded: the answer stays withheld.
    #[tokio::test]
    async fn a_leak_that_cannot_be_recorded_is_still_withheld() {
        let fakes = Fakes {
            alarm: Arc::new(FakeAlarm::broken()),
            ..Fakes::default()
        };

        let outcome = check(
            &fakes,
            &context(),
            &json(),
            CapturedBody::new(DECOY.as_bytes(), BodyExtent::Whole),
        )
        .await;

        assert!(is_withheld(&outcome));
    }

    /// What the request side decides for `request`, sent from `203.0.113.7`.
    async fn presented(fakes: &Fakes, request: &RequestFacts) -> (StageDecision, PipelineContext) {
        let mut ctx = context();
        ctx.ip_address = Fact::Known(IpAddress::new("203.0.113.7").unwrap());
        let decision = fakes
            .stages()
            .canary_presented(&planted(), &ctx, request)
            .await
            .unwrap();
        (decision, ctx)
    }

    /// A bearer header containing the decoy is refused with 401 without
    /// exposing it in the reason; the tenant, address and request are recorded.
    #[tokio::test]
    async fn a_presented_canary_is_refused_and_recorded() {
        let fakes = Fakes::default();
        let mut request = sent("GET", "/orders");
        request.headers.insert(
            "authorization",
            http::HeaderValue::from_str(&format!("Bearer {DECOY}")).unwrap(),
        );

        let (decision, ctx) = presented(&fakes, &request).await;

        assert!(matches!(
            &decision,
            StageDecision::Deny { status, reason }
                if *status == DenialStatus::UNAUTHORIZED && !reason.contains(DECOY)
        ));
        assert_eq!(
            fakes.alarm.presented(),
            [(
                ctx.tenant_id,
                IpAddress::new("203.0.113.7").unwrap(),
                ctx.correlation_id
            )]
        );
    }

    /// A request carrying the planted decoy in its query is refused.
    #[tokio::test]
    async fn a_canary_in_the_query_is_refused() {
        let fakes = Fakes::default();
        let request = sent("GET", &format!("/orders?api_key={DECOY}"));

        let (decision, _) = presented(&fakes, &request).await;

        assert!(decision.is_terminal());
    }

    /// A request carrying the decoy is still refused when the alarm cannot
    /// record its presentation.
    #[tokio::test]
    async fn a_presentation_that_cannot_be_recorded_is_still_refused() {
        let fakes = Fakes {
            alarm: Arc::new(FakeAlarm::broken()),
            ..Fakes::default()
        };
        let request = sent("GET", &format!("/orders?api_key={DECOY}"));

        let (decision, _) = presented(&fakes, &request).await;

        assert!(decision.is_terminal());
    }

    /// Ann's request carries her own token, no decoy. It goes on.
    #[tokio::test]
    async fn a_request_without_a_canary_passes() {
        let fakes = Fakes::default();
        let mut request = sent("GET", "/orders");
        request.headers.insert(
            "authorization",
            http::HeaderValue::from_static("Bearer anns.real.token"),
        );

        let (decision, _) = presented(&fakes, &request).await;

        assert!(matches!(decision, StageDecision::Pass { .. }));
        assert!(fakes.alarm.presented().is_empty());
    }

    /// A stage with no decoys planted lets every answer through.
    #[tokio::test]
    async fn a_stage_with_no_decoys_passes_every_answer() {
        let outcome = Fakes::default()
            .stages()
            .canary_leak(
                &CanaryTokenConfig { tokens: Vec::new() },
                ResponseRead {
                    context: &context(),
                    meta: &json(),
                    body: CapturedBody::new(b"[", BodyExtent::Prefix),
                },
            )
            .await
            .unwrap();

        assert!(is_unchanged(&outcome));
    }
}
