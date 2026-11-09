//! The stages that sign what crosses the gateway and act on the upstream's
//! answer: request and response signatures, redaction, the cache's lookup
//! and store steps, the canary checks on the request and the answer, the
//! token limit's charge and release, the response transform and the
//! security headers.
//!
//! Each runs on what the gateway read: the request line it admitted, the
//! bounded prefix of a body, and whether that prefix is the whole body. A
//! stage that guards the answer (redaction, the canary check) and cannot see
//! all of it withholds the answer rather than pass it on unchecked, and a
//! body is only ever replaced when the whole of it was read.
//!
//! What a stage needs from outside the gateway it reaches through one of
//! the seams below, each call held to [`ResponseLimits::call_timeout`]: a
//! call that fails or does not answer in time is a refusal wherever the
//! stage guards something.

mod body;
mod cache;
mod cached;
mod canary;
mod headers;
mod redact;
mod sign;
mod tokens;
mod transform;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

pub(crate) use cache::ResponseCache;
pub(crate) use canary::CanaryAlarm;
use ianua_app::ports::data_classification::{ClassificationStore, RedactionDigest};
use ianua_app::ports::proxy::{ResponseMeta, ResponseStageOutcome};
use ianua_domain::domains::proxy::request::body::{ByteCap, CapturedBody};
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DenialStatus;
pub use sign::MessageSigner;
pub(crate) use tokens::{TokenLedger, TokenLimit};

use crate::pipeline::facts::RequestFacts;
use crate::request::Admitted;

/// The upstream answer a stage examines for one request.
#[derive(Clone, Copy)]
pub(crate) struct ResponseRead<'a> {
    /// The caller and tenant whose request produced this answer.
    pub(crate) context: &'a PipelineContext,
    /// The status and headers currently handed to the stage.
    pub(crate) meta: &'a ResponseMeta,
    /// The captured bytes and whether they cover the whole answer.
    pub(crate) body: CapturedBody<'a>,
}

/// The request a response answers, as the gateway admitted it: the part
/// of the request's [`RequestFacts`] the cache files an answer under.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Exchange<'a> {
    /// The host, method and canonical path the gateway admitted.
    pub request: &'a Admitted,
    /// The query string the client sent, without the `?`, if any.
    pub query: Option<&'a str>,
}

impl<'a> From<&'a RequestFacts> for Exchange<'a> {
    fn from(facts: &'a RequestFacts) -> Self {
        Self {
            request: &facts.admitted,
            query: facts.query(),
        }
    }
}

/// The bounds the group's stages run under.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResponseLimits {
    /// The longest any call out of the gateway may take: a signature, a rule
    /// set read, a cache write, a recorded leak or a token charge.
    pub call_timeout: Duration,
    /// The largest answer the cache keeps.
    pub cache_max_body: ByteCap,
}

/// What [`ResponseStages`] is built from.
pub(crate) struct ResponseStagesParts {
    /// Signs request and response signatures with the tenant's message keys.
    pub signer: Arc<dyn MessageSigner>,
    /// The tenant's classification rule set, which redaction applies.
    pub classifications: Arc<dyn ClassificationStore>,
    /// The keyed digest a field redacted by hashing is replaced with.
    pub redaction: Arc<dyn RedactionDigest>,
    /// Where cacheable answers are kept.
    pub cache: Arc<dyn ResponseCache>,
    /// Records a canary token found leaking in an answer.
    pub canary_alarm: Arc<dyn CanaryAlarm>,
    /// Settles what an exchange with a language model cost.
    pub tokens: Arc<dyn TokenLedger>,
    /// The bounds the stages run under.
    pub limits: ResponseLimits,
}

/// The signing and response stages, holding what they need.
///
/// One method per stage kind and side: [`request_sign`](Self::request_sign),
/// [`security_headers`](Self::security_headers),
/// [`cache_lookup`](Self::cache_lookup) and
/// [`canary_presented`](Self::canary_presented) run before forwarding, the
/// rest on the upstream's answer, in the order
/// [`Pipeline::response_stages`](ianua_domain::domains::proxy::pipeline::Pipeline::response_stages)
/// gives.
pub(crate) struct ResponseStages {
    signer: Arc<dyn MessageSigner>,
    classifications: Arc<dyn ClassificationStore>,
    redaction: Arc<dyn RedactionDigest>,
    cache: Arc<dyn ResponseCache>,
    canary_alarm: Arc<dyn CanaryAlarm>,
    tokens: Arc<dyn TokenLedger>,
    limits: ResponseLimits,
}

impl std::fmt::Debug for ResponseStages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseStages")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl ResponseStages {
    /// The group, from its parts.
    #[must_use]
    pub(crate) fn new(parts: ResponseStagesParts) -> Self {
        Self {
            signer: parts.signer,
            classifications: parts.classifications,
            redaction: parts.redaction,
            cache: parts.cache,
            canary_alarm: parts.canary_alarm,
            tokens: parts.tokens,
            limits: parts.limits,
        }
    }

    /// What `call` answers, or an error when it fails or outlasts the call
    /// timeout.
    async fn within<T>(
        &self,
        call: impl Future<Output = Result<T, DomainError>>,
    ) -> Result<T, DomainError> {
        tokio::time::timeout(self.limits.call_timeout, call)
            .await
            .map_err(DomainError::infra)?
    }
}

/// The answer withheld from the client, as a bad gateway: the upstream
/// answered, and the gateway would not hand that answer on.
fn withheld(reason: impl Into<String>) -> ResponseStageOutcome {
    ResponseStageOutcome::Block {
        status: DenialStatus::BAD_GATEWAY,
        reason: reason.into(),
    }
}

/// The answer passed on as it came.
fn unchanged(reason: impl Into<String>) -> ResponseStageOutcome {
    ResponseStageOutcome::Pass {
        reason: reason.into(),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::sync::Arc;
    use std::time::Duration;

    use http::Request;
    use ianua_app::ports::data_classification::ClassificationStore;
    use ianua_app::ports::proxy::{ResponseMeta, ResponseStageOutcome};
    use ianua_app::test_support::data_classification::FakeClassificationStore;
    use ianua_domain::domains::proxy::request::body::ByteCap;
    use ianua_domain::domains::proxy::request::context::PipelineContext;
    use ianua_domain::domains::proxy::stages::decision::HeaderEntry;
    use ianua_domain::types::{CorrelationId, HeaderName, HeaderValue, PipelineId, TenantId};
    use ianua_infra::crypto::{HmacRedactionDigest, RootSecret};

    use super::cache::fakes::FakeCache;
    use super::canary::fakes::FakeAlarm;
    use super::sign::fakes::FakeSigner;
    use super::tokens::fakes::FakeLedger;
    use super::{ResponseLimits, ResponseStages, ResponseStagesParts};
    use crate::pipeline::facts::RequestFacts;
    use crate::request::Admitted;

    /// The fakes behind a group, kept so a test can look at what reached
    /// them.
    pub(crate) struct Fakes {
        pub signer: Arc<FakeSigner>,
        pub classifications: Arc<dyn ClassificationStore>,
        pub cache: Arc<FakeCache>,
        pub alarm: Arc<FakeAlarm>,
        pub ledger: Arc<FakeLedger>,
    }

    impl Default for Fakes {
        fn default() -> Self {
            Self {
                signer: Arc::new(FakeSigner::signing()),
                classifications: Arc::new(FakeClassificationStore::empty()),
                cache: Arc::new(FakeCache::default()),
                alarm: Arc::new(FakeAlarm::default()),
                ledger: Arc::new(FakeLedger::default()),
            }
        }
    }

    impl Fakes {
        /// A group over these fakes.
        pub(crate) fn stages(&self) -> ResponseStages {
            ResponseStages::new(ResponseStagesParts {
                signer: self.signer.clone(),
                classifications: Arc::clone(&self.classifications),
                redaction: Arc::new(HmacRedactionDigest::new(&redaction_root())),
                cache: self.cache.clone(),
                canary_alarm: self.alarm.clone(),
                tokens: self.ledger.clone(),
                limits: ResponseLimits {
                    call_timeout: Duration::from_secs(1),
                    cache_max_body: ByteCap::new(1024).unwrap(),
                },
            })
        }
    }

    /// The root the fakes' redaction digests are keyed from.
    pub(crate) fn redaction_root() -> RootSecret {
        RootSecret::parse(&format!("{:064x}", 7)).unwrap()
    }

    /// A fresh context for a request to a new tenant.
    pub(crate) fn context() -> PipelineContext {
        PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new())
    }

    /// `method path` on `shop.acme.com`, as the gateway admits it.
    pub(crate) fn admitted(method: &str, path: &str) -> Admitted {
        sent(method, path).admitted
    }

    /// `method uri` on `shop.acme.com`, as the handler hands it to the
    /// stages.
    pub(crate) fn sent(method: &str, uri: &str) -> RequestFacts {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "shop.acme.com")
            .body(())
            .unwrap();
        RequestFacts::sent(request)
    }

    /// A header entry.
    pub(crate) fn header(name: &str, value: &str) -> HeaderEntry {
        HeaderEntry::new(
            HeaderName::new(name).unwrap(),
            HeaderValue::new(value).unwrap(),
        )
    }

    /// An answer with `status` and `headers`.
    pub(crate) fn answer(status: u16, headers: &[(&str, &str)]) -> ResponseMeta {
        ResponseMeta {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| header(name, value))
                .collect(),
        }
    }

    /// A JSON answer with status 200.
    pub(crate) fn json() -> ResponseMeta {
        answer(200, &[("content-type", "application/json")])
    }

    /// The replacement body a change carries, if any.
    pub(crate) fn replaced(outcome: &ResponseStageOutcome) -> Option<serde_json::Value> {
        let ResponseStageOutcome::Change {
            body: Some(body), ..
        } = outcome
        else {
            return None;
        };
        serde_json::from_slice(body).ok()
    }

    /// Whether the outcome withholds the answer.
    pub(crate) fn is_withheld(outcome: &ResponseStageOutcome) -> bool {
        matches!(outcome, ResponseStageOutcome::Block { status, .. } if status.code() == 502)
    }

    /// Whether the outcome passes the answer on unchanged.
    pub(crate) fn is_unchanged(outcome: &ResponseStageOutcome) -> bool {
        matches!(outcome, ResponseStageOutcome::Pass { .. })
    }
}
