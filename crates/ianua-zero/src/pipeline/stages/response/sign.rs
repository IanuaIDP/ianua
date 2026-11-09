//! `RequestSign` and `ResponseSign`: a signature over what the gateway saw
//! of a request or an answer, so the upstream or the client can check where
//! it came from and that it was not changed on the way.
//!
//! Both sign the method, host, path, a timestamp and a hash of the body
//! prefix the gateway read, and say in `body_complete` whether that prefix
//! is the whole body, so a verifier never takes a prefix hash for a
//! whole-body one. The `sub` claim names the side, so a request's signature
//! cannot be replayed as an answer's.
//!
//! No signature, no forward: a tenant without a key, a signer that fails or
//! does not answer in time refuses the request, or withholds the answer.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub use ianua_app::ports::crypto::MessageSigner;
use ianua_app::ports::proxy::ResponseStageOutcome;
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::request::transform::{RequestMutation, ResponseMutation};
use ianua_domain::domains::proxy::stages::decision::{HeaderEntry, StageDecision};
use ianua_domain::domains::proxy::stages::stage::{RequestSignConfig, ResponseSignConfig};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DenialStatus, HeaderName, HeaderValue, Seconds};
use sha2::{Digest, Sha256};

use super::{ResponseRead, ResponseStages, withheld};
use crate::pipeline::facts::RequestFacts;

/// Which side of the exchange a signature covers.
#[derive(Debug, Clone, Copy)]
enum Side {
    /// The request, before it is forwarded.
    Request,
    /// The answer, with its status.
    Response(u16),
}

/// What one signature covers.
struct Signed<'a> {
    side: Side,
    request: &'a RequestFacts,
    body: CapturedBody<'a>,
    ttl: Seconds,
}

impl ResponseStages {
    /// Signs the request before it is forwarded, into the configured header.
    ///
    /// Refused with `503` when no signature can be made: the upstream was
    /// promised one. A request whose body was not read for the signature is
    /// refused too: the pipeline asks for the body whenever it signs, so an
    /// unread body is a hash that would cover nothing.
    ///
    /// # Errors
    ///
    /// Never: every failure is a refusal.
    pub(crate) async fn request_sign(
        &self,
        config: &RequestSignConfig,
        ctx: &PipelineContext,
        request: &RequestFacts,
    ) -> Result<StageDecision, DomainError> {
        let Some(body) = request.captured_body() else {
            return Ok(unsigned("request signature: the body was not read"));
        };
        let signed = Signed {
            side: Side::Request,
            request,
            body,
            ttl: config.ttl_seconds,
        };
        let Ok(header) = self.signature(ctx, &config.header_name, &signed).await else {
            return Ok(unsigned("request signature could not be made"));
        };
        Ok(StageDecision::Transform {
            mutation: RequestMutation::asserting(vec![header]),
            reason: "request signed".to_owned(),
        })
    }

    /// Signs the answer before it reaches the client, into the configured
    /// header. The body is left as it is.
    ///
    /// Withheld when no signature can be made: the client was promised one.
    ///
    /// # Errors
    ///
    /// Never: every failure withholds the answer.
    pub(crate) async fn response_sign(
        &self,
        config: &ResponseSignConfig,
        request: &RequestFacts,
        answer: ResponseRead<'_>,
    ) -> Result<ResponseStageOutcome, DomainError> {
        let signed = Signed {
            side: Side::Response(answer.meta.status),
            request,
            body: answer.body,
            ttl: config.ttl_seconds,
        };
        let Ok(header) = self
            .signature(answer.context, &config.header_name, &signed)
            .await
        else {
            return Ok(withheld("answer signature could not be made"));
        };
        Ok(ResponseStageOutcome::Change {
            headers: ResponseMutation::asserting(vec![header]),
            body: None,
            reason: "answer signed".to_owned(),
        })
    }

    /// The signature over `signed`, as the header `name`.
    async fn signature(
        &self,
        ctx: &PipelineContext,
        name: &HeaderName,
        signed: &Signed<'_>,
    ) -> Result<HeaderEntry, DomainError> {
        let claims = claims(ctx, signed, clock::now().unix_timestamp()).to_string();
        let jws = self
            .within(self.signer.sign(&ctx.tenant_id, &claims))
            .await
            .inspect_err(|error| {
                tracing::warn!(%error, "a message signature could not be made");
            })?;
        Ok(HeaderEntry::new(name.clone(), HeaderValue::new(jws)?))
    }
}

/// The request refused with `503` for want of the signature its upstream
/// was promised, recorded as `reason`.
fn unsigned(reason: &str) -> StageDecision {
    StageDecision::Deny {
        status: DenialStatus::SERVICE_UNAVAILABLE,
        reason: reason.to_owned(),
    }
}

/// The claims a signature carries, issued at `now` in Unix seconds.
fn claims(ctx: &PipelineContext, signed: &Signed<'_>, now: i64) -> serde_json::Value {
    let request = &signed.request.admitted;
    let mut claims = serde_json::json!({
        "tid": ctx.tenant_id.to_string(),
        "cid": ctx.correlation_id.to_string(),
        "host": request.host().as_str(),
        "method": request.method().as_str(),
        "path": request.path().as_str(),
        "body_hash": URL_SAFE_NO_PAD.encode(Sha256::digest(signed.body.bytes)),
        "body_complete": signed.body.is_whole(),
        "iat": now,
        "exp": now.saturating_add(i64::from(signed.ttl.get())),
    });
    if let Some(query) = signed.request.query() {
        claims["query"] = serde_json::Value::from(query);
    }
    match signed.side {
        Side::Request => claims["sub"] = serde_json::Value::from("request"),
        Side::Response(status) => {
            claims["sub"] = serde_json::Value::from("response");
            claims["status"] = serde_json::Value::from(status);
        }
    }
    claims
}

#[cfg(test)]
pub(crate) mod fakes {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::types::TenantId;

    use super::*;

    /// A signer that signs with a fixed signature, or has no key.
    pub(crate) struct FakeSigner {
        key: Option<&'static str>,
        signed: Mutex<Vec<serde_json::Value>>,
    }

    impl FakeSigner {
        /// A signer with a key.
        pub(crate) fn signing() -> Self {
            Self {
                key: Some("sig"),
                signed: Mutex::default(),
            }
        }

        /// A signer for a tenant that has no key.
        pub(crate) fn without_key() -> Self {
            Self {
                key: None,
                signed: Mutex::default(),
            }
        }

        /// The claims signed so far.
        pub(crate) fn signed(&self) -> Vec<serde_json::Value> {
            self.signed.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MessageSigner for FakeSigner {
        async fn sign(&self, _: &TenantId, claims_json: &str) -> Result<String, DomainError> {
            let key = self
                .key
                .ok_or_else(|| DomainError::infra_msg("no message key"))?;
            self.signed
                .lock()
                .unwrap()
                .push(serde_json::from_str(claims_json).unwrap());
            Ok(format!("header.payload.{key}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyper::body::Bytes;
    use ianua_domain::domains::proxy::request::body::BodyExtent;

    use super::fakes::FakeSigner;
    use super::*;
    use crate::pipeline::stages::response::fixtures::{Fakes, context, is_withheld, json, sent};
    use crate::request::BodyRead;

    /// `method uri`, its body read as `bytes`, whole.
    fn sent_with_body(method: &str, uri: &str, bytes: &'static [u8]) -> RequestFacts {
        let mut request = sent(method, uri);
        request.body = BodyRead::Read {
            prefix: Bytes::from_static(bytes),
            extent: BodyExtent::Whole,
        };
        request
    }

    fn request_config() -> RequestSignConfig {
        RequestSignConfig {
            header_name: HeaderName::new("x-signature").unwrap(),
            ttl_seconds: Seconds::new(30),
        }
    }

    fn response_config() -> ResponseSignConfig {
        ResponseSignConfig {
            header_name: HeaderName::new("x-signature").unwrap(),
            ttl_seconds: Seconds::new(30),
        }
    }

    fn without_key() -> Fakes {
        Fakes {
            signer: Arc::new(FakeSigner::without_key()),
            ..Fakes::default()
        }
    }

    /// A request is forwarded with its signature in the configured header,
    /// covering its method and path, and saying the body was read whole.
    #[tokio::test]
    async fn a_request_is_forwarded_signed() {
        let fakes = Fakes::default();
        let request = sent_with_body("POST", "/orders?page=2", b"{}");

        let decision = fakes
            .stages()
            .request_sign(&request_config(), &context(), &request)
            .await
            .unwrap();

        let StageDecision::Transform { mutation, .. } = decision else {
            panic!("expected the request to be signed");
        };
        assert_eq!(mutation.headers_to_set()[0].name().as_str(), "x-signature");
        let claims = &fakes.signer.signed()[0];
        assert_eq!(claims["sub"], "request");
        assert_eq!(claims["method"], "POST");
        assert_eq!(claims["path"], "/orders");
        assert_eq!(claims["query"], "page=2");
        assert_eq!(claims["body_complete"], true);
        assert!(claims.get("status").is_none());
    }

    /// A signer without a tenant key causes a service-unavailable refusal
    /// when a request signature is required.
    #[tokio::test]
    async fn a_request_that_cannot_be_signed_is_refused() {
        let request = sent_with_body("GET", "/orders", b"");

        let decision = without_key()
            .stages()
            .request_sign(&request_config(), &context(), &request)
            .await
            .unwrap();

        assert!(
            matches!(decision, StageDecision::Deny { status, .. } if status == DenialStatus::SERVICE_UNAVAILABLE)
        );
    }

    /// An unread request body causes a service-unavailable refusal, and the
    /// signer receives no claims.
    #[tokio::test]
    async fn a_request_whose_body_was_not_read_is_refused() {
        let fakes = Fakes::default();

        let decision = fakes
            .stages()
            .request_sign(&request_config(), &context(), &sent("POST", "/orders"))
            .await
            .unwrap();

        assert!(
            matches!(decision, StageDecision::Deny { status, .. } if status == DenialStatus::SERVICE_UNAVAILABLE)
        );
        assert!(fakes.signer.signed().is_empty());
    }

    /// An answer read only in part is signed as such: the hash covers the
    /// prefix and `body_complete` says so.
    #[tokio::test]
    async fn an_answer_read_in_part_is_signed_as_a_prefix() {
        let fakes = Fakes::default();
        let request = sent("GET", "/report");

        let outcome = fakes
            .stages()
            .response_sign(
                &response_config(),
                &request,
                ResponseRead {
                    context: &context(),
                    meta: &json(),
                    body: CapturedBody::new(b"{\"rows\":[", BodyExtent::Prefix),
                },
            )
            .await
            .unwrap();

        assert!(matches!(
            outcome,
            ResponseStageOutcome::Change { body: None, .. }
        ));
        let claims = &fakes.signer.signed()[0];
        assert_eq!(claims["sub"], "response");
        assert_eq!(claims["status"], 200);
        assert_eq!(claims["body_complete"], false);
    }

    /// An answer whose signature cannot be made is withheld, not sent on
    /// unsigned.
    #[tokio::test]
    async fn an_answer_that_cannot_be_signed_is_withheld() {
        let request = sent("GET", "/report");

        let outcome = without_key()
            .stages()
            .response_sign(
                &response_config(),
                &request,
                ResponseRead {
                    context: &context(),
                    meta: &json(),
                    body: CapturedBody::new(b"{}", BodyExtent::Whole),
                },
            )
            .await
            .unwrap();

        assert!(is_withheld(&outcome));
    }

    /// The same bytes hash the same, and other bytes differently.
    #[test]
    fn the_body_hash_follows_the_bytes() {
        let ctx = context();
        let request = sent("GET", "/x");
        let hash = |bytes: &'static [u8]| {
            let signed = Signed {
                side: Side::Request,
                request: &request,
                body: CapturedBody::new(bytes, BodyExtent::Whole),
                ttl: Seconds::new(30),
            };
            claims(&ctx, &signed, 0)["body_hash"].clone()
        };

        assert_eq!(hash(b"same"), hash(b"same"));
        assert_ne!(hash(b"same"), hash(b"other"));
    }

    /// A signature lives for its configured time from when it was made.
    #[test]
    fn a_signature_expires_after_its_lifetime() {
        let request = sent("GET", "/x");
        let signed = Signed {
            side: Side::Response(204),
            request: &request,
            body: CapturedBody::new(b"", BodyExtent::Whole),
            ttl: Seconds::new(30),
        };

        let claims = claims(&context(), &signed, 1_000);

        assert_eq!(claims["iat"], 1_000);
        assert_eq!(claims["exp"], 1_030);
    }
}
