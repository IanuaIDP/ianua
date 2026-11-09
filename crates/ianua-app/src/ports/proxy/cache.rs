//! Where the gateway keeps answers it may serve again, and what each is
//! filed under.
//!
//! An answer is filed per tenant and per caller, so one caller's answer
//! never reaches another: a per-caller cache keeps nothing for an anonymous
//! request, and a shared one nothing for a signed-in caller. The key holds
//! the caller and the query string in the clear, so the cache keeps only a
//! digest of it.

use async_trait::async_trait;
use ianua_domain::domains::proxy::request::context::{Caller, PipelineContext};
use ianua_domain::domains::proxy::stages::decision::HeaderEntry;
use ianua_domain::domains::proxy::stages::stage::CacheScope;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpMethod, Seconds, TenantId};

/// Where the gateway keeps answers it may serve again.
///
/// Every answer lapses with its lifetime, and the cache bounds how large
/// one may be: an answer past the bound is refused, never cut short.
#[async_trait]
pub trait ResponseCache: Send + Sync {
    /// Keeps `answer` under `key` for `ttl`, replacing what was there.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the answer is larger than the cache keeps,
    ///   or cannot be kept.
    async fn store(
        &self,
        key: &CacheKey,
        answer: CachedAnswer<'_>,
        ttl: Seconds,
    ) -> Result<(), DomainError>;

    /// The answer kept under `key`, or `None` when nothing is kept there or
    /// it lapsed.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the cache cannot be read, or holds something
    ///   it never kept. The gateway then forwards the request: not serving
    ///   from the cache is always safe.
    async fn lookup(&self, key: &CacheKey) -> Result<Option<KeptAnswer>, DomainError>;
}

/// An answer as the cache is handed it.
///
/// `Debug` shows the status and the body's length, never a header value or
/// the body.
#[derive(Clone, Copy)]
pub struct CachedAnswer<'a> {
    /// The status the upstream answered with.
    pub status: u16,
    /// The answer's headers, after every earlier response stage.
    pub headers: &'a [HeaderEntry],
    /// The whole body.
    pub body: &'a [u8],
}

impl std::fmt::Debug for CachedAnswer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedAnswer")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// An answer as the cache gives it back.
///
/// `Debug` shows the status and the body's length, never a header value or
/// the body.
#[derive(Clone, PartialEq, Eq)]
pub struct KeptAnswer {
    /// The status the upstream answered with.
    pub status: u16,
    /// The answer's headers, as they were kept.
    pub headers: Vec<HeaderEntry>,
    /// The whole body.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for KeptAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptAnswer")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// The question an answer answers: the method, host and canonical path the
/// gateway admitted, and the query string the client sent.
#[derive(Debug, Clone, Copy)]
pub struct CachedQuestion<'a> {
    /// The method it was sent with.
    pub method: HttpMethod,
    /// The host it was sent to, without a port.
    pub host: &'a str,
    /// Its canonical path.
    pub path: &'a str,
    /// The query string, without the `?`, if any.
    pub query: Option<&'a str>,
}

/// What a cached answer is filed under: the tenant, whose answer it is, and
/// the question it answers.
///
/// `Debug` shows the tenant alone: the rest names the caller and holds the
/// query string, which may carry a token.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    tenant_id: TenantId,
    question: String,
}

impl std::fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheKey")
            .field("tenant_id", &self.tenant_id)
            .finish_non_exhaustive()
    }
}

impl CacheKey {
    /// The key for the request in `ctx` asking `question` under `scope`, or
    /// `None` when the scope keeps nothing for this caller.
    ///
    /// The lookup before forwarding and the store after it use this one key,
    /// so an answer is only ever found by the question and the caller it was
    /// kept for.
    #[must_use]
    pub fn for_request<'a>(
        ctx: &PipelineContext,
        scope: CacheScope,
        question: impl Into<CachedQuestion<'a>>,
    ) -> Option<Self> {
        let holder = holder(ctx.authentication().caller(), scope)?;
        let question = question.into();
        let parts = [
            holder.as_str(),
            question.method.as_str(),
            question.host,
            question.path,
            question.query.unwrap_or_default(),
        ];
        Some(Self {
            tenant_id: ctx.tenant_id,
            question: framed(&parts),
        })
    }

    /// The tenant whose answer it is, kept plainly so a tenant's answers
    /// can be told apart.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Whose answer it is and the question, each part prefixed by its
    /// length so no two keys run together. It names the caller and holds
    /// the query string: a cache keeps a digest of it, never the text.
    #[must_use]
    pub fn question(&self) -> &str {
        &self.question
    }
}

/// `parts` one after another, each after its length and a `:`.
fn framed(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| format!("{}:{part}", part.len()))
        .collect()
}

/// Whose answers a key holds: the caller under a per-caller scope, everyone
/// under a shared one. `None` when the scope keeps nothing for this caller.
///
/// An agent's answers are kept per delegation, so an agent acting for Ann
/// is never served what it fetched for Sam.
fn holder(caller: Option<&Caller>, scope: CacheScope) -> Option<String> {
    match (scope, caller) {
        (CacheScope::Shared, None) => Some("anyone".to_owned()),
        (CacheScope::Shared, Some(_)) | (CacheScope::PerUser, None) => None,
        (CacheScope::PerUser, Some(Caller::User { user_id, .. })) => {
            Some(format!("user:{user_id}"))
        }
        (
            CacheScope::PerUser,
            Some(Caller::Agent {
                agent_id,
                delegation_id,
                ..
            }),
        ) => Some(format!("agent:{agent_id}:{delegation_id}")),
        (CacheScope::PerUser, Some(Caller::Consumer { consumer_id, .. })) => {
            Some(format!("consumer:{consumer_id}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::request::context::{UserSignIn, Verified};
    use ianua_domain::types::{CorrelationId, Expiry, PipelineId, UserId};

    use super::*;

    fn context() -> PipelineContext {
        PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new())
    }

    fn signed_in_as(user_id: UserId) -> PipelineContext {
        let mut ctx = context();
        ctx.authenticate(Verified {
            caller: Caller::User {
                user_id,
                sign_in: UserSignIn::Token,
            },
            expiry: Expiry::Never,
        })
        .unwrap();
        ctx
    }

    fn orders(query: Option<&str>) -> CachedQuestion<'_> {
        CachedQuestion {
            method: HttpMethod::Get,
            host: "shop.acme.test",
            path: "/orders",
            query,
        }
    }

    /// Requests for the same orders page by different signed-in users produce different keys.
    #[test]
    fn one_callers_answer_is_never_filed_under_anothers_key() {
        let ann = CacheKey::for_request(
            &signed_in_as(UserId::new()),
            CacheScope::PerUser,
            orders(None),
        );
        let sam = CacheKey::for_request(
            &signed_in_as(UserId::new()),
            CacheScope::PerUser,
            orders(None),
        );

        assert!(ann.is_some());
        assert_ne!(ann, sam);
    }

    /// Shared caching produces no key for a signed-in caller, and per-user
    /// caching produces none for an anonymous caller.
    #[test]
    fn a_scope_that_does_not_fit_the_caller_keeps_nothing() {
        let shared = CacheKey::for_request(
            &signed_in_as(UserId::new()),
            CacheScope::Shared,
            orders(None),
        );
        let per_user = CacheKey::for_request(&context(), CacheScope::PerUser, orders(None));

        assert_eq!(shared, None);
        assert_eq!(per_user, None);
    }

    /// Moving a character across the path/query boundary produces a different cache key.
    #[test]
    fn parts_never_run_together() {
        let ctx = context();
        let key = |path, query| {
            CacheKey::for_request(
                &ctx,
                CacheScope::Shared,
                CachedQuestion {
                    method: HttpMethod::Get,
                    host: "shop.acme.test",
                    path,
                    query: Some(query),
                },
            )
        };

        assert_ne!(key("/a", "b=1"), key("/ab", "=1"));
    }

    /// Debug formatting a cache key omits the request path and the token in its query.
    #[test]
    fn a_key_never_prints_the_caller_or_the_query() {
        let ctx = context();
        let key =
            CacheKey::for_request(&ctx, CacheScope::Shared, orders(Some("token=s3cret"))).unwrap();

        let printed = format!("{key:?}");

        assert!(!printed.contains("s3cret"));
        assert!(!printed.contains("/orders"));
    }
}
