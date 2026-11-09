//! `Cache`, its store step: keeping an answer the cache may serve again.
//!
//! Only an answer that can be served to the same question again is kept: a
//! `GET`, answered with success, read whole, no larger than the cache's
//! limit, setting no cookie, varying on nothing the key leaves out, and not
//! marked `no-store`. It is filed per tenant and per caller under the app's
//! [`CacheKey`], so one caller's answer never reaches another.
//!
//! The cache runs last among the response stages, so what it keeps was
//! already redacted, transformed and signed. An answer it cannot keep still
//! reaches the client: not caching is always safe.

pub(crate) use ianua_app::ports::proxy::{CacheKey, CachedAnswer, CachedQuestion, ResponseCache};
use ianua_app::ports::proxy::{ResponseMeta, ResponseStageOutcome};
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::stages::stage::CacheConfig;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::HttpMethod;

use super::body::headers_named;
use super::{Exchange, ResponseRead, ResponseStages, unchanged};

impl<'a> From<Exchange<'a>> for CachedQuestion<'a> {
    fn from(exchange: Exchange<'a>) -> Self {
        Self {
            method: exchange.request.method(),
            host: exchange.request.host().as_str(),
            path: exchange.request.path().as_str(),
            query: exchange.query,
        }
    }
}

/// Why an answer is not kept, or `None` when it may be.
fn not_kept(
    exchange: Exchange<'_>,
    response: &ResponseMeta,
    body: CapturedBody<'_>,
    max_body: u64,
) -> Option<&'static str> {
    if exchange.request.method() != HttpMethod::Get {
        return Some("only a GET is cached");
    }
    if !(200..300).contains(&response.status) || response.status == 206 {
        return Some("only a whole successful answer is cached");
    }
    if !body.is_whole() || u64::try_from(body.bytes.len()).unwrap_or(u64::MAX) > max_body {
        return Some("the answer is larger than the cache keeps");
    }
    if headers_named(&response.headers, "set-cookie")
        .next()
        .is_some()
    {
        return Some("an answer setting a cookie is never cached");
    }
    if headers_named(&response.headers, "vary").next().is_some() {
        return Some("an answer that varies is not cached");
    }
    forbids_storing(response).then_some("the upstream forbids storing the answer")
}

/// Whether the answer's `Cache-Control` forbids a cache to keep it.
fn forbids_storing(response: &ResponseMeta) -> bool {
    headers_named(&response.headers, "cache-control")
        .flat_map(|value| value.split(','))
        .map(|directive| directive.trim().split('=').next().unwrap_or_default())
        .any(|directive| directive.eq_ignore_ascii_case("no-store"))
}

impl ResponseStages {
    /// Keeps the answer when it may be served again, filed per tenant and
    /// caller. The answer always reaches the client unchanged.
    ///
    /// # Errors
    ///
    /// Never: an answer the cache cannot keep is passed on.
    pub(crate) async fn cache_store(
        &self,
        config: &CacheConfig,
        exchange: Exchange<'_>,
        read: ResponseRead<'_>,
    ) -> Result<ResponseStageOutcome, DomainError> {
        let ResponseRead {
            context: ctx,
            meta: response,
            body,
        } = read;
        let max_body = self.limits.cache_max_body.get();
        if let Some(reason) = not_kept(exchange, response, body, max_body) {
            return Ok(unchanged(reason));
        }
        let Some(key) = CacheKey::for_request(ctx, config.vary_by_user, exchange) else {
            return Ok(unchanged("the cache keeps nothing for this caller"));
        };
        let answer = CachedAnswer {
            status: response.status,
            headers: &response.headers,
            body: body.bytes,
        };
        let stored = self
            .within(self.cache.store(&key, answer, config.ttl_seconds))
            .await;
        if let Err(error) = stored {
            tracing::warn!(%error, "an answer could not be cached");
            return Ok(unchanged("the answer could not be cached"));
        }
        Ok(unchanged("cached"))
    }
}

#[cfg(test)]
pub(crate) mod fakes {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_app::ports::proxy::KeptAnswer;
    use ianua_domain::types::Seconds;

    use super::*;

    /// A cache that keeps what it is given, by key.
    #[derive(Default)]
    pub(crate) struct FakeCache {
        kept: Mutex<Vec<(CacheKey, KeptAnswer)>>,
    }

    impl FakeCache {
        /// The keys and bodies kept so far.
        pub(crate) fn kept(&self) -> Vec<(CacheKey, Vec<u8>)> {
            self.kept
                .lock()
                .unwrap()
                .iter()
                .map(|(key, answer)| (key.clone(), answer.body.clone()))
                .collect()
        }
    }

    #[async_trait]
    impl ResponseCache for FakeCache {
        async fn store(
            &self,
            key: &CacheKey,
            answer: CachedAnswer<'_>,
            _: Seconds,
        ) -> Result<(), DomainError> {
            let kept = KeptAnswer {
                status: answer.status,
                headers: answer.headers.to_vec(),
                body: answer.body.to_vec(),
            };
            self.kept.lock().unwrap().push((key.clone(), kept));
            Ok(())
        }

        async fn lookup(&self, key: &CacheKey) -> Result<Option<KeptAnswer>, DomainError> {
            Ok(self
                .kept
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(kept, _)| kept == key)
                .map(|(_, answer)| answer.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::request::body::BodyExtent;
    use ianua_domain::domains::proxy::request::context::{
        Caller, PipelineContext, UserSignIn, Verified,
    };
    use ianua_domain::domains::proxy::stages::stage::CacheScope;
    use ianua_domain::types::{Expiry, Seconds, UserId};

    use super::*;
    use crate::pipeline::stages::response::fixtures::{
        Fakes, admitted, answer, context, is_unchanged, json,
    };
    use crate::request::Admitted;

    fn config(scope: CacheScope) -> CacheConfig {
        CacheConfig {
            ttl_seconds: Seconds::new(60),
            vary_by_user: scope,
        }
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

    fn exchange(request: &Admitted) -> Exchange<'_> {
        Exchange {
            request,
            query: None,
        }
    }

    async fn store(
        fakes: &Fakes,
        request: &Admitted,
        read: ResponseRead<'_>,
    ) -> ResponseStageOutcome {
        fakes
            .stages()
            .cache_store(&config(CacheScope::PerUser), exchange(request), read)
            .await
            .unwrap()
    }

    /// Ann's successful `GET` is kept, and the answer still reaches her.
    #[tokio::test]
    async fn a_successful_answer_is_kept() {
        let fakes = Fakes::default();
        let request = admitted("GET", "/orders");

        let outcome = store(
            &fakes,
            &request,
            ResponseRead {
                context: &signed_in_as(UserId::new()),
                meta: &json(),
                body: CapturedBody::new(b"[]", BodyExtent::Whole),
            },
        )
        .await;

        assert!(is_unchanged(&outcome));
        assert_eq!(fakes.cache.kept()[0].1, b"[]");
    }

    /// Ann and Sam receive different cache keys for the same orders page;
    /// an anonymous request has no key under a per-caller cache.
    #[test]
    fn one_callers_answer_is_never_filed_under_anothers_key() {
        let request = admitted("GET", "/orders");
        let ann = signed_in_as(UserId::new());
        let sam = signed_in_as(UserId::new());

        let for_ann = CacheKey::for_request(&ann, CacheScope::PerUser, exchange(&request));
        let for_sam = CacheKey::for_request(&sam, CacheScope::PerUser, exchange(&request));

        assert!(for_ann.is_some());
        assert_ne!(for_ann, for_sam);
        assert_eq!(
            CacheKey::for_request(&context(), CacheScope::PerUser, exchange(&request)),
            None
        );
    }

    /// A shared cache produces no key for a signed-in caller, while an
    /// anonymous request for the same page receives one.
    #[test]
    fn a_shared_cache_keeps_nothing_for_a_signed_in_caller() {
        let request = admitted("GET", "/news");

        assert_eq!(
            CacheKey::for_request(
                &signed_in_as(UserId::new()),
                CacheScope::Shared,
                exchange(&request)
            ),
            None
        );
        assert!(
            CacheKey::for_request(&context(), CacheScope::Shared, exchange(&request)).is_some()
        );
    }

    /// The same caller asking two different questions gets two keys, and
    /// the same question in two tenants gets two keys.
    #[test]
    fn the_key_follows_the_question_and_the_tenant() {
        let orders = admitted("GET", "/orders");
        let invoices = admitted("GET", "/invoices");
        let ctx = context();
        let key = |ctx: &PipelineContext, request: &Admitted, query| {
            CacheKey::for_request(ctx, CacheScope::Shared, Exchange { request, query })
        };

        assert_ne!(key(&ctx, &orders, None), key(&ctx, &invoices, None));
        assert_ne!(key(&ctx, &orders, None), key(&ctx, &orders, Some("page=2")));
        assert_ne!(key(&ctx, &orders, None), key(&context(), &orders, None));
    }

    /// A `POST`, an error, a body read in part, a body over the limit, an
    /// answer setting a cookie, one that varies and one marked `no-store`
    /// are not kept.
    #[tokio::test]
    async fn an_answer_that_cannot_be_served_again_is_not_kept() {
        let ann = signed_in_as(UserId::new());
        let get = admitted("GET", "/orders");
        let post = admitted("POST", "/orders");
        let large = vec![b'a'; 2048];
        for (request, response, body) in uncacheable(&get, &post, &large) {
            let fakes = Fakes::default();
            let read = ResponseRead {
                context: &ann,
                meta: &response,
                body,
            };
            let outcome = store(&fakes, request, read).await;

            assert!(is_unchanged(&outcome));
            assert!(fakes.cache.kept().is_empty(), "{:?}", response.headers);
        }
    }

    /// Answers disqualified independently by method, status, extent, size or headers.
    fn uncacheable<'a>(
        get: &'a Admitted,
        post: &'a Admitted,
        large: &'a [u8],
    ) -> [(&'a Admitted, ResponseMeta, CapturedBody<'a>); 7] {
        [
            (post, json(), CapturedBody::new(b"{}", BodyExtent::Whole)),
            (
                get,
                answer(500, &[]),
                CapturedBody::new(b"{}", BodyExtent::Whole),
            ),
            (get, json(), CapturedBody::new(b"[", BodyExtent::Prefix)),
            (get, json(), CapturedBody::new(large, BodyExtent::Whole)),
            (
                get,
                answer(200, &[("set-cookie", "session=s3cret")]),
                CapturedBody::new(b"{}", BodyExtent::Whole),
            ),
            (
                get,
                answer(200, &[("vary", "accept-language")]),
                CapturedBody::new(b"{}", BodyExtent::Whole),
            ),
            (
                get,
                answer(200, &[("cache-control", "private, no-store")]),
                CapturedBody::new(b"{}", BodyExtent::Whole),
            ),
        ]
    }
}
