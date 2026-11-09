//! The answers the gateway may serve again, kept on shared state so every
//! node serves what one kept.
//!
//! An answer is filed under the tenant, written plainly, and a SHA-256
//! digest of whose it is and the question it answers, so no caller id or
//! query string is ever readable on the cache server. It is kept whole, its
//! status, headers and body together, and lapses with its lifetime. One
//! answer may take at most the bound the cache was given: past it the
//! answer is refused, never cut short, and the client is served as if it
//! were never cached. So may the number of answers held at once: each takes
//! a place on one roster until it lapses, and once every place is taken no
//! new answer is kept, while those held stay.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ianua_app::ports::proxy::{CacheKey, CachedAnswer, KeptAnswer, ResponseCache};
use ianua_domain::domains::proxy::stages::decision::HeaderEntry;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HeaderName, HeaderValue, Seconds};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::cache::state::{LogCapacity, LogEntry, SharedState, key, micros};

/// The roster of the answers held, one place each, across every tenant.
const ROSTER: &str = "response-roster";

/// How long the roster outlives its last change: past the longest an
/// answer may be kept, a week, so it never lapses under a live answer.
const ROSTER_KEPT: Duration = Duration::from_secs(8 * 24 * 60 * 60);

/// An answer as the cache server holds it.
#[derive(Serialize, Deserialize)]
struct Stored {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Stored {
    fn of(answer: CachedAnswer<'_>) -> Self {
        Self {
            status: answer.status,
            headers: answer
                .headers
                .iter()
                .map(|header| {
                    (
                        header.name().as_str().to_owned(),
                        header.value().as_str().to_owned(),
                    )
                })
                .collect(),
            body: STANDARD.encode(answer.body),
        }
    }

    /// The answer it holds, every header checked again: the cache server is
    /// not trusted to hand back only what was kept.
    fn into_answer(self) -> Result<KeptAnswer, DomainError> {
        let headers = self
            .headers
            .into_iter()
            .map(|(name, value)| {
                Ok(HeaderEntry::new(
                    HeaderName::new(name)?,
                    HeaderValue::new(value)?,
                ))
            })
            .collect::<Result<Vec<_>, DomainError>>()?;
        let body = STANDARD.decode(self.body).map_err(DomainError::infra)?;
        Ok(KeptAnswer {
            status: self.status,
            headers,
            body,
        })
    }
}

/// How much the cache keeps: the largest answer and how many at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseRoom {
    /// The most bytes one answer takes as the cache server holds it,
    /// headers and encoded body together.
    pub largest_entry: usize,
    /// The most answers held at once, across every tenant and node. Past
    /// it nothing more is kept, and nothing held is pushed out.
    pub entries: u64,
}

/// The answers the gateway may serve again, on shared state.
pub struct CacheResponseCache {
    state: Arc<dyn SharedState>,
    room: ResponseRoom,
}

impl std::fmt::Debug for CacheResponseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheResponseCache")
            .field("room", &self.room)
            .finish_non_exhaustive()
    }
}

impl CacheResponseCache {
    /// A cache on `state` keeping what `room` allows.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>, room: ResponseRoom) -> Self {
        Self { state, room }
    }

    /// Takes a place among the answers held for the answer at `held`,
    /// lapsing `ttl` from now. The roster lists each answer held under the
    /// moment it lapses, so the answers that lapsed give their places back.
    async fn reserve_entry(&self, held: &str, ttl: Seconds) -> Result<(), DomainError> {
        let now = clock::now();
        let entry = LogEntry {
            text: held,
            at: micros(now.saturating_add(ttl.duration())),
            forget_before: micros(now),
        };
        let placed = self
            .state
            .enroll(
                ROSTER,
                &entry,
                LogCapacity {
                    entries: self.room.entries,
                    keep: ROSTER_KEPT,
                },
            )
            .await?;
        if !placed {
            return Err(DomainError::infra_msg(
                "the cache holds as many answers as it may",
            ));
        }
        Ok(())
    }
}

/// The key the answer filed under `cache_key` is held at.
fn held_at(cache_key: &CacheKey) -> String {
    let question = URL_SAFE_NO_PAD.encode(Sha256::digest(cache_key.question().as_bytes()));
    key(&[
        "response",
        &cache_key.tenant_id().as_uuid().simple().to_string(),
        &question,
    ])
}

#[async_trait]
impl ResponseCache for CacheResponseCache {
    async fn store(
        &self,
        key: &CacheKey,
        answer: CachedAnswer<'_>,
        ttl: Seconds,
    ) -> Result<(), DomainError> {
        let stored = serde_json::to_string(&Stored::of(answer)).map_err(DomainError::infra)?;
        if stored.len() > self.room.largest_entry {
            return Err(DomainError::infra_msg(
                "the answer is larger than the cache keeps one",
            ));
        }
        let held = held_at(key);
        self.reserve_entry(&held, ttl).await?;
        self.state.keep(&held, &stored, ttl.std_duration()).await?;
        Ok(())
    }

    async fn lookup(&self, key: &CacheKey) -> Result<Option<KeptAnswer>, DomainError> {
        let Some(stored) = self.state.text(&held_at(key)).await? else {
            return Ok(None);
        };
        let stored: Stored = serde_json::from_str(&stored).map_err(DomainError::infra)?;
        stored.into_answer().map(Some)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::proxy::CachedQuestion;
    use ianua_domain::domains::proxy::request::context::PipelineContext;
    use ianua_domain::domains::proxy::stages::stage::CacheScope;
    use ianua_domain::types::{CorrelationId, HttpMethod, PipelineId, TenantId};

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::stores::RefusingState;

    /// Acme's question for its orders, one tenant across every test, so
    /// asking it twice files it under one key.
    fn orders_key(query: Option<&str>) -> CacheKey {
        let acme = TenantId::from_uuid(uuid::Uuid::from_u128(1));
        let ctx = PipelineContext::new(acme, PipelineId::new(), CorrelationId::new());
        CacheKey::for_request(
            &ctx,
            CacheScope::Shared,
            CachedQuestion {
                method: HttpMethod::Get,
                host: "shop.acme.test",
                path: "/orders",
                query,
            },
        )
        .unwrap()
    }

    fn json() -> Vec<HeaderEntry> {
        vec![HeaderEntry::new(
            HeaderName::new("content-type").unwrap(),
            HeaderValue::new("application/json").unwrap(),
        )]
    }

    fn cache_on(state: Arc<dyn SharedState>) -> CacheResponseCache {
        CacheResponseCache::new(
            state,
            ResponseRoom {
                largest_entry: 4_096,
                entries: 2,
            },
        )
    }

    fn small(status: u16) -> CachedAnswer<'static> {
        CachedAnswer {
            status,
            headers: &[],
            body: b"{}",
        }
    }

    /// A full response cache rejects a new key while preserving existing entries
    /// and allowing an existing response to be updated.
    #[tokio::test]
    async fn past_its_room_no_new_answer_is_kept() {
        let cache = cache_on(Arc::new(MemoryState::new(100)));
        let ttl = Seconds::new(60);
        cache
            .store(&orders_key(Some("p=1")), small(200), ttl)
            .await
            .unwrap();
        cache
            .store(&orders_key(Some("p=2")), small(200), ttl)
            .await
            .unwrap();

        let third = cache.store(&orders_key(Some("p=3")), small(200), ttl).await;
        let again = cache.store(&orders_key(Some("p=1")), small(201), ttl).await;

        assert!(third.is_err());
        assert!(again.is_ok());
        assert!(
            cache
                .lookup(&orders_key(Some("p=3")))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            cache
                .lookup(&orders_key(Some("p=2")))
                .await
                .unwrap()
                .is_some()
        );
    }

    /// An answer kept is found again whole: its status, its headers and
    /// its body, bytes that are not text included.
    #[tokio::test]
    async fn a_kept_answer_is_found_whole() {
        let cache = cache_on(Arc::new(MemoryState::new(100)));
        let key = orders_key(None);
        let headers = json();
        let body = [0x7b, 0x00, 0xff, 0x7d];

        cache
            .store(
                &key,
                CachedAnswer {
                    status: 200,
                    headers: &headers,
                    body: &body,
                },
                Seconds::new(60),
            )
            .await
            .unwrap();
        let found = cache.lookup(&key).await.unwrap().unwrap();

        assert_eq!(found.status, 200);
        assert_eq!(found.headers, headers);
        assert_eq!(found.body, body);
    }

    /// Nothing is found under a key nothing was kept under.
    #[tokio::test]
    async fn nothing_is_found_where_nothing_was_kept() {
        let cache = cache_on(Arc::new(MemoryState::new(100)));

        let found = cache.lookup(&orders_key(Some("page=2"))).await.unwrap();

        assert!(found.is_none());
    }

    /// An oversized response returns an error and leaves no cached entry.
    #[tokio::test]
    async fn an_answer_past_the_bound_is_refused() {
        let cache = cache_on(Arc::new(MemoryState::new(100)));
        let key = orders_key(None);
        let large = vec![b'a'; 8_192];

        let stored = cache
            .store(
                &key,
                CachedAnswer {
                    status: 200,
                    headers: &[],
                    body: &large,
                },
                Seconds::new(60),
            )
            .await;

        assert!(stored.is_err());
        assert!(cache.lookup(&key).await.unwrap().is_none());
    }

    /// Reading a planted response with line breaks in a header fails validation.
    #[tokio::test]
    async fn a_planted_header_is_refused() {
        let state: Arc<dyn SharedState> = Arc::new(MemoryState::new(100));
        let cache = cache_on(Arc::clone(&state));
        let key = orders_key(None);
        let planted = r#"{"status":200,"headers":[["x-a","1\r\nset-cookie: s=1"]],"body":""}"#;
        state
            .keep(&held_at(&key), planted, std::time::Duration::from_secs(60))
            .await
            .unwrap();

        let found = cache.lookup(&key).await;

        assert!(found.is_err());
    }

    /// The response cache key uses a digest and contains neither the path nor its secret query text.
    #[test]
    fn the_key_holds_no_query_string() {
        let key = orders_key(Some("token=s3cret"));

        let held = held_at(&key);

        assert!(!held.contains("s3cret"));
        assert!(!held.contains("/orders"));
        assert!(held.starts_with("response:"));
    }

    /// A cache server that is down answers an error, and the gateway
    /// forwards the request.
    #[tokio::test]
    async fn a_state_that_is_down_answers_an_error() {
        let cache = cache_on(Arc::new(RefusingState));

        let found = cache.lookup(&orders_key(None)).await;

        assert!(found.is_err());
    }
}
