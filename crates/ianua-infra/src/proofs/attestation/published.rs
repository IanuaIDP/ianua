//! The keys an issuer publishes, and how they are kept between proofs.
//!
//! [`IssuerKeys`] is the seam every token attestation reads keys through.
//! [`FixedIssuerKeys`] reads one issuer's keys from an address the platform
//! configured, such as Google's for its instance identity tokens; the
//! discovered kind reads any trusted issuer's from its discovery document.
//!
//! Each issuer's keys are fetched once and kept for a while, so each
//! attestation does not call the issuer. A token naming a key the kept set
//! lacks makes one fetch anew, for an issuer that rotated its keys, but
//! never sooner than a floor after the last fetch, so tokens naming made-up
//! keys cannot make the platform call the issuer on every attempt. Fetches
//! of one issuer wait for each other; fetches of two issuers do not. A key
//! set that cannot be fetched, or is not one, is an error: nothing is
//! checked against keys that were not read, and no key set is kept past
//! its time because the issuer is down.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::attestation::WorkloadIssuer;
use ianua_domain::shared::errors::DomainError;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};

use crate::crypto::jws::{Compact, JwsAlgorithm, PublicKey, read_jwk};
use crate::http::client::{body_within, fixed};
use crate::proofs::attestation::refused;

/// The most bytes a key set may hold.
pub(crate) const MOST_KEY_SET_BYTES: usize = 65_536;

/// The most keys a key set may list.
const MOST_KEYS: usize = 32;

/// Where a trusted issuer's published keys are read from, inside the
/// adapters.
#[async_trait]
pub trait IssuerKeys: Send + Sync {
    /// The keys `issuer` publishes, as its JWK Set lists them, kept from an
    /// earlier fetch while they are fresh.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be fetched in
    /// time, and `DomainError::Unauthorized` when no keys are read for
    /// `issuer` here.
    async fn keys_of(&self, issuer: &WorkloadIssuer) -> Result<Vec<Value>, DomainError>;

    /// The keys `issuer` publishes, fetched anew unless they were fetched
    /// within the floor: for a token naming a key the kept set lacks.
    ///
    /// # Errors
    ///
    /// As [`keys_of`](Self::keys_of).
    async fn renewed_keys_of(&self, issuer: &WorkloadIssuer) -> Result<Vec<Value>, DomainError>;
}

/// How long an issuer's keys are kept, and how soon they may be fetched
/// again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyKeeping {
    /// How long a fetched key set is used before it is fetched again.
    pub keep_for: Duration,
    /// The shortest time between two fetches of one issuer's keys, even
    /// for a token naming a key the kept set lacks.
    pub renew_after: Duration,
}

/// Whether kept keys serve, or the issuer is asked again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wanted {
    /// Kept keys serve while they are fresh.
    Kept,
    /// The issuer is asked again unless it was asked within the floor.
    Renewed,
}

/// A key set fetched, and when.
struct Fetched {
    at: Instant,
    keys: Vec<Value>,
}

/// One issuer's place in the cache: its keys, if fetched, behind a lock
/// that each fetch of that issuer holds.
type Slot = Arc<Mutex<Option<Fetched>>>;

/// The key sets of at most a bounded number of sources, each kept for a
/// while and fetched at most once at a time. A source is an issuer, or the
/// address a client publishes its keys at.
pub(crate) struct KeyCache<Source = WorkloadIssuer> {
    keeping: KeyKeeping,
    most_issuers: usize,
    slots: RwLock<HashMap<Source, (Instant, Slot)>>,
}

impl<Source: Clone + Eq + Hash> KeyCache<Source> {
    /// A cache keeping keys as `keeping` says, for at most `most_issuers`
    /// sources at once; past that, the source added first is dropped.
    pub(crate) fn new(keeping: KeyKeeping, most_issuers: usize) -> Self {
        Self {
            keeping,
            most_issuers: most_issuers.max(1),
            slots: RwLock::new(HashMap::new()),
        }
    }

    /// The keys of `issuer`, kept or read through `fetch` as `wanted` says.
    pub(crate) async fn keys<F, Fut>(
        &self,
        issuer: &Source,
        wanted: Wanted,
        fetch: F,
    ) -> Result<Vec<Value>, DomainError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<Vec<Value>, DomainError>> + Send,
    {
        let slot = self.slot(issuer).await;
        let mut held = slot.lock().await;
        if let Some(keys) = usable(held.as_ref(), wanted, self.keeping) {
            return Ok(keys);
        }
        let keys = fetch().await?;
        *held = Some(Fetched {
            at: Instant::now(),
            keys: keys.clone(),
        });
        Ok(keys)
    }

    /// The slot of `issuer`, made when it has none.
    async fn slot(&self, issuer: &Source) -> Slot {
        if let Some((_, slot)) = self.slots.read().await.get(issuer) {
            return Arc::clone(slot);
        }
        let mut slots = self.slots.write().await;
        if let Some((_, slot)) = slots.get(issuer) {
            return Arc::clone(slot);
        }
        if slots.len() >= self.most_issuers {
            drop_oldest(&mut slots);
        }
        let slot = Slot::default();
        slots.insert(issuer.clone(), (Instant::now(), Arc::clone(&slot)));
        slot
    }
}

/// Drops the slot added first.
fn drop_oldest<Source: Clone + Eq + Hash>(slots: &mut HashMap<Source, (Instant, Slot)>) {
    let oldest = slots
        .iter()
        .min_by_key(|(_, (added, _))| *added)
        .map(|(issuer, _)| issuer.clone());
    if let Some(issuer) = oldest {
        slots.remove(&issuer);
    }
}

/// The keys of `fetched` when `wanted` lets them serve under `keeping`.
fn usable(fetched: Option<&Fetched>, wanted: Wanted, keeping: KeyKeeping) -> Option<Vec<Value>> {
    let fetched = fetched?;
    let longest = match wanted {
        Wanted::Kept => keeping.keep_for,
        Wanted::Renewed => keeping.renew_after.min(keeping.keep_for),
    };
    (fetched.at.elapsed() < longest).then(|| fetched.keys.clone())
}

/// A JWK Set as an issuer publishes it.
#[derive(Deserialize)]
struct KeySet {
    keys: Vec<Value>,
}

/// The keys of the JWK Set `body` holds, refused when it lists none or
/// more than [`MOST_KEYS`].
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when `body` is no such key set.
pub(crate) fn key_set_in(body: &[u8]) -> Result<Vec<Value>, DomainError> {
    let set: KeySet = serde_json::from_slice(body).map_err(DomainError::infra)?;
    if set.keys.is_empty() || set.keys.len() > MOST_KEYS {
        return Err(DomainError::infra_msg(
            "the issuer's key set lists no keys, or too many",
        ));
    }
    Ok(set.keys)
}

/// The key of `issuer` the token's `kid` names, of one of `algorithms`:
/// read from the kept keys, and from keys fetched anew when they lack it.
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` when the token names no key, or
/// none of `algorithms` that the issuer publishes, and the errors of
/// [`IssuerKeys`].
pub(crate) async fn named_key(
    keys: &dyn IssuerKeys,
    issuer: &WorkloadIssuer,
    token: &Compact,
    algorithms: &[JwsAlgorithm],
) -> Result<PublicKey, DomainError> {
    let Some(kid) = token.header().kid.as_deref() else {
        return Err(refused("the token names no key"));
    };
    if let Some(key) = key_in(&keys.keys_of(issuer).await?, kid, algorithms) {
        return Ok(key);
    }
    key_in(&keys.renewed_keys_of(issuer).await?, kid, algorithms)
        .ok_or_else(|| refused("the issuer publishes no key the token names"))
}

/// The key of `keys` listed under `kid`, when it signs with one of
/// `algorithms`.
fn key_in(keys: &[Value], kid: &str, algorithms: &[JwsAlgorithm]) -> Option<PublicKey> {
    keys.iter()
        .filter_map(|key| read_jwk(key).ok())
        .filter(|jwk| jwk.kid.as_deref() == Some(kid))
        .map(|jwk| jwk.key)
        .find(|key| algorithms.contains(&key.algorithm()))
}

/// The keys of one issuer, read from the address the platform configured
/// for them.
pub struct FixedIssuerKeys {
    issuer: WorkloadIssuer,
    address: url::Url,
    client: reqwest::Client,
    cache: KeyCache,
}

impl FixedIssuerKeys {
    /// The keys `issuer` publishes at `address`, each fetch held to
    /// `timeout`, kept as `keeping` says.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(
        issuer: WorkloadIssuer,
        address: url::Url,
        timeout: Duration,
        keeping: KeyKeeping,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            issuer,
            address,
            client: fixed(timeout)?,
            cache: KeyCache::new(keeping, 1),
        })
    }

    /// The key set read from the issuer now.
    async fn fetch(&self) -> Result<Vec<Value>, DomainError> {
        let response = self
            .client
            .get(self.address.clone())
            .send()
            .await
            .map_err(DomainError::infra)?
            .error_for_status()
            .map_err(DomainError::infra)?;
        key_set_in(&body_within(response, MOST_KEY_SET_BYTES).await?)
    }

    /// The keys of `issuer` as `wanted` says, refused for any issuer but
    /// this one's.
    async fn keys(
        &self,
        issuer: &WorkloadIssuer,
        wanted: Wanted,
    ) -> Result<Vec<Value>, DomainError> {
        if *issuer != self.issuer {
            return Err(refused("no keys are read for that issuer"));
        }
        self.cache.keys(issuer, wanted, || self.fetch()).await
    }
}

#[async_trait]
impl IssuerKeys for FixedIssuerKeys {
    async fn keys_of(&self, issuer: &WorkloadIssuer) -> Result<Vec<Value>, DomainError> {
        self.keys(issuer, Wanted::Kept).await
    }

    async fn renewed_keys_of(&self, issuer: &WorkloadIssuer) -> Result<Vec<Value>, DomainError> {
        self.keys(issuer, Wanted::Renewed).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn google() -> WorkloadIssuer {
        WorkloadIssuer::new("https://accounts.google.com").unwrap()
    }

    async fn publishing(response: ResponseTemplate, times: u64) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/certs"))
            .respond_with(response)
            .expect(times)
            .mount(&server)
            .await;
        server
    }

    fn keeping(renew_after: Duration) -> KeyKeeping {
        KeyKeeping {
            keep_for: Duration::from_secs(600),
            renew_after,
        }
    }

    fn keys_at(server: &MockServer, renew_after: Duration) -> FixedIssuerKeys {
        let address = url::Url::parse(&format!("{}/certs", server.uri())).unwrap();
        FixedIssuerKeys::new(
            google(),
            address,
            Duration::from_secs(5),
            keeping(renew_after),
        )
        .unwrap()
    }

    fn set() -> Value {
        json!({"keys": [{"kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB"}]})
    }

    /// The issuer's keys are fetched once and then kept.
    #[tokio::test]
    async fn the_key_set_is_fetched_once_and_kept() {
        let server = publishing(ResponseTemplate::new(200).set_body_json(set()), 1).await;
        let keys = keys_at(&server, Duration::from_secs(60));

        let first = keys.keys_of(&google()).await.unwrap();
        let second = keys.keys_of(&google()).await.unwrap();

        assert_eq!(first.len(), 1);
        assert_eq!(first, second);
    }

    /// Renewal within the minimum interval reuses cached keys, leaving the issuer with one request.
    #[tokio::test]
    async fn keys_are_not_renewed_within_the_floor() {
        let server = publishing(ResponseTemplate::new(200).set_body_json(set()), 1).await;
        let keys = keys_at(&server, Duration::from_secs(60));

        keys.keys_of(&google()).await.unwrap();
        keys.renewed_keys_of(&google()).await.unwrap();
        keys.renewed_keys_of(&google()).await.unwrap();

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// An issuer that rotated its keys is asked again for a token naming a
    /// key the kept set lacks, once the floor has passed.
    #[tokio::test]
    async fn keys_are_renewed_after_the_floor() {
        let server = publishing(ResponseTemplate::new(200).set_body_json(set()), 2).await;
        let keys = keys_at(&server, Duration::ZERO);

        keys.keys_of(&google()).await.unwrap();
        keys.renewed_keys_of(&google()).await.unwrap();

        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// Asking for a different issuer is unauthorized and sends no request to the configured key endpoint.
    #[tokio::test]
    async fn keys_are_read_only_for_their_own_issuer() {
        let server = publishing(ResponseTemplate::new(200), 0).await;
        let other = WorkloadIssuer::new("https://token.actions.githubusercontent.com").unwrap();

        let read = keys_at(&server, Duration::from_secs(60))
            .keys_of(&other)
            .await;

        assert!(matches!(read, Err(DomainError::Unauthorized(_))));
    }

    /// An HTTP failure, empty key set or oversized response returns an infrastructure error.
    #[tokio::test]
    async fn a_key_set_that_is_not_one_is_an_error() {
        for response in [
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).set_body_json(json!({"keys": []})),
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MOST_KEY_SET_BYTES + 1]),
        ] {
            let server = publishing(response, 1).await;

            let read = keys_at(&server, Duration::from_secs(60))
                .keys_of(&google())
                .await;

            assert!(matches!(read, Err(DomainError::Infrastructure(_))));
        }
    }

    /// Adding a third issuer to a two-entry cache evicts the first;
    /// asking for that issuer again makes a fourth fetch.
    #[tokio::test]
    async fn the_cache_holds_a_bounded_number_of_issuers() {
        let cache = KeyCache::new(keeping(Duration::from_secs(60)), 2);
        let issuers: Vec<WorkloadIssuer> = ["a", "b", "c"]
            .into_iter()
            .map(|name| WorkloadIssuer::new(format!("https://{name}.example")).unwrap())
            .collect();
        let counted = AtomicUsize::new(0);
        let fetches = &counted;
        let fetch = move || async move {
            fetches.fetch_add(1, Ordering::SeqCst);
            Ok::<_, DomainError>(vec![json!({"kty": "RSA"})])
        };

        for issuer in issuers.iter().chain(issuers.first()) {
            cache.keys(issuer, Wanted::Kept, fetch).await.unwrap();
        }

        assert_eq!(cache.slots.read().await.len(), 2);
        assert_eq!(counted.load(Ordering::SeqCst), 4);
    }
}
