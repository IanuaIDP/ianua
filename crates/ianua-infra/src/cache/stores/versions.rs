//! The version every node keeps an owner's cached entries under, held in
//! shared state so a change one node makes is seen by all at once.
//!
//! A version is a fresh unique word, never a count: a count that lapsed or
//! was lost with a cache server's restart would start again and could meet
//! a number entries were kept under before. Raising a version writes a new
//! word; reading one that is not there writes one too, so no entry is ever
//! kept under "no version". A node reads the version before it reads the
//! store and keeps what it read under that version: once a change is
//! committed and the version raised, every entry worked out before it is
//! kept under a word nobody reads again.

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::cache::state::{CacheError, SharedState, key};
use crate::cache::stores::owners::Owner;

/// What a store cache keeps, each under versions of its own, so a change to
/// one never drops the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Cached {
    /// The callers bearers resolve to: which sessions and keys still
    /// answer.
    Callers,
    /// What decides a holder's holdings: roles, groups, assignments,
    /// memberships, resource types and break-glass grants.
    Holdings,
    /// The public halves of a tenant's signing keys, which the gateway
    /// checks the tokens it is shown against.
    SigningKeys,
    /// The assertion key the gateway signs a tenant's upstream identities
    /// and message signatures with, its private half opened.
    AssertionKeys,
    /// A tenant's classification rule set, which the gateway classifies
    /// and redacts by.
    Classifications,
}

impl Cached {
    /// Every store cache.
    pub(crate) const ALL: &'static [Self] = &[
        Self::Callers,
        Self::Holdings,
        Self::SigningKeys,
        Self::AssertionKeys,
        Self::Classifications,
    ];

    /// The cache as a part of a key.
    fn word(self) -> &'static str {
        match self {
            Self::Callers => "callers",
            Self::Holdings => "holdings",
            Self::SigningKeys => "signing-keys",
            Self::AssertionKeys => "assertion-keys",
            Self::Classifications => "classifications",
        }
    }
}

/// One version of one owner's entries in one cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version(String);

/// The versions, in shared state every node reads.
pub(crate) struct Versions {
    state: Arc<dyn SharedState>,
    kept: Duration,
}

impl Versions {
    /// Versions in `state`, each kept `kept` past its last raise. It must
    /// be far longer than any entry's lifetime.
    pub(crate) fn new(state: Arc<dyn SharedState>, kept: Duration) -> Self {
        Self { state, kept }
    }

    /// The key of `owner`'s version in `cached`.
    fn key(cached: Cached, owner: Owner) -> String {
        key(&["store", "version", cached.word(), &owner.word()])
    }

    /// The version `owner`'s entries in `cached` are kept under now.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer: the caller then
    /// reads the store and keeps nothing.
    pub(crate) async fn current(
        &self,
        cached: Cached,
        owner: Owner,
    ) -> Result<Version, CacheError> {
        match self.state.text(&Self::key(cached, owner)).await? {
            Some(word) => Ok(Version(word)),
            None => self.raise(cached, owner).await,
        }
    }

    /// Moves `owner`'s entries in `cached` to a fresh version, so none
    /// kept before is read again, and answers it.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    pub(crate) async fn raise(&self, cached: Cached, owner: Owner) -> Result<Version, CacheError> {
        let fresh = Uuid::now_v7().simple().to_string();
        self.state
            .swap(&Self::key(cached, owner), &fresh, self.kept)
            .await?;
        Ok(Version(fresh))
    }
}

/// Shared state that never answers, for the tests of what holds while the
/// cache server is down.
#[cfg(test)]
pub(crate) struct RefusingState;

#[cfg(test)]
#[async_trait::async_trait]
impl SharedState for RefusingState {
    async fn count(&self, _: &str, _: u64, _: Duration) -> Result<u64, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn read(&self, _: &str) -> Result<Option<u64>, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn lower(&self, _: &str, _: u64) -> Result<Option<u64>, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn hold(&self, _: &str, _: Duration) -> Result<(), CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn add_distinct(&self, _: &str, _: &[String], _: Duration) -> Result<u64, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn distinct(&self, _: &str) -> Result<u64, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn claim_once(&self, _: &str, _: Duration) -> Result<bool, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn swap(&self, _: &str, _: &str, _: Duration) -> Result<Option<String>, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn keep(&self, _: &str, _: &str, _: Duration) -> Result<(), CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn text(&self, _: &str) -> Result<Option<String>, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn forget(&self, _: &str) -> Result<(), CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn log(
        &self,
        _: &str,
        _: &crate::cache::state::LogEntry<'_>,
        _: Duration,
    ) -> Result<(), CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn log_since(&self, _: &str, _: i64) -> Result<Vec<String>, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn enroll(
        &self,
        _: &str,
        _: &crate::cache::state::LogEntry<'_>,
        _: crate::cache::state::LogCapacity,
    ) -> Result<bool, CacheError> {
        Err(CacheError::TimedOut)
    }

    async fn ping(&self) -> Result<(), CacheError> {
        Err(CacheError::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::MemoryState;

    fn versions() -> Versions {
        Versions::new(Arc::new(MemoryState::new(100)), Duration::from_secs(60))
    }

    fn acme() -> Owner {
        Owner::Tenant(Uuid::now_v7())
    }

    /// A version read twice is the same until it is raised, and differs
    /// after.
    #[tokio::test]
    async fn a_version_holds_until_raised() {
        let versions = versions();
        let acme = acme();

        let first = versions.current(Cached::Holdings, acme).await.unwrap();
        let again = versions.current(Cached::Holdings, acme).await.unwrap();
        versions.raise(Cached::Holdings, acme).await.unwrap();
        let after = versions.current(Cached::Holdings, acme).await.unwrap();

        assert_eq!(first, again);
        assert_ne!(first, after);
    }

    /// Raising one cache's version leaves another cache's, and another
    /// owner's, alone.
    #[tokio::test]
    async fn a_raise_moves_one_cache_of_one_owner() {
        let versions = versions();
        let (acme, globex) = (acme(), acme());
        let callers = versions.current(Cached::Callers, acme).await.unwrap();
        let globex_holdings = versions.current(Cached::Holdings, globex).await.unwrap();

        versions.raise(Cached::Holdings, acme).await.unwrap();

        assert_eq!(
            versions.current(Cached::Callers, acme).await.unwrap(),
            callers
        );
        assert_eq!(
            versions.current(Cached::Holdings, globex).await.unwrap(),
            globex_holdings
        );
    }

    /// A fresh shared-state instance generates a version different from the cached one.
    #[tokio::test]
    async fn a_lost_version_never_comes_back() {
        let acme = acme();
        let before = versions().current(Cached::Holdings, acme).await.unwrap();

        let after_restart = versions().current(Cached::Holdings, acme).await.unwrap();

        assert_ne!(before, after_restart);
    }
}
