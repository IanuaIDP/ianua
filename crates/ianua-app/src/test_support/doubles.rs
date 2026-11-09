//! Neutral doubles for the shared ports and values a ports struct fills
//! in when a test does not name them.

use std::sync::{Arc, Mutex};

use ianua_domain::shared::random::RandomSource;
use ianua_domain::test_support::fakes::SequenceRandom;

use crate::test_support::Fake;

/// Same-site rules for tests: two hosts are on one site when their last two
/// labels match. Close enough for test hosts, which never sit under a
/// multi-label public suffix.
pub struct ParentDomainSites;

impl crate::ports::shared::SiteRules for ParentDomainSites {
    fn same_site(
        &self,
        a: &ianua_domain::types::DomainName,
        b: &ianua_domain::types::DomainName,
    ) -> bool {
        let site = |host: &str| {
            let labels: Vec<&str> = host.rsplit('.').take(2).collect();
            labels.join(".")
        };
        site(a.as_str()) == site(b.as_str())
    }

    fn is_public_suffix(&self, name: &ianua_domain::types::DomainName) -> bool {
        matches!(name.as_str(), "com" | "co.uk" | "github.io")
    }
}

impl Fake for Arc<dyn crate::ports::shared::SiteRules> {
    fn fake() -> Self {
        Arc::new(ParentDomainSites)
    }
}

impl Fake
    for Arc<dyn ianua_domain::domains::authentication::credentials::password::PasswordHasher>
{
    fn fake() -> Self {
        Arc::new(ianua_domain::test_support::fakes::FakeHasher)
    }
}

impl Fake for ianua_domain::types::HttpsUrl {
    fn fake() -> Self {
        ianua_domain::types::HttpsUrl::new("https://app.test").unwrap()
    }
}

impl Fake for ianua_domain::shared::security::ssrf::UpstreamNetworks {
    fn fake() -> Self {
        ianua_domain::shared::security::ssrf::UpstreamNetworks::new(Vec::new())
    }
}

/// An optional port is absent unless a test supplies one.
impl<T> Fake for Option<T> {
    fn fake() -> Self {
        None
    }
}

/// Token resolver that recognises no token.
pub struct NoopTokenResolver;
#[::async_trait::async_trait]
impl crate::ports::shared::TokenResolver for NoopTokenResolver {
    async fn resolve(
        &self,
        _: &ianua_domain::shared::security::secret::Secret,
    ) -> Result<
        Option<crate::ports::shared::ResolvedCaller>,
        ianua_domain::shared::errors::DomainError,
    > {
        Ok(None)
    }
}

impl Fake for Arc<dyn crate::ports::shared::TokenResolver> {
    fn fake() -> Self {
        std::sync::Arc::new(NoopTokenResolver)
    }
}

/// Answers every question about ActivityStore with nothing.
pub struct NoopActivityStore;
#[::async_trait::async_trait]
impl crate::ports::activity::ActivityStore for NoopActivityStore {
    async fn daily_category_counts(
        &self,
        _: &ianua_domain::domains::activity::ActivityScope,
        _: &ianua_domain::domains::activity::CalendarRange,
    ) -> Result<
        Vec<ianua_domain::domains::activity::DailyCategoryCount>,
        ianua_domain::shared::errors::DomainError,
    > {
        Ok(vec![])
    }
}

impl Fake for Arc<dyn crate::ports::activity::ActivityStore> {
    fn fake() -> Self {
        std::sync::Arc::new(NoopActivityStore)
    }
}

/// Secure randomness for tests: a fixed sequence, so a test gets the same
/// generated secrets every run.
pub struct SequenceSecureRandom(Mutex<SequenceRandom>);

impl SequenceSecureRandom {
    /// A source starting its sequence at `seed`.
    #[must_use]
    pub fn new(seed: usize) -> Self {
        Self(Mutex::new(SequenceRandom::new(seed)))
    }
}

impl crate::ports::runtime::SecureRandom for SequenceSecureRandom {
    fn index_below(&self, upper: usize) -> usize {
        self.0.lock().unwrap().index_below(upper)
    }
}

impl Fake for Arc<dyn crate::ports::runtime::SecureRandom> {
    fn fake() -> Self {
        Arc::new(SequenceSecureRandom::new(7))
    }
}
