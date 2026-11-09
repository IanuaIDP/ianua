//! The failed passwords counted per account and network, and per account
//! across every network, with each network's lockout of an account.
//!
//! Each count is one counter on the shared state, added to in one step, so
//! two guesses at once both count, and each lapses with the window it was
//! counted in. A lockout is the moment it ends, kept until then; when it is
//! kept the network's count starts again, so the next failure after it is
//! the first. Every key names the account by its tenant or organization and
//! its address, and a network's keys name the network too. Nothing here is
//! a record: when the state is lost, so are the counts, and sign-in starts
//! from none.
//!
//! Each failure also adds its network to a set kept for the account, which
//! lapses with the window it was started in, so how many networks failed
//! on the account is the size of that set. The sign-in that finds an
//! account under attack first claims the right to record it, in one step,
//! so of two sign-ins finding the attack at once one makes the claim and
//! the other finds it made. Once the record is written the account is
//! marked with the moment the attack ends, kept until then; a claim whose
//! record was lost lapses on its own, and the next sign-in claims again.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{AttackClaim, CountedAccount, SignInAttemptCounts};
use ianua_domain::domains::authentication::risk_engine::attack::{
    AttackMark, AttackSigns, FailingNetworks,
};
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::pressure::FailureCount;
use ianua_domain::domains::authentication::risk_engine::rate_limit::Lockout;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Lifetime;
use time::OffsetDateTime;

use crate::cache::state::{CacheError, SharedState, key};

/// The shortest any count or lockout is kept for.
const AT_LEAST: Duration = Duration::from_secs(1);

/// The counts of failed passwords, on shared state.
pub struct CacheSignInAttemptCounts {
    state: Arc<dyn SharedState>,
}

impl CacheSignInAttemptCounts {
    /// Counts kept on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

/// The account's name in a key: its tenant or organization, and its
/// address as written in any case.
fn account_name(account: CountedAccount<'_>) -> String {
    match account {
        CountedAccount::Tenant { tenant, email } => {
            format!(
                "tenant:{}:{}",
                **tenant,
                email.as_str().to_ascii_lowercase()
            )
        }
        CountedAccount::Organization {
            organization,
            email,
        } => format!(
            "organization:{organization}:{}",
            email.as_str().to_ascii_lowercase()
        ),
        CountedAccount::Operator { email } => {
            format!("operator:{}", email.as_str().to_ascii_lowercase())
        }
    }
}

/// The key the account's failures from every network are counted under.
fn on_account(account: CountedAccount<'_>) -> String {
    key(&["sign-in-account-failures", &account_name(account)])
}

/// The key the account's failures from `origin` are counted under.
fn from_origin(account: CountedAccount<'_>, origin: &AttemptOrigin) -> String {
    key(&[
        "sign-in-origin-failures",
        &account_name(account),
        &origin.to_string(),
    ])
}

/// The key of the set of networks that failed on the account.
fn failing_networks(account: CountedAccount<'_>) -> String {
    key(&["sign-in-failing-networks", &account_name(account)])
}

/// The key the account's mark of being under attack is kept under.
fn attack_mark(account: CountedAccount<'_>) -> String {
    key(&["sign-in-account-under-attack", &account_name(account)])
}

/// The key the claim to record the attack on the account is kept under.
fn attack_claim(account: CountedAccount<'_>) -> String {
    key(&["sign-in-account-attack-claim", &account_name(account)])
}

/// The key `origin`'s lockout of the account is kept under.
fn lockout_of(account: CountedAccount<'_>, origin: &AttemptOrigin) -> String {
    key(&[
        "sign-in-origin-lockout",
        &account_name(account),
        &origin.to_string(),
    ])
}

/// `lifetime` as the shared state keeps entries, at least a second.
fn kept_for(lifetime: Lifetime) -> Duration {
    Duration::try_from(lifetime.duration())
        .unwrap_or(AT_LEAST)
        .max(AT_LEAST)
}

/// How long from now until `until`, at least a second.
fn until_then(until: OffsetDateTime) -> Duration {
    Duration::try_from(clock::between(clock::now(), until))
        .unwrap_or(AT_LEAST)
        .max(AT_LEAST)
}

/// The lockout kept as `text`, the unix second it ends at.
fn lockout_from(text: &str) -> Result<Lockout, CacheError> {
    let seconds = text.parse::<i64>().map_err(|_| CacheError::Unexpected)?;
    let until = OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| CacheError::Unexpected)?;
    Ok(Lockout::Until(until))
}

#[async_trait]
impl SignInAttemptCounts for CacheSignInAttemptCounts {
    async fn lockout(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
    ) -> Result<Lockout, DomainError> {
        let kept = self.state.text(&lockout_of(account, origin)).await?;
        let Some(text) = kept else {
            return Ok(Lockout::Open);
        };
        Ok(lockout_from(&text)?)
    }

    async fn account_failures(
        &self,
        account: CountedAccount<'_>,
    ) -> Result<FailureCount, DomainError> {
        let counted = self.state.read(&on_account(account)).await?;
        Ok(FailureCount::from(counted.unwrap_or_default()))
    }

    async fn origin_failures(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
    ) -> Result<u32, DomainError> {
        let counted = self.state.read(&from_origin(account, origin)).await?;
        Ok(u32::try_from(counted.unwrap_or_default()).unwrap_or(u32::MAX))
    }

    async fn attack_signs(&self, account: CountedAccount<'_>) -> Result<AttackSigns, DomainError> {
        let networks = self.state.distinct(&failing_networks(account)).await?;
        let mark = match self.state.text(&attack_mark(account)).await? {
            Some(_) => AttackMark::Marked,
            None => AttackMark::Unmarked,
        };
        Ok(AttackSigns::new(FailingNetworks::from(networks), mark))
    }

    async fn claim_attack(
        &self,
        account: CountedAccount<'_>,
        claim: Lifetime,
    ) -> Result<AttackClaim, DomainError> {
        let claimed = self
            .state
            .claim_once(&attack_claim(account), kept_for(claim))
            .await?;
        if claimed {
            return Ok(AttackClaim::ClaimedNow);
        }
        Ok(AttackClaim::ClaimedBefore)
    }

    async fn mark_attack(
        &self,
        account: CountedAccount<'_>,
        lasting: Lifetime,
    ) -> Result<(), DomainError> {
        let ends = lasting
            .ends_after(clock::now())
            .unix_timestamp()
            .to_string();
        self.state
            .keep(&attack_mark(account), &ends, kept_for(lasting))
            .await?;
        Ok(())
    }

    async fn count_failure(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
        window: Lifetime,
    ) -> Result<u32, DomainError> {
        let window = kept_for(window);
        self.state.count(&on_account(account), 1, window).await?;
        self.state
            .add_distinct(&failing_networks(account), &[origin.to_string()], window)
            .await?;
        let counted = self
            .state
            .count(&from_origin(account, origin), 1, window)
            .await?;
        Ok(u32::try_from(counted).unwrap_or(u32::MAX))
    }

    async fn lock(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
        until: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let ends = until.unix_timestamp().to_string();
        self.state
            .swap(&lockout_of(account, origin), &ends, until_then(until))
            .await?;
        self.state.forget(&from_origin(account, origin)).await?;
        Ok(())
    }

    async fn clear(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
    ) -> Result<(), DomainError> {
        self.state.forget(&from_origin(account, origin)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::types::{Email, Fact, IpAddress, OrganizationId};

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::stores::RefusingState;
    use crate::test_support::cache::test_server;
    use crate::test_support::rows::authorization::tenant;

    fn from(ip: &str) -> AttemptOrigin {
        AttemptOrigin::of(Fact::Known(&IpAddress::new(ip).unwrap()))
    }

    fn mallory() -> AttemptOrigin {
        from("198.51.100.66")
    }

    fn office() -> AttemptOrigin {
        from("203.0.113.7")
    }

    fn fifteen_minutes() -> Lifetime {
        Lifetime::seconds(900).unwrap()
    }

    fn in_memory() -> CacheSignInAttemptCounts {
        CacheSignInAttemptCounts::new(Arc::new(MemoryState::new(1_000)))
    }

    async fn on_the_server() -> CacheSignInAttemptCounts {
        CacheSignInAttemptCounts::new(Arc::new(test_server().await))
    }

    /// Ann's account in a tenant of its own, so runs on one server never
    /// share a count.
    struct Ann {
        tenant: ScopedTenant,
        email: Email,
    }

    impl Ann {
        fn new() -> Self {
            Self {
                tenant: tenant(),
                email: Email::new("ann@acme.test").unwrap(),
            }
        }

        fn account(&self) -> CountedAccount<'_> {
            CountedAccount::Tenant {
                tenant: &self.tenant,
                email: &self.email,
            }
        }
    }

    /// Failures are counted from each network and from all of them
    /// together; a network's count is its own.
    async fn counts_each_network_and_the_account(counts: CacheSignInAttemptCounts) {
        let ann = Ann::new();

        counts
            .count_failure(ann.account(), &mallory(), fifteen_minutes())
            .await
            .unwrap();
        let second = counts
            .count_failure(ann.account(), &mallory(), fifteen_minutes())
            .await
            .unwrap();
        let first_from_office = counts
            .count_failure(ann.account(), &office(), fifteen_minutes())
            .await
            .unwrap();

        assert_eq!(second, 2);
        assert_eq!(first_from_office, 1);
        assert_eq!(
            counts.account_failures(ann.account()).await.unwrap().get(),
            3
        );
    }

    /// Locking Mallory's network leaves Ann's office open and resets Mallory's failed-attempt count.
    async fn locks_only_the_network_locked(counts: CacheSignInAttemptCounts) {
        let ann = Ann::new();
        let until =
            OffsetDateTime::from_unix_timestamp(clock::now().unix_timestamp() + 600).unwrap();
        for _ in 0..3 {
            counts
                .count_failure(ann.account(), &mallory(), fifteen_minutes())
                .await
                .unwrap();
        }

        counts.lock(ann.account(), &mallory(), until).await.unwrap();

        assert_eq!(
            counts.lockout(ann.account(), &mallory()).await.unwrap(),
            Lockout::Until(until)
        );
        assert_eq!(
            counts.lockout(ann.account(), &office()).await.unwrap(),
            Lockout::Open
        );
        let next = counts
            .count_failure(ann.account(), &mallory(), fifteen_minutes())
            .await
            .unwrap();
        assert_eq!(next, 1);
    }

    /// Ann's right password starts her network's count again; the
    /// account's count across every network is left to lapse.
    async fn a_clear_starts_the_networks_count_again(counts: CacheSignInAttemptCounts) {
        let ann = Ann::new();
        counts
            .count_failure(ann.account(), &office(), fifteen_minutes())
            .await
            .unwrap();

        counts.clear(ann.account(), &office()).await.unwrap();
        let next = counts
            .count_failure(ann.account(), &office(), fifteen_minutes())
            .await
            .unwrap();

        assert_eq!(next, 1);
        assert_eq!(
            counts.account_failures(ann.account()).await.unwrap().get(),
            2
        );
    }

    /// A botnet fails on Ann's account from three networks, one of them
    /// twice. Three networks failed, and the account is not yet marked.
    async fn counts_each_failing_network_once(counts: CacheSignInAttemptCounts) {
        let ann = Ann::new();
        for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.2", "192.0.2.3"] {
            counts
                .count_failure(ann.account(), &from(ip), fifteen_minutes())
                .await
                .unwrap();
        }

        let signs = counts.attack_signs(ann.account()).await.unwrap();

        assert_eq!(
            signs,
            AttackSigns::new(FailingNetworks::from(3), AttackMark::Unmarked)
        );
    }

    /// Two sign-ins find the attack on Ann's account at once. The first
    /// claims its record and the second finds it claimed; the account is
    /// not marked until the first says its record is written, and the mark
    /// then reads back.
    async fn marks_an_attack_once(counts: CacheSignInAttemptCounts) {
        let ann = Ann::new();
        let claim = Lifetime::seconds(30).unwrap();
        let hour = Lifetime::seconds(3600).unwrap();

        let first = counts.claim_attack(ann.account(), claim).await.unwrap();
        let second = counts.claim_attack(ann.account(), claim).await.unwrap();
        let before = counts.attack_signs(ann.account()).await.unwrap();
        counts.mark_attack(ann.account(), hour).await.unwrap();
        let after = counts.attack_signs(ann.account()).await.unwrap();

        assert_eq!(first, AttackClaim::ClaimedNow);
        assert_eq!(second, AttackClaim::ClaimedBefore);
        assert_eq!(
            before,
            AttackSigns::new(FailingNetworks::from(0), AttackMark::Unmarked)
        );
        assert_eq!(
            after,
            AttackSigns::new(FailingNetworks::from(0), AttackMark::Marked)
        );
    }

    /// Mallory's network failed on Ann's account and Ann's office did not.
    /// Only Mallory's failures read back.
    async fn reads_each_networks_failures(counts: CacheSignInAttemptCounts) {
        let ann = Ann::new();
        counts
            .count_failure(ann.account(), &mallory(), fifteen_minutes())
            .await
            .unwrap();

        let from_mallory = counts.origin_failures(ann.account(), &mallory()).await;
        let from_office = counts.origin_failures(ann.account(), &office()).await;

        assert_eq!(from_mallory.unwrap(), 1);
        assert_eq!(from_office.unwrap(), 0);
    }

    #[tokio::test]
    async fn each_failing_network_is_counted_once_in_memory() {
        counts_each_failing_network_once(in_memory()).await;
    }

    #[tokio::test]
    async fn each_failing_network_is_counted_once_on_the_server() {
        counts_each_failing_network_once(on_the_server().await).await;
    }

    #[tokio::test]
    async fn an_attack_is_marked_once_in_memory() {
        marks_an_attack_once(in_memory()).await;
    }

    #[tokio::test]
    async fn an_attack_is_marked_once_on_the_server() {
        marks_an_attack_once(on_the_server().await).await;
    }

    #[tokio::test]
    async fn each_networks_failures_read_back_in_memory() {
        reads_each_networks_failures(in_memory()).await;
    }

    #[tokio::test]
    async fn each_networks_failures_read_back_on_the_server() {
        reads_each_networks_failures(on_the_server().await).await;
    }

    #[tokio::test]
    async fn each_network_and_the_account_are_counted_in_memory() {
        counts_each_network_and_the_account(in_memory()).await;
    }

    #[tokio::test]
    async fn each_network_and_the_account_are_counted_on_the_server() {
        counts_each_network_and_the_account(on_the_server().await).await;
    }

    #[tokio::test]
    async fn only_the_locked_network_is_locked_in_memory() {
        locks_only_the_network_locked(in_memory()).await;
    }

    #[tokio::test]
    async fn only_the_locked_network_is_locked_on_the_server() {
        locks_only_the_network_locked(on_the_server().await).await;
    }

    #[tokio::test]
    async fn a_clear_starts_the_count_again_in_memory() {
        a_clear_starts_the_networks_count_again(in_memory()).await;
    }

    #[tokio::test]
    async fn a_clear_starts_the_count_again_on_the_server() {
        a_clear_starts_the_networks_count_again(on_the_server().await).await;
    }

    /// Tenant sign-in attempts count an address case-insensitively,
    /// while the organization account's count remains separate.
    #[tokio::test]
    async fn accounts_are_counted_apart_and_addresses_in_any_case() {
        let counts = on_the_server().await;
        let ann = Ann::new();
        let shouting = Email::new("ANN@acme.test").unwrap();
        let organization = OrganizationId::new();
        let in_her_organization = CountedAccount::Organization {
            organization: &organization,
            email: &ann.email,
        };
        counts
            .count_failure(ann.account(), &mallory(), fifteen_minutes())
            .await
            .unwrap();

        let same_address = CountedAccount::Tenant {
            tenant: &ann.tenant,
            email: &shouting,
        };
        let elsewhere = counts.account_failures(in_her_organization).await.unwrap();
        let alike = counts.account_failures(same_address).await.unwrap();

        assert_eq!(elsewhere.get(), 0);
        assert_eq!(alike.get(), 1);
    }

    /// An unavailable shared state makes each attempt-count and lockout read fail with an infrastructure error.
    #[tokio::test]
    async fn a_state_that_cannot_answer_fails_every_read() {
        let counts = CacheSignInAttemptCounts::new(Arc::new(RefusingState));
        let ann = Ann::new();

        let lockout = counts.lockout(ann.account(), &mallory()).await;
        let failures = counts.account_failures(ann.account()).await;
        let signs = counts.attack_signs(ann.account()).await;

        assert!(matches!(lockout, Err(DomainError::Infrastructure(_))));
        assert!(matches!(failures, Err(DomainError::Infrastructure(_))));
        assert!(matches!(signs, Err(DomainError::Infrastructure(_))));
    }
}
