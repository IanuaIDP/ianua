//! The counts every password check is held to: the lockout of the network
//! it came from on the account, and the account's pace across every
//! network.
//!
//! Every check that counts failed passwords reads and writes them here, the
//! same way. The account's pace is waited out first, before any password is
//! hashed and while no hash permit is held. Then the origin's lockout is
//! read into the tracker the domain decides on. Once the domain decided,
//! what the attempt did is counted or cleared: the failure that reaches the
//! limit locks its origin out of the account, and answers with that lockout
//! for the caller to record. Any count that cannot be read or kept is an
//! internal error, so no password is checked on a lockout nobody could
//! read.
//!
//! The same counts say whether the account is under attack: failures from
//! many networks in the window, or a mark an earlier sign-in set when it
//! found that. The sign-in that finds an attack not yet marked claims its
//! recording, in one step on the shared state, and only the one whose
//! claim took is told the attack begun, so it is recorded once however many
//! nodes find it. The mark is set only once that record is written: a
//! record lost leaves the short claim to lapse, and the next sign-in
//! records the attack.

use std::future::Future;
use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::authentication::risk_engine::attack::{
    AccountAttack, OriginRecord, attack_held_for,
};
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::pace::AccountPace;
use ianua_domain::domains::authentication::risk_engine::rate_limit::{
    AttemptOutcome, AttemptTally, LoginAttemptTracker, OriginLockout, RateLimitPolicy,
};
use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
use ianua_domain::domains::authentication::sign_in_limits::SignInLimits;
use ianua_domain::shared::clock;
use ianua_domain::types::Lifetime;

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{AttackClaim, CountedAccount, SignInAttemptCounts};
use crate::ports::runtime::Pause;

/// How long the sign-in that found an attack holds the right to record it.
/// It records within the request; a record never written lets the claim
/// lapse this soon, so the next sign-in records the attack.
const RECORDING_CLAIM: Lifetime = Lifetime::from_secs(NonZeroU32::MIN.saturating_add(29));

/// The counts of failed passwords, and the wait an account's pace asks.
#[derive(Clone, ianua_macros::Fakes)]
pub struct SignInCounts {
    counts: Arc<dyn SignInAttemptCounts>,
    pause: Arc<dyn Pause>,
}

/// Where one password check is counted: whose account, from where, under
/// which lockout.
#[derive(Clone, Copy)]
pub(crate) struct CountedAt<'a> {
    /// The account the password is checked for.
    pub(crate) account: CountedAccount<'a>,
    /// Where the check came from.
    pub(crate) origin: AttemptOrigin,
    /// When failures lock the origin out, and how long failures count.
    pub(crate) policy: &'a RateLimitPolicy,
}

impl SignInCounts {
    /// Counts kept in `counts`, the account's pace waited out on `pause`.
    #[must_use]
    pub fn new(counts: Arc<dyn SignInAttemptCounts>, pause: Arc<dyn Pause>) -> Self {
        Self { counts, pause }
    }

    /// The tracker for a check at `at`, read once the account's pace has
    /// been waited out.
    ///
    /// `device` says whether the device is one the person trusted, which
    /// does not wait. It is only awaited while the account is being
    /// guessed at, so a sign-in in quiet times costs two reads of the
    /// counts.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when a count or the lockout cannot be read.
    pub(crate) async fn held(
        &self,
        at: CountedAt<'_>,
        device: impl Future<Output = Familiarity> + Send,
    ) -> Result<LoginAttemptTracker, AppError> {
        self.pace(at, device).await?;
        self.standing(at).await
    }

    /// The tracker for a check at `at`, read without waiting: for a check
    /// that counts nothing, such as finding which of several accounts a
    /// password opens before the one it opens is checked and counted.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the lockout cannot be read.
    pub(crate) async fn standing(
        &self,
        at: CountedAt<'_>,
    ) -> Result<LoginAttemptTracker, AppError> {
        let lockout = self
            .counts
            .lockout(at.account, &at.origin)
            .await
            .or_internal()?;
        Ok(LoginAttemptTracker::standing(lockout))
    }

    /// Whether the account at `at` is under attack.
    ///
    /// The recording of an attack the counts just showed is claimed. It is
    /// answered as begun only to the sign-in whose claim took, which
    /// records it and then has the account marked through
    /// [`mark_recorded`](Self::mark_recorded); a sign-in that lost the race to
    /// another finds it ongoing.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the counts cannot be read or the claim
    ///   made.
    pub(crate) async fn attack(&self, at: CountedAt<'_>) -> Result<AccountAttack, AppError> {
        let signs = self.counts.attack_signs(at.account).await.or_internal()?;
        let attack = AccountAttack::of(signs, at.policy, clock::now());
        if attack.begun().is_none() {
            return Ok(attack);
        }
        let claim = self
            .counts
            .claim_attack(at.account, RECORDING_CLAIM)
            .await
            .or_internal()?;
        Ok(attack_after(attack, claim))
    }

    /// Marks the account at `at` under attack for as long as the attack
    /// holds, once the attack this sign-in found begun is recorded. An
    /// attack found ongoing, or none, marks nothing.
    ///
    /// Only an attack on record is marked: were the mark set first and the
    /// record then lost, every later sign-in would find the attack ongoing
    /// and nobody would record it, so nobody would be told.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the mark cannot be kept.
    pub(crate) async fn mark_recorded(
        &self,
        at: CountedAt<'_>,
        attack: AccountAttack,
    ) -> Result<(), AppError> {
        if attack.begun().is_none() {
            return Ok(());
        }
        self.counts
            .mark_attack(at.account, attack_held_for(at.policy))
            .await
            .or_internal()
    }

    /// Whether the network at `at` failed on the account in the current
    /// window.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when its count cannot be read.
    pub(crate) async fn origin_record(&self, at: CountedAt<'_>) -> Result<OriginRecord, AppError> {
        let failures = self
            .counts
            .origin_failures(at.account, &at.origin)
            .await
            .or_internal()?;
        Ok(OriginRecord::of(failures))
    }

    /// Counts or clears what the check at `at` did, as `tracker` tells it,
    /// and answers with the lockout its failure set, when it reached the
    /// limit.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the failure cannot be counted, the
    ///   lockout kept or the count cleared.
    pub(crate) async fn settled(
        &self,
        at: CountedAt<'_>,
        tracker: &LoginAttemptTracker,
    ) -> Result<Option<OriginLockout>, AppError> {
        match tracker.tally() {
            AttemptTally::Untouched => Ok(None),
            AttemptTally::Cleared => {
                self.counts
                    .clear(at.account, &at.origin)
                    .await
                    .or_internal()?;
                Ok(None)
            }
            AttemptTally::Failed => self.counted_failure(at).await,
        }
    }

    /// Waits as long as the account's failures across every origin ask of
    /// a check from `device`.
    async fn pace(
        &self,
        at: CountedAt<'_>,
        device: impl Future<Output = Familiarity> + Send,
    ) -> Result<(), AppError> {
        let failures = self
            .counts
            .account_failures(at.account)
            .await
            .or_internal()?;
        let pace = AccountPace::for_failures(failures, at.policy);
        if pace.is_unhurried() {
            return Ok(());
        }
        let wait = pace.wait_for(device.await);
        if !wait.is_positive() {
            return Ok(());
        }
        self.pause.hold(wait).await;
        Ok(())
    }

    /// Counts a failure at `at`, and locks its origin out of the account
    /// once its count reaches the limit.
    async fn counted_failure(&self, at: CountedAt<'_>) -> Result<Option<OriginLockout>, AppError> {
        let failures = self
            .counts
            .count_failure(at.account, &at.origin, at.policy.window())
            .await
            .or_internal()?;
        let outcome = at.policy.after_failures(failures, clock::now());
        let Some(until) = outcome.locked_until() else {
            return Ok(None);
        };
        self.counts
            .lock(at.account, &at.origin, until)
            .await
            .or_internal()?;
        Ok(lockout_set(outcome))
    }
}

/// The lockout the sign-in `limits` of a tenant or an organization set, for
/// counting a password checked under them.
///
/// # Errors
///
/// - `AppError::Internal` when the limits make no lockout. They were checked
///   when the configuration was made, so this is a broken record, not
///   something the caller sent.
pub(crate) fn lockout_of(limits: SignInLimits) -> Result<RateLimitPolicy, AppError> {
    limits.lockout().map_err(AppError::internal)
}

/// The attack `found` once claiming its recording came to `claim`: begun
/// for the sign-in that made the claim, ongoing for one that found it made.
fn attack_after(found: AccountAttack, claim: AttackClaim) -> AccountAttack {
    match claim {
        AttackClaim::ClaimedNow => found,
        AttackClaim::ClaimedBefore => AccountAttack::Ongoing,
    }
}

/// The lockout `outcome` set, when its failure was the one that reached the
/// limit. A failure past it locks again, but records nothing new.
fn lockout_set(outcome: AttemptOutcome) -> Option<OriginLockout> {
    match outcome {
        AttemptOutcome::LockedOut(lockout) => Some(lockout),
        AttemptOutcome::Allowed { .. } | AttemptOutcome::PastTheLimit { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::authentication::risk_engine::pace::MOST_PACE;
    use ianua_domain::types::{Email, Fact, IpAddress, OrganizationId};

    use super::*;
    use crate::test_support::authentication::{
        FakeSignInAttemptCounts, RecordingPause, UnreachableSignInAttemptCounts,
    };
    use crate::test_support::block_on;

    const MALLORY: &str = "198.51.100.66";
    const ANN: &str = "203.0.113.7";

    fn from(ip: &str) -> AttemptOrigin {
        AttemptOrigin::of(Fact::Known(&IpAddress::new(ip).unwrap()))
    }

    fn three_tries() -> RateLimitPolicy {
        RateLimitPolicy::new(
            NonZeroU32::new(3).unwrap(),
            Lifetime::seconds(600).unwrap(),
            Lifetime::seconds(900).unwrap(),
        )
    }

    struct Fixture {
        counts: Arc<FakeSignInAttemptCounts>,
        pause: Arc<RecordingPause>,
        organization: OrganizationId,
        email: Email,
        policy: RateLimitPolicy,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                counts: Arc::new(FakeSignInAttemptCounts::default()),
                pause: Arc::new(RecordingPause::default()),
                organization: OrganizationId::new(),
                email: Email::new("ann@acme.test").unwrap(),
                policy: three_tries(),
            }
        }

        fn service(&self) -> SignInCounts {
            SignInCounts::new(self.counts.clone(), self.pause.clone())
        }

        fn at(&self, ip: &str) -> CountedAt<'_> {
            CountedAt {
                account: self.account(),
                origin: from(ip),
                policy: &self.policy,
            }
        }

        fn account(&self) -> CountedAccount<'_> {
            CountedAccount::Organization {
                organization: &self.organization,
                email: &self.email,
            }
        }

        /// One check from `ip` on `device`, ending as `outcome` says, held
        /// and settled.
        fn check(&self, ip: &str, device: Familiarity, outcome: Check) -> Option<OriginLockout> {
            let service = self.service();
            let mut tracker = block_on(service.held(self.at(ip), async move { device })).unwrap();
            match outcome {
                Check::Wrong => tracker.record_failure(),
                Check::Right => tracker.reset(),
            }
            block_on(service.settled(self.at(ip), &tracker)).unwrap()
        }

        fn attack(&self, ip: &str) -> AccountAttack {
            block_on(self.service().attack(self.at(ip))).unwrap()
        }

        fn locked(&self, ip: &str) -> bool {
            let tracker = block_on(
                self.service()
                    .held(self.at(ip), async { Familiarity::Known }),
            )
            .unwrap();
            tracker.is_locked(clock::now())
        }
    }

    #[derive(Clone, Copy)]
    enum Check {
        Wrong,
        Right,
    }

    /// The third failed attempt reaches the policy limit and locks its
    /// origin. The first two return no lockout, and another origin stays open.
    #[test]
    fn the_failure_at_the_limit_locks_only_its_origin() {
        let fixture = Fixture::new();

        let first = fixture.check(MALLORY, Familiarity::New, Check::Wrong);
        let second = fixture.check(MALLORY, Familiarity::New, Check::Wrong);
        let third = fixture.check(MALLORY, Familiarity::New, Check::Wrong);

        assert!(first.is_none() && second.is_none());
        assert_eq!(third.map(|lockout| lockout.failed_attempts()), Some(3));
        assert!(fixture.locked(MALLORY));
        assert!(!fixture.locked(ANN));
    }

    /// Ann mistypes twice, then types her password right. Her network's
    /// count starts again: two more mistakes do not lock her out.
    #[test]
    fn a_right_password_starts_the_origins_count_again() {
        let fixture = Fixture::new();
        fixture.check(ANN, Familiarity::New, Check::Wrong);
        fixture.check(ANN, Familiarity::New, Check::Wrong);

        fixture.check(ANN, Familiarity::New, Check::Right);
        fixture.check(ANN, Familiarity::New, Check::Wrong);
        fixture.check(ANN, Familiarity::New, Check::Wrong);

        assert!(!fixture.locked(ANN));
    }

    /// A botnet's failures against Ann's account pile up from many
    /// networks. Her next check from a new device waits, never past the
    /// cap; on her trusted laptop it does not wait.
    #[test]
    fn guessing_from_many_origins_slows_untrusted_devices_only() {
        let fixture = Fixture::new();
        for bot in 0..40 {
            fixture.check(&format!("192.0.2.{bot}"), Familiarity::New, Check::Wrong);
        }
        let waited_by_bots = fixture.pause.waited().len();

        fixture.check(ANN, Familiarity::New, Check::Right);
        let waited_on_her_phone = fixture.pause.waited();
        fixture.check(ANN, Familiarity::Known, Check::Right);
        let waited_on_her_laptop = fixture.pause.waited();

        assert_eq!(waited_on_her_phone.len(), waited_by_bots + 1);
        assert_eq!(waited_on_her_phone.last(), Some(&MOST_PACE));
        assert_eq!(waited_on_her_laptop.len(), waited_on_her_phone.len());
        assert!(!fixture.locked(ANN));
    }

    /// Failures from six networks produce one newly detected attack; the
    /// next lookup sees it as ongoing. Acknowledging its record then marks
    /// the account under attack.
    #[test]
    fn many_networks_begin_an_attack_once() {
        let fixture = Fixture::new();
        for bot in 0..6 {
            fixture.check(&format!("192.0.2.{bot}"), Familiarity::New, Check::Wrong);
        }

        let first = fixture.attack(ANN);
        let second = fixture.attack(ANN);
        block_on(fixture.service().mark_recorded(fixture.at(ANN), first)).unwrap();

        assert_eq!(first.begun().map(|begun| begun.networks().get()), Some(6));
        assert_eq!(second, AccountAttack::Ongoing);
        assert!(fixture.counts.marked_under_attack(fixture.account()));
    }

    /// Detecting an attack from six networks does not itself mark the
    /// account. The mark remains absent before recording is acknowledged.
    #[test]
    fn an_attack_is_not_marked_before_it_is_recorded() {
        let fixture = Fixture::new();
        for bot in 0..6 {
            fixture.check(&format!("192.0.2.{bot}"), Familiarity::New, Check::Wrong);
        }

        let found = fixture.attack(ANN);

        assert!(found.begun().is_some());
        assert!(!fixture.counts.marked_under_attack(fixture.account()));
    }

    /// A sign-in that found the attack ongoing marks nothing when it is
    /// recorded: the mark stays the one the first record set.
    #[test]
    fn an_ongoing_attack_marks_nothing_when_recorded() {
        let fixture = Fixture::new();

        block_on(
            fixture
                .service()
                .mark_recorded(fixture.at(ANN), AccountAttack::Ongoing),
        )
        .unwrap();

        assert!(!fixture.counts.marked_under_attack(fixture.account()));
    }

    /// Mallory guesses at Ann's account from her one network until it is
    /// locked out, and on. The account is never under attack.
    #[test]
    fn guessing_from_one_network_never_begins_an_attack() {
        let fixture = Fixture::new();
        for _ in 0..20 {
            fixture.check(MALLORY, Familiarity::New, Check::Wrong);
        }

        assert_eq!(fixture.attack(ANN), AccountAttack::Quiet);
    }

    /// Under attack, a network that failed on Ann's account is on record,
    /// and her own network, which never failed, is not.
    #[test]
    fn only_a_network_that_failed_is_on_record() {
        let fixture = Fixture::new();
        fixture.check(MALLORY, Familiarity::New, Check::Wrong);
        let service = fixture.service();

        let mallory = block_on(service.origin_record(fixture.at(MALLORY))).unwrap();
        let ann = block_on(service.origin_record(fixture.at(ANN))).unwrap();

        assert_eq!(mallory, OriginRecord::Failed);
        assert_eq!(ann, OriginRecord::Clean);
    }

    /// Failure to read the shared counts returns an internal error even
    /// for a trusted device; no tracker is supplied for the password check.
    #[test]
    fn an_unreachable_count_refuses_the_check() {
        let fixture = Fixture::new();
        let service = SignInCounts::new(
            Arc::new(UnreachableSignInAttemptCounts),
            fixture.pause.clone(),
        );

        let held = block_on(service.held(fixture.at(ANN), async { Familiarity::Known }));

        assert!(matches!(held, Err(AppError::Internal(_))));
    }
}
