//! The sweeps renewing what the platform keeps at services before it
//! lapses. Workflows' registrations and accounts' channels go through the
//! same round, so it is written here once.
//!
//! One a service will not renew, or whose account is gone, lapses out loud.
//! A service that cannot be reached is asked again next round, until its
//! time runs out; then it lapses too, so the sweep ends.

use async_trait::async_trait;
use ianua_domain::domains::workflows::triggers::channel::AccountChannel;
use ianua_domain::domains::workflows::triggers::subscription::{
    Lapse, LapseReason, Registration, ServiceSubscription,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use time::{Duration, OffsetDateTime};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{ChannelRegistered, Registered, RegistrationFailure};
use crate::services::sweep_round::SweepRound;
use crate::tenancy::ScopedTenant;

/// How long before it lapses a registration or channel is renewed.
const RENEW_AHEAD: Duration = Duration::hours(24);

/// How many one round renews at most; the next round renews the rest.
const MOST_PER_ROUND: u32 = 200;

/// The longest a lapse's reason may be, past which a service's own words
/// are cut.
const LONGEST_REASON: usize = 500;

/// The reason a registration or channel lapses when the account it was
/// registered through is gone.
pub(crate) const ACCOUNT_GONE: &str = "the account it was registered through is gone";

/// A registration or channel kept at a service, which a sweep renews or
/// lapses.
pub(crate) trait Lapsing {
    /// What its service answers a renewal with.
    type Answer;

    /// The reason it lapses when its service stayed out of reach until its
    /// time ran out.
    const OUT_OF_REACH: &'static str;

    /// The service's side of it, for when it lapses.
    fn registration(&self) -> &Registration;

    /// Takes the service's `answer` to a renewal.
    ///
    /// # Errors
    ///
    /// `DomainError` when it may no longer change.
    fn take_answer(&mut self, answer: Self::Answer) -> Result<(), DomainError>;

    /// Lapses it for `reason`.
    ///
    /// # Errors
    ///
    /// `DomainError` when it may not lapse now.
    fn lapse(&mut self, reason: LapseReason) -> Result<(), DomainError>;
}

impl Lapsing for ServiceSubscription<ResolvedTenant> {
    type Answer = Registered;

    const OUT_OF_REACH: &'static str =
        "the service could not be reached before the registration lapsed";

    fn registration(&self) -> &Registration {
        ServiceSubscription::registration(self)
    }

    fn take_answer(&mut self, answer: Registered) -> Result<(), DomainError> {
        self.register(answer.remote, answer.lapses)
    }

    fn lapse(&mut self, reason: LapseReason) -> Result<(), DomainError> {
        ServiceSubscription::lapse(self, reason)
    }
}

impl Lapsing for AccountChannel<ResolvedTenant> {
    type Answer = ChannelRegistered;

    const OUT_OF_REACH: &'static str = "the service could not be reached before the channel lapsed";

    fn registration(&self) -> &Registration {
        AccountChannel::registration(self)
    }

    fn take_answer(&mut self, answer: ChannelRegistered) -> Result<(), DomainError> {
        self.register(answer.remote, answer.lapses, answer.history)
    }

    fn lapse(&mut self, reason: LapseReason) -> Result<(), DomainError> {
        AccountChannel::lapse(self, reason)
    }
}

/// What renewing one of them came to.
pub(crate) enum Renewed<T> {
    /// The service renewed it, or it lapsed; either way it changed.
    Changed(Box<T>),
    /// The service could not be reached and it has time left; next round.
    Later,
    /// It is no longer live; nothing to do.
    Skipped,
}

/// One kind of renewal sweep: what it lists and how it renews and keeps
/// one.
#[async_trait]
pub(crate) trait RenewalSweep: Send + Sync {
    /// Where one due is kept.
    type At: Send + Sync;
    /// What it renews.
    type Held: Lapsing + Send;

    /// Up to `limit` that lapse before `before`, across every tenant.
    ///
    /// # Errors
    ///
    /// `DomainError::Infrastructure` when they cannot be listed.
    async fn due(&self, before: OffsetDateTime, limit: u32) -> Result<Vec<Self::At>, DomainError>;

    /// The tenant the one at `at` belongs to.
    fn tenant_of(at: &Self::At) -> TenantId;

    /// Renews the one at `at`, or lapses it, without keeping it.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when it or its account cannot be read.
    async fn renew_or_lapse(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        at: &Self::At,
    ) -> Result<Renewed<Self::Held>, AppError>;

    /// Saves `held` and records what it raised, by the platform, together.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when either cannot be kept.
    async fn keep(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        held: &mut Self::Held,
    ) -> Result<(), AppError>;
}

/// One round of `sweep` over everything lapsing within a day: each renewed
/// or lapsed and kept with its record, in a unit of its own, or counted as
/// failed and found again next round.
///
/// # Errors
///
/// `AppError::Internal` when what is due cannot be listed.
pub(crate) async fn run_round<S: RenewalSweep>(
    sweep: &S,
    auditor: &RequestAuditor,
) -> Result<SweepRound, AppError> {
    let before = clock::now() + RENEW_AHEAD;
    let due = sweep.due(before, MOST_PER_ROUND).await.or_internal()?;
    let mut round = SweepRound::default();
    for at in &due {
        round = round_with(sweep, round, auditor, at).await;
    }
    Ok(round)
}

/// `round` with the one at `at` renewed, lapsed, left for the next round,
/// or skipped.
async fn round_with<S: RenewalSweep>(
    sweep: &S,
    round: SweepRound,
    auditor: &RequestAuditor,
    at: &S::At,
) -> SweepRound {
    let tenant = ScopedTenant::for_background(S::tenant_of(at));
    let mut held = match sweep.renew_or_lapse(auditor, &tenant, at).await {
        Ok(Renewed::Changed(held)) => *held,
        Ok(Renewed::Skipped) => return round,
        Ok(Renewed::Later) | Err(_) => return round.with_failed(),
    };
    match sweep.keep(auditor, &tenant, &mut held).await {
        Ok(()) => round.with_changed(),
        Err(_) => round.with_failed(),
    }
}

/// What `answer`, the service's answer to renewing `held`, comes to:
/// renewed, lapsed out loud, or left for the next round while it has time
/// left.
///
/// # Errors
///
/// `AppError::Domain` when it may no longer change.
pub(crate) fn after_answer<T: Lapsing>(
    mut held: T,
    answer: Result<T::Answer, RegistrationFailure>,
) -> Result<Renewed<T>, AppError> {
    match answer {
        Ok(taken) => held.take_answer(taken).map_err(AppError::from_domain)?,
        Err(RegistrationFailure::Refused(why)) => lapse(
            &mut held,
            &format!("the service refused to renew it: {why}"),
        )?,
        Err(RegistrationFailure::Unreachable) if ran_out(&held, clock::now()) => {
            lapse(&mut held, T::OUT_OF_REACH)?;
        }
        Err(RegistrationFailure::Unreachable) => return Ok(Renewed::Later),
    }
    Ok(Renewed::Changed(Box::new(held)))
}

/// `held` lapsed for `why`, cut to what a reason holds when a service said
/// more.
///
/// # Errors
///
/// `AppError::Domain` when it may not lapse now, or `why` is empty.
pub(crate) fn lapse<T: Lapsing>(held: &mut T, why: &str) -> Result<(), AppError> {
    let cut: String = why
        .chars()
        .filter(|c| !c.is_control())
        .take(LONGEST_REASON)
        .collect();
    let reason = LapseReason::new(cut).map_err(|refused| AppError::from_domain(refused.into()))?;
    held.lapse(reason).map_err(AppError::from_domain)
}

/// Whether `held`'s time ran out by `now`.
fn ran_out<T: Lapsing>(held: &T, now: OffsetDateTime) -> bool {
    matches!(
        held.registration(),
        Registration::Taken {
            lapses: Lapse::At(at),
            ..
        } if *at <= now
    )
}
