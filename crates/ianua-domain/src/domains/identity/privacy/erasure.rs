//! Requests to erase a person's data, under GDPR Article 17, the "right to
//! be forgotten".
//!
//! A request first waits out a grace period, during which the person can
//! cancel. After it, an adapter deletes the person's data from every store
//! for good.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::identity::account::control::{
    AccountAction, AccountControlCheck, DepartureCheck, SignedInPerson, ensure_holder,
};
use crate::domains::identity::account::user::User;
use crate::domains::identity::events::privacy::{
    ErasureCancelled, ErasureCompleted, ErasureFailed, ErasureHeld, ErasureReleased,
    ErasureRequested, ErasureStarted,
};
use crate::domains::identity::privacy::erasure_status::{ErasureStatus, InvalidErasureTransition};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::numeric::validate_range;
use crate::types::{Email, ErasureRequestId, EventLabel, Text, TokenHash, UserId};

/// How long a person has to cancel an erasure before deletion starts. It is
/// from one to 30 days.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GracePeriod(u32);

impl GracePeriod {
    /// The shortest grace period, in days.
    pub const MIN_DAYS: u32 = 1;
    /// The longest grace period, in days.
    pub const MAX_DAYS: u32 = 30;

    /// A grace period of `days`.
    ///
    /// Without at least a day, a request made by mistake or from a stolen
    /// session could not be withdrawn.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `days` is outside
    ///   [`Self::MIN_DAYS`] to [`Self::MAX_DAYS`].
    pub fn days(days: u32) -> Result<Self, DomainError> {
        validate_range("grace_period_days", days, Self::MIN_DAYS..=Self::MAX_DAYS)?;
        Ok(Self(days))
    }

    /// The grace period as a length of time.
    pub(crate) fn as_duration(self) -> time::Duration {
        time::Duration::days(i64::from(self.0))
    }

    /// Whether `gap` is from [`Self::MIN_DAYS`] to [`Self::MAX_DAYS`] long.
    pub(crate) fn allows(gap: time::Duration) -> bool {
        let shortest = Self(Self::MIN_DAYS).as_duration();
        let longest = Self(Self::MAX_DAYS).as_duration();
        (shortest..=longest).contains(&gap)
    }
}

/// Where an erasure request stands, with the time it finished when it did.
///
/// It is one value, not a status beside an optional time. So a request can
/// never read as completed with no time, or pending with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasureState {
    /// Waiting out the grace period.
    Pending,
    /// Data is being deleted.
    Processing,
    /// Every record was deleted.
    Completed {
        /// When it finished.
        at: OffsetDateTime,
    },
    /// Cancelled during the grace period.
    Cancelled,
    /// Paused by a legal hold.
    Held,
    /// Deletion stopped part way.
    Failed,
}

impl ErasureState {
    /// The [`ErasureStatus`] for this state.
    #[must_use]
    pub fn status(self) -> ErasureStatus {
        match self {
            Self::Pending => ErasureStatus::Pending,
            Self::Processing => ErasureStatus::Processing,
            Self::Completed { .. } => ErasureStatus::Completed,
            Self::Cancelled => ErasureStatus::Cancelled,
            Self::Held => ErasureStatus::Held,
            Self::Failed => ErasureStatus::Failed,
        }
    }

    /// Reads a state back from its stored status and completion time.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a completed request has no
    ///   time.
    /// - [`DomainError::Infrastructure`] when a request that is not completed
    ///   has one.
    pub fn from_stored(
        status: ErasureStatus,
        completed_at: Option<OffsetDateTime>,
    ) -> Result<Self, DomainError> {
        match (status, completed_at) {
            (ErasureStatus::Completed, Some(at)) => Ok(Self::Completed { at }),
            (ErasureStatus::Pending, None) => Ok(Self::Pending),
            (ErasureStatus::Processing, None) => Ok(Self::Processing),
            (ErasureStatus::Cancelled, None) => Ok(Self::Cancelled),
            (ErasureStatus::Held, None) => Ok(Self::Held),
            (ErasureStatus::Failed, None) => Ok(Self::Failed),
            (status, _) => Err(DomainError::infra_msg(format!(
                "stored {status:?} erasure request has a completion time that contradicts it"
            ))),
        }
    }

    /// When it finished, if it did. Storage keeps it this way.
    #[must_use]
    pub fn completed_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Completed { at } => Some(at),
            Self::Pending | Self::Processing | Self::Cancelled | Self::Held | Self::Failed => None,
        }
    }
}

/// A user's request to have their data deleted for good.
///
/// Who asked, why and when are fixed when it is made. Its status moves by
/// the [`ErasureStatus`] rules.
#[derive(Debug)]
pub struct ErasureRequest<T: TenantScope> {
    /// The request's id.
    id: ErasureRequestId,
    /// The user asking for erasure.
    user_id: UserId,
    /// Why the user wants their data deleted, if they said.
    reason: Option<Text>,
    /// Where the request stands.
    state: ErasureState,
    /// When the user asked.
    requested_at: OffsetDateTime,
    /// When the grace period ends and deletion may start.
    scheduled_at: OffsetDateTime,
    /// The hash of the token in the cancel link mailed to the person.
    cancel_token_hash: TokenHash,
    /// The address the cancel link was mailed to.
    sent_to: Email,
    /// What the request raised and has not handed over yet.
    raised: Raised<T>,
    /// Which tenant scope this belongs to. See [`crate::isolation`].
    _scope: PhantomData<T>,
}

/// What a new erasure request is made from.
pub struct RequestErasureParams {
    /// Why the user wants their data deleted, if they said.
    pub reason: Option<Text>,
    /// How long the person has to cancel before deletion starts.
    pub grace_period: GracePeriod,
    /// The hash of the token in the cancel link mailed to the person. They
    /// cannot sign in while the request waits, so the link is how they
    /// cancel it.
    pub cancel_token_hash: TokenHash,
}

/// An erasure request as storage keeps it, checked again by
/// [`ErasureRequest::reconstitute`].
pub struct ErasureRequestRow {
    /// The request's id.
    pub id: ErasureRequestId,
    /// The user asking for erasure.
    pub user_id: UserId,
    /// Why the user wants their data deleted, if they said.
    pub reason: Option<Text>,
    /// Where the request stands. See [`ErasureState::from_stored`].
    pub state: ErasureState,
    /// When the user asked.
    pub requested_at: OffsetDateTime,
    /// When deletion may start.
    pub scheduled_at: OffsetDateTime,
    /// The hash of the token in the cancel link mailed to the person.
    pub cancel_token_hash: TokenHash,
    /// The address the cancel link was mailed to.
    pub sent_to: Email,
}

impl<T: TenantScope> ErasureRequest<T> {
    /// Creates a pending erasure request for the signed-in holder and closes the account.
    /// Deletion waits for the grace period. The caller ends sessions and mails the cancel link.
    /// Raises `identity.erasure_requested`.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] if another person signed in.
    /// [`DomainError::Conflict`] if [`DepartureCheck::ensure_may_leave`] protects the last administrator.
    pub fn submit(
        params: RequestErasureParams,
        account: &mut User<T>,
        by: &impl SignedInPerson<T>,
        departure: &impl DepartureCheck,
    ) -> Result<Self, DomainError> {
        ensure_holder(by, account.id())?;
        departure.ensure_may_leave(account.id())?;
        account.close_for_erasure()?;
        Ok(Self::open(params, account))
    }

    /// Makes a new erasure request for someone else, as `control` allows.
    /// Raises `identity.erasure_requested`.
    ///
    /// Erasing an account destroys all it holds, so it needs the right to
    /// delete users and everything the account holds. Sam may manage users.
    /// Without this check, he asks to erase Ann, an admin, and after the
    /// grace period her account is gone.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses erasing the
    ///   account.
    pub fn submit_for(
        params: RequestErasureParams,
        account: &mut User<T>,
        control: &impl AccountControlCheck,
    ) -> Result<Self, DomainError> {
        control.ensure_allowed(account.id(), AccountAction::Erase)?;
        account.close_for_erasure()?;
        Ok(Self::open(params, account))
    }

    fn open(params: RequestErasureParams, account: &User<T>) -> Self {
        let now = crate::shared::clock::now();
        let scheduled = now.saturating_add(params.grace_period.as_duration());

        let mut request = Self {
            id: ErasureRequestId::new(),
            user_id: *account.id(),
            reason: params.reason,
            state: ErasureState::Pending,
            requested_at: now,
            scheduled_at: scheduled,
            cancel_token_hash: params.cancel_token_hash,
            sent_to: account.email().clone(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        request.raised.raise(ErasureRequested {
            scheduled_at: scheduled,
            occurred_at: now,
        });
        request
    }

    /// Rebuilds an erasure request from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the time from asking to being
    ///   due is not a [`GracePeriod`] of one to 30 days.
    /// - [`DomainError::Infrastructure`] when the row says it completed
    ///   before its grace period was over.
    pub fn reconstitute(row: ErasureRequestRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            reason: row.reason,
            state: row.state,
            requested_at: row.requested_at,
            scheduled_at: row.scheduled_at,
            cancel_token_hash: row.cancel_token_hash,
            sent_to: row.sent_to,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ErasureRequestRow) -> Result<(), DomainError> {
        RowCheck::of("erasure request")
            .holds(
                GracePeriod::allows(crate::shared::clock::between(
                    row.requested_at,
                    row.scheduled_at,
                )),
                "scheduled outside the grace period's bounds",
            )
            .in_order_if(
                row.scheduled_at,
                row.state.completed_at(),
                "completed before its grace period was over",
            )
            .finish()
    }

    /// The request's id.
    #[must_use]
    pub fn id(&self) -> &ErasureRequestId {
        &self.id
    }

    /// The user asking for erasure.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The hash of the token in the cancel link mailed to the person.
    #[must_use]
    pub fn cancel_token_hash(&self) -> &TokenHash {
        &self.cancel_token_hash
    }

    /// The address the cancel link was mailed to.
    #[must_use]
    pub fn sent_to(&self) -> &Email {
        &self.sent_to
    }

    /// Why the user wants their data deleted, if they said.
    #[must_use]
    pub fn reason(&self) -> Option<&Text> {
        self.reason.as_ref()
    }

    /// Where the request stands now.
    #[must_use]
    pub fn status(&self) -> ErasureStatus {
        self.state.status()
    }

    /// Where the request stands, with the time it finished if it did.
    #[must_use]
    pub fn state(&self) -> ErasureState {
        self.state
    }

    /// When the user asked.
    #[must_use]
    pub fn requested_at(&self) -> OffsetDateTime {
        self.requested_at
    }

    /// When deletion may start.
    #[must_use]
    pub fn scheduled_at(&self) -> OffsetDateTime {
        self.scheduled_at
    }

    /// When the erasure finished, if it did.
    #[must_use]
    pub fn completed_at(&self) -> Option<OffsetDateTime> {
        self.state.completed_at()
    }

    /// Whether the request is pending and its grace period is over at
    /// `now`, so deletion can start.
    #[must_use]
    pub fn is_due(&self, now: OffsetDateTime) -> bool {
        self.state == ErasureState::Pending && now >= self.scheduled_at
    }

    /// Whether the user can still cancel, which is while it is pending or
    /// held.
    #[must_use]
    pub fn is_cancellable(&self) -> bool {
        matches!(self.state, ErasureState::Pending | ErasureState::Held)
    }

    /// Starts deleting once the grace period is over. Raises
    /// `identity.erasure_started`.
    ///
    /// Until then the person may still cancel, and deleting their data would
    /// take that away.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the request is pending and
    ///   its grace period is not over at `now`.
    /// - [`DomainError::InvalidTransition`] when the request is neither
    ///   pending nor failed.
    pub fn start_processing(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.state == ErasureState::Pending && now < self.scheduled_at {
            return Err(DomainError::invalid_transition(message!(
                "identity-the-erasure-grace-period-is-not",
                "the erasure grace period is not over yet"
            )));
        }
        self.move_to(ErasureState::Processing)?;
        self.raise_started();
        Ok(())
    }

    /// Marks the erasure complete, at the current time, once all data is
    /// deleted. Raises `identity.erasure_completed`.
    ///
    /// # Errors
    ///
    /// - [`InvalidErasureTransition`] when it is not `Processing`.
    pub fn complete(&mut self) -> Result<(), InvalidErasureTransition> {
        let at = crate::shared::clock::now();
        self.move_to(ErasureState::Completed { at })?;
        self.raised.raise(ErasureCompleted {
            user_id: self.user_id,
            user_label: self.label(),
            occurred_at: at,
        });
        Ok(())
    }

    /// Cancels the request from the link mailed to the person, and opens
    /// their account again. Raises `identity.erasure_cancelled`.
    ///
    /// Following the link proves the reader holds the mailbox it went to.
    /// It counts only while the account still has that address.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is another account, or no
    ///   longer has the address the link went to.
    /// - [`DomainError::InvalidTransition`] when it is neither pending nor
    ///   held.
    pub fn cancel_from_link(&mut self, account: &mut User<T>) -> Result<(), DomainError> {
        if *account.id() != self.user_id || *account.email() != self.sent_to {
            return Err(DomainError::forbidden(message!(
                "identity-the-cancel-link-is-for-another",
                "the cancel link is for another account or an address it no longer has"
            )));
        }
        self.cancel(account)
    }

    /// Cancels the request for someone else, as `control` allows erasing
    /// them, and opens their account again. Raises
    /// `identity.erasure_cancelled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is not the one the
    ///   request is for, or `control` refuses erasing it.
    /// - [`DomainError::InvalidTransition`] when it is neither pending nor
    ///   held.
    pub fn cancel_for(
        &mut self,
        account: &mut User<T>,
        control: &impl AccountControlCheck,
    ) -> Result<(), DomainError> {
        if *account.id() != self.user_id {
            return Err(DomainError::forbidden(message!(
                "identity-the-request-is-for-another-account",
                "the request is for another account"
            )));
        }
        control.ensure_allowed(&self.user_id, AccountAction::Erase)?;
        self.cancel(account)
    }

    fn cancel(&mut self, account: &mut User<T>) -> Result<(), DomainError> {
        self.move_to(ErasureState::Cancelled)?;
        account.reopen_after_erasure()?;
        self.raised.raise(ErasureCancelled {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Pauses a pending request under a legal hold, as `control` allows.
    /// Raises `identity.erasure_held`.
    ///
    /// A tenant under a court order or an audit duty must keep the person's
    /// records. The request waits, past its grace period, until the hold is
    /// lifted.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses erasing the
    ///   account.
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub fn hold(&mut self, control: &impl AccountControlCheck) -> Result<(), DomainError> {
        control.ensure_allowed(&self.user_id, AccountAction::Erase)?;
        self.move_to(ErasureState::Held)?;
        self.raised.raise(ErasureHeld {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Lifts a legal hold, as `control` allows. The request is pending
    /// again, and due at once if its grace period has passed. Raises
    /// `identity.erasure_released`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses erasing the
    ///   account.
    /// - [`DomainError::InvalidTransition`] when it is not held.
    pub fn release(&mut self, control: &impl AccountControlCheck) -> Result<(), DomainError> {
        control.ensure_allowed(&self.user_id, AccountAction::Erase)?;
        if self.state != ErasureState::Held {
            return Err(DomainError::invalid_transition(message!(
                "identity-only-a-held-erasure-request-is",
                "only a held erasure request is released"
            )));
        }
        self.move_to(ErasureState::Pending)?;
        self.raised.raise(ErasureReleased {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Marks the erasure failed, when deletion stopped part way. Raises
    /// `identity.erasure_failed`.
    ///
    /// # Errors
    ///
    /// - [`InvalidErasureTransition`] when it is not `Processing`.
    pub fn fail(&mut self) -> Result<(), InvalidErasureTransition> {
        self.move_to(ErasureState::Failed)?;
        self.raised.raise(ErasureFailed {
            user_id: self.user_id,
            user_label: self.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Starts deleting again after a failure. Raises
    /// `identity.erasure_started`.
    ///
    /// A pending request starts through
    /// [`start_processing`](Self::start_processing) instead, which waits out
    /// its grace period.
    ///
    /// # Errors
    ///
    /// - [`InvalidErasureTransition`] when it is not `Failed`.
    pub fn retry(&mut self) -> Result<(), InvalidErasureTransition> {
        if self.state != ErasureState::Failed {
            return Err(InvalidErasureTransition {
                from: self.status(),
                to: ErasureStatus::Processing,
            });
        }
        self.move_to(ErasureState::Processing)?;
        self.raise_started();
        Ok(())
    }

    fn raise_started(&mut self) {
        self.raised.raise(ErasureStarted {
            user_id: self.user_id,
            user_label: self.label(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// How the audit trail names the person: by their account id only. The
    /// records are permanent, so a name or an address written into them
    /// would outlive the very data the person asked to have removed.
    fn label(&self) -> EventLabel {
        EventLabel::of(&self.user_id.to_string())
    }

    fn move_to(&mut self, to: ErasureState) -> Result<(), InvalidErasureTransition> {
        self.status().try_transition(to.status())?;
        self.state = to;
        Ok(())
    }
}

impl<T: TenantScope> Raises for ErasureRequest<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::granter::{AccountControl, Departure, Handout};
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::stewardship::Stewardship;
    use crate::domains::identity::account::user::tests::{control_over, signed_in_as};
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::user;
    use crate::test_support::events::{raised, raised_names};

    /// The account every test request is about.
    const ANN: uuid::Uuid = uuid::Uuid::from_u128(11);

    fn ann() -> UserId {
        UserId::from_uuid(ANN)
    }

    fn params() -> RequestErasureParams {
        RequestErasureParams {
            reason: Some(Text::new("reason", "I no longer use this service").unwrap()),
            grace_period: GracePeriod::days(30).unwrap(),
            cancel_token_hash: TokenHash::from_stored("cancelhash".to_owned()),
        }
    }

    /// Ann's active account, with her address verified.
    fn ann_account() -> User<ResolvedTenant> {
        let mut account = user(ann(), "ann@example.com");
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// Ann asks to be erased. Gives the request and her account after it.
    fn asked() -> (ErasureRequest<ResolvedTenant>, User<ResolvedTenant>) {
        let mut account = ann_account();
        let request = ErasureRequest::submit(
            params(),
            &mut account,
            &signed_in_as::<ResolvedTenant>(ann()),
            &leaving(),
        )
        .unwrap();
        (request, account)
    }

    fn request() -> ErasureRequest<ResolvedTenant> {
        asked().0
    }

    /// Someone acting on Ann's account, holding `held`, while Ann holds
    /// nothing.
    fn acting_on_ann(held: &'static [SystemPermission]) -> AccountControl<'static> {
        AccountControl::assumed(
            anyone_holding(held),
            ann(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        )
    }

    /// Ann leaving a tenant someone else administers too.
    fn leaving() -> Departure {
        Departure::assumed(ann(), Stewardship::OthersAdminister)
    }

    fn deleter() -> AccountControl<'static> {
        acting_on_ann(&[SystemPermission::Users(UserAction::Delete)])
    }

    /// A user asks for erasure. The request is pending, can be cancelled and
    /// has no completion time.
    #[test]
    fn submit_creates_pending_request() {
        let req = request();
        assert_eq!(req.status(), ErasureStatus::Pending);
        assert!(req.is_cancellable());
        assert!(req.completed_at().is_none());
    }

    /// With a 30-day grace period, deletion is due about 30 days after the
    /// request.
    #[test]
    fn scheduled_at_is_after_grace_period() {
        let req = request();
        let diff = req.scheduled_at() - req.requested_at();
        assert!(diff.whole_days() >= 29);
    }

    /// Right after the request, deletion is not due yet.
    #[test]
    fn not_due_during_grace_period() {
        let req = request();
        assert!(!req.is_due(crate::shared::clock::now()));
    }

    /// 31 days after a request with a 30-day grace period, deletion is due.
    #[test]
    fn due_after_grace_period() {
        let req = request();
        let future = crate::shared::clock::now() + Duration::days(31);
        assert!(req.is_due(future));
    }

    /// After the grace period the request starts processing and can no
    /// longer be cancelled. Completing it sets a completion time.
    #[test]
    fn an_erasure_runs_through_processing_to_completed() {
        let mut req = request();

        req.start_processing(after_grace(&req)).unwrap();
        assert_eq!(req.status(), ErasureStatus::Processing);
        assert!(!req.is_cancellable());

        req.complete().unwrap();
        assert_eq!(req.status(), ErasureStatus::Completed);
        assert!(req.completed_at().is_some());
    }

    fn after_grace(req: &ErasureRequest<ResolvedTenant>) -> OffsetDateTime {
        req.scheduled_at() + Duration::seconds(1)
    }

    /// Erasure remains pending when started one second before its grace period
    /// ends, then can start at the scheduled time.
    #[test]
    fn processing_waits_for_the_grace_period() {
        let mut req = request();

        let early = req.start_processing(req.scheduled_at() - Duration::seconds(1));

        assert!(matches!(early, Err(DomainError::InvalidTransition(_))));
        assert_eq!(req.status(), ErasureStatus::Pending);
        assert!(req.start_processing(req.scheduled_at()).is_ok());
    }

    /// Retrying a pending erasure is refused and leaves the request pending.
    #[test]
    fn a_pending_request_cannot_be_retried() {
        let mut req = request();

        assert!(req.retry().is_err());
        assert_eq!(req.status(), ErasureStatus::Pending);
    }

    /// Ann follows the cancel link during the grace period. The request is
    /// cancelled.
    #[test]
    fn cancel_during_grace_period() {
        let (mut req, mut account) = asked();
        req.cancel_from_link(&mut account).unwrap();
        assert_eq!(req.status(), ErasureStatus::Cancelled);
    }

    /// Once deletion has started, cancelling is refused.
    #[test]
    fn cannot_cancel_after_processing() {
        let (mut req, mut account) = asked();
        req.start_processing(after_grace(&req)).unwrap();
        assert!(req.cancel_from_link(&mut account).is_err());
    }

    /// Deletion starts and fails part way. Retrying puts it back to
    /// processing.
    #[test]
    fn fail_and_retry() {
        let mut req = request();
        req.start_processing(after_grace(&req)).unwrap();
        req.fail().unwrap();
        assert_eq!(req.status(), ErasureStatus::Failed);

        req.retry().unwrap();
        assert_eq!(req.status(), ErasureStatus::Processing);
    }

    /// A request names the user and keeps the reason "I no longer use this
    /// service". A request with no reason reads back with none.
    #[test]
    fn a_request_names_the_user_and_keeps_the_reason_given() {
        let request = request();

        assert_eq!(*request.user_id(), ann());
        assert_eq!(
            request.reason().map(Text::as_str),
            Some("I no longer use this service")
        );
        assert!(!request.id().as_uuid().is_nil());

        let unexplained = ErasureRequest::<ResolvedTenant>::submit(
            RequestErasureParams {
                reason: None,
                ..params()
            },
            &mut ann_account(),
            &signed_in_as::<ResolvedTenant>(ann()),
            &leaving(),
        )
        .unwrap();
        assert_eq!(unexplained.reason(), None);
    }

    /// A stored request says it completed one second before it was asked
    /// for. It is refused as corrupt.
    #[test]
    fn a_stored_erasure_completed_before_it_was_requested_is_refused() {
        let request = request();
        let row = ErasureRequestRow {
            id: request.id,
            user_id: request.user_id,
            reason: request.reason.clone(),
            state: ErasureState::Completed {
                at: request.requested_at - time::Duration::SECOND,
            },
            requested_at: request.requested_at,
            scheduled_at: request.scheduled_at,
            cancel_token_hash: request.cancel_token_hash.clone(),
            sent_to: request.sent_to.clone(),
        };

        assert!(refused_as_corrupt(
            &ErasureRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Grace periods of 0 and 31 days are refused, and 1 day is accepted. A
    /// grace period of nothing would make a request due at once, so it could
    /// never be cancelled.
    #[test]
    fn a_grace_period_outside_a_day_to_a_month_is_refused() {
        assert!(matches!(
            GracePeriod::days(0),
            Err(DomainError::Validation(_))
        ));
        assert!(matches!(
            GracePeriod::days(31),
            Err(DomainError::Validation(_))
        ));
        assert!(GracePeriod::days(1).is_ok());
    }

    /// A stored request is due the same moment it was asked for, leaving no
    /// time to cancel. It is refused as corrupt.
    #[test]
    fn a_stored_erasure_due_the_moment_it_was_requested_is_refused() {
        let request = request();
        let row = ErasureRequestRow {
            id: request.id,
            user_id: request.user_id,
            reason: request.reason.clone(),
            state: ErasureState::Pending,
            requested_at: request.requested_at,
            scheduled_at: request.requested_at,
            cancel_token_hash: request.cancel_token_hash.clone(),
            sent_to: request.sent_to.clone(),
        };

        assert!(refused_as_corrupt(
            &ErasureRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    fn stored(request: &ErasureRequest<ResolvedTenant>) -> ErasureRequestRow {
        ErasureRequestRow {
            id: request.id,
            user_id: request.user_id,
            reason: request.reason.clone(),
            state: request.state,
            requested_at: request.requested_at,
            scheduled_at: request.scheduled_at,
            cancel_token_hash: request.cancel_token_hash.clone(),
            sent_to: request.sent_to.clone(),
        }
    }

    /// A stored erasure scheduled one second after its request violates the
    /// minimum grace period and is rejected as corrupt.
    #[test]
    fn a_stored_erasure_due_sooner_than_a_day_is_refused() {
        let request = request();
        let row = ErasureRequestRow {
            scheduled_at: request.requested_at + Duration::SECOND,
            ..stored(&request)
        };

        assert!(refused_as_corrupt(
            &ErasureRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored request is due 31 days after it was asked for, longer than
    /// any grace period. It is refused as corrupt.
    #[test]
    fn a_stored_erasure_due_later_than_thirty_days_is_refused() {
        let request = request();
        let row = ErasureRequestRow {
            scheduled_at: request.requested_at + Duration::days(31),
            ..stored(&request)
        };

        assert!(refused_as_corrupt(
            &ErasureRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored erasure completed before its grace period ends is rejected as corrupt.
    #[test]
    fn a_stored_erasure_completed_inside_its_grace_period_is_refused() {
        let request = request();
        let row = ErasureRequestRow {
            state: ErasureState::Completed {
                at: request.scheduled_at - Duration::SECOND,
            },
            ..stored(&request)
        };

        assert!(refused_as_corrupt(
            &ErasureRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A request made with a one-day and one with a 30-day grace period both
    /// load back from their rows.
    #[test]
    fn a_stored_erasure_within_the_grace_period_bounds_loads() {
        for days in [GracePeriod::MIN_DAYS, GracePeriod::MAX_DAYS] {
            let request = ErasureRequest::<ResolvedTenant>::submit(
                RequestErasureParams {
                    grace_period: GracePeriod::days(days).unwrap(),
                    ..params()
                },
                &mut ann_account(),
                &signed_in_as::<ResolvedTenant>(ann()),
                &leaving(),
            )
            .unwrap();

            assert!(ErasureRequest::<ResolvedTenant>::reconstitute(stored(&request)).is_ok());
        }
    }

    /// Mallory's own sign-in cannot submit Ann's personal erasure request.
    #[test]
    fn only_the_person_asks_for_their_own_erasure() {
        let mallory = signed_in_as::<ResolvedTenant>(UserId::new());

        let asked = ErasureRequest::submit(params(), &mut ann_account(), &mallory, &leaving());

        assert!(matches!(asked, Err(DomainError::Forbidden(_))));
    }

    /// The tenant's last administrator cannot request her own erasure, and her
    /// account remains able to authenticate.
    #[test]
    fn the_last_administrator_cannot_erase_themselves() {
        let mut account = ann_account();
        let last = Departure::assumed(ann(), Stewardship::LastAdministrator);

        let asked = ErasureRequest::submit(
            params(),
            &mut account,
            &signed_in_as::<ResolvedTenant>(ann()),
            &last,
        );

        assert!(matches!(asked, Err(DomainError::Conflict(_))));
        assert!(account.can_authenticate());
    }

    /// A check worked out for another account does not let Ann leave.
    #[test]
    fn a_departure_worked_out_for_someone_else_is_refused() {
        let for_bob = Departure::assumed(UserId::new(), Stewardship::OthersAdminister);

        let asked = ErasureRequest::submit(
            params(),
            &mut ann_account(),
            &signed_in_as::<ResolvedTenant>(ann()),
            &for_bob,
        );

        assert!(matches!(asked, Err(DomainError::Forbidden(_))));
    }

    /// Updating users does not authorize erasing Ann's account, while permission
    /// to delete users allows the request.
    #[test]
    fn asking_for_someone_elses_erasure_needs_the_right_to_delete_users() {
        let sam = acting_on_ann(&[SystemPermission::Users(UserAction::Update)]);

        let by_sam = ErasureRequest::submit_for(params(), &mut ann_account(), &sam);
        let by_deleter = ErasureRequest::submit_for(params(), &mut ann_account(), &deleter());

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_deleter.is_ok());
    }

    /// A court order arrives during Ann's grace period. The request is held
    /// and cannot start deleting once the grace period is over. The hold is
    /// lifted, and it may start.
    #[test]
    fn a_held_request_waits_until_the_hold_is_lifted() {
        let mut req = request();
        req.hold(&deleter()).unwrap();

        let while_held = req.start_processing(after_grace(&req));
        req.release(&deleter()).unwrap();

        assert!(while_held.is_err());
        assert!(!req.is_due(req.requested_at()));
        assert!(req.start_processing(after_grace(&req)).is_ok());
    }

    /// Ann follows her cancel link while the request is held. It is
    /// cancelled.
    #[test]
    fn a_held_request_can_still_be_cancelled_by_its_person() {
        let (mut req, mut account) = asked();
        req.hold(&deleter()).unwrap();

        req.cancel_from_link(&mut account).unwrap();

        assert_eq!(req.status(), ErasureStatus::Cancelled);
    }

    /// Ann asks to be erased. Her account is closed and cannot sign in, and
    /// an admin cannot activate it. She follows her cancel link, and
    /// it is active again.
    #[test]
    fn asking_for_erasure_closes_the_account_until_it_is_cancelled() {
        let (mut req, mut account) = asked();
        let closed = account.status();
        let activated = account.activate(&control_over(&account));

        req.cancel_from_link(&mut account).unwrap();

        assert_eq!(closed, UserStatus::Closing);
        assert!(matches!(activated, Err(DomainError::InvalidTransition(_))));
        assert_eq!(account.status(), UserStatus::Active);
    }

    /// A cancel link sent before Ann's address changed cannot cancel her erasure,
    /// which remains pending.
    #[test]
    fn a_cancel_link_to_an_old_address_does_nothing() {
        let (mut req, mut account) = asked();
        account
            .change_email(
                Email::new("ann@new.example").unwrap(),
                &control_over(&account),
            )
            .unwrap();

        let cancelled = req.cancel_from_link(&mut account);

        assert!(matches!(cancelled, Err(DomainError::Forbidden(_))));
        assert_eq!(req.status(), ErasureStatus::Pending);
    }

    /// An admin who may delete users cancels Ann's request for her. Her
    /// account opens again.
    #[test]
    fn an_admin_cancelling_opens_the_account_again() {
        let (mut req, mut account) = asked();

        req.cancel_for(&mut account, &deleter()).unwrap();

        assert_eq!(req.status(), ErasureStatus::Cancelled);
        assert_eq!(account.status(), UserStatus::Active);
    }

    /// Sam cannot cancel Ann's erasure with update-only rights. The request
    /// remains pending and her account remains closing.
    #[test]
    fn cancelling_someone_elses_erasure_needs_the_right_to_delete_users() {
        let (mut req, mut account) = asked();
        let sam = acting_on_ann(&[SystemPermission::Users(UserAction::Update)]);

        let result = req.cancel_for(&mut account, &sam);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(req.status(), ErasureStatus::Pending);
        assert_eq!(account.status(), UserStatus::Closing);
    }

    /// Ann asks to be erased. The request raises that it was asked for,
    /// with the day deletion is due.
    #[test]
    fn asking_raises_identity_erasure_requested() {
        let mut req = request();

        let events = raised(&mut req);

        assert_eq!(
            events[0].event_type().to_string(),
            "identity.erasure_requested"
        );
        assert_eq!(
            events[0].payload().get("scheduled_at"),
            Some(req.scheduled_at().to_string().as_str())
        );
    }

    /// Ann's request is held and released, then carried out: it starts,
    /// fails, starts again and completes. Each step is raised, in order, and
    /// the steps of the deletion name her by her id only.
    #[test]
    fn every_step_of_an_erasure_is_raised_in_order() {
        let mut req = request();
        raised_names(&mut req);
        req.hold(&deleter()).unwrap();
        req.release(&deleter()).unwrap();

        req.start_processing(after_grace(&req)).unwrap();
        req.fail().unwrap();
        req.retry().unwrap();
        req.complete().unwrap();

        let events = raised(&mut req);
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "identity.erasure_held",
                "identity.erasure_released",
                "identity.erasure_started",
                "identity.erasure_failed",
                "identity.erasure_started",
                "identity.erasure_completed",
            ]
        );
        let Some(FieldValue::Reference(user)) = events[5].payload().value("user").cloned() else {
            panic!("the completed erasure names the account");
        };
        assert_eq!(user.label(), ann().to_string());
    }

    /// Ann cancels her request from the link, and an admin cancels another
    /// for her. Each cancelling is raised.
    #[test]
    fn cancelling_raises_identity_erasure_cancelled() {
        let (mut by_link, mut account) = asked();
        raised_names(&mut by_link);
        let (mut by_admin, mut other) = asked();
        raised_names(&mut by_admin);

        by_link.cancel_from_link(&mut account).unwrap();
        by_admin.cancel_for(&mut other, &deleter()).unwrap();

        assert_eq!(raised_names(&mut by_link), ["identity.erasure_cancelled"]);
        assert_eq!(raised_names(&mut by_admin), ["identity.erasure_cancelled"]);
    }

    /// Unauthorized holds and cancellation, and processing before the grace
    /// period ends, are refused without raising events.
    #[test]
    fn a_refused_erasure_change_raises_nothing() {
        let (mut req, mut account) = asked();
        raised_names(&mut req);
        let sam = acting_on_ann(&[SystemPermission::Users(UserAction::Update)]);

        let held = req.hold(&sam);
        let cancelled = req.cancel_for(&mut account, &sam);
        let started = req.start_processing(crate::shared::clock::now());

        assert!(held.is_err());
        assert!(cancelled.is_err());
        assert!(started.is_err());
        assert!(raised_names(&mut req).is_empty());
    }

    /// Ann's request is read back from storage. It has raised nothing.
    #[test]
    fn a_request_read_back_from_storage_has_raised_nothing() {
        let mut req = ErasureRequest::<ResolvedTenant>::reconstitute(stored(&request())).unwrap();

        assert!(raised_names(&mut req).is_empty());
    }
}
