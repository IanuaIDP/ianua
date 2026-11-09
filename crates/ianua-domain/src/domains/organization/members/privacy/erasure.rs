//! An organization member's request to have their data deleted for good,
//! under GDPR Article 17.
//!
//! It keeps the rules of a tenant user's
//! [`ErasureRequest`](crate::domains::identity::privacy::erasure::ErasureRequest):
//! a grace period of one to 30 days the member can cancel from a mailed
//! link, a legal hold that pauses it, and deletion only once the period is
//! over. The organization keeps an owner: the last active owner cannot ask
//! to be erased.

use time::OffsetDateTime;

use crate::domains::identity::account::control::AccountAction;
use crate::domains::identity::privacy::erasure::{ErasureState, GracePeriod, RequestErasureParams};
use crate::domains::identity::privacy::erasure_status::{ErasureStatus, InvalidErasureTransition};
use crate::domains::organization::events::privacy::{
    OrgUserErasureCancelled, OrgUserErasureCompleted, OrgUserErasureFailed, OrgUserErasureHeld,
    OrgUserErasureReleased, OrgUserErasureRequested, OrgUserErasureStarted,
};
use crate::domains::organization::members::account_control::OrgAccountControl;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::owners::Owners;
use crate::domains::organization::members::privacy::ensure_in_person;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{Email, ErasureRequestId, OrgUserId, OrganizationId, Text, TokenHash};

/// A member's request to have their data deleted for good.
#[derive(Debug)]
pub struct OrgErasureRequest {
    id: ErasureRequestId,
    organization_id: OrganizationId,
    org_user_id: OrgUserId,
    /// Why the member wants their data deleted, if they said.
    reason: Option<Text>,
    state: ErasureState,
    requested_at: OffsetDateTime,
    scheduled_at: OffsetDateTime,
    cancel_token_hash: TokenHash,
    sent_to: Email,
    raised: RaisedEvents,
}

/// A member's erasure request as storage keeps it, checked again by
/// [`OrgErasureRequest::reconstitute`].
pub struct OrgErasureRequestRow {
    /// The request's id.
    pub id: ErasureRequestId,
    /// The organization the member belongs to.
    pub organization_id: OrganizationId,
    /// The member to be erased.
    pub org_user_id: OrgUserId,
    /// Why the member wants their data deleted, if they said.
    pub reason: Option<Text>,
    /// Where the request stands. See [`ErasureState::from_stored`].
    pub state: ErasureState,
    /// When the member asked.
    pub requested_at: OffsetDateTime,
    /// When deletion may start.
    pub scheduled_at: OffsetDateTime,
    /// The hash of the token in the cancel link mailed to the member.
    pub cancel_token_hash: TokenHash,
    /// The address the cancel link was mailed to.
    pub sent_to: Email,
}

impl OrgErasureRequest {
    /// Requests self-erasure from the member's own session and closes the account.
    /// `owners` must include every current member. The caller ends sessions and mails
    /// the cancellation link. Raises `organization.org_user_erasure_requested`.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] unless `by` is the member using their own session.
    /// [`DomainError::Conflict`] if the member is the last active owner.
    pub fn submit(
        params: RequestErasureParams,
        member: &mut OrgUser,
        by: &OrgControl<'_>,
        owners: Owners<'_>,
    ) -> Result<Self, DomainError> {
        ensure_in_person(member, by)?;
        member.ensure_an_owner_stays(owners)?;
        member.close_for_erasure()?;
        Ok(Self::open(params, member))
    }

    /// Requests erasure under another person's removal authority and closes the account.
    /// Raises `organization.org_user_erasure_requested`.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another member's control, missing removal rights,
    /// self-removal, or a non-owner acting on an owner.
    /// [`DomainError::Conflict`] if the member is the last active owner.
    pub fn submit_for(
        params: RequestErasureParams,
        member: &mut OrgUser,
        control: &OrgAccountControl<'_>,
        owners: Owners<'_>,
    ) -> Result<Self, DomainError> {
        control.ensure_on(member.id(), AccountAction::Erase)?;
        member.ensure_an_owner_stays(owners)?;
        member.close_for_erasure()?;
        Ok(Self::open(params, member))
    }

    fn open(params: RequestErasureParams, member: &OrgUser) -> Self {
        let now = crate::shared::clock::now();
        let scheduled_at = now.saturating_add(params.grace_period.as_duration());
        let mut request = Self {
            id: ErasureRequestId::new(),
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            reason: params.reason,
            state: ErasureState::Pending,
            requested_at: now,
            scheduled_at,
            cancel_token_hash: params.cancel_token_hash,
            sent_to: member.email().clone(),
            raised: RaisedEvents::default(),
        };
        request.raised.raise_organization(OrgUserErasureRequested {
            organization_id: request.organization_id,
            org_user_id: request.org_user_id,
            scheduled_at,
            occurred_at: now,
        });
        request
    }

    /// Rebuilds a member's erasure request from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the time from asking to being
    ///   due is not a [`GracePeriod`] of one to 30 days.
    /// - [`DomainError::Infrastructure`] when the row says it completed
    ///   before its grace period was over.
    pub fn reconstitute(row: OrgErasureRequestRow) -> Result<Self, DomainError> {
        RowCheck::of("organization erasure request")
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
            .finish()?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            org_user_id: row.org_user_id,
            reason: row.reason,
            state: row.state,
            requested_at: row.requested_at,
            scheduled_at: row.scheduled_at,
            cancel_token_hash: row.cancel_token_hash,
            sent_to: row.sent_to,
            raised: RaisedEvents::default(),
        })
    }

    /// The request's id.
    #[must_use]
    pub fn id(&self) -> &ErasureRequestId {
        &self.id
    }

    /// The organization the member belongs to.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The member to be erased.
    #[must_use]
    pub fn org_user_id(&self) -> &OrgUserId {
        &self.org_user_id
    }

    /// Why the member wants their data deleted, if they said.
    #[must_use]
    pub fn reason(&self) -> Option<&Text> {
        self.reason.as_ref()
    }

    /// Where the request stands, with the time it finished if it did.
    #[must_use]
    pub fn state(&self) -> ErasureState {
        self.state
    }

    /// Where the request stands.
    #[must_use]
    pub fn status(&self) -> ErasureStatus {
        self.state.status()
    }

    /// When the member asked.
    #[must_use]
    pub fn requested_at(&self) -> OffsetDateTime {
        self.requested_at
    }

    /// When deletion may start.
    #[must_use]
    pub fn scheduled_at(&self) -> OffsetDateTime {
        self.scheduled_at
    }

    /// The hash of the token in the cancel link mailed to the member.
    #[must_use]
    pub fn cancel_token_hash(&self) -> &TokenHash {
        &self.cancel_token_hash
    }

    /// The address the cancel link was mailed to.
    #[must_use]
    pub fn sent_to(&self) -> &Email {
        &self.sent_to
    }

    /// Whether the request is pending and its grace period is over at
    /// `now`, so deletion can start.
    #[must_use]
    pub fn is_due(&self, now: OffsetDateTime) -> bool {
        self.state == ErasureState::Pending && now >= self.scheduled_at
    }

    /// Starts deleting once the grace period is over. Raises
    /// `organization.org_user_erasure_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the request is pending and
    ///   its grace period is not over at `now`, or is neither pending nor
    ///   failed.
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

    /// Starts deleting again after a failure. Raises
    /// `organization.org_user_erasure_started`.
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

    /// Marks the erasure complete, at the current time, once every record
    /// of the member is deleted. Raises
    /// `organization.org_user_erasure_completed`.
    ///
    /// # Errors
    ///
    /// - [`InvalidErasureTransition`] when it is not `Processing`.
    pub fn complete(&mut self) -> Result<(), InvalidErasureTransition> {
        let at = crate::shared::clock::now();
        self.move_to(ErasureState::Completed { at })?;
        self.raised.raise_organization(OrgUserErasureCompleted {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            occurred_at: at,
        });
        Ok(())
    }

    /// Marks the erasure failed, when deletion stopped part way. Raises
    /// `organization.org_user_erasure_failed`.
    ///
    /// # Errors
    ///
    /// - [`InvalidErasureTransition`] when it is not `Processing`.
    pub fn fail(&mut self) -> Result<(), InvalidErasureTransition> {
        self.move_to(ErasureState::Failed)?;
        self.raised.raise_organization(OrgUserErasureFailed {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Cancels the request from the link mailed to the member, and opens
    /// their account again. Raises
    /// `organization.org_user_erasure_cancelled`.
    ///
    /// Following the link proves the reader holds the mailbox it went to,
    /// and counts only while the account still has that address.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `member` is another member, or no
    ///   longer has the address the link went to.
    /// - [`DomainError::InvalidTransition`] when it is neither pending nor
    ///   held.
    pub fn cancel_from_link(&mut self, member: &mut OrgUser) -> Result<(), DomainError> {
        if *member.id() != self.org_user_id || *member.email() != self.sent_to {
            return Err(DomainError::forbidden(message!(
                "organization-the-cancel-link-is-for-another",
                "the cancel link is for another member or an address they no longer have"
            )));
        }
        self.cancel(member)
    }

    /// Cancels the request for someone else, as `control` allows removing
    /// the member, and opens their account again. Raises
    /// `organization.org_user_erasure_cancelled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `member` is not the one the request
    ///   is for, or `control` refuses removing them.
    /// - [`DomainError::InvalidTransition`] when it is neither pending nor
    ///   held.
    pub fn cancel_for(
        &mut self,
        member: &mut OrgUser,
        control: &OrgAccountControl<'_>,
    ) -> Result<(), DomainError> {
        if *member.id() != self.org_user_id {
            return Err(DomainError::forbidden(message!(
                "organization-the-request-is-for-another-member",
                "the request is for another member"
            )));
        }
        control.ensure_on(&self.org_user_id, AccountAction::Erase)?;
        self.cancel(member)
    }

    fn cancel(&mut self, member: &mut OrgUser) -> Result<(), DomainError> {
        self.move_to(ErasureState::Cancelled)?;
        member.reopen_after_erasure()?;
        self.raised.raise_organization(OrgUserErasureCancelled {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Pauses a pending request under a legal hold, as `control` allows
    /// removing the member. Raises `organization.org_user_erasure_held`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses removing the
    ///   member.
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub fn hold(&mut self, control: &OrgAccountControl<'_>) -> Result<(), DomainError> {
        control.ensure_on(&self.org_user_id, AccountAction::Erase)?;
        self.move_to(ErasureState::Held)?;
        self.raised.raise_organization(OrgUserErasureHeld {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Lifts a legal hold, as `control` allows removing the member. The
    /// request is pending again, and due at once if its grace period has
    /// passed. Raises `organization.org_user_erasure_released`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses removing the
    ///   member.
    /// - [`DomainError::InvalidTransition`] when it is not held.
    pub fn release(&mut self, control: &OrgAccountControl<'_>) -> Result<(), DomainError> {
        control.ensure_on(&self.org_user_id, AccountAction::Erase)?;
        if self.state != ErasureState::Held {
            return Err(DomainError::invalid_transition(message!(
                "identity-only-a-held-erasure-request-is",
                "only a held erasure request is released"
            )));
        }
        self.move_to(ErasureState::Pending)?;
        self.raised.raise_organization(OrgUserErasureReleased {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    fn raise_started(&mut self) {
        self.raised.raise_organization(OrgUserErasureStarted {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            occurred_at: crate::shared::clock::now(),
        });
    }

    fn move_to(&mut self, to: ErasureState) -> Result<(), InvalidErasureTransition> {
        self.status().try_transition(to.status())?;
        self.state = to;
        Ok(())
    }
}

impl RaisesComplete for OrgErasureRequest {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::organization::members::control::tests::{
        acting, founder, member_of, session_of,
    };
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user_status::OrgUserStatus;
    use crate::domains::organization::members::privacy::tests::copy_of;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;

    fn params() -> RequestErasureParams {
        RequestErasureParams {
            reason: None,
            grace_period: GracePeriod::days(30).unwrap(),
            cancel_token_hash: TokenHash::from_stored("cancelhash".to_owned()),
        }
    }

    /// Sam, a plain member, asks to be erased from his own sign-in. His
    /// account closes while the request waits out its grace period, and the
    /// request is recorded.
    #[test]
    fn a_member_asks_to_be_erased() {
        let ann = founder();
        let mut sam = member_of(&ann);
        let him = copy_of(&sam);
        let session = session_of(&him);
        let members = [ann, him];

        let mut request = OrgErasureRequest::submit(
            params(),
            &mut sam,
            &acting(&members[1], &session),
            Owners::of(&members),
        )
        .unwrap();

        assert_eq!(request.status(), ErasureStatus::Pending);
        assert_eq!(sam.status(), OrgUserStatus::Closing);
        assert!(!sam.status().can_authenticate());
        assert_eq!(
            raised_complete_names(&mut request),
            ["organization.org_user_erasure_requested"]
        );
    }

    /// Ann's self-erasure is refused while she is the sole owner, leaving
    /// her account active.
    #[test]
    fn the_last_owner_cannot_ask_to_be_erased() {
        let mut ann = founder();
        let her = copy_of(&ann);
        let session = session_of(&her);
        let members = [copy_of(&ann)];

        let refused = OrgErasureRequest::submit(
            params(),
            &mut ann,
            &acting(&her, &session),
            Owners::of(&members),
        );

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(ann.status(), OrgUserStatus::Active);
        assert_eq!(her.role(), OrgRole::Owner);
    }

    /// Sam's session cannot submit Bob's self-erasure request.
    #[test]
    fn a_member_asks_to_erase_only_themselves() {
        let ann = founder();
        let sam = member_of(&ann);
        let mut bob = member_of(&ann);
        let session = session_of(&sam);
        let members = [copy_of(&ann), copy_of(&sam)];

        let refused = OrgErasureRequest::submit(
            params(),
            &mut bob,
            &acting(&sam, &session),
            Owners::of(&members),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Ann, an owner, asks to erase Sam for him. Sam later follows the
    /// cancel link, and his account is open again.
    #[test]
    fn an_owner_asks_for_a_member_and_the_link_cancels_it() {
        let ann = founder();
        let mut sam = member_of(&ann);
        let target = copy_of(&sam);
        let session = session_of(&ann);
        let control = OrgAccountControl::new(acting(&ann, &session), &target);
        let members = [copy_of(&ann), copy_of(&sam)];
        let mut request =
            OrgErasureRequest::submit_for(params(), &mut sam, &control, Owners::of(&members))
                .unwrap();

        request.cancel_from_link(&mut sam).unwrap();

        assert_eq!(request.status(), ErasureStatus::Cancelled);
        assert_eq!(sam.status(), OrgUserStatus::Active);
    }

    /// An owner cannot reactivate Sam through an ordinary status change
    /// after he requests erasure; his account remains closing.
    #[test]
    fn a_closing_member_comes_back_only_through_the_erasure() {
        let ann = founder();
        let mut sam = member_of(&ann);
        let him = copy_of(&sam);
        let own_session = session_of(&him);
        let members = [copy_of(&ann), copy_of(&sam)];
        OrgErasureRequest::submit(
            params(),
            &mut sam,
            &acting(&him, &own_session),
            Owners::of(&members),
        )
        .unwrap();
        let session = session_of(&ann);

        let refused = sam.change_status(
            OrgUserStatus::Active,
            &acting(&ann, &session),
            Owners::of(&members),
        );

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
        assert_eq!(sam.status(), OrgUserStatus::Closing);
    }

    /// Sam's member role cannot submit an administrative erasure request
    /// for Bob.
    #[test]
    fn a_plain_member_cannot_ask_to_erase_another() {
        let ann = founder();
        let sam = member_of(&ann);
        let mut bob = member_of(&ann);
        let target = copy_of(&bob);
        let session = session_of(&sam);
        let control = OrgAccountControl::new(acting(&sam, &session), &target);
        let members = [copy_of(&ann)];

        let refused =
            OrgErasureRequest::submit_for(params(), &mut bob, &control, Owners::of(&members));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Processing is refused one second before the erasure is due. At its
    /// scheduled time processing and completion succeed.
    #[test]
    fn deletion_waits_for_the_grace_period() {
        let ann = founder();
        let mut sam = member_of(&ann);
        let him = copy_of(&sam);
        let session = session_of(&him);
        let members = [copy_of(&ann)];
        let mut request = OrgErasureRequest::submit(
            params(),
            &mut sam,
            &acting(&him, &session),
            Owners::of(&members),
        )
        .unwrap();

        let early = request.start_processing(request.scheduled_at() - Duration::seconds(1));

        assert!(matches!(early, Err(DomainError::InvalidTransition(_))));
        assert!(request.start_processing(request.scheduled_at()).is_ok());
        assert!(request.complete().is_ok());
        assert_eq!(request.status(), ErasureStatus::Completed);
    }

    /// Sam's cancellation link cannot cancel against Bob's account; Sam's
    /// erasure request remains pending.
    #[test]
    fn a_cancel_link_counts_only_for_its_own_member() {
        let ann = founder();
        let mut sam = member_of(&ann);
        let him = copy_of(&sam);
        let session = session_of(&him);
        let members = [copy_of(&ann)];
        let mut request = OrgErasureRequest::submit(
            params(),
            &mut sam,
            &acting(&him, &session),
            Owners::of(&members),
        )
        .unwrap();
        let mut bob = member_of(&ann);

        let refused = request.cancel_from_link(&mut bob);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(request.status(), ErasureStatus::Pending);
    }

    /// A stored request due a year after it was asked for is refused as
    /// corrupt.
    #[test]
    fn a_stored_request_outside_the_grace_period_is_refused() {
        let ann = founder();
        let now = crate::shared::clock::now();
        let row = OrgErasureRequestRow {
            id: ErasureRequestId::new(),
            organization_id: *ann.organization_id(),
            org_user_id: *ann.id(),
            reason: None,
            state: ErasureState::Pending,
            requested_at: now,
            scheduled_at: now + Duration::days(365),
            cancel_token_hash: TokenHash::from_stored("cancelhash".to_owned()),
            sent_to: ann.email().clone(),
        };

        assert!(refused_as_corrupt(&OrgErasureRequest::reconstitute(row)));
    }
}
