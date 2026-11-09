//! The offer an invitation carries: the link that answers it, how long it
//! stands, and whether it was taken up. Tenant and organization invitations
//! hold one each and differ only in who is invited to what.

use time::OffsetDateTime;

use crate::domains::identity::invitations::status::{InvitationLifecycle, InvitationStatus};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{Text, TokenHash};

/// Where an offer stands, with the time it was accepted when it was.
///
/// An accepted offer always has a time, and no other offer has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferState {
    /// Sent and waiting for an answer.
    Pending,
    /// Taken up.
    Accepted {
        /// When it was taken up.
        at: OffsetDateTime,
    },
    /// Turned down by the invitee.
    Declined,
    /// Marked expired.
    Expired,
    /// Withdrawn before it was taken up.
    Revoked,
}

impl OfferState {
    /// The status of this state, without the time.
    #[must_use]
    pub fn status(self) -> InvitationStatus {
        match self {
            Self::Pending => InvitationStatus::Pending,
            Self::Accepted { .. } => InvitationStatus::Accepted,
            Self::Declined => InvitationStatus::Declined,
            Self::Expired => InvitationStatus::Expired,
            Self::Revoked => InvitationStatus::Revoked,
        }
    }

    /// Reads a state back from its stored status and acceptance time.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when an accepted offer has no time.
    /// - [`DomainError::Infrastructure`] when any other offer has one.
    pub fn from_stored(
        status: InvitationStatus,
        accepted_at: Option<OffsetDateTime>,
    ) -> Result<Self, DomainError> {
        match (status, accepted_at) {
            (InvitationStatus::Accepted, Some(at)) => Ok(Self::Accepted { at }),
            (InvitationStatus::Pending, None) => Ok(Self::Pending),
            (InvitationStatus::Declined, None) => Ok(Self::Declined),
            (InvitationStatus::Expired, None) => Ok(Self::Expired),
            (InvitationStatus::Revoked, None) => Ok(Self::Revoked),
            (status, _) => Err(DomainError::infra_msg(format!(
                "stored {status:?} invitation has an acceptance time that contradicts it"
            ))),
        }
    }

    /// When it was accepted, if it was. Storage keeps it this way.
    #[must_use]
    pub fn accepted_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Accepted { at } => Some(at),
            Self::Pending | Self::Declined | Self::Expired | Self::Revoked => None,
        }
    }
}

/// An invitation's offer and where it stands.
#[derive(Debug)]
pub struct InvitationOffer {
    token_hash: TokenHash,
    state: OfferState,
    message: Option<Text>,
    expires_at: OffsetDateTime,
}

/// An offer as storage keeps it.
pub struct OfferRow {
    /// The hash of the link's token.
    pub token_hash: TokenHash,
    /// Where the offer stands. See [`OfferState::from_stored`].
    pub state: OfferState,
    /// The personal message sent with it.
    pub message: Option<Text>,
    /// When the link stops working.
    pub expires_at: OffsetDateTime,
}

impl InvitationOffer {
    /// A fresh, pending offer.
    ///
    /// An offer has no rule of who may answer it. Only the invitation that
    /// holds it opens and moves it, after its own checks, so these are kept
    /// to the crate.
    #[must_use]
    pub(crate) fn open(
        token_hash: TokenHash,
        message: Option<Text>,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            token_hash,
            state: OfferState::Pending,
            message,
            expires_at,
        }
    }

    /// Rebuilds an offer from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the offer was
    ///   accepted once its link had run out.
    pub fn reconstitute(row: OfferRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            token_hash: row.token_hash,
            state: row.state,
            message: row.message,
            expires_at: row.expires_at,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OfferRow) -> Result<(), DomainError> {
        RowCheck::of("invitation offer")
            .holds(
                row.state.accepted_at().is_none_or(|at| at < row.expires_at),
                "accepted after its link ran out",
            )
            .finish()
    }

    /// The hash of the link's token.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// Where the offer stands in storage.
    #[must_use]
    pub fn status(&self) -> InvitationStatus {
        self.state.status()
    }

    /// Where the offer stands, with its acceptance time when it was
    /// accepted.
    #[must_use]
    pub fn offer_state(&self) -> OfferState {
        self.state
    }

    /// The personal message sent with it.
    #[must_use]
    pub fn message(&self) -> Option<&Text> {
        self.message.as_ref()
    }

    /// When the link stops working.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When it was accepted, if it was.
    #[must_use]
    pub fn accepted_at(&self) -> Option<OffsetDateTime> {
        self.state.accepted_at()
    }

    /// Whether the link can still be accepted at `now`.
    #[must_use]
    pub fn is_pending(&self, now: OffsetDateTime) -> bool {
        self.state == OfferState::Pending && now < self.expires_at
    }

    /// What following the link at `now` gets you.
    ///
    /// Expiry is judged here, not stored. So a link that has run out still
    /// reads `Pending` in storage.
    #[must_use]
    pub fn state(&self, now: OffsetDateTime) -> InvitationLifecycle {
        match self.state {
            OfferState::Pending if now < self.expires_at => InvitationLifecycle::Pending,
            OfferState::Pending | OfferState::Expired => InvitationLifecycle::Expired,
            OfferState::Accepted { .. } | OfferState::Declined | OfferState::Revoked => {
                InvitationLifecycle::Closed
            }
        }
    }

    /// Takes up the offer.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when its link has run out.
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub(crate) fn accept(&mut self) -> Result<(), DomainError> {
        let now = crate::shared::clock::now();
        if self.state(now) == InvitationLifecycle::Expired {
            return Err(DomainError::conflict(message!(
                "identity-the-invitation-has-expired",
                "the invitation has expired"
            )));
        }
        self.move_to(OfferState::Accepted { at: now })
    }

    /// Marks the offer expired once its link has run out at `now`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the link has not run out yet.
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub(crate) fn lapse(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.state == OfferState::Pending && now < self.expires_at {
            return Err(DomainError::conflict(message!(
                "identity-the-invitation-has-not-run-out",
                "the invitation has not run out yet"
            )));
        }
        self.move_to(OfferState::Expired)
    }

    /// Turns the offer down.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub(crate) fn decline(&mut self) -> Result<(), DomainError> {
        self.move_to(OfferState::Declined)
    }

    /// Withdraws the offer before it is taken up.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub(crate) fn revoke(&mut self) -> Result<(), DomainError> {
        self.move_to(OfferState::Revoked)
    }

    /// Replaces the link and sets a new expiry. The offer stays pending and
    /// the old link stops working.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not pending. A new
    ///   link does not reopen an accepted or revoked invitation.
    pub(crate) fn rotate_token(
        &mut self,
        new_token_hash: TokenHash,
        new_expires_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if self.state != OfferState::Pending {
            return Err(DomainError::invalid_transition(message!(
                "identity-a-invitation-cannot-be-sent-again",
                format!("a {:?} invitation cannot be sent again", self.status())
            )));
        }
        self.token_hash = new_token_hash;
        self.expires_at = new_expires_at;
        Ok(())
    }

    fn move_to(&mut self, to: OfferState) -> Result<(), DomainError> {
        self.status()
            .try_transition(to.status())
            .map_err(|refused| {
                DomainError::invalid_transition(message!(
                    "identity-an-invitation-cannot-move-from-to",
                    format!(
                        "an invitation cannot move from {:?} to {:?}",
                        refused.from, refused.to
                    )
                ))
            })?;
        self.state = to;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::shared::model::row_check::refused_as_corrupt;

    fn offer_expiring_in(lifetime: Duration) -> InvitationOffer {
        InvitationOffer::open(
            TokenHash::from_stored("hashed_token".to_owned()),
            None,
            crate::shared::clock::now() + lifetime,
        )
    }

    fn pending() -> InvitationOffer {
        offer_expiring_in(Duration::days(7))
    }

    /// A pending offer is accepted. It reads as accepted and has an
    /// acceptance time.
    #[test]
    fn accepting_records_when() {
        let mut offer = pending();

        offer.accept().unwrap();

        assert_eq!(offer.status(), InvitationStatus::Accepted);
        assert!(offer.accepted_at().is_some());
    }

    /// An offer that expired a second ago still reads `Pending` in storage.
    /// Accepting it is refused as a conflict, and it stays pending.
    #[test]
    fn an_expired_offer_cannot_be_accepted() {
        let mut offer = offer_expiring_in(-Duration::seconds(1));

        let result = offer.accept();

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(offer.status(), InvitationStatus::Pending);
    }

    /// An accepted offer is accepted again, then revoked. Both are refused.
    #[test]
    fn an_accepted_offer_cannot_be_accepted_or_revoked() {
        let mut offer = pending();
        offer.accept().unwrap();

        assert!(matches!(
            offer.accept(),
            Err(DomainError::InvalidTransition(_))
        ));
        assert!(matches!(
            offer.revoke(),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// A revoked invitation refuses token rotation for a resend.
    #[test]
    fn a_revoked_offer_cannot_be_sent_again() {
        let mut offer = pending();
        offer.revoke().unwrap();

        let result = offer.rotate_token(
            TokenHash::from_stored("new".to_owned()),
            crate::shared::clock::now() + Duration::days(7),
        );

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// A pending offer gets a new link that expires in 14 days. It holds the
    /// new hash and the later expiry, and is still pending.
    #[test]
    fn a_new_link_replaces_the_old_one_and_extends_the_offer() {
        let mut offer = pending();
        let original_expiry = offer.expires_at();
        let new_expiry = crate::shared::clock::now() + Duration::days(14);

        offer
            .rotate_token(
                TokenHash::from_stored("rotated_hash".to_owned()),
                new_expiry,
            )
            .unwrap();

        assert_eq!(offer.token_hash().as_str(), "rotated_hash");
        assert_eq!(offer.expires_at(), new_expiry);
        assert!(offer.expires_at() > original_expiry);
        assert!(offer.is_pending(crate::shared::clock::now()));
    }

    /// One second before expiry the offer is pending. At the expiry instant
    /// it is neither pending nor shown as pending to whoever opens the link.
    #[test]
    fn an_offer_lapses_at_the_instant_it_expires_not_after() {
        let offer = pending();
        let expiry = offer.expires_at();

        assert!(offer.is_pending(expiry - Duration::seconds(1)));
        assert!(!offer.is_pending(expiry));
        assert_eq!(
            offer.state(expiry - Duration::seconds(1)),
            InvitationLifecycle::Pending
        );
        assert_eq!(offer.state(expiry), InvitationLifecycle::Expired);
    }

    /// An accepted offer and a revoked offer both read as closed to whoever
    /// opens the link.
    #[test]
    fn an_accepted_or_revoked_offer_is_closed() {
        let now = crate::shared::clock::now();
        let mut accepted = pending();
        accepted.accept().unwrap();
        let mut revoked = pending();
        revoked.revoke().unwrap();

        assert_eq!(accepted.state(now), InvitationLifecycle::Closed);
        assert_eq!(revoked.state(now), InvitationLifecycle::Closed);
    }

    /// Stored accepted with a time reads back as accepted at that time.
    /// Accepted with no time, or pending with one, is refused as corrupt.
    #[test]
    fn a_stored_status_and_acceptance_time_must_agree() {
        let now = crate::shared::clock::now();

        assert_eq!(
            OfferState::from_stored(InvitationStatus::Accepted, Some(now)).unwrap(),
            OfferState::Accepted { at: now }
        );
        assert!(OfferState::from_stored(InvitationStatus::Accepted, None).is_err());
        assert!(OfferState::from_stored(InvitationStatus::Pending, Some(now)).is_err());
    }

    fn stored(state: OfferState, expires_at: OffsetDateTime) -> OfferRow {
        OfferRow {
            token_hash: TokenHash::from_stored("hashed_token".to_owned()),
            state,
            message: None,
            expires_at,
        }
    }

    /// A stored offer says it was accepted at the instant its link ran out.
    /// No link is taken up once it runs out, so loading it is refused as
    /// corrupt. One accepted a second before is loaded.
    #[test]
    fn a_stored_offer_accepted_once_its_link_ran_out_is_refused() {
        let expiry = crate::shared::clock::now();
        let at_expiry = stored(OfferState::Accepted { at: expiry }, expiry);
        let in_date = stored(
            OfferState::Accepted {
                at: expiry - Duration::SECOND,
            },
            expiry,
        );

        assert!(refused_as_corrupt(&InvitationOffer::reconstitute(
            at_expiry
        )));
        assert!(InvitationOffer::reconstitute(in_date).is_ok());
    }
}
