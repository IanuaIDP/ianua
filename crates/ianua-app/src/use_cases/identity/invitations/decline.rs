//! Decline invitation: the invitee follows their link and turns the
//! invitation down, and the account waiting on it is closed.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{InvitationStore, UserStore};
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::lookup::invitation_by_link;

/// The ports [`DeclineUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeclinePorts {
    /// Loads and saves the invited account.
    pub user_store: Arc<dyn UserStore>,
    /// Loads and saves invitations.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// Hashes the link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Turns an invitation down for the invitee holding its link.
pub struct DeclineUseCase {
    ports: DeclinePorts,
}

impl DeclineUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeclinePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeclineUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<(), AppError>;

    /// Declines the invitation `raw_token` belongs to. Its link stops
    /// working, and the account that waited on it is closed rather than
    /// deleted, so its history stays.
    ///
    /// Following the link proves the reader holds the invited mailbox. It
    /// counts only while the account still has that address.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed, or the invitation was
    ///   already accepted, declined, revoked or marked expired.
    /// - `AppError::NotFound` if the link is unknown or its account is gone.
    /// - `AppError::Forbidden` when the account left the invited address.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<(), AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let (users, invitations) = (
            self.ports.user_store.as_ref(),
            self.ports.invitation_store.as_ref(),
        );
        let presented = self.ports.token_generator.hash_raw(&raw_token);
        let mut invitation = invitation_by_link(invitations, tenant, &presented).await?;
        let mut user = existing_user(users, tenant, invitation.user_id()).await?;
        invitation.decline(&user).map_err(AppError::from_domain)?;
        let closed = invitation.close_unanswered(&mut user);
        closed.map_err(AppError::from_domain)?;

        invitations.save(tenant, &invitation).await.or_internal()?;
        users.save(tenant, &user).await.or_internal()?;
        let actor = ActorRef::User(*user.id());
        auditor
            .dispatch_by(&actor, invitation.take_events(tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::invitations::status::InvitationStatus;
    use ianua_domain::types::{RoleId, UserId};

    use super::*;
    use crate::test_support::identity::{
        FakeInvitationStore, FakeUserStore, InvitationSeed, hash_of_link, stored_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const LINK: &str = "bob-invite";

    /// Bob, invited at bob@acme.com and waiting, holding his link.
    struct Invited {
        bob: UserId,
        users: Arc<FakeUserStore>,
        invitations: Arc<FakeInvitationStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Invited {
        fn new() -> Self {
            let bob = UserId::new();
            let invitation = InvitationSeed::for_user(bob, "bob@acme.com", RoleId::new(), LINK);
            Self {
                bob,
                users: Arc::new(FakeUserStore::with_invited_user(bob, "bob@acme.com")),
                invitations: Arc::new(FakeInvitationStore::holding(invitation.stored())),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn decline(&self, raw_token: &str) -> Result<(), AppError> {
            let use_case = DeclineUseCase::new(DeclinePorts {
                user_store: self.users.clone(),
                invitation_store: self.invitations.clone(),
                ..DeclinePorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                raw_token.to_owned(),
            ))
        }

        fn status(&self) -> InvitationStatus {
            block_on(
                self.invitations
                    .find_by_token_hash(&test_ctx().tenant(), &hash_of_link(LINK)),
            )
            .unwrap()
            .unwrap()
            .status()
        }
    }

    /// Bob does not want to join and turns the invitation down from his
    /// link. It is declined, his waiting account is closed, and it is
    /// recorded.
    #[test]
    fn declining_closes_the_waiting_account() {
        let invited = Invited::new();

        invited.decline(LINK).unwrap();

        assert_eq!(invited.status(), InvitationStatus::Declined);
        assert_eq!(
            invited.users.get_status(&invited.bob),
            Some(UserStatus::Deactivated)
        );
        assert_eq!(
            invited.sink.records.lock().unwrap().as_slice(),
            ["identity.invitation_declined"]
        );
    }

    /// Bob follows his link again after declining. The invitation is no
    /// longer pending.
    #[test]
    fn a_declined_invitation_is_not_declined_again() {
        let invited = Invited::new();
        invited.decline(LINK).unwrap();

        let again = invited.decline(LINK);

        assert!(matches!(again, Err(AppError::Domain(_))));
    }

    /// After Bob changes address, his old invitation link cannot decline
    /// the invitation. It remains pending.
    #[test]
    fn an_account_that_left_the_invited_address_is_refused() {
        let invited = Invited::new();
        let moved = stored_user(invited.bob, "bob@elsewhere.com", UserStatus::Invited);
        block_on(invited.users.save(&test_ctx().tenant(), &moved)).unwrap();

        let result = invited.decline(LINK);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(invited.status(), InvitationStatus::Pending);
    }

    /// A link nobody sent is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let invited = Invited::new();

        let result = invited.decline("nobody-sent-this");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
