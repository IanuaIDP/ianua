//! Decline org invitation: the invitee follows the emailed link and turns
//! the invitation down, and the account that waited on it is closed.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgInvitationStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::invitations::FollowedInvitation;
use crate::use_cases::organization::invitations::offers::link::InvitationLinks;
use crate::use_cases::organization::lookup::existing_member;

/// The ports [`DeclineOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeclineOrgPorts {
    /// Loads and saves the invited member.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Loads and saves invitations.
    pub org_invitation_store: Arc<dyn OrgInvitationStore>,
    /// Hashes the link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Lets an invitee turn down the invitation mailed to them.
pub struct DeclineOrgUseCase {
    ports: DeclineOrgPorts,
}

impl DeclineOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeclineOrgPorts) -> Self {
        Self { ports }
    }
}

impl Command for DeclineOrgUseCase {
    type Caller = ();
    type Input = FollowedInvitation;
    type Output = Result<(), AppError>;

    /// Turns down the invitation of `organization_id` that `raw_token`
    /// belongs to, closes the account that waited on it, and records
    /// `organization.org_user_invitation_declined`.
    ///
    /// No session is needed: following the link shows the reader holds the
    /// invited mailbox. The account is closed rather than deleted, so its
    /// history stays and an owner may still let it in.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is unknown, the invitation was
    ///   already accepted, declined or revoked, or the member is gone.
    /// - `AppError::LinkExpired` if the invitation ran out unused.
    /// - `AppError::Forbidden` if the member moved off the invited address.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        link: FollowedInvitation,
    ) -> Result<(), AppError> {
        let organization_id = &link.organization_id;
        let links = InvitationLinks {
            invitations: self.ports.org_invitation_store.as_ref(),
            token_generator: self.ports.token_generator.as_ref(),
        };
        let mut invitation = links.open(organization_id, &link.raw_token).await?;
        let members = self.ports.org_user_store.as_ref();
        let mut invitee =
            existing_member(members, organization_id, invitation.org_user_id()).await?;
        invitation
            .decline(&invitee)
            .map_err(AppError::from_domain)?;
        invitation
            .close_unanswered(&mut invitee)
            .map_err(AppError::from_domain)?;

        self.ports
            .org_invitation_store
            .save(&invitation)
            .await
            .or_internal()?;
        members.save(&invitee).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*invitee.id()), invitation.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::invitation::OrgInvitation;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::types::{OrgUserId, OrganizationId, TokenHash};

    use super::*;
    use crate::test_support::organization::{
        FakeOrgInvitationStore, FakeOrgUserStore, expired_org_invitation, invited_org_user,
        org_user_store_with, pending_org_invitation,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const LINK: &str = "fake_refresh_7";
    const BOB: &str = "bob@acme.test";

    fn link_hash() -> TokenHash {
        TokenHash::from_stored("fake_hash_7".to_owned())
    }

    struct Setup {
        uc: DeclineOrgUseCase,
        organization_id: OrganizationId,
        bob: OrgUserId,
        members: Arc<FakeOrgUserStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(invitation: impl FnOnce(OrganizationId, OrgUserId) -> OrgInvitation) -> Self {
            let organization_id = OrganizationId::new();
            let bob = invited_org_user(organization_id, BOB, OrgRole::Member);
            let bob_id = *bob.id();
            let members = Arc::new(org_user_store_with([bob]));
            Self {
                uc: DeclineOrgUseCase::new(DeclineOrgPorts {
                    org_user_store: members.clone(),
                    org_invitation_store: Arc::new(FakeOrgInvitationStore::holding([invitation(
                        organization_id,
                        bob_id,
                    )])),
                    ..DeclineOrgPorts::fakes()
                }),
                organization_id,
                bob: bob_id,
                members,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn pending() -> Self {
            Self::with(|organization_id, bob| {
                pending_org_invitation(organization_id, bob, BOB, link_hash())
            })
        }

        fn decline(&self) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &(),
                &test_auditor(self.audit.clone()),
                FollowedInvitation {
                    organization_id: self.organization_id,
                    raw_token: LINK.to_owned(),
                },
            ))
        }
    }

    /// Bob follows his invitation and turns it down. His waiting account is
    /// closed and the refusal is recorded.
    #[test]
    fn declining_closes_the_waiting_account() {
        let setup = Setup::pending();

        setup.decline().unwrap();

        assert_eq!(
            setup.members.get_status(&setup.bob),
            Some(OrgUserStatus::Deactivated)
        );
        assert_eq!(
            setup.audit.records.lock().unwrap().clone(),
            vec!["organization.org_user_invitation_declined"]
        );
    }

    /// Replaying an invitation link after declining returns not found.
    #[test]
    fn a_replayed_link_is_not_found() {
        let setup = Setup::pending();
        setup.decline().unwrap();

        let replayed = setup.decline();

        assert!(matches!(replayed, Err(AppError::NotFound(_))));
    }

    /// Bob follows his invitation after it ran out. He is told it expired,
    /// and his account is left as it is.
    #[test]
    fn an_expired_invitation_is_link_expired() {
        let setup = Setup::with(|organization_id, bob| {
            expired_org_invitation(organization_id, bob, BOB, link_hash())
        });

        let result = setup.decline();

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert_eq!(
            setup.members.get_status(&setup.bob),
            Some(OrgUserStatus::Invited)
        );
    }

    /// An invitation for a different address cannot be declined for the member.
    #[test]
    fn an_invitation_to_an_address_the_member_left_is_refused() {
        let setup = Setup::with(|organization_id, bob| {
            pending_org_invitation(organization_id, bob, "bob.old@acme.test", link_hash())
        });

        let result = setup.decline();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
