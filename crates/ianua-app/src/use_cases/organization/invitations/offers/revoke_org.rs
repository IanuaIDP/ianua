//! Revoke org invitation: an owner, or the platform, withdraws a waiting
//! invitation, and the account waiting on it is closed.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{OrgUserId, OrganizationId};

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgInvitationStore, OrgUserStore, OrganizationStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::{existing_member, existing_pending_invitation};
use crate::use_cases::organization::steward::{OrganizationSteward, StewardSources, Stewarding};

/// The ports [`RevokeOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeOrgPorts {
    /// Loads and saves invitations.
    pub org_invitation_store: Arc<dyn OrgInvitationStore>,
    /// Loads and saves the account waiting on the invitation.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Organizations, for the one an operator names.
    pub organization_store: Arc<dyn OrganizationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Whose invitation to withdraw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeOrgRequest {
    /// The organization that sent the invitation.
    pub organization_id: OrganizationId,
    /// The invited member.
    pub org_user_id: OrgUserId,
}

/// Withdraws a waiting invitation of an organization.
pub struct RevokeOrgUseCase {
    ports: RevokeOrgPorts,
}

impl RevokeOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeOrgPorts) -> Self {
        Self { ports }
    }

    async fn stewarding(
        &self,
        caller: &OrganizationSteward,
        organization_id: &OrganizationId,
    ) -> Result<Stewarding, AppError> {
        let sources = StewardSources {
            org_actors: self.ports.org_actors.as_ref(),
            operators: self.ports.operator_authorities.as_ref(),
            organizations: self.ports.organization_store.as_ref(),
        };
        Stewarding::resolve(sources, caller, organization_id).await
    }
}

impl Command for RevokeOrgUseCase {
    type Caller = OrganizationSteward;
    type Input = RevokeOrgRequest;
    type Output = Result<(), AppError>;

    /// Withdraws the pending invitation of `request.org_user_id` and records
    /// `organization.org_user_invitation_revoked`. Its link stops working at
    /// once, and the account that waited on it is closed rather than
    /// deleted, so its history stays and an owner may still let it in.
    ///
    /// A member who already accepted has no pending invitation, so they are
    /// never touched here.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when a member may not invite members, the
    ///   operator is disabled, or the credential is someone else's.
    /// - `AppError::NotFound` if the organization, the member or a pending
    ///   invitation for them does not exist, or a member names another
    ///   organization than their own.
    /// - `AppError::Domain` if the invitation or account cannot be closed.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        caller: &OrganizationSteward,
        auditor: &RequestAuditor,
        request: RevokeOrgRequest,
    ) -> Result<(), AppError> {
        let stewarding = self.stewarding(caller, &request.organization_id).await?;
        let organization_id = stewarding.organization().id();
        let (members, invitations) = (
            self.ports.org_user_store.as_ref(),
            self.ports.org_invitation_store.as_ref(),
        );
        let mut invitee = existing_member(members, organization_id, &request.org_user_id).await?;
        let mut invitation =
            existing_pending_invitation(invitations, organization_id, invitee.id()).await?;
        stewarding.decide(|by| invitation.revoke(by))?;
        invitation
            .close_unanswered(&mut invitee)
            .map_err(AppError::from_domain)?;

        invitations.save(&invitation).await.or_internal()?;
        members.save(&invitee).await.or_internal()?;
        auditor
            .dispatch_by(&stewarding.audit_actor(), invitation.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::invitations::status::InvitationStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::types::{OperatorId, TokenHash};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, FakeOrgActors, Refusal};
    use crate::test_support::notifications::operator_caller;
    use crate::test_support::organization::{
        FakeOrgInvitationStore, FakeOrgUserStore, invited_org_user, org_store_with,
        org_user_store_with, pending_org_invitation, test_org, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    const BOB: &str = "bob@acme.test";

    struct Setup {
        uc: RevokeOrgUseCase,
        bob: OrgUserId,
        members: Arc<FakeOrgUserStore>,
        invitations: Arc<FakeOrgInvitationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(ports: RevokeOrgPorts) -> Self {
            let organization = test_org_caller().organization_id();
            let bob = invited_org_user(organization, BOB, OrgRole::Member);
            let bob_id = *bob.id();
            let link = TokenHash::from_stored("link".to_owned());
            let invitations = Arc::new(FakeOrgInvitationStore::holding([pending_org_invitation(
                organization,
                bob_id,
                BOB,
                link,
            )]));
            let members = Arc::new(org_user_store_with([bob]));
            Self {
                uc: RevokeOrgUseCase::new(RevokeOrgPorts {
                    org_invitation_store: invitations.clone(),
                    org_user_store: members.clone(),
                    organization_store: org_store_with([test_org(organization, "acme")]),
                    ..ports
                }),
                bob: bob_id,
                members,
                invitations,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn as_member(role: OrgRole) -> Self {
            Self::with(RevokeOrgPorts {
                org_actors: Arc::new(FakeOrgActors::in_role(role)),
                ..RevokeOrgPorts::fakes()
            })
        }

        fn revoke_as(
            &self,
            caller: &OrganizationSteward,
            member: OrgUserId,
        ) -> Result<(), AppError> {
            let request = RevokeOrgRequest {
                organization_id: test_org_caller().organization_id(),
                org_user_id: member,
            };
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), request),
            )
        }

        fn revoke(&self) -> Result<(), AppError> {
            self.revoke_as(&OrganizationSteward::Member(test_org_caller()), self.bob)
        }

        fn pending(&self) -> usize {
            let organization = test_org_caller().organization_id();
            block_on(self.invitations.list_pending(&organization))
                .unwrap()
                .len()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Olivia, an owner, withdraws Bob's invitation. It is revoked, his
    /// waiting account is closed, and the withdrawal is recorded.
    #[test]
    fn an_owner_withdraws_an_invitation_and_closes_the_account() {
        let setup = Setup::as_member(OrgRole::Owner);

        setup.revoke().unwrap();

        assert_eq!(setup.pending(), 0);
        assert_eq!(
            setup.members.get_status(&setup.bob),
            Some(OrgUserStatus::Deactivated)
        );
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_user_invitation_revoked"]
        );
    }

    /// The platform withdraws Bob's invitation through an operator. It is
    /// a platform action, so it goes through.
    #[test]
    fn an_operator_withdraws_an_invitation() {
        let setup = Setup::as_member(OrgRole::Owner);
        let operator = OrganizationSteward::Platform(operator_caller(OperatorId::new()));

        setup.revoke_as(&operator, setup.bob).unwrap();

        assert_eq!(setup.pending(), 0);
    }

    /// An operator refused by the authority port cannot withdraw an
    /// invitation, which stays pending.
    #[test]
    fn a_refused_operator_is_refused() {
        let setup = Setup::with(RevokeOrgPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..RevokeOrgPorts::fakes()
        });
        let operator = OrganizationSteward::Platform(operator_caller(OperatorId::new()));

        let result = setup.revoke_as(&operator, setup.bob);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.pending(), 1);
    }

    /// A member without invitation rights cannot revoke an invitation;
    /// it stays pending and the invitee's account still waits to join.
    #[test]
    fn a_member_without_the_invite_right_is_refused() {
        let setup = Setup::as_member(OrgRole::Member);

        let result = setup.revoke();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.pending(), 1);
        assert_eq!(
            setup.members.get_status(&setup.bob),
            Some(OrgUserStatus::Invited)
        );
    }

    /// A signed-out session cannot authorize invitation revocation.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(RevokeOrgPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..RevokeOrgPorts::fakes()
        });

        let result = setup.revoke();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Olivia names a member nobody invited. There is no invitation to
    /// withdraw.
    #[test]
    fn a_member_without_a_pending_invitation_is_not_found() {
        let setup = Setup::as_member(OrgRole::Owner);

        let result = setup.revoke_as(
            &OrganizationSteward::Member(test_org_caller()),
            OrgUserId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann already accepted her invitation. Withdrawing finds nothing
    /// pending, and Ann's account stays as it is.
    #[test]
    fn a_member_who_already_joined_is_left_in_place() {
        let setup = Setup::as_member(OrgRole::Owner);
        let organization = test_org_caller().organization_id();
        let ann = test_org_user(organization, "ann@acme.test", OrgRole::Member);
        let ann_id = *ann.id();
        block_on(setup.members.save(&ann)).unwrap();

        let result = setup.revoke_as(&OrganizationSteward::Member(test_org_caller()), ann_id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            setup.members.get_status(&ann_id),
            Some(OrgUserStatus::Active)
        );
    }

    /// An owner naming another organization receives not found, leaving
    /// the invitation in her own organization pending.
    #[test]
    fn a_member_naming_another_organization_is_not_found() {
        let setup = Setup::as_member(OrgRole::Owner);
        let request = RevokeOrgRequest {
            organization_id: OrganizationId::new(),
            org_user_id: setup.bob,
        };

        let result = block_on(setup.uc.execute(
            &OrganizationSteward::Member(test_org_caller()),
            &test_auditor(setup.audit.clone()),
            request,
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        let stored = block_on(
            setup
                .invitations
                .list_pending(&test_org_caller().organization_id()),
        )
        .unwrap();
        assert_eq!(stored[0].status(), InvitationStatus::Pending);
    }
}
