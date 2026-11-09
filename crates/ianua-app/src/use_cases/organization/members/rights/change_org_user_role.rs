//! Giving a member another of the five organization roles: owner, admin,
//! member, billing contact or viewer.
//!
//! The domain decides who hands out which role: only an owner makes or
//! unmakes an owner or a billing contact, an admin makes admins, and anyone
//! who may update members makes members and viewers. The organization
//! always keeps an active owner. The member's sessions end, since the role
//! they carry was read when they signed in.

use std::sync::Arc;

use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::members::owners::Owners;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, OrgUserId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::{current_owners, existing_member};
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// Whose role changes, and to what.
pub struct ChangeOrgUserRoleRequest {
    /// The member re-roled.
    pub member: OrgUserId,
    /// The role they hold from now on.
    pub role: OrgRole,
}

/// The ports [`ChangeOrgUserRoleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeOrgUserRolePorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' sessions, ended because they carry the old role.
    pub org_sessions: Arc<dyn OrgSessionStore>,
}

/// Changes a member's role in the organization.
pub struct ChangeOrgUserRoleUseCase {
    ports: ChangeOrgUserRolePorts,
}

impl ChangeOrgUserRoleUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ChangeOrgUserRolePorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeOrgUserRoleUseCase {
    type Caller = OrgCaller;
    type Input = ChangeOrgUserRoleRequest;
    type Output = Result<(), AppError>;

    /// Gives `request.member` the role `request.role`, ends their sessions
    /// and records `organization.org_user_role_changed`. Asking for the role
    /// they already hold changes nothing and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update members, or
    ///   hands out or takes away a role their own does not let them: an
    ///   owner or billing contact without being an owner, an admin without
    ///   being an owner or admin.
    /// - `AppError::Conflict` when it would demote the last active owner.
    /// - `AppError::NotFound` when the organization has no such member.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: ChangeOrgUserRoleRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let users = self.ports.org_users.as_ref();
        let owners = current_owners(users, organization.id()).await?;
        let mut member = existing_member(users, organization.id(), &request.member).await?;
        let previous = member.role();
        member
            .change_role(request.role, &control, Owners::of(&owners))
            .map_err(AppError::from_domain)?;
        if previous == request.role {
            return Ok(());
        }
        users.save(&member).await.or_internal()?;
        sign_out_member(self.ports.org_sessions.as_ref(), member.id()).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), member.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgUserStore, RecordingOrgSessionStore, org_user_store_with, stored_caller,
        test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ChangeOrgUserRoleUseCase,
        users: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn holding(actors: FakeOrgActors, members: Vec<OrgUser>) -> Self {
            let users = Arc::new(org_user_store_with(members));
            let sessions = Arc::new(RecordingOrgSessionStore::new());
            Self {
                uc: ChangeOrgUserRoleUseCase::new(ChangeOrgUserRolePorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    org_sessions: sessions.clone(),
                    ..ChangeOrgUserRolePorts::fakes()
                }),
                users,
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn change(&self, member: OrgUserId, role: OrgRole) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                ChangeOrgUserRoleRequest { member, role },
            ))
        }

        fn role_of(&self, member: OrgUserId) -> OrgRole {
            block_on(self.users.find_by_id(&member))
                .unwrap()
                .unwrap()
                .role()
        }
    }

    fn in_acme(email: &str, role: OrgRole) -> OrgUser {
        test_org_user(test_org_caller().organization_id(), email, role)
    }

    /// Olivia, an owner, makes Sam an owner. His role changes, his sessions
    /// end, and the change is recorded.
    #[test]
    fn an_owner_promotes_a_member_and_retires_their_sessions() {
        let sam = in_acme("sam@acme.test", OrgRole::Member);
        let sam_id = *sam.id();
        let setup = Setup::holding(
            FakeOrgActors::in_role(OrgRole::Owner),
            vec![sam, stored_caller(OrgRole::Owner, "pw")],
        );

        setup.change(sam_id, OrgRole::Owner).unwrap();

        assert_eq!(setup.role_of(sam_id), OrgRole::Owner);
        assert!(setup.sessions.revoked(&sam_id));
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_role_changed"]
        );
    }

    /// Olivia demotes Oscar while she stays an owner herself.
    #[test]
    fn an_owner_demotes_another_while_one_remains() {
        let oscar = in_acme("oscar@acme.test", OrgRole::Owner);
        let oscar_id = *oscar.id();
        let setup = Setup::holding(
            FakeOrgActors::in_role(OrgRole::Owner),
            vec![oscar, stored_caller(OrgRole::Owner, "pw")],
        );

        setup.change(oscar_id, OrgRole::Member).unwrap();

        assert_eq!(setup.role_of(oscar_id), OrgRole::Member);
    }

    /// Demoting the only owner conflicts, leaving her ownership intact.
    #[test]
    fn demoting_the_last_owner_is_refused() {
        let setup = Setup::holding(
            FakeOrgActors::in_role(OrgRole::Owner),
            vec![stored_caller(OrgRole::Owner, "pw")],
        );

        let result = setup.change(*test_org_caller().member(), OrgRole::Member);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.role_of(*test_org_caller().member()), OrgRole::Owner);
    }

    /// A plain member cannot promote themselves and keeps the member role.
    #[test]
    fn a_member_promoting_themselves_is_refused() {
        let setup = Setup::holding(
            FakeOrgActors::in_role(OrgRole::Member),
            vec![stored_caller(OrgRole::Member, "pw")],
        );

        let result = setup.change(*test_org_caller().member(), OrgRole::Owner);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.role_of(*test_org_caller().member()), OrgRole::Member);
    }

    /// Ada, an admin, makes Sam an admin too. His role changes and the
    /// change is recorded.
    #[test]
    fn an_admin_makes_another_admin() {
        let sam = in_acme("sam@acme.test", OrgRole::Member);
        let sam_id = *sam.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Admin), vec![sam]);

        setup.change(sam_id, OrgRole::Admin).unwrap();

        assert_eq!(setup.role_of(sam_id), OrgRole::Admin);
    }

    /// Olivia, an owner, makes Bea the billing contact and Vic a viewer.
    /// Both roles are saved.
    #[test]
    fn an_owner_hands_out_billing_and_viewer() {
        let bea = in_acme("bea@acme.test", OrgRole::Member);
        let vic = in_acme("vic@acme.test", OrgRole::Member);
        let (bea_id, vic_id) = (*bea.id(), *vic.id());
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Owner), vec![bea, vic]);

        setup.change(bea_id, OrgRole::Billing).unwrap();
        setup.change(vic_id, OrgRole::Viewer).unwrap();

        assert_eq!(setup.role_of(bea_id), OrgRole::Billing);
        assert_eq!(setup.role_of(vic_id), OrgRole::Viewer);
    }

    /// An admin cannot promote Sam to owner; he remains a member and no
    /// role change is recorded.
    #[test]
    fn an_admin_making_an_owner_is_refused() {
        let sam = in_acme("sam@acme.test", OrgRole::Member);
        let sam_id = *sam.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Admin), vec![sam]);

        let result = setup.change(sam_id, OrgRole::Owner);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.role_of(sam_id), OrgRole::Member);
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// An admin cannot assign the billing role, leaving Sam a member.
    #[test]
    fn an_admin_making_a_billing_contact_is_refused() {
        let sam = in_acme("sam@acme.test", OrgRole::Member);
        let sam_id = *sam.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Admin), vec![sam]);

        let result = setup.change(sam_id, OrgRole::Billing);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.role_of(sam_id), OrgRole::Member);
    }

    /// An admin cannot demote an owner to viewer; the owner keeps her role.
    #[test]
    fn an_admin_demoting_an_owner_is_refused() {
        let olivia = in_acme("olivia@acme.test", OrgRole::Owner);
        let olivia_id = *olivia.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Admin), vec![olivia]);

        let result = setup.change(olivia_id, OrgRole::Viewer);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.role_of(olivia_id), OrgRole::Owner);
    }

    /// A billing contact cannot make Sam a viewer, leaving him a member.
    #[test]
    fn a_billing_contact_changing_roles_is_refused() {
        let sam = in_acme("sam@acme.test", OrgRole::Member);
        let sam_id = *sam.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Billing), vec![sam]);

        let result = setup.change(sam_id, OrgRole::Viewer);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.role_of(sam_id), OrgRole::Member);
    }

    /// Another organization's member is not found for promotion and keeps
    /// her member role.
    #[test]
    fn a_member_of_another_organization_is_not_found() {
        let victim = test_org_user(OrganizationId::new(), "eve@other.test", OrgRole::Member);
        let victim_id = *victim.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Owner), vec![victim]);

        let result = setup.change(victim_id, OrgRole::Owner);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.role_of(victim_id), OrgRole::Member);
    }

    /// Asking for the role Sam already holds changes nothing: no session
    /// ends and nothing is recorded.
    #[test]
    fn the_same_role_changes_nothing() {
        let sam = in_acme("sam@acme.test", OrgRole::Member);
        let sam_id = *sam.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Owner), vec![sam]);

        setup.change(sam_id, OrgRole::Member).unwrap();

        assert!(!setup.sessions.revoked(&sam_id));
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller must authenticate before changing roles.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::holding(FakeOrgActors::refusing(Refusal::SignedOut), Vec::new());

        let result = setup.change(OrgUserId::new(), OrgRole::Owner);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents assigning an owner role.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::holding(FakeOrgActors::refusing(Refusal::Forbidden), Vec::new());

        let result = setup.change(OrgUserId::new(), OrgRole::Owner);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
