//! What one member of the caller's organization may reach: the caller's
//! own view, or another member's for whoever may view members.

use std::sync::Arc;

use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::permission::{MemberAction, OrgPermission};
use ianua_domain::types::{OrgUserId, OrganizationId};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::authorization::RoleStore;
use crate::ports::organization::{OrgTenantGrantStore, OrgUserStore};
use crate::ports::tenant::TenantStore;
use crate::use_case::Query;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::members::rights::access::{AccessSources, OrgUserAccess};

/// Whose reach is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhoseReach {
    /// The caller's own. Every member reads it, whatever their role: a
    /// billing contact's dashboard is built from it too.
    Own,
    /// Another member's, for whoever may view members.
    Member(OrgUserId),
}

/// The ports [`GetOrgUserAccessUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetOrgUserAccessPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// The organization's tenants.
    pub tenants: Arc<dyn TenantStore>,
    /// Each tenant's roles, to name and expand granted roles.
    pub roles: Arc<dyn RoleStore>,
    /// The tenants and roles members were granted.
    pub grants: Arc<dyn OrgTenantGrantStore>,
}

/// Works out what a member may reach.
pub struct GetOrgUserAccessUseCase {
    ports: GetOrgUserAccessPorts,
}

impl GetOrgUserAccessUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetOrgUserAccessPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetOrgUserAccessUseCase {
    type Caller = OrgCaller;
    type Input = WhoseReach;
    type Output = Result<OrgUserAccess, AppError>;

    /// What the member `whose` names, in the caller's organization, reaches
    /// now: the caller's own reach for any member, another member's for
    /// whoever may view members.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller asks for another member's
    ///   reach and may not view members.
    /// - `AppError::NotFound` when the organization has no such member.
    /// - `AppError::Internal` when a store fails.
    async fn execute(
        &self,
        caller: &OrgCaller,
        whose: WhoseReach,
    ) -> Result<OrgUserAccess, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let id = readable_member(&control, organization.id(), actor.member(), whose)?;
        let member = existing_member(self.ports.org_users.as_ref(), organization.id(), &id).await?;
        let sources = AccessSources {
            tenants: self.ports.tenants.as_ref(),
            roles: self.ports.roles.as_ref(),
            grants: self.ports.grants.as_ref(),
        };
        sources.reach_of(&member).await
    }
}

/// The member whose reach `whose` names, once `control` may read it in
/// `organization`: `caller` reads their own, named or by id, and another
/// member's needs the right to view members.
fn readable_member(
    control: &OrgControl<'_>,
    organization: &OrganizationId,
    caller: &OrgUser,
    whose: WhoseReach,
) -> Result<OrgUserId, AppError> {
    match whose {
        WhoseReach::Own => Ok(*caller.id()),
        WhoseReach::Member(id) if id == *caller.id() => Ok(id),
        WhoseReach::Member(id) => {
            control
                .ensure_may(organization, OrgPermission::Members(MemberAction::View))
                .map_err(AppError::from_domain)?;
            Ok(id)
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::tenant_grant::{
        OrgTenantGrant, OrgTenantGrantRow,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ActedBy, OrganizationId, RoleId, TenantId};

    use super::*;
    use crate::acting::organization::{OrgActing, OrgActingPorts};
    use crate::context::OrgCredential;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authorization::{FakeRoleStore, stored_role};
    use crate::test_support::organization::{
        FakeOrgTenantGrantStore, OrgShape, RecordingOrgSessionStore, org_session_on_organization,
        org_shaped, org_store_with, org_user_store_with, stored_caller, test_org_user,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{Fake, block_on, test_org_caller};

    struct Setup {
        uc: GetOrgUserAccessUseCase,
        grants: Arc<FakeOrgTenantGrantStore>,
        member: OrgUserId,
        owner: OrgUserId,
        production: TenantId,
        staging: TenantId,
        elsewhere: TenantId,
        editor: RoleId,
        viewer: RoleId,
    }

    /// Acme with a member, an owner and two tenants, and a third tenant of
    /// another organization.
    fn setup_as(actors: FakeOrgActors) -> Setup {
        let org_id = test_org_caller().organization_id();
        let member = test_org_user(org_id, "sam@acme.test", OrgRole::Member);
        let owner = test_org_user(org_id, "olivia@acme.test", OrgRole::Owner);
        let (member_id, owner_id) = (*member.id(), *owner.id());
        let production = test_tenant_in(org_id, "production", "production.test");
        let staging = test_tenant_in(org_id, "staging", "staging.test");
        let elsewhere = test_tenant_in(OrganizationId::new(), "elsewhere", "elsewhere.test");
        let (production_id, staging_id, elsewhere_id) =
            (*production.id(), *staging.id(), *elsewhere.id());
        let roles = production_roles(production_id);
        let grants = Arc::new(FakeOrgTenantGrantStore::empty());
        Setup {
            uc: GetOrgUserAccessUseCase::new(GetOrgUserAccessPorts {
                org_actors: Arc::new(actors),
                org_users: Arc::new(org_user_store_with([member, owner])),
                tenants: Arc::new(FakeTenantStore::holding_all([
                    production, staging, elsewhere,
                ])),
                roles: roles.store,
                grants: grants.clone(),
            }),
            grants,
            member: member_id,
            owner: owner_id,
            production: production_id,
            staging: staging_id,
            elsewhere: elsewhere_id,
            editor: roles.editor,
            viewer: roles.viewer,
        }
    }

    /// The two production roles and the store used to resolve their permissions.
    struct ProductionRoles {
        store: Arc<FakeRoleStore>,
        editor: RoleId,
        viewer: RoleId,
    }

    /// Holds distinct editor and viewer permissions in the production tenant.
    fn production_roles(tenant: TenantId) -> ProductionRoles {
        let editor = stored_role("Editor", vec![SystemPermission::all()[0]], Vec::new());
        let viewer = stored_role("Viewer", vec![SystemPermission::all()[1]], Vec::new());
        ProductionRoles {
            editor: *editor.id(),
            viewer: *viewer.id(),
            store: Arc::new(FakeRoleStore::holding(tenant, [editor, viewer])),
        }
    }

    fn setup() -> Setup {
        setup_as(FakeOrgActors::in_role(OrgRole::Member))
    }

    fn grant(s: &Setup, tenant_id: TenantId, roles: &[RoleId]) {
        let issued: Vec<OrgTenantGrant> = roles
            .iter()
            .map(|role_id| {
                OrgTenantGrant::reconstitute(OrgTenantGrantRow {
                    org_user_id: s.member,
                    tenant_id,
                    role_id: *role_id,
                    granted_by: ActedBy::By(s.owner),
                    granted_at: clock::now(),
                })
                .unwrap()
            })
            .collect();
        block_on(s.grants.replace_in_tenant(&s.member, &tenant_id, &issued)).unwrap();
    }

    fn access_of(s: &Setup, who: OrgUserId) -> OrgUserAccess {
        block_on(s.uc.execute(&test_org_caller(), WhoseReach::Member(who))).unwrap()
    }

    /// The use case reading as a member in `role`, whose own account is
    /// stored.
    fn reading_own_as(role: OrgRole) -> GetOrgUserAccessUseCase {
        GetOrgUserAccessUseCase::new(GetOrgUserAccessPorts {
            org_actors: Arc::new(FakeOrgActors::in_role(role)),
            org_users: Arc::new(org_user_store_with([stored_caller(role, "irrelevant")])),
            ..GetOrgUserAccessPorts::fakes()
        })
    }

    /// Bea handles Acme's invoices and may not view members. She still
    /// reads her own reach, which the dashboard is built from: her role,
    /// and no tenant.
    #[test]
    fn a_billing_contact_reads_their_own_reach() {
        let uc = reading_own_as(OrgRole::Billing);

        let access = block_on(uc.execute(&test_org_caller(), WhoseReach::Own)).unwrap();

        assert_eq!(access.org_role, OrgRole::Billing);
        assert!(access.tenants.is_empty());
    }

    /// Sam signed in before anyone granted him a tenant, so his session
    /// works on the organization alone. He reads his own reach through that
    /// session: a member, and no tenant.
    #[test]
    fn a_member_signed_in_to_the_organization_alone_reads_their_reach() {
        let organization_id = OrganizationId::new();
        let sam = test_org_user(organization_id, "sam@acme.test", OrgRole::Member);
        let session = org_session_on_organization(&sam);
        let caller = OrgCaller::new(
            *sam.id(),
            OrgCredential::Session(*session.id()),
            organization_id,
        );
        let members = Arc::new(org_user_store_with([sam]));
        let actors = OrgActing::new(OrgActingPorts {
            organizations: org_store_with([org_shaped(
                organization_id,
                OrgShape::owning(&[TenantId::new()]),
            )]),
            org_users: members.clone(),
            org_sessions: Arc::new(RecordingOrgSessionStore::holding([session])),
            org_api_keys: Fake::fake(),
        });
        let uc = GetOrgUserAccessUseCase::new(GetOrgUserAccessPorts {
            org_actors: Arc::new(actors),
            org_users: members,
            ..GetOrgUserAccessPorts::fakes()
        });

        let access = block_on(uc.execute(&caller, WhoseReach::Own)).unwrap();

        assert_eq!(access.org_role, OrgRole::Member);
        assert!(access.tenants.is_empty());
    }

    /// A billing contact cannot read another member's access.
    #[test]
    fn a_billing_contact_does_not_read_another_members_reach() {
        let s = setup_as(FakeOrgActors::in_role(OrgRole::Billing));

        let result = block_on(s.uc.execute(&test_org_caller(), WhoseReach::Member(s.owner)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    fn tenant_ids(access: &OrgUserAccess) -> Vec<TenantId> {
        access.tenants.iter().map(|t| t.tenant_id).collect()
    }

    /// Olivia, an owner, reaches every tenant of Acme with every
    /// permission, and no tenant of another organization.
    #[test]
    fn an_owner_reaches_every_tenant_of_their_organization_and_no_other() {
        let s = setup();

        let access = access_of(&s, s.owner);

        let reached = tenant_ids(&access);
        assert_eq!(reached.len(), 2, "{reached:?}");
        assert!(reached.contains(&s.production) && reached.contains(&s.staging));
        assert!(
            access
                .tenants
                .iter()
                .all(|t| t.permissions == SystemPermission::all().to_vec())
        );
    }

    /// Sam, a plain member granted Editor in production, reaches only
    /// production, as an Editor.
    #[test]
    fn a_member_reaches_only_the_tenants_they_were_granted() {
        let s = setup();
        grant(&s, s.production, &[s.editor]);

        let access = access_of(&s, s.member);

        assert_eq!(tenant_ids(&access), vec![s.production]);
        assert_eq!(access.tenants[0].role_names, vec!["Editor".to_owned()]);
    }

    /// Sam holds no grant. He reaches nothing.
    #[test]
    fn a_member_with_no_grants_reaches_nothing() {
        let s = setup();

        assert!(access_of(&s, s.member).tenants.is_empty());
    }

    /// Sam holds two roles in production. They show as one tenant holding
    /// both.
    #[test]
    fn two_roles_in_one_tenant_are_one_entry_holding_both() {
        let s = setup();
        grant(&s, s.production, &[s.editor, s.viewer]);

        let access = access_of(&s, s.member);

        assert_eq!(tenant_ids(&access), vec![s.production]);
        let mut names = access.tenants[0].role_names.clone();
        names.sort();
        assert_eq!(names, vec!["Editor".to_owned(), "Viewer".to_owned()]);
    }

    /// A grant can outlive the tenant's place in the organization. The
    /// view never reaches past the organization it was asked about.
    #[test]
    fn a_grant_into_another_organizations_tenant_never_appears() {
        let s = setup();
        grant(&s, s.elsewhere, &[s.editor]);

        assert!(access_of(&s, s.member).tenants.is_empty());
    }

    /// Someone outside Acme is not found.
    #[test]
    fn someone_outside_the_organization_is_not_found() {
        let s = setup();

        let result =
            block_on(s.uc.execute(&test_org_caller(), WhoseReach::Member(OrgUserId::new())));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller must authenticate before reading member access.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let s = setup_as(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = block_on(s.uc.execute(&test_org_caller(), WhoseReach::Member(s.member)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents reading Sam's access.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let s = setup_as(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = block_on(s.uc.execute(&test_org_caller(), WhoseReach::Member(s.member)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A member's key without the view scope cannot read an owner's access.
    #[test]
    fn a_key_without_the_view_scope_is_refused() {
        let s = setup_as(FakeOrgActors::through_key(OrgRole::Member, Vec::new()));

        let result = block_on(s.uc.execute(&test_org_caller(), WhoseReach::Member(s.owner)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
