//! Granting, narrowing or withdrawing a plain member's access to one
//! tenant.
//!
//! Access is given in the tenant's own roles, named the way an
//! administrator names them, and stored as exactly the set asked for: so
//! narrowing "Editor and Viewer" to "Viewer" takes Editor away. An empty
//! set withdraws access to the tenant. An owner reaches every tenant
//! already and is given no grants.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::organization::events::members::OrgUserTenantAccessChanged;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::permission::{OrgPermission, TenantAccessAction};
use ianua_domain::domains::organization::members::tenant_grant::{GrantRequest, OrgTenantGrant};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{ActedBy, ActorRef, Label, OrgUserId, TenantSlug};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::RoleStore;
use crate::ports::organization::{OrgTenantGrantStore, OrgUserStore};
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::{existing_member, existing_tenant_named};

/// What changing a member's access to a tenant takes.
const MANAGE_ACCESS: OrgPermission = OrgPermission::TenantAccess(TenantAccessAction::Manage);

/// Whose access to which tenant changes, and to what.
pub struct SetOrgUserTenantAccessRequest {
    /// The member whose access changes.
    pub member: OrgUserId,
    /// The tenant, named by its slug within the organization.
    pub tenant_slug: TenantSlug,
    /// The tenant roles the member holds from now on, by name. Empty
    /// withdraws access to the tenant.
    pub role_names: Vec<Label>,
}

/// The ports [`SetOrgUserTenantAccessUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetOrgUserTenantAccessPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Tenants, to find the one the slug names.
    pub tenants: Arc<dyn TenantStore>,
    /// The tenant's roles, found by name.
    pub roles: Arc<dyn RoleStore>,
    /// The tenants and roles members were granted.
    pub grants: Arc<dyn OrgTenantGrantStore>,
}

/// Replaces a plain member's roles in one tenant.
pub struct SetOrgUserTenantAccessUseCase {
    ports: SetOrgUserTenantAccessPorts,
}

/// The grants a member holds in one tenant before a change, and the ones
/// that replace them.
struct Replacement<'a> {
    member: &'a OrgUser,
    tenant: &'a Tenant,
    held: Vec<OrgTenantGrant>,
    issued: Vec<OrgTenantGrant>,
}

impl SetOrgUserTenantAccessUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: SetOrgUserTenantAccessPorts) -> Self {
        Self { ports }
    }

    /// The tenant's roles `names` names, each once.
    ///
    /// Names belong to one tenant, so the same role in two tenants has two
    /// ids. Finding them in the tenant's own store is what makes them its
    /// roles.
    async fn roles_named(
        &self,
        tenant: &ScopedTenant,
        names: &[Label],
    ) -> Result<Vec<Role<ResolvedTenant>>, AppError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let mut seen = HashSet::new();
        let names: Vec<_> = names
            .iter()
            .filter(|name| seen.insert(*name))
            .cloned()
            .collect();
        let found = self
            .ports
            .roles
            .find_by_names(tenant, &names)
            .await
            .or_internal()?;
        let mut by_name: HashMap<_, _> = found
            .into_iter()
            .map(|role| (role.name().clone(), role))
            .collect();
        names
            .iter()
            .map(|name| by_name.remove(name).ok_or_else(|| no_such_role(name)))
            .collect()
    }

    /// The grants `member` holds in `tenant` now.
    async fn held_in(
        &self,
        member: &OrgUser,
        tenant: &Tenant,
    ) -> Result<Vec<OrgTenantGrant>, AppError> {
        self.ports
            .grants
            .list_by_user_in_tenant(member.id(), tenant.id())
            .await
            .or_internal()
    }

    /// The names of the roles `grants` give in `tenant`.
    async fn names_of(
        &self,
        tenant: &ScopedTenant,
        grants: &[OrgTenantGrant],
    ) -> Result<Vec<Label>, AppError> {
        let ids: Vec<_> = grants.iter().map(|grant| *grant.role_id()).collect();
        let roles = self
            .ports
            .roles
            .find_by_ids(tenant, &ids)
            .await
            .or_internal()?;
        Ok(roles.iter().map(|role| role.name().clone()).collect())
    }

    /// Stores `change.issued` in place of what the member held in the
    /// tenant, giving the member `roles`, and gives back the record of it.
    async fn replaced(
        &self,
        change: Replacement<'_>,
        roles: &[Role<ResolvedTenant>],
    ) -> Result<DomainEvent, AppError> {
        let scoped = ScopedTenant::from_registry(change.tenant);
        let held = self.names_of(&scoped, &change.held).await?;
        self.ports
            .grants
            .replace_in_tenant(change.member.id(), change.tenant.id(), &change.issued)
            .await
            .or_internal()?;
        Ok(OrgUserTenantAccessChanged::replaced(
            change.member,
            change.tenant,
            held,
            roles,
        ))
    }
}

impl Command for SetOrgUserTenantAccessUseCase {
    type Caller = OrgCaller;
    type Input = SetOrgUserTenantAccessRequest;
    type Output = Result<(), AppError>;

    /// Gives `request.member` exactly the roles `request.role_names` names
    /// in the tenant, and records
    /// `organization.org_user_tenant_access_granted`, or
    /// `organization.org_user_tenant_access_revoked` for an empty set.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without tenant-access rights or for a foreign tenant.
    /// - `AppError::Conflict` for an owner already reaching every tenant; `Domain` for a role outside the tenant.
    /// - `AppError::NotFound` for a missing organization member/tenant; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: SetOrgUserTenantAccessRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_may_manage_access(&organization, control)?;
        let users = self.ports.org_users.as_ref();
        let member = existing_member(users, organization.id(), &request.member).await?;
        let tenants = self.ports.tenants.as_ref();
        let tenant =
            existing_tenant_named(tenants, organization.id(), &request.tenant_slug).await?;
        let roles = self
            .roles_named(&ScopedTenant::from_registry(&tenant), &request.role_names)
            .await?;
        let held = self.held_in(&member, &tenant).await?;
        let grantee = Grantee {
            organization: &organization,
            control,
            member: &member,
            tenant: &tenant,
        };
        let change = replacement(&grantee, held, &roles)?;
        let replaced = self.replaced(change, &roles).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), vec![replaced])
            .await
            .or_internal()
    }
}

/// Refuses a caller who may not manage tenant access, before anything is
/// read: an empty set grants and withdraws nothing, so the checks on each
/// grant would never run for it.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when `control` does not carry the right.
fn ensure_may_manage_access(
    organization: &Organization,
    control: OrgControl<'_>,
) -> Result<(), AppError> {
    control
        .ensure_may(organization.id(), MANAGE_ACCESS)
        .map_err(AppError::from_domain)
}

/// Refuses taking any of `held` away unless `control` may withdraw it from
/// `organization`.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when the caller may not manage tenant
/// access, or a grant's tenant is not the organization's.
fn ensure_withdrawable(
    held: &[OrgTenantGrant],
    organization: &Organization,
    control: OrgControl<'_>,
) -> Result<(), AppError> {
    held.iter()
        .try_for_each(|grant| grant.ensure_withdrawable(organization, ActedBy::By(control)))
        .map_err(AppError::from_domain)
}

/// Who receives the grants, from whom, and where.
struct Grantee<'a> {
    organization: &'a Organization,
    control: OrgControl<'a>,
    member: &'a OrgUser,
    tenant: &'a Tenant,
}

/// `held` replaced by one grant per role in `roles`, once the caller may
/// take each of `held` away.
///
/// # Errors
///
/// Returns `AppError::Forbidden` or `AppError::Conflict` when the domain
/// refuses withdrawing a grant or issuing one.
fn replacement<'a>(
    grantee: &Grantee<'a>,
    held: Vec<OrgTenantGrant>,
    roles: &[Role<ResolvedTenant>],
) -> Result<Replacement<'a>, AppError> {
    ensure_withdrawable(&held, grantee.organization, grantee.control)?;
    let issued = issued_grants(grantee, roles).map_err(AppError::from_domain)?;
    Ok(Replacement {
        member: grantee.member,
        tenant: grantee.tenant,
        held,
        issued,
    })
}

/// One grant per role in `roles`, issued by the domain.
fn issued_grants(
    grantee: &Grantee<'_>,
    roles: &[Role<ResolvedTenant>],
) -> Result<Vec<OrgTenantGrant>, DomainError> {
    roles
        .iter()
        .map(|role| {
            OrgTenantGrant::issue(GrantRequest {
                organization: grantee.organization,
                issuer: grantee.control,
                grantee: grantee.member,
                tenant_id: *grantee.tenant.id(),
                role_id: *role.id(),
            })
        })
        .collect()
}

fn no_such_role(name: &Label) -> AppError {
    AppError::from_domain(DomainError::invalid(message!(
        "organization-no-role-named-in-this-tenant",
        format!("no role named {name} in this tenant")
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::types::{RoleId, TenantId};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authorization::{FakeRoleStore, stored_role};
    use crate::test_support::organization::{
        FakeOrgTenantGrantStore, org_user_store_with, test_org_user,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    const GRANTED: &str = "organization.org_user_tenant_access_granted";

    struct Setup {
        uc: SetOrgUserTenantAccessUseCase,
        roles: Arc<FakeRoleStore>,
        grants: Arc<FakeOrgTenantGrantStore>,
        audit: Arc<FakeEventDispatcher>,
        member: OrgUserId,
        owner: OrgUserId,
        tenant_id: TenantId,
        editor: RoleId,
        viewer: RoleId,
    }

    /// Acme with Sam, a member, and Oscar, an owner, and its production
    /// tenant holding an Editor and a Viewer role. The caller acts in
    /// `role`.
    fn setup_as(role: OrgRole) -> Setup {
        let org_id = test_org_caller().organization_id();
        let tenant = test_tenant_in(org_id, "production", "production.test");
        let tenant_id = *tenant.id();
        setup_with(FakeOrgActors::in_role(role).owning(&[tenant_id]), tenant)
    }

    fn setup_with(actors: FakeOrgActors, tenant: Tenant) -> Setup {
        let org_id = test_org_caller().organization_id();
        let member = test_org_user(org_id, "sam@acme.test", OrgRole::Member);
        let owner = test_org_user(org_id, "oscar@acme.test", OrgRole::Owner);
        let (member_id, owner_id) = (*member.id(), *owner.id());
        let tenant_id = *tenant.id();
        let editor = stored_role("Editor", vec![SystemPermission::all()[0]], Vec::new());
        let viewer = stored_role("Viewer", vec![SystemPermission::all()[1]], Vec::new());
        let (editor_id, viewer_id) = (*editor.id(), *viewer.id());
        let grants = Arc::new(FakeOrgTenantGrantStore::empty());
        let roles = Arc::new(FakeRoleStore::holding(tenant_id, [editor, viewer]));
        let uc = SetOrgUserTenantAccessUseCase::new(SetOrgUserTenantAccessPorts {
            org_actors: Arc::new(actors),
            org_users: Arc::new(org_user_store_with([member, owner])),
            tenants: Arc::new(FakeTenantStore::holding(tenant)),
            roles: roles.clone(),
            grants: grants.clone(),
        });
        Setup {
            uc,
            roles,
            grants,
            audit: Arc::new(FakeEventDispatcher::new()),
            member: member_id,
            owner: owner_id,
            tenant_id,
            editor: editor_id,
            viewer: viewer_id,
        }
    }

    fn slug(value: &str) -> TenantSlug {
        TenantSlug::new(value, &DomainLimits::default().slug).unwrap()
    }

    fn set_access(s: &Setup, who: OrgUserId, tenant: &str, roles: &[&str]) -> Result<(), AppError> {
        let request = SetOrgUserTenantAccessRequest {
            member: who,
            tenant_slug: slug(tenant),
            role_names: roles
                .iter()
                .map(|name| Label::new("role_name", *name).unwrap())
                .collect(),
        };
        block_on(s.uc.execute(&test_org_caller(), &test_auditor(s.audit.clone()), request))
    }

    fn held_by(s: &Setup, who: OrgUserId) -> Vec<RoleId> {
        block_on(s.grants.list_by_user_in_tenant(&who, &s.tenant_id))
            .unwrap()
            .iter()
            .map(|grant| *grant.role_id())
            .collect()
    }

    /// Olivia, an owner, grants Sam the Editor role in production. He
    /// holds exactly that.
    #[test]
    fn a_member_is_given_exactly_the_roles_named() {
        let s = setup_as(OrgRole::Owner);

        set_access(&s, s.member, "production", &["Editor"]).unwrap();

        assert_eq!(held_by(&s, s.member), vec![s.editor]);
    }

    /// Naming Editor twice grants it once.
    #[test]
    fn naming_a_role_twice_grants_it_once() {
        let s = setup_as(OrgRole::Owner);

        set_access(&s, s.member, "production", &["Editor", "Editor"]).unwrap();

        assert_eq!(held_by(&s, s.member), vec![s.editor]);
    }

    /// Several requested names are resolved together, keeping first-request order
    /// and granting a repeated role only once with the same audit description.
    #[test]
    fn named_roles_share_one_validation_read() {
        let s = setup_as(OrgRole::Owner);

        set_access(&s, s.member, "production", &["Viewer", "Editor", "Viewer"]).unwrap();

        assert_eq!(held_by(&s, s.member), vec![s.viewer, s.editor]);
        let payload = s.audit.payload_of(GRANTED);
        let Some(FieldValue::Change(change)) = payload.value("roles") else {
            panic!("the record carries the role change");
        };
        assert_eq!(change.to(), Some("Viewer, Editor"));
        assert_eq!(s.roles.name_reads(), 1);
    }

    /// Sam held Editor and Viewer, and Olivia narrows him to Viewer.
    /// Editor goes.
    #[test]
    fn narrowing_access_removes_the_roles_left_out() {
        let s = setup_as(OrgRole::Owner);
        set_access(&s, s.member, "production", &["Editor", "Viewer"]).unwrap();

        set_access(&s, s.member, "production", &["Viewer"]).unwrap();

        assert_eq!(held_by(&s, s.member), vec![s.viewer]);
    }

    /// Olivia names no role for Sam. His access to production is withdrawn.
    #[test]
    fn an_empty_set_withdraws_access_to_the_tenant() {
        let s = setup_as(OrgRole::Owner);
        set_access(&s, s.member, "production", &["Editor"]).unwrap();

        set_access(&s, s.member, "production", &[]).unwrap();

        assert!(held_by(&s, s.member).is_empty());
    }

    /// Oscar is an owner and reaches every tenant already. Giving him a
    /// grant is refused.
    #[test]
    fn an_owner_cannot_be_given_tenant_grants() {
        let s = setup_as(OrgRole::Owner);

        let result = set_access(&s, s.owner, "production", &["Editor"]);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(held_by(&s, s.owner).is_empty());
    }

    /// A role production does not have is refused, and nothing is granted.
    #[test]
    fn a_role_the_tenant_does_not_have_is_refused_and_nothing_is_granted() {
        let s = setup_as(OrgRole::Owner);

        let result = set_access(&s, s.member, "production", &["Editor", "Superuser"]);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(held_by(&s, s.member).is_empty());
    }

    /// A slug the organization has no tenant under is not found.
    #[test]
    fn a_tenant_slug_the_organization_does_not_have_is_not_found() {
        let s = setup_as(OrgRole::Owner);

        let result = set_access(&s, s.member, "someone-elses", &["Editor"]);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The record of the change names the roles Sam held before and after.
    #[test]
    fn the_audit_record_names_the_roles_before_and_after() {
        let s = setup_as(OrgRole::Owner);
        set_access(&s, s.member, "production", &["Viewer"]).unwrap();
        s.audit.payloads.lock().unwrap().clear();

        set_access(&s, s.member, "production", &["Editor", "Viewer"]).unwrap();

        let payload = s.audit.payload_of(GRANTED);
        let Some(FieldValue::Change(change)) = payload.value("roles") else {
            panic!("the record carries the role change");
        };
        assert_eq!(change.from(), Some("Viewer"));
        assert_eq!(change.to(), Some("Editor, Viewer"));
    }

    /// A plain member cannot grant Editor access; the target keeps no roles
    /// in production.
    #[test]
    fn a_member_granting_themselves_access_is_refused() {
        let s = setup_as(OrgRole::Member);

        let result = set_access(&s, s.member, "production", &["Editor"]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(held_by(&s, s.member).is_empty());
    }

    /// A plain member cannot submit even an empty tenant-role set; the
    /// permission refusal produces no access-change record.
    #[test]
    fn an_empty_set_from_a_member_without_the_right_is_refused() {
        let s = setup_as(OrgRole::Member);

        let result = set_access(&s, s.member, "production", &[]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(s.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller must authenticate before granting tenant access.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let org_id = test_org_caller().organization_id();
        let s = setup_with(
            FakeOrgActors::refusing(Refusal::SignedOut),
            test_tenant_in(org_id, "production", "production.test"),
        );

        let result = set_access(&s, s.member, "production", &["Editor"]);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents granting Sam tenant access.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let org_id = test_org_caller().organization_id();
        let s = setup_with(
            FakeOrgActors::refusing(Refusal::Forbidden),
            test_tenant_in(org_id, "production", "production.test"),
        );

        let result = set_access(&s, s.member, "production", &["Editor"]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
