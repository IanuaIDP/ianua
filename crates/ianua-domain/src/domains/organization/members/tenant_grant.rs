//! Which tenants an org Member reaches, and with what authority.
//!
//! An [`OrgRole::Owner`] runs the organization and reaches every tenant in
//! it through the role alone. An [`OrgRole::Member`] reaches only the tenants
//! granted to them. Each grant names a tenant role, the same kind of role the
//! tenant's own users get. So the organization and the tenant share one
//! permission model.
//!
//! [`OrgRole::Owner`]: crate::domains::organization::members::membership::OrgRole::Owner
//! [`OrgRole::Member`]: crate::domains::organization::members::membership::OrgRole::Member

use time::OffsetDateTime;

use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::membership::TenantReach;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::permission::{OrgPermission, TenantAccessAction};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{ActedBy, OrgUserId, RoleId, TenantId};

/// The right that gives and takes away tenant access.
const MANAGE_ACCESS: OrgPermission = OrgPermission::TenantAccess(TenantAccessAction::Manage);

/// A grant as stored, for rebuilding it with [`OrgTenantGrant::reconstitute`].
#[derive(Clone, Copy)]
pub struct OrgTenantGrantRow {
    /// The org user the grant belongs to.
    pub org_user_id: OrgUserId,
    /// The tenant the grant opens.
    pub tenant_id: TenantId,
    /// The tenant role the grant confers.
    pub role_id: RoleId,
    /// The owner who issued the grant, or the platform.
    pub granted_by: ActedBy<OrgUserId>,
    /// When the grant was issued.
    pub granted_at: OffsetDateTime,
}

/// One org user's hold on one tenant role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgTenantGrant {
    org_user_id: OrgUserId,
    tenant_id: TenantId,
    role_id: RoleId,
    granted_by: ActedBy<OrgUserId>,
    granted_at: OffsetDateTime,
}

/// Who asks for a grant, for whom, and to what.
#[derive(Clone, Copy)]
pub struct GrantRequest<'a> {
    /// The organization the tenant and both members belong to.
    pub organization: &'a Organization,
    /// The member issuing the grant, with what they act through.
    pub issuer: OrgControl<'a>,
    /// The member who receives it.
    pub grantee: &'a OrgUser,
    /// The tenant it opens.
    pub tenant_id: TenantId,
    /// The tenant role it confers. The caller loads it through the store
    /// opened for `tenant_id`, which is what makes it that tenant's role.
    pub role_id: RoleId,
}

impl OrgTenantGrant {
    /// Issues a grant, stamped now.
    ///
    /// Only a member who may manage tenant access issues one, only to a
    /// member of the same organization, and only to a tenant the
    /// organization owns. Without these a member could grant themselves a
    /// tenant, or an owner of one organization reach into another's.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the issuer may not manage tenant
    ///   access in the organization, the grantee is in another organization,
    ///   or the tenant is not the organization's.
    /// - [`DomainError::Conflict`] when the grantee is an owner or admin, who
    ///   already reaches every tenant, or a billing contact or viewer, who
    ///   reaches none.
    pub fn issue(request: GrantRequest<'_>) -> Result<Self, DomainError> {
        Self::ensure_grantable(&request)?;
        Ok(Self {
            org_user_id: *request.grantee.id(),
            tenant_id: request.tenant_id,
            role_id: request.role_id,
            granted_by: ActedBy::By(*request.issuer.by().id()),
            granted_at: crate::shared::clock::now(),
        })
    }

    fn ensure_grantable(request: &GrantRequest<'_>) -> Result<(), DomainError> {
        let organization_id = request.organization.id();
        request.issuer.ensure_may(organization_id, MANAGE_ACCESS)?;
        if request.grantee.organization_id() != organization_id {
            return Err(DomainError::forbidden(message!(
                "organization-tenant-access-is-granted-only-to",
                "tenant access is granted only to members of the organization"
            )));
        }
        if !request.organization.owns_tenant(&request.tenant_id) {
            return Err(DomainError::forbidden(message!(
                "organization-the-tenant-does-not-belong-to",
                "the tenant does not belong to the organization"
            )));
        }
        match request.grantee.role().tenant_reach() {
            TenantReach::Granted => Ok(()),
            TenantReach::Every => Err(DomainError::conflict(message!(
                "organization-an-owner-or-admin-already-reaches",
                "an owner or admin already reaches every tenant"
            ))),
            TenantReach::Nothing => Err(DomainError::conflict(message!(
                "organization-a-billing-contact-or-viewer-reaches",
                "a billing contact or viewer reaches no tenant, granted or not"
            ))),
        }
    }

    /// Refuses withdrawing this grant from `organization` unless `by` is the
    /// platform, as when a tenant is deleted or a member removed, or a
    /// member who may manage tenant access there.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a member withdraws it without the
    ///   right, or the grant's tenant is not `organization`'s.
    pub fn ensure_withdrawable(
        &self,
        organization: &Organization,
        by: ActedBy<OrgControl<'_>>,
    ) -> Result<(), DomainError> {
        let ActedBy::By(control) = by else {
            return Ok(());
        };
        control.ensure_may(organization.id(), MANAGE_ACCESS)?;
        if !organization.owns_tenant(&self.tenant_id) {
            return Err(DomainError::forbidden(message!(
                "organization-the-tenant-does-not-belong-to",
                "the tenant does not belong to the organization"
            )));
        }
        Ok(())
    }

    /// Rebuilds a tenant grant from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the member granted
    ///   the access to themselves.
    pub fn reconstitute(row: OrgTenantGrantRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            org_user_id: row.org_user_id,
            tenant_id: row.tenant_id,
            role_id: row.role_id,
            granted_by: row.granted_by,
            granted_at: row.granted_at,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    ///
    /// Only an owner grants, and an owner is never a grantee. So nobody
    /// holds a grant they gave themselves.
    fn ensure_consistent(row: &OrgTenantGrantRow) -> Result<(), DomainError> {
        RowCheck::of("org tenant grant")
            .holds(
                row.granted_by.account() != Some(&row.org_user_id),
                "granted by the member to themselves",
            )
            .finish()
    }

    /// The org user the grant belongs to.
    #[must_use]
    pub fn org_user_id(&self) -> &OrgUserId {
        &self.org_user_id
    }

    /// The tenant the grant opens.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The tenant role the grant confers.
    #[must_use]
    pub fn role_id(&self) -> &RoleId {
        &self.role_id
    }

    /// The owner who issued the grant, or the platform.
    #[must_use]
    pub fn granted_by(&self) -> &ActedBy<OrgUserId> {
        &self.granted_by
    }

    /// When the grant was issued.
    #[must_use]
    pub fn granted_at(&self) -> OffsetDateTime {
        self.granted_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::access::session::OrgSession;
    use crate::domains::organization::billing::plan::OrganizationPlan;
    use crate::domains::organization::lifecycle::CreateOrganizationParams;
    use crate::domains::organization::lifecycle::tests::{founding_of, tenant_with};
    use crate::domains::organization::members::control::tests::{acting, session_of};
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword,
    };
    use crate::domains::organization::members::org_user_status::OrgUserStatus;
    use crate::domains::organization::members::owners::Owners;
    use crate::shared::config::{DisplayNameLimits, SlugLimits};
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{DisplayName, Email, Label, OrganizationId, TenantSlug};

    struct Setting {
        organization: Organization,
        tenant: TenantId,
        owner: OrgUser,
        member: OrgUser,
    }

    fn person(organization: &Organization, role: OrgRole, email: &str) -> OrgUser {
        let params = |role, email: &str| CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: *organization.id(),
            email: Email::new(email).unwrap(),
            display_name: DisplayName::new("Someone", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::NotSet,
            role,
        };
        let founder = OrgUser::create(
            params(OrgRole::Owner, "founder@acme.com"),
            AddedBy::Founding(founding_of(*organization.id())),
        )
        .unwrap();
        let session = session_of(&founder);
        OrgUser::create(
            params(role, email),
            AddedBy::Member(acting(&founder, &session)),
        )
        .unwrap()
    }

    fn organization() -> Organization {
        Organization::create(CreateOrganizationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Acme").unwrap(),
            contact_email: Email::new("admin@acme.com").unwrap(),
            display_name: DisplayName::new("Acme", &DisplayNameLimits::default()).unwrap(),
            plan: OrganizationPlan::Free,
        })
        .unwrap()
        .0
    }

    fn setting() -> Setting {
        let mut organization = organization();
        let tenant = TenantId::new();
        organization
            .add_tenant(&tenant_with(tenant), ActedBy::Platform)
            .unwrap();
        let owner = person(&organization, OrgRole::Owner, "owner@acme.com");
        let member = person(&organization, OrgRole::Member, "member@acme.com");
        Setting {
            organization,
            tenant,
            owner,
            member,
        }
    }

    fn request<'a>(
        setting: &'a Setting,
        issuer: &'a OrgUser,
        session: &'a OrgSession,
    ) -> GrantRequest<'a> {
        GrantRequest {
            organization: &setting.organization,
            issuer: acting(issuer, session),
            grantee: &setting.member,
            tenant_id: setting.tenant,
            role_id: RoleId::new(),
        }
    }

    /// An active owner of Acme grants a member a role in one of Acme's
    /// tenants. The grant names that member and records the owner who gave it.
    #[test]
    fn issue_records_the_granting_owner() {
        let setting = setting();
        let session = session_of(&setting.owner);

        let grant = OrgTenantGrant::issue(request(&setting, &setting.owner, &session)).unwrap();

        assert_eq!(grant.granted_by(), &ActedBy::By(*setting.owner.id()));
        assert_eq!(grant.org_user_id(), setting.member.id());
    }

    /// A plain member cannot issue a tenant grant to themselves.
    #[test]
    fn a_member_cannot_grant_themselves_a_tenant() {
        let setting = setting();
        let session = session_of(&setting.member);

        let result = OrgTenantGrant::issue(request(&setting, &setting.member, &session));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An owner's grant request is refused for billing and viewer members,
    /// whose roles have no tenant reach.
    #[test]
    fn a_role_that_reaches_no_tenant_receives_no_grant() {
        let setting = setting();
        let session = session_of(&setting.owner);

        for role in [OrgRole::Billing, OrgRole::Viewer] {
            let grantee = person(&setting.organization, role, "bob@acme.com");
            let result = OrgTenantGrant::issue(GrantRequest {
                grantee: &grantee,
                ..request(&setting, &setting.owner, &session)
            });

            assert!(matches!(result, Err(DomainError::Conflict(_))), "{role}");
        }
    }

    /// A locked owner cannot issue a tenant grant through a session.
    #[test]
    fn a_locked_owner_grants_nothing() {
        let mut setting = setting();
        let co_owner = person(&setting.organization, OrgRole::Owner, "co-owner@acme.com");
        let co_session = session_of(&co_owner);
        setting
            .owner
            .change_status(
                OrgUserStatus::Locked,
                &acting(&co_owner, &co_session),
                Owners::of(std::slice::from_ref(&co_owner)),
            )
            .unwrap();
        let session = session_of(&setting.owner);

        let result = OrgTenantGrant::issue(request(&setting, &setting.owner, &session));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An owner from another organization cannot issue Acme tenant grants.
    #[test]
    fn an_owner_of_another_organization_grants_nothing() {
        let setting = setting();
        let stranger = person(&organization(), OrgRole::Owner, "owner@other.com");
        let session = session_of(&stranger);

        let result = OrgTenantGrant::issue(request(&setting, &stranger, &session));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Acme's owner cannot issue a tenant grant to another organization's
    /// member.
    #[test]
    fn a_member_of_another_organization_receives_nothing() {
        let setting = setting();
        let outsider = person(&organization(), OrgRole::Member, "member@other.com");
        let session = session_of(&setting.owner);

        let result = OrgTenantGrant::issue(GrantRequest {
            grantee: &outsider,
            ..request(&setting, &setting.owner, &session)
        });

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Acme's owner cannot grant a tenant absent from Acme's tenant list.
    #[test]
    fn a_tenant_the_organization_does_not_own_is_not_granted() {
        let setting = setting();
        let session = session_of(&setting.owner);

        let result = OrgTenantGrant::issue(GrantRequest {
            tenant_id: TenantId::new(),
            ..request(&setting, &setting.owner, &session)
        });

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A member cannot authorize withdrawing a tenant grant; an owner and
    /// the platform both can.
    #[test]
    fn only_someone_who_manages_access_withdraws_a_grant() {
        let setting = setting();
        let owners = session_of(&setting.owner);
        let grant = OrgTenantGrant::issue(request(&setting, &setting.owner, &owners)).unwrap();
        let sams = session_of(&setting.member);

        let by_sam = grant.ensure_withdrawable(
            &setting.organization,
            ActedBy::By(acting(&setting.member, &sams)),
        );
        let by_owner = grant.ensure_withdrawable(
            &setting.organization,
            ActedBy::By(acting(&setting.owner, &owners)),
        );

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_owner.is_ok());
        assert!(
            grant
                .ensure_withdrawable(&setting.organization, ActedBy::Platform)
                .is_ok()
        );
    }

    /// A grant the platform gave is loaded from storage. Its member, tenant,
    /// role, granter and time come back as stored.
    #[test]
    fn reconstitute_preserves_every_field() {
        let org_user_id = OrgUserId::new();
        let tenant_id = TenantId::new();
        let role_id = RoleId::new();
        let granted_at = crate::shared::clock::now();

        let grant = OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id,
            tenant_id,
            role_id,
            granted_by: ActedBy::Platform,
            granted_at,
        })
        .unwrap();

        assert_eq!(*grant.org_user_id(), org_user_id);
        assert_eq!(*grant.tenant_id(), tenant_id);
        assert_eq!(*grant.role_id(), role_id);
        assert_eq!(grant.granted_by(), &ActedBy::Platform);
        assert_eq!(grant.granted_at(), granted_at);
    }

    /// A stored grant naming the same member as issuer and recipient is
    /// refused as corrupt.
    #[test]
    fn a_stored_grant_the_member_gave_themselves_is_refused() {
        let sam = OrgUserId::new();

        let loaded = OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: sam,
            tenant_id: TenantId::new(),
            role_id: RoleId::new(),
            granted_by: ActedBy::By(sam),
            granted_at: crate::shared::clock::now(),
        });

        assert!(refused_as_corrupt(&loaded));
    }
}
