//! What a member of an organization holds inside one of its tenants.
//!
//! An owner reaches every tenant with everything. A plain member holds only
//! the roles their tenant grants name there. The organization works it out
//! from its own records and the tenant's, for the session the member opened
//! in that tenant or a key they made there, so nobody writes a member's
//! rights in a tenant by hand.

use time::OffsetDateTime;

use crate::domains::authorization::authority::{
    Holdings, OutsideHolder, TenantAccess, TenantAuthority,
};
use crate::domains::authorization::held::Held;
use crate::domains::authorization::inviter::InviterNow;
use crate::domains::authorization::key_authority::{KeyCharter, ensure_key_works};
use crate::domains::authorization::permission::SystemPermission;
use crate::domains::authorization::run_authority::{
    RunCharter, acts_for_someone_else, ensure_running,
};
use crate::domains::organization::access::session::SessionPlace;
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::control::{Carried, OrgControl};
use crate::domains::organization::members::membership::TenantReach;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::reach::MemberReach;
use crate::domains::organization::members::tenant_grant::OrgTenantGrant;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ActorRef, Human, HumanAccount, PersonKey, PrincipalRef, RoleId, TenantId};

/// What `control`'s member holds in the tenant `access` was read from.
///
/// `grants` are the member's tenant grants, loaded fresh.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the member acts through a key. A key
///   acts on the organization, never inside a tenant.
/// - [`DomainError::Forbidden`] when their session was opened in another
///   tenant.
/// - The cases [`OrgControl::ensure_genuine`] lists.
/// - [`DomainError::Infrastructure`] when a grant names a role the tenant
///   does not have.
pub fn authority_in<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    control: &OrgControl<'_>,
    grants: &[OrgTenantGrant],
) -> Result<TenantAuthority, DomainError> {
    let Carried::Session(checked) = control.carries() else {
        return Err(DomainError::forbidden(message!(
            "organization-a-key-acts-on-the-organization",
            "a key acts on the organization, never inside a tenant"
        )));
    };
    if checked.session().place() != SessionPlace::Tenant(access.tenant) {
        return Err(DomainError::forbidden(message!(
            "organization-the-member-s-session-was-opened",
            "the member's session was opened in another tenant, or in none"
        )));
    }
    let member = control.by();
    control.ensure_genuine(member.organization_id())?;
    let who = Human::new(
        HumanAccount::OrgUser(*member.id()),
        PersonKey::of(member.email()),
    );
    Ok(TenantAuthority::assemble(
        who,
        access.tenant,
        standing_in(access, member, grants)?,
        Holdings::default(),
    ))
}

/// Who made a key a member acts through in a tenant: the member as they are
/// now, their organization, and their tenant grants.
#[derive(Debug, Clone, Copy)]
pub struct KeyMaker<'a> {
    /// The member who made the key.
    pub member: &'a OrgUser,
    /// Their organization, as it stands now.
    pub organization: &'a Organization,
    /// The member's tenant grants, loaded fresh.
    pub grants: &'a [OrgTenantGrant],
}

/// What `key`, made by `maker.member`, may do in `access`'s tenant at `now`:
/// the permissions its scopes name that the member holds there now.
///
/// Sam is a plain member granted only `staging`. A key he made in
/// `production` holds nothing there, whatever its scopes say. Once the
/// platform suspends Acme, his keys stop with his sessions.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the key no longer works.
/// - [`DomainError::Forbidden`] when the member did not make the key.
/// - [`DomainError::Forbidden`] when the member may not sign in now, or
///   belongs to another organization.
/// - [`DomainError::Forbidden`] when the organization does not own the
///   tenant, is closed, or is suspended and the member is not an owner.
/// - [`DomainError::Infrastructure`] when a grant names a role the tenant
///   does not have.
pub fn authority_of_member_key<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    key: &impl KeyCharter,
    maker: KeyMaker<'_>,
    now: OffsetDateTime,
) -> Result<TenantAuthority, DomainError> {
    ensure_key_works(key, now)?;
    let member = maker.member;
    if !matches!(key.creator(), ActorRef::OrgUser(id) if id == member.id()) {
        return Err(DomainError::forbidden(message!(
            "authorization-the-key-was-made-by-someone",
            "the key was made by someone else"
        )));
    }
    ensure_member_reaches(member, maker.organization, &access.tenant)?;
    let who = Human::new(
        HumanAccount::OrgUser(*member.id()),
        PersonKey::of(member.email()),
    );
    let held = standing_in(access, member, maker.grants)?;
    Ok(TenantAuthority::assemble(
        who,
        access.tenant,
        held.narrowed_to(key.scopes()),
        Holdings::default(),
    ))
}

/// The member a workflow run acts for in a tenant: the member as they are
/// now, their organization, and their tenant grants.
#[derive(Debug, Clone, Copy)]
pub struct RunMember<'a> {
    /// The member the run acts for.
    pub member: &'a OrgUser,
    /// Their organization, as it stands now.
    pub organization: &'a Organization,
    /// The member's tenant grants, loaded fresh.
    pub grants: &'a [OrgTenantGrant],
}

/// What `run`, acting for `person.member`, may do in `access`'s tenant now:
/// everything the member holds there now, and nothing more.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the run has ended or acts for someone
///   else.
/// - [`DomainError::Forbidden`] when the member may not sign in now, or the
///   organization does not let them into the tenant now.
/// - [`DomainError::Infrastructure`] when a grant names a role the tenant
///   does not have.
pub fn authority_of_member_run<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    run: &impl RunCharter,
    person: RunMember<'_>,
) -> Result<TenantAuthority, DomainError> {
    ensure_running(run)?;
    let member = person.member;
    if run.acting_for().account() != HumanAccount::OrgUser(*member.id()) {
        return Err(acts_for_someone_else());
    }
    ensure_member_reaches(member, person.organization, &access.tenant)?;
    let who = Human::new(
        HumanAccount::OrgUser(*member.id()),
        PersonKey::of(member.email()),
    );
    let held = standing_in(access, member, person.grants)?;
    Ok(TenantAuthority::assemble(
        who,
        access.tenant,
        held,
        Holdings::default(),
    ))
}

/// Checks current tenant reach for member keys, workflows, webhooks and approvals.
///
/// # Errors
/// [`DomainError::Forbidden`] if the member cannot sign in, belongs elsewhere,
/// or the organization does not own the tenant, is closed, or is suspended
/// and the member is not an owner.
pub(crate) fn ensure_member_reaches(
    member: &OrgUser,
    organization: &Organization,
    tenant: &TenantId,
) -> Result<(), DomainError> {
    ensure_reaches(member.reach(), organization, tenant)
}

/// [`ensure_member_reaches`] on what a member's reach reads of them.
fn ensure_reaches(
    member: MemberReach,
    organization: &Organization,
    tenant: &TenantId,
) -> Result<(), DomainError> {
    if !member.status().can_authenticate() || member.organization_id() != organization.id() {
        return Err(DomainError::forbidden(message!(
            "organization-only-an-active-member-of-the",
            "only an active member of the organization acts in its tenants"
        )));
    }
    if !organization.owns_tenant(tenant) {
        return Err(DomainError::forbidden(message!(
            "organization-the-tenant-is-not-one-of",
            "the tenant is not one of the organization's"
        )));
    }
    organization.standing().ensure_admits(member.role())
}

/// What `member`, who sent an invitation into `access`'s tenant, holds
/// there now, for checking the role it offers when it is accepted.
///
/// Sam invited someone as an admin, then left Acme. His invitation offers
/// what he holds now, which is nothing, so it gives no admin role.
///
/// # Errors
///
/// - [`DomainError::Infrastructure`] when a grant names a role the tenant
///   does not have.
pub fn member_as_inviter<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    organization: &Organization,
    member: &OrgUser,
    grants: &[OrgTenantGrant],
) -> Result<InviterNow, DomainError> {
    let sender = ActorRef::OrgUser(*member.id());
    if ensure_member_reaches(member, organization, &access.tenant).is_err() {
        return Ok(InviterNow::holding(sender, Holdings::default()));
    }
    Ok(InviterNow::holding(
        sender,
        standing_in(access, member, grants)?,
    ))
}

/// The organization's members who hold rights in `access`'s tenant now,
/// for working out whether someone other than a policy's submitter may
/// approve it.
///
/// Only members who may act in the tenant now count: an owner, or a plain
/// member through their grants there. Ann is a tenant admin whose only peer
/// is Acme's owner. The owner counts, so Ann does not approve her own
/// policy.
///
/// # Errors
///
/// - [`DomainError::Infrastructure`] when a grant names a role the tenant
///   does not have.
pub fn members_holding_in<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    organization: &Organization,
    members: &[OrgUser],
    grants: &[OrgTenantGrant],
) -> Result<Vec<OutsideHolder>, DomainError> {
    members
        .iter()
        .filter(|member| ensure_member_reaches(member, organization, &access.tenant).is_ok())
        .map(|member| {
            let who = Human::new(
                HumanAccount::OrgUser(*member.id()),
                PersonKey::of(member.email()),
            );
            Ok(OutsideHolder::new(
                who,
                standing_in(access, member, grants)?,
            ))
        })
        .collect()
}

/// The organization's members who have access to `tenant` now: they may
/// act in it, and their role reaches every tenant or `grants` give them a
/// role there. They are the organization's side of the people told what
/// happens inside the tenant.
///
/// Ann owns Acme and Sam is a plain member granted a role in production.
/// Both have access to production. Bea, a plain member with no grant
/// there, and Bill, Acme's billing contact, have none, so neither hears
/// what happens in it.
#[must_use]
pub fn members_with_access<'m>(
    organization: &Organization,
    tenant: &TenantId,
    members: &'m [OrgUser],
    grants: &[OrgTenantGrant],
) -> Vec<&'m OrgUser> {
    members
        .iter()
        .filter(|member| ensure_member_reaches(member, organization, tenant).is_ok())
        .filter(|member| reaches_with_role(member, tenant, grants))
        .collect()
}

/// Whether `member`'s role reaches `tenant`: every tenant for an owner or
/// an admin, a tenant a grant names for a plain member, none otherwise.
fn reaches_with_role(member: &OrgUser, tenant: &TenantId, grants: &[OrgTenantGrant]) -> bool {
    match member.role().tenant_reach() {
        TenantReach::Every => true,
        TenantReach::Granted => grants
            .iter()
            .any(|grant| grant.org_user_id() == member.id() && grant.tenant_id() == tenant),
        TenantReach::Nothing => false,
    }
}

/// Computes tenant holdings: all for owners/admins, grants for members, none for billing/viewers.
/// The caller first checks sign-in eligibility, tenant ownership and organization access.
/// Reading grants does not require the member to be signed in, allowing background work.
///
/// # Errors
/// [`DomainError::Infrastructure`] if a grant names a missing tenant role.
pub(crate) fn standing_in<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    member: &OrgUser,
    grants: &[OrgTenantGrant],
) -> Result<Holdings, DomainError> {
    standing_of(access, member.reach(), grants)
}

/// [`standing_in`] on what a member's reach reads of them.
fn standing_of<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    member: MemberReach,
    grants: &[OrgTenantGrant],
) -> Result<Holdings, DomainError> {
    match member.role().tenant_reach() {
        TenantReach::Every => Ok(Holdings::of(SystemPermission::all().to_vec(), Vec::new())),
        TenantReach::Granted => access.given_by_roles(
            &granted_roles(member, access, grants),
            "organization tenant grant",
        ),
        TenantReach::Nothing => Ok(Holdings::default()),
    }
}

/// The roles `grants` give `member` in `access`'s tenant.
fn granted_roles<T: TenantScope>(
    member: MemberReach,
    access: &TenantAccess<'_, T>,
    grants: &[OrgTenantGrant],
) -> Vec<RoleId> {
    grants
        .iter()
        .filter(|grant| grant.org_user_id() == member.id() && *grant.tenant_id() == access.tenant)
        .map(|grant| *grant.role_id())
        .collect()
}

/// An organization member as the tenant's records and their organization
/// hold them now, while nobody is signed in: their reach, their
/// organization and their tenant grants.
#[derive(Debug, Clone, Copy)]
pub struct MemberInTenant<'a> {
    /// What their reach reads of them.
    pub member: MemberReach,
    /// The freshly loaded owner whose standing determines access to its tenants.
    pub organization: &'a Organization,
    /// Their tenant grants.
    pub grants: &'a [OrgTenantGrant],
}

/// What `member` holds in `access`'s tenant now, as a request decision
/// reads it, for work done for them while they are signed out, such as an
/// agent acting under their delegation. The same rule as for an
/// [`AccountNow::Member`](crate::domains::organization::members::account_now::AccountNow::Member): they must
/// reach the tenant, and they hold what their role and grants there give,
/// with the granted roles and their groups named.
///
/// Sam, a plain member granted the tenant's `Viewer` role, delegates to his
/// reporting agent. The agent's request is judged on `Viewer`; once Sam
/// leaves Acme, or Acme is closed, it is judged on nothing at all.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the member does not reach the tenant
///   now, as [`ensure_member_reaches`] says.
/// - [`DomainError::Infrastructure`] when a grant or the records name a role
///   or group the tenant does not have.
pub fn held_by_member<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    member: MemberInTenant<'_>,
) -> Result<Held, DomainError> {
    ensure_reaches(member.member, member.organization, &access.tenant)?;
    let holdings = standing_of(access, member.member, member.grants)?;
    let granted = granted_roles(member.member, access, member.grants);
    Held::granted(
        access,
        PrincipalRef::OrgUser(*member.member.id()),
        holdings,
        &granted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::{RoleAction, UserAction};
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::domains::organization::access::session::tests::{acme_with, plain_member};
    use crate::domains::organization::members::control::tests::{
        acting, founder, joined_as, key_of, member_of, session_at, session_of, tenant_of,
    };
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::OrgUser;
    use crate::domains::organization::members::org_user_status::OrgUserStatus;
    use crate::domains::organization::members::reach::MemberReachParts;
    use crate::domains::organization::members::tenant_grant::OrgTenantGrantRow;
    use crate::domains::organization::status::{OrgStanding, OrganizationStatus};
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::label;
    use crate::types::{ActedBy, TenantId};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const MANAGE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Manage);

    /// The tenant `roles` belong to, with no other records.
    fn access(
        tenant: TenantId,
        roles: &[Role<ResolvedTenant>],
    ) -> TenantAccess<'_, ResolvedTenant> {
        TenantAccess {
            tenant,
            grants: TenantGrants {
                roles,
                assignments: &[],
                groups: &[] as &[Group<ResolvedTenant>],
                memberships: &[] as &[GroupMembership<ResolvedTenant>],
            },
            catalogue: &[],
            break_glass: &[],
        }
    }

    fn viewer() -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("viewer"),
            system_permissions: vec![VIEW_USERS],
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    /// A grant of `role` in `tenant` to `member`.
    fn grant(member: &OrgUser, tenant: TenantId, role: &Role<ResolvedTenant>) -> OrgTenantGrant {
        OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: *member.id(),
            tenant_id: tenant,
            role_id: *role.id(),
            granted_by: ActedBy::Platform,
            granted_at: crate::shared::clock::now(),
        })
        .unwrap()
    }

    /// Sam, a plain member of Acme granted the viewer role in production,
    /// delegated to an agent and signed out. The agent's request is judged
    /// on what Sam holds there now: the viewer role and what it gives.
    #[test]
    fn a_signed_out_member_holds_what_their_grant_gives() {
        let production = TenantId::new();
        let (acme, ann) = acme_with(production);
        let sam = member_of(&ann);
        let role = viewer();
        let grants = [grant(&sam, production, &role)];
        let roles = [role];

        let held = held_by_member(
            &access(production, &roles),
            MemberInTenant {
                member: sam.reach(),
                organization: &acme,
                grants: &grants,
            },
        )
        .unwrap();

        assert!(held.holdings().holds(VIEW_USERS));
        assert!(!held.holdings().holds(MANAGE_ROLES));
        assert_eq!(held.roles(), &[*roles[0].id()]);
    }

    /// Resolving Sam's holdings is forbidden when he is deactivated or
    /// when the tenant is outside his organization, despite his grant.
    #[test]
    fn a_member_who_does_not_reach_the_tenant_holds_nothing_there() {
        let production = TenantId::new();
        let (acme, ann) = acme_with(production);
        let sam = member_of(&ann);
        let role = viewer();
        let grants = [grant(&sam, production, &role)];
        let roles = [role];
        let deactivated = MemberReach::new(MemberReachParts {
            status: OrgUserStatus::Deactivated,
            ..parts_of(&sam)
        });

        let gone = held_by_member(
            &access(production, &roles),
            MemberInTenant {
                member: deactivated,
                organization: &acme,
                grants: &grants,
            },
        );
        let elsewhere = held_by_member(
            &access(TenantId::new(), &roles),
            MemberInTenant {
                member: sam.reach(),
                organization: &acme,
                grants: &grants,
            },
        );

        assert!(matches!(gone, Err(DomainError::Forbidden(_))));
        assert!(matches!(elsewhere, Err(DomainError::Forbidden(_))));
    }

    /// What `member`'s reach is made of.
    fn parts_of(member: &OrgUser) -> MemberReachParts {
        let reach = member.reach();
        MemberReachParts {
            id: *reach.id(),
            organization_id: *reach.organization_id(),
            role: reach.role(),
            status: reach.status(),
        }
    }

    /// Ann owns Acme's organization and signs in to one of its tenants. She
    /// holds everything there.
    #[test]
    fn an_owner_holds_everything_in_a_tenant() {
        let ann = founder();
        let session = session_of(&ann);

        let authority = authority_in(
            &access(tenant_of(&session), &[]),
            &acting(&ann, &session),
            &[],
        )
        .unwrap();

        assert!(authority.holds(MANAGE_ROLES));
        assert_eq!(authority.who().account(), HumanAccount::OrgUser(*ann.id()));
    }

    /// Sam is a plain member granted the viewer role in production. He
    /// holds what that role gives there, and nothing more.
    #[test]
    fn a_member_holds_only_what_their_grant_gives() {
        let ann = founder();
        let sam = member_of(&ann);
        let session = session_of(&sam);
        let role = viewer();
        let grants = [grant(&sam, tenant_of(&session), &role)];
        let roles = [role];

        let authority = authority_in(
            &access(tenant_of(&session), &roles),
            &acting(&sam, &session),
            &grants,
        )
        .unwrap();

        assert!(authority.holds(VIEW_USERS));
        assert!(!authority.holds(MANAGE_ROLES));
    }

    /// A grant in another tenant does not give Sam the user-viewing right
    /// in his session's tenant.
    #[test]
    fn a_grant_for_another_tenant_gives_nothing_here() {
        let ann = founder();
        let sam = member_of(&ann);
        let session = session_of(&sam);
        let role = viewer();
        let grants = [grant(&sam, TenantId::new(), &role)];
        let roles = [role];

        let authority = authority_in(
            &access(tenant_of(&session), &roles),
            &acting(&sam, &session),
            &grants,
        )
        .unwrap();

        assert!(!authority.holds(VIEW_USERS));
    }

    /// An owner's session cannot resolve authority in a different tenant
    /// from the one where it was opened.
    #[test]
    fn a_session_works_only_in_the_tenant_it_was_opened_in() {
        let ann = founder();
        let session = session_of(&ann);

        let acted = authority_in(&access(TenantId::new(), &[]), &acting(&ann, &session), &[]);

        assert!(matches!(acted, Err(DomainError::Forbidden(_))));
    }

    /// An organization-only session cannot act in production even when
    /// its member has a grant there.
    #[test]
    fn a_session_on_the_organization_alone_acts_in_no_tenant() {
        let ann = founder();
        let sam = member_of(&ann);
        let session = session_at(&sam, SessionPlace::Organization);
        let role = viewer();
        let production = TenantId::new();
        let grants = [grant(&sam, production, &role)];
        let roles = [role];

        let acted = authority_in(
            &access(production, &roles),
            &acting(&sam, &session),
            &grants,
        );

        assert!(matches!(acted, Err(DomainError::Forbidden(_))));
    }

    /// An organization key cannot provide session-based tenant authority.
    #[test]
    fn a_key_does_not_act_inside_a_tenant() {
        let ann = founder();
        let key = key_of(&ann, &["org:tenants:view"]);
        let by_key = OrgControl::new(
            OrgStanding::new(*ann.organization_id(), OrganizationStatus::Active),
            &ann,
            Carried::Key(&key),
        );

        let acted = authority_in(&access(TenantId::new(), &[]), &by_key, &[]);

        assert!(matches!(acted, Err(DomainError::Forbidden(_))));
    }

    /// A key `member` made in a tenant, scoped to `scopes`.
    struct Key {
        scopes: Vec<crate::types::Scope>,
        creator: ActorRef,
    }

    impl crate::domains::identity::sealed::Sealed for Key {}

    impl KeyCharter for Key {
        fn scopes(&self) -> &[crate::types::Scope] {
            &self.scopes
        }

        fn creator(&self) -> &ActorRef {
            &self.creator
        }

        fn works_at(&self, _now: OffsetDateTime) -> bool {
            true
        }
    }

    fn key_by(member: &OrgUser, scopes: &[&str]) -> Key {
        Key {
            scopes: scopes
                .iter()
                .map(|scope| crate::types::Scope::new(*scope).unwrap())
                .collect(),
            creator: ActorRef::OrgUser(*member.id()),
        }
    }

    /// Sam is a plain member granted the viewer role in production. His key
    /// there, scoped to viewing users and managing roles, views users and
    /// manages nothing.
    #[test]
    fn a_members_key_carries_what_their_grant_gives_and_its_scopes_name() {
        let production = TenantId::new();
        let (organization, ann) = acme_with(production);
        let sam = plain_member(&organization, &ann);
        let role = viewer();
        let grants = [grant(&sam, production, &role)];
        let roles = [role];
        let key = key_by(&sam, &["idp:users:view", "idp:roles:manage"]);

        let authority = authority_of_member_key(
            &access(production, &roles),
            &key,
            KeyMaker {
                member: &sam,
                organization: &organization,
                grants: &grants,
            },
            crate::shared::clock::now(),
        )
        .unwrap();

        assert!(authority.holds(VIEW_USERS));
        assert!(!authority.holds(MANAGE_ROLES));
    }

    /// Suspending Acme prevents a plain member's tenant key from acting,
    /// while an owner's key still resolves authority.
    #[test]
    fn a_suspension_stops_a_plain_members_keys() {
        let production = TenantId::new();
        let (mut organization, ann) = acme_with(production);
        let sam = plain_member(&organization, &ann);
        organization
            .change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();
        let (sams, anns) = (
            key_by(&sam, &["idp:users:view"]),
            key_by(&ann, &["idp:users:view"]),
        );
        let roles: [Role<ResolvedTenant>; 0] = [];
        let made_by = |member| KeyMaker {
            member,
            organization: &organization,
            grants: &[],
        };

        let by_sam = authority_of_member_key(
            &access(production, &roles),
            &sams,
            made_by(&sam),
            crate::shared::clock::now(),
        );
        let by_ann = authority_of_member_key(
            &access(production, &roles),
            &anns,
            made_by(&ann),
            crate::shared::clock::now(),
        );

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_ann.is_ok());
    }

    /// Ann's key cannot resolve tenant authority when Sam is named as its
    /// maker.
    #[test]
    fn a_members_key_acts_only_for_its_maker() {
        let production = TenantId::new();
        let (organization, ann) = acme_with(production);
        let sam = plain_member(&organization, &ann);
        let roles: [Role<ResolvedTenant>; 0] = [];

        let acted = authority_of_member_key(
            &access(production, &roles),
            &key_by(&ann, &["idp:users:view"]),
            KeyMaker {
                member: &sam,
                organization: &organization,
                grants: &[],
            },
            crate::shared::clock::now(),
        );

        assert!(matches!(acted, Err(DomainError::Forbidden(_))));
    }

    /// Ann's key cannot resolve authority in a tenant her organization
    /// does not own.
    #[test]
    fn a_members_key_does_not_reach_another_organizations_tenant() {
        let (organization, ann) = acme_with(TenantId::new());
        let roles: [Role<ResolvedTenant>; 0] = [];

        let acted = authority_of_member_key(
            &access(TenantId::new(), &roles),
            &key_by(&ann, &["idp:users:view"]),
            KeyMaker {
                member: &ann,
                organization: &organization,
                grants: &[],
            },
            crate::shared::clock::now(),
        );

        assert!(matches!(acted, Err(DomainError::Forbidden(_))));
    }

    /// Ann owns Acme and Sam is a plain member with no grant in
    /// production. Both may act there now: Ann with everything, Sam with
    /// nothing. Once the platform suspends Acme, only Ann still counts.
    #[test]
    fn the_members_who_may_act_in_a_tenant_are_worked_out_from_records() {
        let production = TenantId::new();
        let (mut organization, ann) = acme_with(production);
        let sam = plain_member(&organization, &ann);
        let roles: [Role<ResolvedTenant>; 0] = [];
        let ann_id = *ann.id();
        let members = [ann, sam];

        let open =
            members_holding_in(&access(production, &roles), &organization, &members, &[]).unwrap();
        organization
            .change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();
        let suspended =
            members_holding_in(&access(production, &roles), &organization, &members, &[]).unwrap();

        assert_eq!(open.len(), 2);
        assert_eq!(suspended.len(), 1);
        assert_eq!(suspended[0].who().account(), HumanAccount::OrgUser(ann_id));
    }

    /// Ann owns Acme and Sam is a plain member granted a role in
    /// production; both have access to it. Bea, a plain member granted a
    /// role only in staging, and Bill, the billing contact, have none.
    #[test]
    fn members_with_access_to_a_tenant_are_reached_by_role_or_grant() {
        let production = TenantId::new();
        let (organization, ann) = acme_with(production);
        let sam = plain_member(&organization, &ann);
        let bea = plain_member(&organization, &ann);
        let bill = joined_as(&ann, OrgRole::Billing);
        let role = viewer();
        let grants = [
            grant(&sam, production, &role),
            grant(&bea, TenantId::new(), &role),
            grant(&bill, production, &role),
        ];
        let (ann_id, sam_id) = (*ann.id(), *sam.id());
        let members = [ann, sam, bea, bill];

        let told = members_with_access(&organization, &production, &members, &grants);

        let ids: Vec<_> = told.iter().map(|member| *member.id()).collect();
        assert_eq!(ids, vec![ann_id, sam_id]);
    }

    /// In suspended Acme, Sam's inviter holdings are empty despite his
    /// tenant grant; Ann's owner holdings remain nonempty.
    #[test]
    fn a_member_inviter_offers_only_what_they_hold_now() {
        let production = TenantId::new();
        let (mut organization, ann) = acme_with(production);
        let sam = plain_member(&organization, &ann);
        let role = viewer();
        let grants = [grant(&sam, production, &role)];
        let roles = [role];
        organization
            .change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();

        let by_sam =
            member_as_inviter(&access(production, &roles), &organization, &sam, &grants).unwrap();
        let by_ann =
            member_as_inviter(&access(production, &roles), &organization, &ann, &grants).unwrap();

        assert!(by_sam.held().system().is_empty());
        assert!(!by_ann.held().system().is_empty());
    }
}
