//! Who is acting in a tenant, and what they hold there, worked out from the
//! tenant's own records.
//!
//! Every rule that asks "may this person do it" reads what they hold. If a
//! use case wrote that list itself, one slip or one forged line would grant
//! anything: Sam's request arrives, and the list says "manage users". So the
//! list is never written by hand. It is worked out here from the roles,
//! groups, ladders and break-glass grants the tenant stores, for the account
//! that is signed in now.

mod outside_holder;

use time::OffsetDateTime;

use crate::domains::audit::access::{AuditLogAccess, AuditLogOf};
pub use crate::domains::authorization::authority::outside_holder::OutsideHolder;
use crate::domains::authorization::break_glass::BreakGlassGrant;
use crate::domains::authorization::granter::{AccountControl, Departure, Handout, HeldByGranter};
use crate::domains::authorization::group_tree::role_named;
use crate::domains::authorization::permission::{
    AuditLogAction, CustomPermission, DataAccessAction, PolicySetAction, SystemPermission,
};
use crate::domains::authorization::policy::review::{OtherApprovers, PolicyApprover};
use crate::domains::authorization::resource_type::{ResourceType, conferred};
use crate::domains::authorization::role::Role;
use crate::domains::authorization::stewardship::{AdministratorCount, Stewardship, TenantGrants};
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::identity::account::control::{SignedInPerson, ensure_holder};
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::without_repeats;
use crate::types::{
    ActorRef, Human, HumanAccount, Label, PermissionName, PersonKey, PrincipalRef, RoleId, Scope,
    TenantId, UserId,
};

/// The right that puts a policy live.
const ACTIVATES_POLICIES: SystemPermission = SystemPermission::PolicySet(PolicySetAction::Activate);

/// Permissions someone holds, built-in and app-defined, each named once.
///
/// Only the domain works one out, from a tenant's records, so no caller
/// adds a permission to it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Holdings {
    system: Vec<SystemPermission>,
    custom: Vec<CustomPermission>,
}

impl Holdings {
    /// `system` and `custom`, each named once.
    pub(crate) fn of(system: Vec<SystemPermission>, custom: Vec<CustomPermission>) -> Self {
        Self {
            system: without_repeats(system),
            custom: without_repeats(custom),
        }
    }

    /// The built-in permissions held.
    #[must_use]
    pub fn system(&self) -> &[SystemPermission] {
        &self.system
    }

    /// The app-defined permissions held, with what the ladders confer.
    #[must_use]
    pub fn custom(&self) -> &[CustomPermission] {
        &self.custom
    }

    /// Whether this covers the app permission `permission`: one held that
    /// covers it, a wildcard included.
    #[must_use]
    pub fn holds_custom(&self, permission: &CustomPermission) -> bool {
        CustomPermission::can_delegate(&self.custom, std::slice::from_ref(permission))
    }

    /// Every permission held, written out as a token carries it: each
    /// built-in one under the platform's realm, each app-defined one as the
    /// tenant named it. One whose name a token cannot carry is left out, so
    /// a list read from this never says more than is held.
    #[must_use]
    pub fn names(&self) -> Vec<PermissionName> {
        self.system
            .iter()
            .map(ToString::to_string)
            .chain(self.custom.iter().map(ToString::to_string))
            .filter_map(|name| PermissionName::new(name).ok())
            .collect()
    }

    /// What this hands to whoever holds it.
    pub(crate) fn handout(&self) -> Handout<'_> {
        Handout {
            system: &self.system,
            custom: &self.custom,
        }
    }

    /// Whether this holds `right`, as it is or through a wider permission.
    #[must_use]
    pub fn holds(&self, right: SystemPermission) -> bool {
        self.system.iter().any(|held| held.implies(&right))
    }

    /// The built-in permissions `scopes` name that this holds, and nothing
    /// app-defined: what a key with those scopes carries for whoever holds
    /// this.
    pub(crate) fn narrowed_to(&self, scopes: &[Scope]) -> Self {
        let system = SystemPermission::ALL_VARIANTS
            .iter()
            .copied()
            .filter(|right| scopes.iter().any(|scope| right.is_named_by(scope)))
            .filter(|right| self.holds(*right))
            .collect();
        Self::of(system, Vec::new())
    }

    /// This and `more` together.
    fn with(&self, more: &Self) -> Self {
        Self::of(
            self.system.iter().chain(&more.system).copied().collect(),
            self.custom.iter().chain(&more.custom).cloned().collect(),
        )
    }
}

/// A person acting in one tenant, with what they hold there now.
///
/// Only [`TenantAccess::authority_of`] makes one for a tenant user,
/// [`authority_of_key`](crate::domains::authorization::key_authority::authority_of_key)
/// for a key a tenant user made, and the organization for one of its
/// members or their keys. Its fields are private, so no
/// caller adds a right to it.
#[derive(Debug, Clone)]
pub struct TenantAuthority {
    who: Human,
    tenant: TenantId,
    standing: Holdings,
    emergency: Holdings,
}

impl TenantAuthority {
    /// `who`, holding `standing` in `tenant`, plus `emergency` from an
    /// active break-glass grant.
    pub(crate) fn assemble(
        who: Human,
        tenant: TenantId,
        standing: Holdings,
        emergency: Holdings,
    ) -> Self {
        Self {
            who,
            tenant,
            standing,
            emergency,
        }
    }

    /// `who`, holding `system` and `custom` in `tenant`, as a test says,
    /// without the records behind it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(
        who: Human,
        tenant: TenantId,
        system: &[SystemPermission],
        custom: &[CustomPermission],
    ) -> Self {
        Self::assemble(
            who,
            tenant,
            Holdings::of(system.to_vec(), custom.to_vec()),
            Holdings::default(),
        )
    }

    /// Someone a test does not name, holding nothing standing and `system`
    /// through an active break-glass grant, in a tenant of their own.
    #[cfg(test)]
    pub(crate) fn in_emergency(system: &[SystemPermission]) -> &'static Self {
        let someone = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("someone@example.test").unwrap(),
        );
        Box::leak(Box::new(Self::assemble(
            someone,
            TenantId::new(),
            Holdings::default(),
            Holdings::of(system.to_vec(), Vec::new()),
        )))
    }

    /// The person acting.
    #[must_use]
    pub fn who(&self) -> &Human {
        &self.who
    }

    /// The person acting, as the actor a record names.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        ActorRef::from(self.who.account())
    }

    /// The tenant whose records this was worked out from.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// What they may hand on: their standing rights, without what a
    /// break-glass grant adds for the emergency.
    #[must_use]
    pub fn standing(&self) -> HeldByGranter<'_> {
        HeldByGranter::new(&self.standing.system, &self.standing.custom)
    }

    /// Whether they may use `right` now, through their standing rights or
    /// an active break-glass grant.
    #[must_use]
    pub fn holds(&self, right: SystemPermission) -> bool {
        self.standing.holds(right) || self.emergency.holds(right)
    }

    /// Whether they may use the app permission `permission` now, through
    /// their standing rights or an active break-glass grant: a permission
    /// they hold that covers it, a wildcard included.
    #[must_use]
    pub fn holds_custom(&self, permission: &CustomPermission) -> bool {
        self.standing.holds_custom(permission) || self.emergency.holds_custom(permission)
    }

    /// The most sensitive data class they may see now.
    ///
    /// Everyone acting in a tenant sees its internal data. Confidential and
    /// restricted data need a role, or an active break-glass grant, that
    /// gives them. Sam approves a call that reads payroll only if he may
    /// see confidential data himself.
    #[must_use]
    pub fn data_clearance(&self) -> DataClassLevel {
        if self.holds(SystemPermission::Data(DataAccessAction::Restricted)) {
            return DataClassLevel::Restricted;
        }
        if self.holds(SystemPermission::Data(DataAccessAction::Confidential)) {
            return DataClassLevel::Confidential;
        }
        DataClassLevel::Internal
    }

    /// Refuses unless they may use `right` now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold `right`.
    pub fn ensure_holds(&self, right: SystemPermission) -> Result<(), DomainError> {
        if self.holds(right) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "authorization-this-needs",
            format!("this needs {right}")
        )))
    }

    /// Refuses unless this was worked out in `tenant`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when it was worked out in another tenant.
    pub fn ensure_within(&self, tenant: &TenantId) -> Result<(), DomainError> {
        if self.tenant != *tenant {
            return Err(DomainError::forbidden(message!(
                "authorization-what-the-person-holds-was-worked",
                "what the person holds was worked out in another tenant"
            )));
        }
        Ok(())
    }

    /// The proof that they may export this tenant's audit log and download
    /// the file.
    ///
    /// Exporting needs its own right, not only the right to view the log:
    /// Sam reads entries to answer a support ticket, and is not handed every
    /// record of the tenant in one file.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they may not export the audit log.
    pub fn audit_log_export(&self) -> Result<AuditLogAccess, DomainError> {
        self.ensure_holds(SystemPermission::AuditLog(AuditLogAction::Export))?;
        Ok(AuditLogAccess::granted(
            AuditLogOf::Tenant(self.tenant),
            self.actor(),
        ))
    }
}

/// Everyone who might approve a policy in a tenant besides the approver,
/// as a use case loads them for [`TenantAccess::policy_approver`].
#[derive(Debug, Clone, Copy)]
pub struct ApproverPool<'a, T: TenantScope> {
    /// The tenant's users, as they are now. Every user the roles and groups
    /// name must be among them.
    pub users: &'a [User<T>],
    /// The organization's members who hold rights in the tenant.
    pub members: &'a [OutsideHolder],
}

/// One tenant's records of who holds what: the roles, groups and
/// memberships, the catalogue of app permissions, and the break-glass
/// grants.
///
/// It is read from the store opened for `tenant`. What it says about a
/// person is worked out here, never written by the caller.
///
/// It is read whole, or narrowed to one person: their own assignments and
/// memberships, the groups above those, the roles all of them name, and
/// their break-glass grants. What one person holds, and what may be done
/// to their account, is the same either way. What spans people, such as
/// [`policy_approver`](Self::policy_approver), needs it whole.
#[derive(Debug)]
pub struct TenantAccess<'a, T: TenantScope> {
    /// The tenant these records were read from.
    pub tenant: TenantId,
    /// Who holds which roles.
    pub grants: TenantGrants<'a, T>,
    /// The tenant's resource types, whose ladders confer app permissions.
    pub catalogue: &'a [ResourceType<T>],
    /// The tenant's break-glass grants.
    pub break_glass: &'a [BreakGlassGrant],
}

impl<T: TenantScope> TenantAccess<'_, T> {
    /// What `account` holds in this tenant, for the person signed in to it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `signed_in` is someone else.
    /// - [`DomainError::Forbidden`] when the account may not sign in now.
    /// - The cases [`TenantGrants::administrators`] lists, for records that
    ///   name a role or group that is not there.
    pub fn authority_of(
        &self,
        account: &User<T>,
        signed_in: &impl SignedInPerson<T>,
        now: OffsetDateTime,
    ) -> Result<TenantAuthority, DomainError> {
        ensure_holder(signed_in, account.id())?;
        if !account.can_authenticate() {
            return Err(DomainError::forbidden(message!(
                "authorization-this-account-may-not-act-now",
                "this account may not act now"
            )));
        }
        let who = Human::new(
            HumanAccount::User(*account.id()),
            PersonKey::of(account.email()),
        );
        Ok(TenantAuthority::assemble(
            who,
            self.tenant,
            self.standing_of(PrincipalRef::User(*account.id()))?,
            self.emergency_of(account.id(), now),
        ))
    }

    /// `actor` acting on `account`'s sign-in, with what that account holds
    /// and whether it is the tenant's last administrator worked out here,
    /// from these records and `administrators`, the tenant's count.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `actor` was worked out in another
    ///   tenant.
    /// - The cases [`TenantGrants::administrators`] lists.
    pub fn account_control<'s>(
        &self,
        actor: &'s TenantAuthority,
        account: &UserId,
        administrators: AdministratorCount,
        now: OffsetDateTime,
    ) -> Result<AccountControl<'s>, DomainError> {
        actor.ensure_within(&self.tenant)?;
        Ok(AccountControl::new(
            actor,
            *account,
            Stewardship::of(&self.grants, account, administrators)?,
            self.everything_held_by(account, now)?,
        ))
    }

    /// `account` closing itself, with whether the tenant keeps an
    /// administrator worked out here, from these records and
    /// `administrators`, the tenant's count.
    ///
    /// # Errors
    ///
    /// - The cases [`TenantGrants::administrators`] lists.
    pub fn departure_of(
        &self,
        account: &UserId,
        administrators: AdministratorCount,
    ) -> Result<Departure, DomainError> {
        Ok(Departure::new(
            *account,
            Stewardship::of(&self.grants, account, administrators)?,
        ))
    }

    /// The names of the roles `account` holds, given to it or to a group it
    /// is in or one above, each named once: what an app reads in the
    /// `roles` claim.
    ///
    /// # Errors
    ///
    /// - The cases [`TenantGrants::administrators`] lists.
    pub fn role_names_held(&self, account: &UserId) -> Result<Vec<Label>, DomainError> {
        let roles = self.grants.roles_held_by(PrincipalRef::User(*account))?;
        Ok(without_repeats(
            roles.into_iter().map(|role| role.name().clone()).collect(),
        ))
    }

    /// The roles `principal` holds, given to it or to a group it is in or
    /// one above, each once: what a gateway policy matches on by id, and
    /// what an upstream reads by name.
    ///
    /// # Errors
    ///
    /// - The cases [`TenantGrants::administrators`] lists.
    pub fn roles_held_by(&self, principal: PrincipalRef) -> Result<Vec<&Role<T>>, DomainError> {
        let held = self.grants.roles_held_by(principal)?;
        Ok(held.into_iter().fold(Vec::new(), |mut kept, role| {
            if !kept.iter().any(|seen: &&Role<T>| seen.id() == role.id()) {
                kept.push(role);
            }
            kept
        }))
    }

    /// Computes built-in and app permissions for gateway checks at `now`.
    /// Includes direct and group roles, their ladders and active user break-glass grants.
    /// Unknown principals hold nothing; expired emergency grants contribute nothing.
    ///
    /// # Errors
    /// Propagates the cases listed by [`TenantGrants::administrators`].
    pub fn permissions_held_by(
        &self,
        principal: PrincipalRef,
        now: OffsetDateTime,
    ) -> Result<Holdings, DomainError> {
        let PrincipalRef::User(account) = principal else {
            return self.standing_of(principal);
        };
        self.everything_held_by(&account, now)
    }

    /// `approver` approving a policy, with whether anyone else may approve
    /// it worked out here, from `pool`.
    ///
    /// Someone else is another person, not another account of the
    /// approver's, who may sign in and may activate policies: a user of the
    /// tenant, or a member of its organization. Ann submits a policy and is
    /// the tenant's only admin among its users, while Owen owns the
    /// organization. Owen approves it, not Ann. Bob's account, locked last
    /// week, approves nothing, so it does not stop Ann approving her own.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `approver` was worked out in
    ///   another tenant.
    /// - [`DomainError::Infrastructure`] when a role or group names a user
    ///   that is not in `pool.users`.
    /// - The cases [`TenantGrants::administrators`] lists.
    pub fn policy_approver<'s>(
        &self,
        approver: &'s TenantAuthority,
        pool: &ApproverPool<'_, T>,
    ) -> Result<PolicyApprover<'s>, DomainError> {
        approver.ensure_within(&self.tenant)?;
        let by_member = pool
            .members
            .iter()
            .any(|member| member.approves_instead_of(approver.who()));
        if by_member || self.another_user_approves(approver.who(), pool.users)? {
            return Ok(PolicyApprover::new(approver, OtherApprovers::Exist));
        }
        Ok(PolicyApprover::new(approver, OtherApprovers::NoneInTenant))
    }

    /// Whether a user other than `approver`, among `users`, may sign in and
    /// activate policies.
    fn another_user_approves(
        &self,
        approver: &Human,
        users: &[User<T>],
    ) -> Result<bool, DomainError> {
        for id in self.grants.users() {
            let Some(account) = users.iter().find(|user| *user.id() == id) else {
                return Err(DomainError::corrupt_row(
                    "tenant grants",
                    "a role or group names a user that is not there",
                ));
            };
            if self.approves_instead_of(account, approver)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether `account` may approve a policy instead of `approver`: another
    /// person, who may sign in and may activate policies.
    fn approves_instead_of(
        &self,
        account: &User<T>,
        approver: &Human,
    ) -> Result<bool, DomainError> {
        let person = Human::new(
            HumanAccount::User(*account.id()),
            PersonKey::of(account.email()),
        );
        if !account.can_authenticate() || person.is_same_person_as(approver) {
            return Ok(false);
        }
        Ok(self
            .standing_of(PrincipalRef::User(*account.id()))?
            .holds(ACTIVATES_POLICIES))
    }

    /// Everything `account` holds now, standing and through an active
    /// break-glass grant: what acting on its sign-in would hand out.
    ///
    /// # Errors
    ///
    /// - The cases [`TenantGrants::administrators`] lists.
    pub(crate) fn everything_held_by(
        &self,
        account: &UserId,
        now: OffsetDateTime,
    ) -> Result<Holdings, DomainError> {
        let standing = self.standing_of(PrincipalRef::User(*account))?;
        Ok(standing.with(&self.emergency_of(account, now)))
    }

    /// What `principal`'s roles give, with what the ladders confer.
    ///
    /// # Errors
    ///
    /// - The cases [`TenantGrants::administrators`] lists.
    pub(crate) fn standing_of(&self, principal: PrincipalRef) -> Result<Holdings, DomainError> {
        self.given_by(&self.grants.roles_held_by(principal)?)
    }

    /// What the tenant's roles named `ids` give together, for a record
    /// called `holder`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when an id names no role of the
    ///   tenant.
    pub(crate) fn given_by_roles(
        &self,
        ids: &[RoleId],
        holder: &'static str,
    ) -> Result<Holdings, DomainError> {
        let roles = ids
            .iter()
            .map(|id| role_named(self.grants.roles, id, holder))
            .collect::<Result<Vec<_>, _>>()?;
        self.given_by(&roles)
    }

    /// What `roles` give, with what the ladders confer.
    fn given_by(&self, roles: &[&Role<T>]) -> Result<Holdings, DomainError> {
        let system = roles
            .iter()
            .flat_map(|role| role.system_permissions().iter().copied())
            .collect();
        let custom: Vec<CustomPermission> = roles
            .iter()
            .flat_map(|role| role.custom_permissions().iter().cloned())
            .collect();
        Ok(Holdings::of(system, conferred(self.catalogue, &custom)?))
    }

    /// What `account`'s break-glass grants in this tenant add, while they
    /// are active.
    fn emergency_of(&self, account: &UserId, now: OffsetDateTime) -> Holdings {
        let active: Vec<&BreakGlassGrant> = self
            .break_glass
            .iter()
            .filter(|grant| grant.user_id() == account && *grant.tenant_id() == self.tenant)
            .filter(|grant| grant.is_active(now))
            .collect();
        Holdings::of(
            active
                .iter()
                .flat_map(|grant| grant.access().system().iter().copied())
                .collect(),
            active
                .iter()
                .flat_map(|grant| grant.access().custom().iter().cloned())
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::break_glass::{
        BreakGlassAccess, BreakGlassGrantRow, GrantApproval,
    };
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::{PermissionSegment, RoleAction, UserAction};
    use crate::domains::authorization::resource_type::{ActionDefinition, NewResourceType};
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, RoleAssignment};
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::identity::account::control::AccountAction;
    use crate::domains::identity::account::user::tests::signed_in_as;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::{label, user};
    use crate::types::{BreakGlassGrantId, OrgUserId, ResourceTypeId, Revocation, Text};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const MANAGE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Manage);

    /// Acme, the tenant every test reads.
    fn acme() -> TenantId {
        TenantId::from_uuid(uuid::Uuid::from_u128(1))
    }

    /// Audit-log viewing alone does not authorize export, while the export right
    /// produces authority for a tenant audit log.
    #[test]
    fn exporting_the_audit_log_needs_the_export_right() {
        let sam = anyone_holding(&[SystemPermission::ViewAuditLog]);
        let ann = anyone_holding(&[SystemPermission::ExportAuditLog]);

        let refused = sam.audit_log_export();
        let granted = ann.audit_log_export().unwrap();

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(matches!(granted.log(), AuditLogOf::Tenant(_)));
    }

    /// Ann may view users and approve invoices. Written out as a token
    /// carries them, she holds `idp:users:view` and `invoices:approve`.
    #[test]
    fn holdings_are_written_out_as_tokens_name_them() {
        let holdings = Holdings::of(
            vec![VIEW_USERS],
            vec![CustomPermission::new("invoices", "approve").unwrap()],
        );

        let names: Vec<String> = holdings
            .names()
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();

        assert_eq!(names, ["idp:users:view", "invoices:approve"]);
    }

    /// The records of a tenant, owned, so a test can lend them out.
    struct Records {
        roles: Vec<Role<ResolvedTenant>>,
        assignments: Vec<RoleAssignment<ResolvedTenant>>,
        catalogue: Vec<ResourceType<ResolvedTenant>>,
        break_glass: Vec<BreakGlassGrant>,
    }

    impl Records {
        fn access(&self) -> TenantAccess<'_, ResolvedTenant> {
            TenantAccess {
                tenant: acme(),
                grants: TenantGrants {
                    roles: &self.roles,
                    assignments: &self.assignments,
                    groups: &[] as &[Group<ResolvedTenant>],
                    memberships: &[] as &[GroupMembership<ResolvedTenant>],
                },
                catalogue: &self.catalogue,
                break_glass: &self.break_glass,
            }
        }
    }

    fn active(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    fn role(system: &[SystemPermission], custom: &[&str]) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("team"),
            system_permissions: system.to_vec(),
            custom_permissions: custom
                .iter()
                .map(|text| CustomPermission::parse(text).unwrap())
                .collect(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn given(
        account: &User<ResolvedTenant>,
        role: &Role<ResolvedTenant>,
    ) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::create(
            PrincipalRef::User(*account.id()),
            role,
            anyone_holding(SystemPermission::all()),
        )
        .unwrap()
    }

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).unwrap()
    }

    /// `project` with `admin` bringing `write`, and `write` bringing `read`.
    fn project_ladder() -> ResourceType<ResolvedTenant> {
        let action = |key: &str, implies: &[&str]| {
            ActionDefinition::new(
                segment(key),
                label(key),
                implies.iter().map(|k| segment(k)).collect(),
            )
        };
        ResourceType::create(
            NewResourceType {
                data_class: DataClassLevel::Internal,
                id: ResourceTypeId::new(),
                key: segment("project"),
                display_name: label("Project"),
                description: None,
                actions: vec![
                    action("read", &[]),
                    action("write", &["read"]),
                    action("admin", &["write"]),
                ],
            },
            &HeldByGranter::new(SystemPermission::all(), &[]),
        )
        .unwrap()
    }

    /// An active break-glass grant in `tenant` for `account`, giving
    /// `system`.
    fn emergency(
        tenant: TenantId,
        account: &User<ResolvedTenant>,
        system: &[SystemPermission],
    ) -> BreakGlassGrant {
        let now = crate::shared::clock::now();
        BreakGlassGrant::reconstitute(BreakGlassGrantRow {
            id: BreakGlassGrantId::new(),
            tenant_id: tenant,
            user_id: *account.id(),
            grantee_person: PersonKey::of(account.email()),
            access: BreakGlassAccess::new(system.to_vec(), Vec::new()).unwrap(),
            reason: Text::new("reason", "Production incident INC-1234").unwrap(),
            approved_by: GrantApproval::SelfApproved,
            expires_at: now + Duration::hours(1),
            revocation: Revocation::InForce,
            created_at: now,
        })
        .unwrap()
    }

    /// Ann holds a role that may view users and gives `project:admin`. What
    /// she holds is worked out from it, with the ladder's `write` and `read`.
    #[test]
    fn what_someone_holds_comes_from_their_roles_and_the_ladders() {
        let ann = active("ann@acme.test");
        let viewer = role(&[VIEW_USERS], &["project:admin"]);
        let records = Records {
            assignments: vec![given(&ann, &viewer)],
            roles: vec![viewer],
            catalogue: vec![project_ladder()],
            break_glass: Vec::new(),
        };

        let authority = records
            .access()
            .authority_of(&ann, &signed_in_as(*ann.id()), crate::shared::clock::now())
            .unwrap();

        let custom: Vec<String> = authority
            .standing()
            .custom()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(authority.holds(VIEW_USERS));
        assert!(!authority.holds(MANAGE_ROLES));
        assert_eq!(
            custom,
            vec!["project:admin", "project:read", "project:write"]
        );
        assert_eq!(*authority.tenant(), acme());
    }

    /// Ann holds the "team" role and Bob none. An app reading their roles
    /// claim sees "team" for Ann and nothing for Bob.
    #[test]
    fn the_role_names_held_come_from_the_records() {
        let ann = active("ann@acme.test");
        let bob = active("bob@acme.test");
        let team = role(&[VIEW_USERS], &[]);
        let records = Records {
            assignments: vec![given(&ann, &team)],
            roles: vec![team],
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };

        let anns = records.access().role_names_held(ann.id()).unwrap();
        let bobs = records.access().role_names_held(bob.id()).unwrap();

        assert_eq!(anns, vec![label("team")]);
        assert!(bobs.is_empty());
    }

    /// The consumer "billing-sync" holds the "team" role. The gateway reads
    /// it once, by id and name; a consumer the records do not name holds
    /// none.
    #[test]
    fn the_roles_held_by_any_principal_come_from_the_records() {
        let billing = PrincipalRef::Consumer(crate::types::ConsumerId::new());
        let team = role(&[VIEW_USERS], &[]);
        let team_id = *team.id();
        let given = RoleAssignment::create(billing, &team, anyone_holding(SystemPermission::all()))
            .unwrap();
        let records = Records {
            assignments: vec![given],
            roles: vec![team],
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };
        let access = records.access();

        let held = access.roles_held_by(billing).unwrap();
        let stranger = access
            .roles_held_by(PrincipalRef::Consumer(crate::types::ConsumerId::new()))
            .unwrap();

        let named: Vec<(RoleId, Label)> = held
            .iter()
            .map(|role| (*role.id(), role.name().clone()))
            .collect();
        assert_eq!(named, vec![(team_id, label("team"))]);
        assert!(stranger.is_empty());
    }

    /// Ann holds `project:admin` and an hour of break-glass "manage roles".
    /// The gateway reads both for her, with the ladder's `project:read`,
    /// until the hour is over. An agent the records do not name holds
    /// nothing.
    #[test]
    fn the_permissions_held_count_roles_ladders_and_live_emergency_access() {
        let ann = active("ann@acme.test");
        let admin = role(&[], &["project:admin"]);
        let records = Records {
            assignments: vec![given(&ann, &admin)],
            roles: vec![admin],
            catalogue: vec![project_ladder()],
            break_glass: vec![emergency(acme(), &ann, &[MANAGE_ROLES])],
        };
        let access = records.access();
        let now = crate::shared::clock::now();
        let reading = CustomPermission::parse("project:read").unwrap();

        let during = access
            .permissions_held_by(PrincipalRef::User(*ann.id()), now)
            .unwrap();
        let after = access
            .permissions_held_by(PrincipalRef::User(*ann.id()), now + Duration::hours(2))
            .unwrap();
        let stranger = access
            .permissions_held_by(PrincipalRef::Agent(crate::types::AgentId::new()), now)
            .unwrap();

        assert!(during.holds(MANAGE_ROLES) && during.holds_custom(&reading));
        assert!(!after.holds(MANAGE_ROLES) && after.holds_custom(&reading));
        assert_eq!(stranger, Holdings::default());
    }

    /// Mallory's sign-in cannot obtain Ann's tenant authority.
    #[test]
    fn nobody_acts_with_another_accounts_rights() {
        let ann = active("ann@acme.test");
        let mallory = active("mallory@acme.test");
        let records = Records {
            roles: Vec::new(),
            assignments: Vec::new(),
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };

        let borrowed = records.access().authority_of(
            &ann,
            &signed_in_as(*mallory.id()),
            crate::shared::clock::now(),
        );

        assert!(matches!(borrowed, Err(DomainError::Forbidden(_))));
    }

    /// Bob cannot obtain tenant authority after his account is locked, even with
    /// proof of his own sign-in.
    #[test]
    fn a_shut_account_acts_with_nothing() {
        let mut bob = active("bob@acme.test");
        bob.lock(&crate::domains::identity::account::user::tests::control_over(&bob))
            .unwrap();
        let records = Records {
            roles: Vec::new(),
            assignments: Vec::new(),
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };

        let acting = records.access().authority_of(
            &bob,
            &signed_in_as(*bob.id()),
            crate::shared::clock::now(),
        );

        assert!(matches!(acting, Err(DomainError::Forbidden(_))));
    }

    /// Ann gets "manage roles" for an hour of an incident. She may use it,
    /// but may not hand it on, so she cannot keep it after the grant ends.
    /// A grant in another tenant gives her nothing here.
    #[test]
    fn break_glass_is_for_using_not_for_handing_on() {
        let ann = active("ann@acme.test");
        let records = Records {
            roles: Vec::new(),
            assignments: Vec::new(),
            catalogue: Vec::new(),
            break_glass: vec![
                emergency(acme(), &ann, &[MANAGE_ROLES]),
                emergency(TenantId::new(), &ann, &[VIEW_USERS]),
            ],
        };

        let authority = records
            .access()
            .authority_of(&ann, &signed_in_as(*ann.id()), crate::shared::clock::now())
            .unwrap();

        assert!(authority.holds(MANAGE_ROLES));
        assert!(!authority.standing().holds(MANAGE_ROLES));
        assert!(!authority.holds(VIEW_USERS));
    }

    /// Ann's emergency role-management access prevents Sam from changing her
    /// sign-in when his standing rights allow only user updates.
    #[test]
    fn acting_on_an_account_counts_its_emergency_access() {
        let ann = active("ann@acme.test");
        let sam = active("sam@acme.test");
        let updater = role(&[SystemPermission::Users(UserAction::Update)], &[]);
        let records = Records {
            assignments: vec![given(&sam, &updater)],
            roles: vec![updater],
            catalogue: Vec::new(),
            break_glass: vec![emergency(acme(), &ann, &[MANAGE_ROLES])],
        };
        let access = records.access();
        let now = crate::shared::clock::now();
        let by_sam = access
            .authority_of(&sam, &signed_in_as(*sam.id()), now)
            .unwrap();

        let counted = access.grants.administrator_count().unwrap();

        let control = access
            .account_control(&by_sam, ann.id(), counted, now)
            .unwrap();

        assert!(matches!(
            control.ensure_allowed(ann.id(), AccountAction::ChangeSignIn),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Records identifying Ann as the sole tenant administrator prevent even a
    /// fully authorized organization member from shutting her out.
    #[test]
    fn the_last_administrator_is_found_in_the_records() {
        let ann = active("ann@acme.test");
        let admin = role(SystemPermission::all(), &[]);
        let records = Records {
            assignments: vec![given(&ann, &admin)],
            roles: vec![admin],
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };
        let owen = TenantAuthority::assumed(
            Human::new(
                HumanAccount::OrgUser(OrgUserId::new()),
                PersonKey::new("owen@acme.test").unwrap(),
            ),
            acme(),
            SystemPermission::all(),
            &[],
        );
        let access = records.access();
        let counted = access.grants.administrator_count().unwrap();

        let locking = access
            .account_control(&owen, ann.id(), counted, crate::shared::clock::now())
            .unwrap()
            .ensure_allowed(ann.id(), AccountAction::ShutOut);

        assert!(matches!(locking, Err(DomainError::Conflict(_))));
    }

    /// Owen locks Ann out, reading only Ann's own records, which show her
    /// as an administrator. The tenant counts two administrators, so
    /// someone else still runs it, and the lock goes through.
    #[test]
    fn an_administrator_read_alone_is_not_the_last_while_others_are_counted() {
        let ann = active("ann@acme.test");
        let admin = role(SystemPermission::all(), &[]);
        let ann_alone = Records {
            assignments: vec![given(&ann, &admin)],
            roles: vec![admin],
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };
        let owen = TenantAuthority::assumed(
            Human::new(
                HumanAccount::OrgUser(OrgUserId::new()),
                PersonKey::new("owen@acme.test").unwrap(),
            ),
            acme(),
            SystemPermission::all(),
            &[],
        );
        let access = ann_alone.access();

        let locking = access
            .account_control(
                &owen,
                ann.id(),
                AdministratorCount::new(2),
                crate::shared::clock::now(),
            )
            .unwrap()
            .ensure_allowed(ann.id(), AccountAction::ShutOut);

        assert!(locking.is_ok());
    }

    /// Authority from another tenant cannot produce account control using Acme's records.
    #[test]
    fn an_authority_works_only_in_its_own_tenant() {
        let ann = active("ann@acme.test");
        let records = Records {
            roles: Vec::new(),
            assignments: Vec::new(),
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };
        let elsewhere = TenantAuthority::assumed(
            Human::new(HumanAccount::User(*ann.id()), PersonKey::of(ann.email())),
            TenantId::new(),
            SystemPermission::all(),
            &[],
        );

        let control = records.access().account_control(
            &elsewhere,
            ann.id(),
            AdministratorCount::new(0),
            crate::shared::clock::now(),
        );

        assert!(matches!(control, Err(DomainError::Forbidden(_))));
    }

    /// Ann may activate policies. While Bob may too, she has a second
    /// approver. When she is the only one, she approves her own.
    #[test]
    fn whether_someone_else_could_approve_comes_from_the_records() {
        let users = [active("ann@acme.test"), active("bob@acme.test")];
        let [ann, bob] = &users;
        let approvers = role(&[ACTIVATES_POLICIES], &[]);
        let alone = Records {
            assignments: vec![given(ann, &approvers)],
            roles: vec![approvers.clone()],
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };
        let together = Records {
            assignments: vec![given(ann, &approvers), given(bob, &approvers)],
            roles: vec![approvers],
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };
        let (ann_alone, ann_together) = (signed_in(ann, &alone), signed_in(ann, &together));

        let sole = alone
            .access()
            .policy_approver(&ann_alone, &pool(&users, &[]))
            .unwrap();
        let second = together
            .access()
            .policy_approver(&ann_together, &pool(&users, &[]))
            .unwrap();

        assert_eq!(sole.others(), OtherApprovers::NoneInTenant);
        assert_eq!(second.others(), OtherApprovers::Exist);
    }

    fn pool<'a>(
        users: &'a [User<ResolvedTenant>],
        members: &'a [OutsideHolder],
    ) -> ApproverPool<'a, ResolvedTenant> {
        ApproverPool { users, members }
    }

    /// What `account` holds in `records`, signed in now.
    fn signed_in(account: &User<ResolvedTenant>, records: &Records) -> TenantAuthority {
        records
            .access()
            .authority_of(
                account,
                &signed_in_as(*account.id()),
                crate::shared::clock::now(),
            )
            .unwrap()
    }

    /// Records where each of `approving` may activate policies.
    fn approvers_among(approving: &[&User<ResolvedTenant>]) -> Records {
        let approvers = role(&[ACTIVATES_POLICIES], &[]);
        Records {
            assignments: approving
                .iter()
                .map(|account| given(account, &approvers))
                .collect(),
            roles: vec![approvers],
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        }
    }

    /// An organization member at `address`, holding everything in Acme.
    fn owner_at(address: &str) -> OutsideHolder {
        OutsideHolder::assumed(
            Human::new(
                HumanAccount::OrgUser(OrgUserId::new()),
                PersonKey::new(address).unwrap(),
            ),
            SystemPermission::all(),
        )
    }

    /// An organization member with policy-activation rights counts as another
    /// approver even when Ann is the only tenant user with those rights.
    #[test]
    fn an_organization_member_counts_as_another_approver() {
        let users = [active("ann@acme.test")];
        let records = approvers_among(&[&users[0]]);
        let by_ann = signed_in(&users[0], &records);
        let members = [owner_at("owen@acme.test")];

        let approver = records
            .access()
            .policy_approver(&by_ann, &pool(&users, &members))
            .unwrap();

        assert_eq!(approver.others(), OtherApprovers::Exist);
    }

    /// Ann also has an organization account at the same address, which may
    /// activate policies. It is her, not a second person, so she remains
    /// the only approver and approves her own.
    #[test]
    fn the_approvers_own_organization_account_is_not_another_approver() {
        let users = [active("ann@acme.test")];
        let records = approvers_among(&[&users[0]]);
        let by_ann = signed_in(&users[0], &records);
        let members = [owner_at("Ann@acme.test")];

        let approver = records
            .access()
            .policy_approver(&by_ann, &pool(&users, &members))
            .unwrap();

        assert_eq!(approver.others(), OtherApprovers::NoneInTenant);
    }

    /// Bob may activate policies too, but his account was locked. He cannot
    /// approve anything, so Ann, the only other approver, approves her own.
    #[test]
    fn a_locked_account_is_not_another_approver() {
        let mut bob = active("bob@acme.test");
        bob.lock(&crate::domains::identity::account::user::tests::control_over(&bob))
            .unwrap();
        let users = [active("ann@acme.test"), bob];
        let records = approvers_among(&[&users[0], &users[1]]);
        let by_ann = signed_in(&users[0], &records);

        let approver = records
            .access()
            .policy_approver(&by_ann, &pool(&users, &[]))
            .unwrap();

        assert_eq!(approver.others(), OtherApprovers::NoneInTenant);
    }

    /// An approver pool missing Bob's account fails with an infrastructure error
    /// when the tenant's assignments name him.
    #[test]
    fn a_user_left_out_of_the_pool_is_refused() {
        let users = [active("ann@acme.test"), active("bob@acme.test")];
        let records = approvers_among(&[&users[0], &users[1]]);
        let by_ann = signed_in(&users[0], &records);

        let approver = records
            .access()
            .policy_approver(&by_ann, &pool(&users[..1], &[]));

        assert!(matches!(approver, Err(DomainError::Infrastructure(_))));
    }

    /// What someone with `system` from their roles is cleared for.
    fn cleared_with(system: &[SystemPermission]) -> DataClassLevel {
        let sam = active("sam@acme.test");
        let team = role(system, &[]);
        let records = Records {
            assignments: vec![given(&sam, &team)],
            roles: vec![team],
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        };
        records
            .access()
            .authority_of(&sam, &signed_in_as(*sam.id()), crate::shared::clock::now())
            .unwrap()
            .data_clearance()
    }

    /// Sam's roles give no data access. He is cleared for the tenant's
    /// internal data, and nothing more sensitive.
    #[test]
    fn everyone_in_a_tenant_is_cleared_for_internal_data() {
        assert_eq!(cleared_with(&[VIEW_USERS]), DataClassLevel::Internal);
    }

    /// A role that gives confidential data clears Sam for it. One that gives
    /// restricted data clears him for restricted, which covers confidential.
    #[test]
    fn clearance_comes_from_the_data_access_a_role_gives() {
        let confidential = SystemPermission::Data(DataAccessAction::Confidential);
        let restricted = SystemPermission::Data(DataAccessAction::Restricted);

        assert_eq!(cleared_with(&[confidential]), DataClassLevel::Confidential);
        assert_eq!(cleared_with(&[restricted]), DataClassLevel::Restricted);
        assert!(restricted.implies(&confidential));
        assert!(!confidential.implies(&restricted));
    }
}
