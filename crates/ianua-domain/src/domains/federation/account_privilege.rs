//! Whether an account holds built-in permissions that give power, which
//! limits what an identity provider's or a directory's word may do for it.
//!
//! A federation admin can connect a provider they run themselves. So a
//! provider never speaks for an account that holds such permissions. It
//! does not link such an account on its own, and its report of a second
//! factor does not count for one. The metrics overview every member holds
//! gives no power, so on its own it leaves an account ordinary.
//!
//! What an account holds is read from the tenant's records, through
//! [`TenantAccess::privilege_of`]. A use case never says it, so Fay cannot
//! call the CEO's account ordinary and sign in as her through a provider she
//! runs.

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAccess;
use crate::domains::authorization::granter::Handout;
use crate::domains::authorization::permission::SystemPermission;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::UserId;

/// Whether an account holds any built-in permission that gives power.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountPrivilege {
    /// The account holds no built-in permission that gives power. It may
    /// hold the metrics overview and app-defined permissions.
    Ordinary,
    /// The account holds at least one built-in permission that gives power,
    /// such as managing users.
    Privileged,
}

impl AccountPrivilege {
    /// The privilege of an account that holds `held`, through every role,
    /// group and break-glass grant it has: privileged once one of its
    /// built-in permissions gives power, ordinary on the metrics overview
    /// alone.
    pub(crate) fn of(held: &Handout<'_>) -> Self {
        if held.system.iter().any(SystemPermission::gives_power) {
            return Self::Privileged;
        }
        Self::Ordinary
    }
}

/// What an account's holdings mean for a provider's word. It is federation's
/// rule, so it sits here, beside the privilege it works out.
impl<T: TenantScope> TenantAccess<'_, T> {
    /// Checks built-in power from account roles, groups and active break-glass at `now`.
    /// Emergency privileges also prevent a provider from speaking for the account.
    ///
    /// # Errors
    /// Propagates missing-role/group errors from
    /// [`TenantGrants::administrators`](crate::domains::authorization::stewardship::TenantGrants::administrators).
    pub fn privilege_of(
        &self,
        account: &UserId,
        now: OffsetDateTime,
    ) -> Result<AccountPrivilege, DomainError> {
        let held = self.everything_held_by(account, now)?;
        Ok(AccountPrivilege::of(&held.handout()))
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::break_glass::{
        BreakGlassAccess, BreakGlassGrant, BreakGlassGrantRow, GrantApproval,
    };
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::{
        CustomPermission, SystemPermission, UserAction,
    };
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role, RoleAssignment};
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::label;
    use crate::types::{BreakGlassGrantId, PersonKey, PrincipalRef, RoleId, TenantId, Text};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);

    /// Acme's records: `roles`, each given to the account beside it, and
    /// `break_glass`.
    struct Records {
        roles: Vec<Role<ResolvedTenant>>,
        assignments: Vec<RoleAssignment<ResolvedTenant>>,
        break_glass: Vec<BreakGlassGrant>,
    }

    impl Records {
        fn holding(account: UserId, system: &[SystemPermission], custom: &[&str]) -> Self {
            let role = Role::provisioned(NewRole {
                id: RoleId::new(),
                name: label("team"),
                system_permissions: system.to_vec(),
                custom_permissions: custom
                    .iter()
                    .map(|text| CustomPermission::parse(text).unwrap())
                    .collect(),
                assignment: DefaultAssignment::Manual,
            });
            let given = RoleAssignment::create(
                PrincipalRef::User(account),
                &role,
                anyone_holding(SystemPermission::all()),
            )
            .unwrap();
            Self {
                roles: vec![role],
                assignments: vec![given],
                break_glass: Vec::new(),
            }
        }

        fn access(&self) -> TenantAccess<'_, ResolvedTenant> {
            TenantAccess {
                tenant: acme(),
                grants: TenantGrants {
                    roles: &self.roles,
                    assignments: &self.assignments,
                    groups: &[] as &[Group<ResolvedTenant>],
                    memberships: &[] as &[GroupMembership<ResolvedTenant>],
                },
                catalogue: &[],
                break_glass: &self.break_glass,
            }
        }
    }

    fn acme() -> TenantId {
        TenantId::from_uuid(uuid::Uuid::from_u128(1))
    }

    /// An active break-glass grant in Acme for `account`, giving `system`.
    fn emergency(account: UserId, system: &[SystemPermission]) -> BreakGlassGrant {
        let now = crate::shared::clock::now();
        BreakGlassGrant::reconstitute(BreakGlassGrantRow {
            id: BreakGlassGrantId::new(),
            tenant_id: acme(),
            user_id: account,
            grantee_person: PersonKey::new("ann@acme.test").unwrap(),
            access: BreakGlassAccess::new(system.to_vec(), Vec::new()).unwrap(),
            reason: Text::new("reason", "Production incident INC-1234").unwrap(),
            approved_by: GrantApproval::SelfApproved,
            expires_at: now + Duration::hours(1),
            revocation: crate::types::Revocation::InForce,
            created_at: now,
        })
        .unwrap()
    }

    /// Ann may view users. Her account counts as privileged, so no provider
    /// speaks for it.
    #[test]
    fn an_account_with_a_built_in_permission_is_privileged() {
        let ann = UserId::new();
        let records = Records::holding(ann, &[VIEW_USERS], &[]);

        let privilege = records
            .access()
            .privilege_of(&ann, crate::shared::clock::now());

        assert_eq!(privilege.unwrap(), AccountPrivilege::Privileged);
    }

    /// Bob holds only the app permission "invoices:view". His account is
    /// ordinary.
    #[test]
    fn an_account_with_only_app_permissions_is_ordinary() {
        let bob = UserId::new();
        let records = Records::holding(bob, &[], &["invoices:view"]);

        let privilege = records
            .access()
            .privilege_of(&bob, crate::shared::clock::now());

        assert_eq!(privilege.unwrap(), AccountPrivilege::Ordinary);
    }

    /// Pat holds the Member role every new user gets, with its view of the
    /// metrics overview and nothing else built in. Her account is ordinary,
    /// so her company's directory may move her and its provider may link
    /// her.
    #[test]
    fn a_member_with_only_the_metrics_overview_is_ordinary() {
        let pat = UserId::new();
        let records = Records::holding(pat, &[SystemPermission::ViewMetrics], &[]);

        let privilege = records
            .access()
            .privilege_of(&pat, crate::shared::clock::now());

        assert_eq!(privilege.unwrap(), AccountPrivilege::Ordinary);
    }

    /// Ann has no assigned role but holds an active emergency grant to
    /// view users, so her account is classified as privileged.
    #[test]
    fn an_active_break_glass_grant_makes_an_account_privileged() {
        let ann = UserId::new();
        let mut records = Records::holding(UserId::new(), &[], &[]);
        records.break_glass.push(emergency(ann, &[VIEW_USERS]));

        let privilege = records
            .access()
            .privilege_of(&ann, crate::shared::clock::now());

        assert_eq!(privilege.unwrap(), AccountPrivilege::Privileged);
    }

    /// Bob's assignment names a missing role, so evaluating his privilege
    /// fails with an infrastructure error.
    #[test]
    fn records_naming_a_missing_role_say_nothing_about_privilege() {
        let bob = UserId::new();
        let mut records = Records::holding(bob, &[VIEW_USERS], &[]);
        records.roles.clear();

        let privilege = records
            .access()
            .privilege_of(&bob, crate::shared::clock::now());

        assert!(matches!(privilege, Err(DomainError::Infrastructure(_))));
    }
}
