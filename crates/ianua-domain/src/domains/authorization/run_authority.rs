//! What a workflow run may do in a tenant: what the person it acts for
//! holds now, and only while it runs.
//!
//! Pat's workflow signs Lee out after a risky sign-in. The step calls the
//! same sign-out a person calls from the dashboard, as Pat. It holds what
//! Pat holds the moment it acts, not what Pat held when the run started. If
//! Pat has since lost the right to manage roles, or left, the step is
//! refused. A run that has ended acts for nobody.

use crate::domains::authorization::authority::{Holdings, TenantAccess, TenantAuthority};
use crate::domains::identity::account::user::User;
use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{Human, HumanAccount, PersonKey, PrincipalRef};

/// What a workflow run tells authorization: who it acts for, and whether it
/// still runs.
///
/// The workflows context's execution answers it. Authorization sits below
/// workflows, so it names only this.
pub trait RunCharter: Sealed {
    /// The person the run acts for.
    fn acting_for(&self) -> &Human;

    /// Whether the run still has steps to run.
    fn is_running(&self) -> bool;
}

/// What `run`, acting for the tenant user `person`, may do in `access`'s
/// tenant now: everything `person` holds there now, and nothing more.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the run has ended.
/// - [`DomainError::Forbidden`] when the run acts for someone else.
/// - [`DomainError::Forbidden`] when `person` may not sign in now.
/// - The cases
///   [`TenantGrants::administrators`](crate::domains::authorization::stewardship::TenantGrants::administrators)
///   lists, for records that name a role or group that is not there.
pub fn authority_of_run<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    run: &impl RunCharter,
    person: &User<T>,
) -> Result<TenantAuthority, DomainError> {
    ensure_running(run)?;
    if run.acting_for().account() != HumanAccount::User(*person.id()) {
        return Err(acts_for_someone_else());
    }
    if !person.can_authenticate() {
        return Err(DomainError::forbidden(message!(
            "authorization-the-run-s-person-may-not",
            "the person the run acts for may not act now"
        )));
    }
    let who = Human::new(
        HumanAccount::User(*person.id()),
        PersonKey::of(person.email()),
    );
    let held = access.standing_of(PrincipalRef::User(*person.id()))?;
    Ok(TenantAuthority::assemble(
        who,
        access.tenant,
        held,
        Holdings::default(),
    ))
}

/// Refuses a run that has ended: it acts for nobody.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the run has ended.
pub(crate) fn ensure_running(run: &impl RunCharter) -> Result<(), DomainError> {
    if run.is_running() {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "authorization-the-run-has-ended",
        "the run has ended and acts for nobody"
    )))
}

/// The refusal of a run that acts for another person than the one named.
pub(crate) fn acts_for_someone_else() -> DomainError {
    DomainError::forbidden(message!(
        "authorization-the-run-acts-for-someone-else",
        "the run acts for someone else"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
    use crate::domains::authorization::resource_type::ResourceType;
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role, RoleAssignment};
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::{label, user};
    use crate::types::{RoleId, TenantId, UserId};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const MANAGE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Manage);

    /// A run as a test writes it.
    struct Run {
        acting_for: Human,
        running: bool,
    }

    impl Sealed for Run {}

    impl RunCharter for Run {
        fn acting_for(&self) -> &Human {
            &self.acting_for
        }

        fn is_running(&self) -> bool {
            self.running
        }
    }

    fn run_for(person: &User<ResolvedTenant>, running: bool) -> Run {
        Run {
            acting_for: Human::new(
                HumanAccount::User(*person.id()),
                PersonKey::of(person.email()),
            ),
            running,
        }
    }

    fn active(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// What `run` may do as `person`, when `system` is all their roles give.
    fn through(
        person: &User<ResolvedTenant>,
        system: &[SystemPermission],
        run: &Run,
    ) -> Result<TenantAuthority, DomainError> {
        let team = Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("team"),
            system_permissions: system.to_vec(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        });
        let assignments = vec![
            RoleAssignment::create(
                PrincipalRef::User(*person.id()),
                &team,
                anyone_holding(SystemPermission::all()),
            )
            .unwrap(),
        ];
        let roles = vec![team];
        let access = TenantAccess {
            tenant: TenantId::new(),
            grants: TenantGrants {
                roles: &roles,
                assignments: &assignments,
                groups: &[] as &[Group<ResolvedTenant>],
                memberships: &[] as &[GroupMembership<ResolvedTenant>],
            },
            catalogue: &[] as &[ResourceType<ResolvedTenant>],
            break_glass: &[],
        };
        authority_of_run(&access, run, person)
    }

    /// Pat may view users and manage roles. Her running workflow holds
    /// exactly that, as Pat.
    #[test]
    fn a_run_holds_what_its_person_holds_now() {
        let pat = active("pat@acme.test");

        let authority = through(&pat, &[VIEW_USERS, MANAGE_ROLES], &run_for(&pat, true)).unwrap();

        assert!(authority.holds(VIEW_USERS));
        assert!(authority.holds(MANAGE_ROLES));
        assert_eq!(authority.who().account(), HumanAccount::User(*pat.id()));
    }

    /// A running workflow cannot manage roles when its publisher currently holds
    /// only permission to view users.
    #[test]
    fn a_run_never_holds_more_than_its_person_does_now() {
        let pat = active("pat@acme.test");

        let authority = through(&pat, &[VIEW_USERS], &run_for(&pat, true)).unwrap();

        assert!(!authority.holds(MANAGE_ROLES));
    }

    /// An ended workflow run cannot obtain tenant authority for its publisher.
    #[test]
    fn an_ended_run_holds_nothing() {
        let pat = active("pat@acme.test");

        let result = through(&pat, &[VIEW_USERS], &run_for(&pat, false));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann's workflow run cannot obtain authority for Mallory's account.
    #[test]
    fn a_run_acts_only_for_its_own_person() {
        let ann = active("ann@acme.test");
        let mallory = active("mallory@acme.test");

        let result = through(&mallory, &[VIEW_USERS], &run_for(&ann, true));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
