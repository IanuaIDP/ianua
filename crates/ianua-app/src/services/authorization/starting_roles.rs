//! The roles a new tenant user starts with.
//!
//! A tenant marks roles as given to every new user. Which roles a new user
//! holds is a rule about users, not about the way they arrived, so every
//! path that creates one grants them here: an administrator, self sign-up,
//! SCIM, a first sign-in through an external identity provider. An
//! invitation is the exception: the person gets the one role it names.
//!
//! A path may add roles of its own, already checked by the domain: those an
//! administrator named, checked when they were handed out, or the default role a
//! directory or a sign-in connection gives, from its `default_assignment`.

use std::collections::HashSet;

use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{PrincipalRef, RoleId, UserId};

use crate::error::AppError;
use crate::ports::authorization::{RoleAssignmentStore, RoleStore};
use crate::tenancy::ScopedTenant;

/// Where roles and role assignments are kept.
pub(crate) struct RoleStores<'a> {
    /// Reads the default roles.
    pub(crate) role_store: &'a dyn RoleStore,
    /// Records the grants.
    pub(crate) assignment_store: &'a dyn RoleAssignmentStore,
}

/// Gives `user_id` the tenant's default roles, then `extra`.
///
/// Defaults are the floor, not a substitute, and the two can overlap: asking
/// for a default role is agreement with it, so each role is given once, as
/// the default, rather than failing on a role the user already holds.
///
/// # Errors
///
/// - `AppError::Internal` when an extra assignment gives a role to someone
///   other than `user_id`, or a role the store reads as a default is not one.
/// - `AppError::Internal` when the defaults cannot be read or a grant cannot
///   be saved.
pub(crate) async fn grant(
    stores: RoleStores<'_>,
    tenant: &ScopedTenant,
    user_id: UserId,
    extra: Vec<RoleAssignment<ResolvedTenant>>,
) -> Result<(), AppError> {
    let defaults = defaults(stores.role_store, tenant).await?;
    let starting = Starting {
        user_id,
        defaults: &defaults,
        extra,
    };
    grant_from(stores.assignment_store, tenant, starting).await
}

/// The roles the tenant gives every new user, read once for however many
/// accounts are about to start with them.
///
/// # Errors
///
/// - `AppError::Internal` when the roles cannot be read.
pub(crate) async fn defaults(
    role_store: &dyn RoleStore,
    tenant: &ScopedTenant,
) -> Result<Vec<Role<ResolvedTenant>>, AppError> {
    role_store
        .find_defaults(tenant)
        .await
        .map_err(AppError::internal)
}

/// A new user, the default roles read for them beforehand, and the roles a
/// path adds.
pub(crate) struct Starting<'a> {
    /// The new user.
    pub(crate) user_id: UserId,
    /// The tenant's default roles, from [`defaults`].
    pub(crate) defaults: &'a [Role<ResolvedTenant>],
    /// Roles the path adds, already checked by the domain.
    pub(crate) extra: Vec<RoleAssignment<ResolvedTenant>>,
}

/// Gives `starting`'s user the defaults read beforehand, then the extras,
/// each role once, as [`grant`] does.
///
/// # Errors
///
/// - `AppError::Internal` when an extra assignment gives a role to someone
///   else, a default is not one, or a grant cannot be saved.
pub(crate) async fn grant_from(
    assignment_store: &dyn RoleAssignmentStore,
    tenant: &ScopedTenant,
    starting: Starting<'_>,
) -> Result<(), AppError> {
    let Starting {
        user_id,
        defaults,
        extra,
    } = starting;
    ensure_all_for(user_id, &extra)?;
    for assignment in starting_assignments(user_id, defaults, extra)? {
        assignment_store
            .save(tenant, &assignment)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(())
}

/// Refuses an extra assignment that gives a role to another principal.
fn ensure_all_for(
    user_id: UserId,
    extra: &[RoleAssignment<ResolvedTenant>],
) -> Result<(), AppError> {
    let user = PrincipalRef::User(user_id);
    if extra
        .iter()
        .any(|assignment| *assignment.principal() != user)
    {
        return Err(AppError::internal_msg(
            "a starting role was made for another principal",
        ));
    }
    Ok(())
}

/// Each role `user_id` starts with, once: the defaults first, then the
/// extras not already among them.
fn starting_assignments(
    user_id: UserId,
    defaults: &[Role<ResolvedTenant>],
    extra: Vec<RoleAssignment<ResolvedTenant>>,
) -> Result<Vec<RoleAssignment<ResolvedTenant>>, AppError> {
    let mut seen: HashSet<RoleId> = HashSet::new();
    let by_default = defaults
        .iter()
        .map(|role| RoleAssignment::by_default(PrincipalRef::User(user_id), role))
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::internal)?;
    Ok(by_default
        .into_iter()
        .chain(extra)
        .filter(|assignment| seen.insert(*assignment.role_id()))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use ianua_domain::domains::authorization::authority::TenantAuthority;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{ActorRef, Human, HumanAccount, Label, PersonKey, TenantId};

    use super::*;
    use crate::listing::{Page, PageRequest, SortOrder};
    use crate::ports::TenantScoped;
    use crate::ports::authorization::RoleSortField;
    use crate::test_support::authorization::{FakeRoleAssignmentStore, FakeRoleStore};
    use crate::test_support::block_on;

    /// A role store whose defaults cannot be read.
    struct UnreadableRoles;

    impl TenantScoped for UnreadableRoles {}

    #[async_trait]
    impl RoleStore for UnreadableRoles {
        async fn find_by_principals(
            &self,
            _: &ScopedTenant,
            _: &[PrincipalRef],
        ) -> Result<HashMap<PrincipalRef, Vec<Role<ResolvedTenant>>>, DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn find_by_names(
            &self,
            _: &ScopedTenant,
            _: &[Label],
        ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn find_by_id(
            &self,
            _: &ScopedTenant,
            _: &RoleId,
        ) -> Result<Option<Role<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn find_by_ids(
            &self,
            _: &ScopedTenant,
            _: &[RoleId],
        ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn find_by_name(
            &self,
            _: &ScopedTenant,
            _: &Label,
        ) -> Result<Option<Role<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn list_all(
            &self,
            _: &ScopedTenant,
            _: &SortOrder<RoleSortField>,
            _: &PageRequest,
        ) -> Result<Page<Role<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn find_defaults(
            &self,
            _: &ScopedTenant,
        ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn save(
            &self,
            _: &ScopedTenant,
            _: &Role<ResolvedTenant>,
        ) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn delete(&self, _: &ScopedTenant, _: &RoleId) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn find_by_principal(
            &self,
            _: &ScopedTenant,
            _: &PrincipalRef,
        ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }

        async fn find_effective_by_principal(
            &self,
            _: &ScopedTenant,
            _: &PrincipalRef,
        ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("roles unreachable"))
        }
    }

    fn tenant() -> ScopedTenant {
        ScopedTenant::for_test(TenantId::new())
    }

    fn role(name: &str, assignment: DefaultAssignment) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", name).unwrap(),
            system_permissions: Vec::new(),
            custom_permissions: Vec::new(),
            assignment,
        })
    }

    fn ann(tenant: &ScopedTenant) -> TenantAuthority {
        let person = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("ann@example.test").unwrap(),
        );
        TenantAuthority::assumed(
            person,
            **tenant,
            &[SystemPermission::Users(UserAction::Update)],
            &[],
        )
    }

    fn given_by_ann(
        user_id: UserId,
        role: &Role<ResolvedTenant>,
        ann: &TenantAuthority,
    ) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::create(PrincipalRef::User(user_id), role, ann).unwrap()
    }

    fn start(
        roles: &dyn RoleStore,
        assignments: &FakeRoleAssignmentStore,
        tenant: &ScopedTenant,
        user_id: UserId,
        extra: Vec<RoleAssignment<ResolvedTenant>>,
    ) -> Result<(), AppError> {
        let stores = RoleStores {
            role_store: roles,
            assignment_store: assignments,
        };
        block_on(grant(stores, tenant, user_id, extra))
    }

    fn held_by(
        assignments: &FakeRoleAssignmentStore,
        tenant: &ScopedTenant,
        user_id: UserId,
    ) -> Vec<RoleAssignment<ResolvedTenant>> {
        block_on(assignments.find_by_principal(tenant, &PrincipalRef::User(user_id))).unwrap()
    }

    /// Acme gives every new user the member role. Bob signs up and holds
    /// it, given by the system, while the manual editor role stays away.
    #[test]
    fn a_new_user_starts_with_the_default_roles() {
        let tenant = tenant();
        let member = role("member", DefaultAssignment::NewUsers);
        let editor = role("editor", DefaultAssignment::Manual);
        let roles = FakeRoleStore::holding(*tenant, [member.clone(), editor]);
        let assignments = FakeRoleAssignmentStore::empty();
        let bob = UserId::new();

        start(&roles, &assignments, &tenant, bob, Vec::new()).unwrap();

        let held = held_by(&assignments, &tenant, bob);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].role_id(), member.id());
        assert!(matches!(held[0].assigned_by(), ActorRef::System));
    }

    /// Ann registers Bob with the editor role. He holds it beside the
    /// member role every new user gets.
    #[test]
    fn extra_roles_are_given_beside_the_defaults() {
        let tenant = tenant();
        let member = role("member", DefaultAssignment::NewUsers);
        let editor = role("editor", DefaultAssignment::Manual);
        let roles = FakeRoleStore::holding(*tenant, [member, editor.clone()]);
        let assignments = FakeRoleAssignmentStore::empty();
        let bob = UserId::new();
        let extra = vec![given_by_ann(bob, &editor, &ann(&tenant))];

        start(&roles, &assignments, &tenant, bob, extra).unwrap();

        assert_eq!(held_by(&assignments, &tenant, bob).len(), 2);
    }

    /// Ann registers Bob and names the member role, which he would get
    /// anyway. He holds it once, as the default.
    #[test]
    fn a_default_role_also_named_is_given_once() {
        let tenant = tenant();
        let member = role("member", DefaultAssignment::NewUsers);
        let roles = FakeRoleStore::holding(*tenant, [member.clone()]);
        let assignments = FakeRoleAssignmentStore::empty();
        let bob = UserId::new();
        let extra = vec![given_by_ann(bob, &member, &ann(&tenant))];

        start(&roles, &assignments, &tenant, bob, extra).unwrap();

        let held = held_by(&assignments, &tenant, bob);
        assert_eq!(held.len(), 1);
        assert!(matches!(held[0].assigned_by(), ActorRef::System));
    }

    /// A starting assignment for another person fails internally before any
    /// default or extra role is saved.
    #[test]
    fn an_extra_role_made_for_someone_else_is_refused() {
        let tenant = tenant();
        let member = role("member", DefaultAssignment::NewUsers);
        let editor = role("editor", DefaultAssignment::Manual);
        let roles = FakeRoleStore::holding(*tenant, [member, editor.clone()]);
        let assignments = FakeRoleAssignmentStore::empty();
        let bob = UserId::new();
        let extra = vec![given_by_ann(UserId::new(), &editor, &ann(&tenant))];

        let result = start(&roles, &assignments, &tenant, bob, extra);

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(assignments.count(), 0);
    }

    /// Failure to read default roles returns an internal error from the grant operation.
    #[test]
    fn unreadable_defaults_refuse() {
        let tenant = tenant();
        let assignments = FakeRoleAssignmentStore::empty();

        let result = start(
            &UnreadableRoles,
            &assignments,
            &tenant,
            UserId::new(),
            Vec::new(),
        );

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
