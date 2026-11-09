//! Roles a person hands out by naming them.
//!
//! Someone registering an account, or giving roles to an existing one, names
//! the roles by id. Each named role must exist in the tenant, and the person
//! must be able to give it: the right to change that principal's roles, and
//! every permission the role carries. That second part is the domain's call,
//! made when [`RoleAssignment::create`] takes the person's authority. This
//! module only finds the roles and asks it, so a use case gets the
//! assignments to save, or a refusal before anything is written.
//!
//! Other ways a role reaches people check themselves in the domain: a role
//! an invitation carries when the invitation is made, a provider's or a
//! directory's default role when it is named, a group's roles when a member
//! joins, and a role every new user gets when it is made a default.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{PrincipalRef, RoleId};

use crate::error::AppError;
use crate::ports::authorization::RoleStore;
use crate::tenancy::ScopedTenant;

/// Roles named for one principal, by one person.
pub(crate) struct NamedRoles<'a> {
    /// Who gets the roles.
    pub(crate) principal: PrincipalRef,
    /// The roles named, by id.
    pub(crate) roles: &'a [RoleId],
    /// What the person handing them out holds in the tenant.
    pub(crate) granter: &'a TenantAuthority,
}

/// The roles named, and the assignments that give `named.principal` each
/// of them.
pub(crate) struct Grants {
    /// The roles named, each once, so a caller can ask about what they carry.
    pub(crate) roles: Vec<Role<ResolvedTenant>>,
    /// The assignments to save.
    pub(crate) assignments: Vec<RoleAssignment<ResolvedTenant>>,
}

/// The named roles and the assignments that give `named.principal` each of
/// them, once the domain lets `named.granter` give them.
///
/// A role named twice is given once. Nothing is read when no role is named.
///
/// # Errors
///
/// - `AppError::Forbidden` if the granter's authority was worked out in
///   another tenant.
/// - `AppError::NotFound` if a named role does not exist in the tenant.
/// - `AppError::Forbidden` if the granter may not change the principal's
///   roles, or may not hand out everything a role carries.
/// - `AppError::Internal` if the roles cannot be read.
pub(crate) async fn grants(
    role_store: &dyn RoleStore,
    tenant: &ScopedTenant,
    named: NamedRoles<'_>,
) -> Result<Grants, AppError> {
    if named.roles.is_empty() {
        return Ok(Grants {
            roles: Vec::new(),
            assignments: Vec::new(),
        });
    }
    named
        .granter
        .ensure_within(tenant)
        .map_err(AppError::from_domain)?;
    let roles = role_store
        .find_by_ids(tenant, named.roles)
        .await
        .map_err(AppError::internal)?;
    ensure_all_found(named.roles, &roles)?;
    let assignments = roles
        .iter()
        .map(|role| RoleAssignment::create(named.principal, role, named.granter))
        .collect::<Result<_, _>>()
        .map_err(AppError::from_domain)?;
    Ok(Grants { roles, assignments })
}

/// Refuses when a role in `named` is missing from `found`.
fn ensure_all_found(named: &[RoleId], found: &[Role<ResolvedTenant>]) -> Result<(), AppError> {
    let missing = named
        .iter()
        .any(|id| found.iter().all(|role| role.id() != id));
    if missing {
        return Err(AppError::NotFound(message!(
            "app-role-not-found",
            "role not found"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        AgentAction, CustomPermission, RoleAction, SystemPermission, UserAction,
    };
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole};
    use ianua_domain::types::{
        ActorRef, AgentId, Human, HumanAccount, Label, PersonKey, TenantId, UserId,
    };

    use super::*;
    use crate::test_support::authorization::FakeRoleStore;
    use crate::test_support::block_on;

    const UPDATE_USERS: SystemPermission = SystemPermission::Users(UserAction::Update);

    fn tenant() -> ScopedTenant {
        ScopedTenant::for_test(TenantId::new())
    }

    fn ann() -> UserId {
        UserId::new()
    }

    fn holding(
        who: UserId,
        tenant: &ScopedTenant,
        system: &[SystemPermission],
        custom: &[CustomPermission],
    ) -> TenantAuthority {
        let person = Human::new(
            HumanAccount::User(who),
            PersonKey::new("ann@example.test").unwrap(),
        );
        TenantAuthority::assumed(person, **tenant, system, custom)
    }

    fn role(name: &str, system: &[SystemPermission], custom: &[&str]) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", name).unwrap(),
            system_permissions: system.to_vec(),
            custom_permissions: custom
                .iter()
                .map(|text| CustomPermission::parse(text).unwrap())
                .collect(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn give(
        store: &FakeRoleStore,
        tenant: &ScopedTenant,
        principal: PrincipalRef,
        roles: &[RoleId],
        granter: &TenantAuthority,
    ) -> Result<Vec<RoleAssignment<ResolvedTenant>>, AppError> {
        block_on(grants(
            store,
            tenant,
            NamedRoles {
                principal,
                roles,
                granter,
            },
        ))
        .map(|grants| grants.assignments)
    }

    /// Ann may update users and holds `orders:refund`. She registers Bob
    /// with the refunds role, and he gets it, recorded as given by her.
    #[test]
    fn a_role_the_granter_could_give_becomes_an_assignment() {
        let tenant = tenant();
        let refunds = role("refunds", &[], &["orders:refund"]);
        let store = FakeRoleStore::holding(*tenant, [refunds.clone()]);
        let ann_id = ann();
        let refund = CustomPermission::parse("orders:refund").unwrap();
        let ann = holding(ann_id, &tenant, &[UPDATE_USERS], &[refund]);
        let bob = PrincipalRef::User(UserId::new());

        let given = give(&store, &tenant, bob, &[*refunds.id()], &ann).unwrap();

        assert_eq!(given.len(), 1);
        assert_eq!(given[0].principal(), &bob);
        assert_eq!(given[0].role_id(), refunds.id());
        assert!(matches!(given[0].assigned_by(), ActorRef::User(id) if *id == ann_id));
    }

    /// Ann may escalate, so she gives Bob the billing role though she does
    /// not hold `billing:admin` herself.
    #[test]
    fn escalate_lets_the_granter_give_app_permissions_beyond_her_own() {
        let tenant = tenant();
        let billing = role("billing", &[], &["billing:admin"]);
        let store = FakeRoleStore::holding(*tenant, [billing.clone()]);
        let rights = [UPDATE_USERS, SystemPermission::Roles(RoleAction::Escalate)];
        let ann = holding(ann(), &tenant, &rights, &[]);

        let given = give(
            &store,
            &tenant,
            PrincipalRef::User(UserId::new()),
            &[*billing.id()],
            &ann,
        );

        assert!(given.is_ok());
    }

    /// Ann names the viewer role twice for Bob. He is given it once.
    #[test]
    fn a_role_named_twice_is_given_once() {
        let tenant = tenant();
        let viewer = role("viewer", &[], &[]);
        let store = FakeRoleStore::holding(*tenant, [viewer.clone()]);
        let ann = holding(ann(), &tenant, &[UPDATE_USERS], &[]);

        let given = give(
            &store,
            &tenant,
            PrincipalRef::User(UserId::new()),
            &[*viewer.id(), *viewer.id()],
            &ann,
        )
        .unwrap();

        assert_eq!(given.len(), 1);
    }

    /// Ann registers Bob without naming a role. Nothing is given, and Ann
    /// needs no right for it.
    #[test]
    fn naming_no_role_gives_nothing() {
        let tenant = tenant();
        let ann = holding(ann(), &tenant, &[], &[]);

        let given = give(
            &FakeRoleStore::empty(),
            &tenant,
            PrincipalRef::User(UserId::new()),
            &[],
            &ann,
        )
        .unwrap();

        assert!(given.is_empty());
    }

    /// A grant naming both an existing role and an unknown role returns not found.
    #[test]
    fn an_unknown_role_is_refused() {
        let tenant = tenant();
        let viewer = role("viewer", &[], &[]);
        let store = FakeRoleStore::holding(*tenant, [viewer.clone()]);
        let mallory = holding(ann(), &tenant, &[UPDATE_USERS], &[]);

        let given = give(
            &store,
            &tenant,
            PrincipalRef::User(UserId::new()),
            &[*viewer.id(), RoleId::new()],
            &mallory,
        );

        assert!(matches!(given, Err(AppError::NotFound(_))));
    }

    /// A caller without assignment rights cannot grant a user the viewer role.
    #[test]
    fn a_granter_without_the_assignment_right_is_refused() {
        let tenant = tenant();
        let viewer = role("viewer", &[], &[]);
        let store = FakeRoleStore::holding(*tenant, [viewer.clone()]);
        let mallory = holding(ann(), &tenant, &[], &[]);

        let given = give(
            &store,
            &tenant,
            PrincipalRef::User(UserId::new()),
            &[*viewer.id()],
            &mallory,
        );

        assert!(matches!(given, Err(AppError::Forbidden(_))));
    }

    /// User-update rights do not permit granting a role to an agent.
    #[test]
    fn the_right_follows_the_kind_of_principal() {
        let tenant = tenant();
        let viewer = role("viewer", &[], &[]);
        let store = FakeRoleStore::holding(*tenant, [viewer.clone()]);
        let mallory = holding(ann(), &tenant, &[UPDATE_USERS], &[]);

        let given = give(
            &store,
            &tenant,
            PrincipalRef::Agent(AgentId::new()),
            &[*viewer.id()],
            &mallory,
        );

        assert!(matches!(given, Err(AppError::Forbidden(_))));
    }

    /// Ann may update agents, and gives an agent the viewer role.
    #[test]
    fn an_agent_is_given_a_role_by_someone_who_may_update_agents() {
        let tenant = tenant();
        let viewer = role("viewer", &[], &[]);
        let store = FakeRoleStore::holding(*tenant, [viewer.clone()]);
        let rights = [SystemPermission::Agents(AgentAction::Update)];
        let ann = holding(ann(), &tenant, &rights, &[]);

        let given = give(
            &store,
            &tenant,
            PrincipalRef::Agent(AgentId::new()),
            &[*viewer.id()],
            &ann,
        );

        assert!(given.is_ok());
    }

    /// Escalation rights do not permit granting an admin role carrying
    /// built-in user-management rights that the granter lacks.
    #[test]
    fn escalate_never_covers_built_in_permissions() {
        let tenant = tenant();
        let admin = role("admin", &[SystemPermission::ManageUsers], &[]);
        let store = FakeRoleStore::holding(*tenant, [admin.clone()]);
        let rights = [UPDATE_USERS, SystemPermission::Roles(RoleAction::Escalate)];
        let mallory = holding(ann(), &tenant, &rights, &[]);

        let given = give(
            &store,
            &tenant,
            PrincipalRef::User(UserId::new()),
            &[*admin.id()],
            &mallory,
        );

        assert!(matches!(given, Err(AppError::Forbidden(_))));
    }

    /// A user updater cannot grant an admin role carrying broader built-in
    /// user-management rights.
    #[test]
    fn a_role_carrying_a_built_in_permission_the_granter_lacks_is_refused() {
        let tenant = tenant();
        let admin = role("admin", &[SystemPermission::ManageUsers], &[]);
        let store = FakeRoleStore::holding(*tenant, [admin.clone()]);
        let mallory = holding(ann(), &tenant, &[UPDATE_USERS], &[]);

        let given = give(
            &store,
            &tenant,
            PrincipalRef::User(UserId::new()),
            &[*admin.id()],
            &mallory,
        );

        assert!(matches!(given, Err(AppError::Forbidden(_))));
    }

    /// User-update and role-editing rights do not permit granting refunds
    /// without the app permission or escalation rights.
    #[test]
    fn a_role_carrying_an_app_permission_the_granter_lacks_is_refused() {
        let tenant = tenant();
        let refunds = role("refunds", &[], &["orders:refund"]);
        let store = FakeRoleStore::holding(*tenant, [refunds.clone()]);
        let rights = [
            UPDATE_USERS,
            SystemPermission::Roles(RoleAction::Create),
            SystemPermission::Roles(RoleAction::Update),
            SystemPermission::Roles(RoleAction::Assign),
        ];
        let mallory = holding(ann(), &tenant, &rights, &[]);

        let given = give(
            &store,
            &tenant,
            PrincipalRef::User(UserId::new()),
            &[*refunds.id()],
            &mallory,
        );

        assert!(matches!(given, Err(AppError::Forbidden(_))));
    }

    /// Authority held in Globex cannot authorize granting an Acme role.
    #[test]
    fn an_authority_from_another_tenant_is_refused() {
        let acme = tenant();
        let globex = tenant();
        let viewer = role("viewer", &[], &[]);
        let store = FakeRoleStore::holding(*acme, [viewer.clone()]);
        let mallory = holding(ann(), &globex, SystemPermission::all(), &[]);

        let given = give(
            &store,
            &acme,
            PrincipalRef::User(UserId::new()),
            &[*viewer.id()],
            &mallory,
        );

        assert!(matches!(given, Err(AppError::Forbidden(_))));
    }
}
