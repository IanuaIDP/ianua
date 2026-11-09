//! Get role: one role of the tenant, with how many hold it.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::RoleId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{RoleAssignmentStore, RoleStore};
use crate::services::lookup::existing_role;
use crate::use_case::Query;
use crate::use_cases::authorization::roles::WithAssignments;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads roles.
    pub role_store: Arc<dyn RoleStore>,
    /// Counts who the role is given to.
    pub role_assignment_store: Arc<dyn RoleAssignmentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one role of the caller's tenant.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = RoleId;
    type Output = Result<WithAssignments<ResolvedTenant>, AppError>;

    /// The role `id`, with how many principals hold it directly.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles.
    /// - `AppError::NotFound` when the tenant has no such role.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: RoleId,
    ) -> Result<WithAssignments<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        let role = existing_role(self.ports.role_store.as_ref(), &ctx.tenant(), &id).await?;
        let assigned_user_count = self
            .ports
            .role_assignment_store
            .count_by_role(&ctx.tenant(), role.id())
            .await
            .or_internal()?;
        Ok(WithAssignments {
            role,
            assigned_user_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use ianua_domain::domains::authorization::role_assignment::{
        RoleAssignment, RoleAssignmentRow,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ActorRef, Expiry, Label, PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeRoleAssignmentStore, FakeRoleStore};
    use crate::test_support::{block_on, test_ctx};

    fn admin_role() -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", "admin").unwrap(),
            system_permissions: Vec::new(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn given(role_id: RoleId) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(UserId::new()),
            role_id,
            assigned_by: ActorRef::System,
            assigned_at: clock::now(),
            expires: Expiry::Never,
        })
        .unwrap()
    }

    fn get(ports: GetPorts, id: RoleId) -> Result<WithAssignments<ResolvedTenant>, AppError> {
        block_on(GetUseCase::new(ports).execute(&test_ctx(), id))
    }

    fn holding(role: Role<ResolvedTenant>) -> Arc<FakeRoleStore> {
        Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), [role]))
    }

    /// Ann reads the "admin" role by its id.
    #[test]
    fn a_role_is_read_by_its_id() {
        let role = admin_role();
        let id = *role.id();

        let read = get(
            GetPorts {
                role_store: holding(role),
                ..GetPorts::fakes()
            },
            id,
        )
        .unwrap();

        assert_eq!(read.role.name().as_str(), "admin");
    }

    /// Two people hold "admin". Reading it says so.
    #[test]
    fn the_role_shows_how_many_hold_it() {
        let role = admin_role();
        let id = *role.id();
        let assignments =
            FakeRoleAssignmentStore::holding(test_ctx().tenant_id(), [given(id), given(id)]);

        let read = get(
            GetPorts {
                role_store: holding(role),
                role_assignment_store: Arc::new(assignments),
                ..GetPorts::fakes()
            },
            id,
        )
        .unwrap();

        assert_eq!(read.assigned_user_count, 2);
    }

    /// Ann asks for a role the tenant does not have. It is not found.
    #[test]
    fn an_unknown_role_is_not_found() {
        let result = get(GetPorts::fakes(), RoleId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The admin role exists, but a caller without role-view permission
    /// receives a forbidden result when requesting it.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let role = admin_role();
        let id = *role.id();

        let result = get(
            GetPorts {
                role_store: holding(role),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
                ..GetPorts::fakes()
            },
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading a role with signed-out authority returns unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = get(
            GetPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
                ..GetPorts::fakes()
            },
            RoleId::new(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
