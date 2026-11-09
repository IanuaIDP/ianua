//! Get group: one group of the tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::group::Group;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::GroupId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::GroupStore;
use crate::use_case::Query;
use crate::use_cases::authorization::lookup::existing_group;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads groups.
    pub group_store: Arc<dyn GroupStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one group of the caller's tenant.
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
    type Input = GroupId;
    type Output = Result<Group<ResolvedTenant>, AppError>;

    /// The group `id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles, which
    ///   covers groups.
    /// - `AppError::NotFound` when the tenant has no such group.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: GroupId,
    ) -> Result<Group<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        existing_group(self.ports.group_store.as_ref(), &ctx.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeGroupStore, stored_group};
    use crate::test_support::{block_on, test_ctx};

    fn engineering() -> (Arc<FakeGroupStore>, GroupId) {
        let group = stored_group("Engineering", GroupPlace::TopLevel, Vec::new());
        let id = *group.id();
        let store = FakeGroupStore::holding(test_ctx().tenant_id(), [group]);
        (Arc::new(store), id)
    }

    fn get(ports: GetPorts, id: GroupId) -> Result<Group<ResolvedTenant>, AppError> {
        block_on(GetUseCase::new(ports).execute(&test_ctx(), id))
    }

    /// Ann reads "Engineering" by its id.
    #[test]
    fn a_group_is_read_by_its_id() {
        let (group_store, id) = engineering();

        let group = get(
            GetPorts {
                group_store,
                ..GetPorts::fakes()
            },
            id,
        )
        .unwrap();

        assert_eq!(group.name().as_str(), "Engineering");
    }

    /// Ann asks for a group the tenant does not have. It is not found.
    #[test]
    fn an_unknown_group_is_not_found() {
        let result = get(GetPorts::fakes(), GroupId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading Engineering is forbidden without role view permission.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let (group_store, id) = engineering();

        let result = get(
            GetPorts {
                group_store,
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
                ..GetPorts::fakes()
            },
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read a group.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (group_store, id) = engineering();

        let result = get(
            GetPorts {
                group_store,
                tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
                ..GetPorts::fakes()
            },
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
