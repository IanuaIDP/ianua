//! Checks app permissions against the tenant's declared catalogue.
//!
//! Every path that puts an app permission where it will later be enforced,
//! a role or a route's required permissions, checks it here. The check lives
//! in one place because the failure it prevents is silent: a route requiring
//! `projects:write` while the role grants `project:write` refuses every
//! caller and reports nothing.

use ianua_domain::domains::authorization::permission::CustomPermission;
use ianua_domain::domains::authorization::resource_type::undeclared;
use ianua_domain::shared::errors::DomainError;

use crate::error::AppError;
use crate::ports::authorization::ResourceTypeStore;
use crate::tenancy::ScopedTenant;

/// Refuses `permissions` unless the tenant's catalogue declares each one.
///
/// An empty set passes without reading the catalogue.
///
/// # Errors
///
/// - `AppError::Domain` with a validation message naming each undeclared
///   permission, so an operator who ticked twelve boxes is told which one is
///   wrong rather than that something is.
/// - `AppError::Internal` if the catalogue cannot be read.
pub(crate) async fn ensure_declared(
    store: &dyn ResourceTypeStore,
    tenant: &ScopedTenant,
    permissions: &[CustomPermission],
) -> Result<(), AppError> {
    if permissions.is_empty() {
        return Ok(());
    }
    let catalogue = store.list_every(tenant).await.map_err(AppError::internal)?;
    let missing = undeclared(&catalogue, permissions);
    if missing.is_empty() {
        return Ok(());
    }
    Err(AppError::Domain(DomainError::invalid(undeclared_message(
        &missing,
    ))))
}

/// What a caller is told about the permissions the catalogue lacks.
fn undeclared_message(missing: &[CustomPermission]) -> String {
    let names: Vec<String> = missing.iter().map(ToString::to_string).collect();
    format!(
        "not declared in this tenant's permission catalogue: {}. Declare the resource type \
         first, or correct the spelling.",
        names.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::authorization::permission::PermissionSegment;
    use ianua_domain::domains::authorization::resource_type::ResourceType;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{ResourceTypeId, TenantId};

    use super::*;
    use crate::listing::{Page, PageRequest, SortOrder};
    use crate::ports::TenantScoped;
    use crate::ports::authorization::ResourceTypeSortField;
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::block_on;

    /// A catalogue that cannot be read.
    struct UnreadableCatalogue;

    impl TenantScoped for UnreadableCatalogue {}

    #[async_trait]
    impl ResourceTypeStore for UnreadableCatalogue {
        async fn find_by_id(
            &self,
            _: &ScopedTenant,
            _: &ResourceTypeId,
        ) -> Result<Option<ResourceType<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("catalogue unreachable"))
        }

        async fn find_by_key(
            &self,
            _: &ScopedTenant,
            _: &PermissionSegment,
        ) -> Result<Option<ResourceType<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("catalogue unreachable"))
        }

        async fn list_all(
            &self,
            _: &ScopedTenant,
            _: &SortOrder<ResourceTypeSortField>,
            _: &PageRequest,
        ) -> Result<Page<ResourceType<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("catalogue unreachable"))
        }

        async fn list_every(
            &self,
            _: &ScopedTenant,
        ) -> Result<Vec<ResourceType<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("catalogue unreachable"))
        }

        async fn save(
            &self,
            _: &ScopedTenant,
            _: &ResourceType<ResolvedTenant>,
        ) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("catalogue unreachable"))
        }

        async fn delete(&self, _: &ScopedTenant, _: &ResourceTypeId) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("catalogue unreachable"))
        }

        async fn count_roles_using(
            &self,
            _: &ScopedTenant,
            _: &PermissionSegment,
        ) -> Result<u64, DomainError> {
            Err(DomainError::infra_msg("catalogue unreachable"))
        }
    }

    fn tenant() -> ScopedTenant {
        ScopedTenant::for_test(TenantId::new())
    }

    fn permission(resource: &str, action: &str) -> CustomPermission {
        CustomPermission::new(resource, action).unwrap()
    }

    /// Acme declares `project` with `read` and `write`. Ann puts
    /// `project:write` on a role and it passes.
    #[test]
    fn a_declared_permission_passes() {
        let tenant = tenant();
        let store = FakeResourceTypeStore::seeded(*tenant);

        let result = block_on(ensure_declared(
            &store,
            &tenant,
            &[permission("project", "write")],
        ));

        assert!(result.is_ok());
    }

    /// A mixed permission set is rejected with the undeclared permission named
    /// and the declared permission omitted from the error.
    #[test]
    fn an_undeclared_permission_is_refused_by_name() {
        let tenant = tenant();
        let store = FakeResourceTypeStore::seeded(*tenant);

        let error = block_on(ensure_declared(
            &store,
            &tenant,
            &[
                permission("project", "read"),
                permission("projects", "write"),
            ],
        ))
        .unwrap_err();

        assert!(matches!(
            error,
            AppError::Domain(DomainError::Validation(_))
        ));
        assert!(error.to_string().contains("projects:write"));
        assert!(!error.to_string().contains("project:read"));
    }

    /// A permission declared only in another tenant fails local validation.
    #[test]
    fn another_tenants_declaration_does_not_count() {
        let tenant = tenant();
        let store = FakeResourceTypeStore::seeded(TenantId::new());

        let result = block_on(ensure_declared(
            &store,
            &tenant,
            &[permission("project", "write")],
        ));

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    /// Ann saves a role with no app permission. The catalogue is not read,
    /// so even one that cannot be reached lets it through.
    #[test]
    fn an_empty_set_never_reads_the_catalogue() {
        let result = block_on(ensure_declared(&UnreadableCatalogue, &tenant(), &[]));

        assert!(result.is_ok());
    }

    /// An unreadable catalogue returns an internal error for a nonempty permission set.
    #[test]
    fn an_unreadable_catalogue_refuses() {
        let result = block_on(ensure_declared(
            &UnreadableCatalogue,
            &tenant(),
            &[permission("project", "write")],
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
