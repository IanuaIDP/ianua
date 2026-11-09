//! Get an import: where an import of accounts stands, how many it opened,
//! and which records it set aside and why.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::identity::account::import::run::UserImport;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::UserImportId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserImportStore;
use crate::use_case::Query;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads imports.
    pub import_store: Arc<dyn UserImportStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one import of the caller's tenant.
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
    type Input = UserImportId;
    type Output = Result<UserImport<ResolvedTenant>, AppError>;

    /// The import with `import_id`, for a caller who may view users.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view users.
    /// - `AppError::NotFound` if the tenant has no such import.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        import_id: UserImportId,
    ) -> Result<UserImport<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Users(UserAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .import_store
            .find_by_id(&ctx.tenant(), &import_id)
            .await
            .or_internal()?
            .ok_or_else(|| AppError::NotFound(message!("identity-user-import", "user import")))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::import::state::ImportStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeUserImportStore, import_batch};
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_link_scope,
    };
    use crate::use_case::Command as _;
    use crate::use_cases::identity::imports::start::{StartPorts, StartRequest, StartUseCase};

    /// Ann started an import of three accounts, kept in `imports`.
    fn started_in(imports: &Arc<FakeUserImportStore>) -> UserImportId {
        let start = StartUseCase::new(StartPorts {
            import_store: imports.clone(),
            ..StartPorts::fakes()
        });
        let request = StartRequest {
            batch: import_batch(3),
            scope: test_link_scope(),
        };
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(start.execute(&test_ctx(), &auditor, request)).unwrap()
    }

    fn reading(imports: &Arc<FakeUserImportStore>) -> GetUseCase {
        GetUseCase::new(GetPorts {
            import_store: imports.clone(),
            ..GetPorts::fakes()
        })
    }

    /// Ann looks up the import she started. It is still waiting, with all
    /// three records to go.
    #[test]
    fn an_import_shows_where_it_stands() {
        let imports = Arc::new(FakeUserImportStore::empty());
        let id = started_in(&imports);

        let import = block_on(reading(&imports).execute(&test_ctx(), id)).unwrap();

        assert_eq!(import.status(), ImportStatus::Pending);
        assert_eq!(import.counts().remaining, 3);
    }

    /// Ann asks for an import Acme never had. It is not found.
    #[test]
    fn an_unknown_import_is_not_found() {
        let imports = Arc::new(FakeUserImportStore::empty());

        let result = block_on(reading(&imports).execute(&test_ctx(), UserImportId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without user-viewing rights cannot read an existing import.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let imports = Arc::new(FakeUserImportStore::empty());
        let id = started_in(&imports);
        let use_case = GetUseCase::new(GetPorts {
            import_store: imports.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
        });

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot read an import.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = GetUseCase::new(GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..GetPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), UserImportId::new()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
