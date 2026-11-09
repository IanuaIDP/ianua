//! Get attribute schema: every attribute the tenant declared, to resolve
//! against.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::identity::attribute::MetadataSchema;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::identity::UserAttributeStore;
use crate::use_case::Query;
use crate::use_cases::identity::attributes::declared_schema::declared_schema;

/// The ports [`GetSchemaUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetSchemaPorts {
    /// Reads declarations.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the caller's tenant's whole attribute schema.
pub struct GetSchemaUseCase {
    ports: GetSchemaPorts,
}

impl GetSchemaUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetSchemaPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetSchemaUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<MetadataSchema<ResolvedTenant>, AppError>;

    /// The whole schema, for a caller who may view users.
    ///
    /// For resolving against rather than showing: a filter, a sort, a value
    /// being stored. Those pass the caller's clearance to the schema, which
    /// refuses what the caller may not touch.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view users.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<MetadataSchema<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Users(UserAction::View))
            .map_err(AppError::from_domain)?;
        declared_schema(self.ports.attribute_store.as_ref(), &ctx.tenant()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::attribute::{AttributeKind, AttributeNamespace};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeUserAttributeStore, declaration, declared};
    use crate::test_support::{block_on, test_ctx};

    fn read(
        tenant_authorities: FakeTenantAuthorities,
    ) -> Result<MetadataSchema<ResolvedTenant>, AppError> {
        let tier = declared(declaration(
            "tier",
            AttributeNamespace::App,
            AttributeKind::Text,
        ));
        let use_case = GetSchemaUseCase::new(GetSchemaPorts {
            attribute_store: Arc::new(FakeUserAttributeStore::holding(vec![tier])),
            tenant_authorities: Arc::new(tenant_authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann reads the schema. It holds the tenant's `tier`.
    #[test]
    fn the_schema_holds_every_declaration() {
        let schema = read(FakeTenantAuthorities::holding_everything()).unwrap();

        assert_eq!(schema.attributes().len(), 1);
    }

    /// A caller without user-viewing rights cannot read the attribute schema.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let result = read(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot read the attribute schema.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
