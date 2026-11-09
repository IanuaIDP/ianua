//! Declare user attribute: add a custom field to a tenant's own users.
//!
//! Before anyone can store a department, a shirt size or a salary against a
//! user, somebody has to say that the field exists and what sort of thing it
//! holds. That declaration is what later lets a form render it, a listing
//! carry it, and a filter narrow by it.

use std::sync::Arc;

use ianua_domain::domains::identity::attribute::{
    AttributeDefinition, AttributeKey, AttributeNamespace, DeclareAttribute,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserAttributeStore;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`DeclareUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeclarePorts {
    /// Reads and saves declarations.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// Holds the tenant to its plan's attribute limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Declares a custom user attribute in the caller's tenant.
pub struct DeclareUseCase {
    ports: DeclarePorts,
}

impl DeclareUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeclarePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeclareUseCase {
    type Caller = CallerContext;
    type Input = DeclareAttribute;
    type Output = Result<AttributeDefinition<ResolvedTenant>, AppError>;

    /// Declares `attribute` for the tenant's users, for a caller who may
    /// change the schema.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the schema, or
    ///   the plan allows no further attributes.
    /// - `AppError::Conflict` if that namespace already has an attribute by
    ///   that name.
    /// - `AppError::Domain` if the declaration contradicts the kind it chose.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        attribute: DeclareAttribute,
    ) -> Result<AttributeDefinition<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &tenant, ResourceKind::UserAttributes)
            .await
            .map_err(AppError::from_domain)?;
        let store = self.ports.attribute_store.as_ref();
        ensure_name_free(store, &tenant, attribute.namespace, &attribute.key).await?;
        let mut definition =
            AttributeDefinition::declare(attribute, &authority).map_err(AppError::from_domain)?;

        store.save(&tenant, &definition).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), definition.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(definition)
    }
}

/// Refuses a name already in use in that namespace.
///
/// An archived attribute still holds its name. Its values are still stored
/// under it, so letting a second attribute take the name would leave two
/// meanings sharing one key and the old data read as the new field.
async fn ensure_name_free(
    store: &dyn UserAttributeStore,
    tenant: &ScopedTenant,
    namespace: AttributeNamespace,
    key: &AttributeKey,
) -> Result<(), AppError> {
    let Some(existing) = store.find(tenant, namespace, key).await.or_internal()? else {
        return Ok(());
    };
    if existing.archived() {
        return Err(AppError::Conflict(message!(
            "identity-is-withdrawn-but-still-holds-its",
            format!(
                "'{key}' is withdrawn but still holds its stored values; restore it or delete it before reusing the name"
            )
        )));
    }
    Err(AppError::Conflict(message!(
        "identity-is-already-declared-for-these-users",
        format!("'{key}' is already declared for these users")
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::attribute::AttributeKind;
    use ianua_domain::shared::model::restriction::Restriction;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeUserAttributeStore, declaration};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    fn tier() -> DeclareAttribute {
        declaration("tier", AttributeNamespace::App, AttributeKind::Text)
    }

    /// A tenant's declarations and what a declaration records.
    struct Schema {
        attributes: Arc<FakeUserAttributeStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Schema {
        fn new() -> Self {
            Self {
                attributes: Arc::new(FakeUserAttributeStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> DeclarePorts {
            DeclarePorts {
                attribute_store: self.attributes.clone(),
                ..DeclarePorts::fakes()
            }
        }

        fn declare_with(
            &self,
            ports: DeclarePorts,
            attribute: DeclareAttribute,
        ) -> Result<AttributeDefinition<ResolvedTenant>, AppError> {
            block_on(DeclareUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                attribute,
            ))
        }

        fn declare(
            &self,
            attribute: DeclareAttribute,
        ) -> Result<AttributeDefinition<ResolvedTenant>, AppError> {
            self.declare_with(self.ports(), attribute)
        }
    }

    /// Ann declares a `tier`. It is stored and recorded.
    #[test]
    fn a_declaration_is_stored_and_recorded() {
        let schema = Schema::new();

        schema.declare(tier()).unwrap();

        assert_eq!(schema.attributes.count_declared(), 1);
        assert_eq!(
            schema.sink.records.lock().unwrap().as_slice(),
            ["identity.attribute_declared"]
        );
    }

    /// Ann declares `tier` twice in one namespace. The second is a
    /// conflict.
    #[test]
    fn the_same_name_twice_is_a_conflict() {
        let schema = Schema::new();
        schema.declare(tier()).unwrap();

        let again = schema.declare(tier());

        assert!(matches!(again, Err(AppError::Conflict(_))));
    }

    /// A `tier` the person keeps and a `tier` the billing system keeps are
    /// different attributes with one name.
    #[test]
    fn the_same_name_in_the_other_namespace_is_a_different_attribute() {
        let schema = Schema::new();
        schema.declare(tier()).unwrap();

        let own = schema.declare(declaration(
            "tier",
            AttributeNamespace::User,
            AttributeKind::Text,
        ));

        assert!(own.is_ok());
        assert_eq!(schema.attributes.count_declared(), 2);
    }

    /// Ann's `tier` was withdrawn but keeps its values. Declaring a new
    /// `tier` is refused, so the old values are not read as the new field.
    #[test]
    fn a_withdrawn_attribute_still_holds_its_name() {
        let schema = Schema::new();
        let mut old = schema.declare(tier()).unwrap();
        old.archive(ianua_domain::test_support::authority::user_editor())
            .unwrap();
        block_on(schema.attributes.save(&test_ctx().tenant(), &old)).unwrap();

        let again = schema.declare(tier());

        assert!(matches!(again, Err(AppError::Conflict(_))));
    }

    /// A text attribute with numeric bounds contradicts its kind. It is
    /// refused.
    #[test]
    fn a_declaration_contradicting_its_kind_is_refused() {
        let schema = Schema::new();
        let mut attribute = tier();
        attribute.minimum = Restriction::To(1.0);

        let result = schema.declare(attribute);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(schema.attributes.count_declared(), 0);
    }

    /// The tenant's plan allows no more attributes. The next is refused and
    /// nothing is recorded.
    #[test]
    fn a_plan_that_allows_no_more_attributes_refuses_the_next() {
        let schema = Schema::new();
        let ports = DeclarePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..schema.ports()
        };

        let result = schema.declare_with(ports, tier());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(schema.sink.records.lock().unwrap().is_empty());
    }

    /// A new attribute is listed, filtered and sorted by nobody until
    /// someone opens it, so declaring it cannot widen what a directory
    /// shows.
    #[test]
    fn a_new_attribute_is_queryable_by_nobody_until_it_is_opened() {
        let schema = Schema::new();

        let declared = schema.declare(tier()).unwrap();

        assert!(!declared.is_listed());
        assert!(!declared.is_filterable());
        assert!(!declared.is_sortable());
    }

    /// User-viewing rights do not permit declaring a tier attribute.
    /// The refusal leaves the schema empty.
    #[test]
    fn a_caller_who_may_not_change_the_schema_is_refused() {
        let schema = Schema::new();
        let ports = DeclarePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..schema.ports()
        };

        let result = schema.declare_with(ports, tier());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(schema.attributes.count_declared(), 0);
    }

    /// A signed-out caller cannot declare an attribute.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let schema = Schema::new();
        let ports = DeclarePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..schema.ports()
        };

        let result = schema.declare_with(ports, tier());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
