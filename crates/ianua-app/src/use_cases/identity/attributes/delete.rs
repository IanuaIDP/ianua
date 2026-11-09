//! Delete user attribute: discard a field and everything stored under it.
//!
//! The irreversible half of removing a field, and the only step here that
//! destroys data. It is not the first step: an attribute must be withdrawn
//! from use before it is deleted, so removing a column and discarding what a
//! thousand people put in it are two decisions rather than one click.

use std::sync::Arc;

use ianua_domain::domains::identity::attribute::{
    AttributeDefinition, AttributeKey, AttributeNamespace, SchemaControlCheck,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{MetadataStore, UserAttributeStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::lookup::existing_attribute;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Reads and removes declarations.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// Discards the values stored under the attribute.
    pub metadata_store: Arc<dyn MetadataStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// The declared attribute to discard.
pub struct DeleteRequest {
    /// Which namespace the attribute is declared in.
    pub namespace: AttributeNamespace,
    /// The attribute's key.
    pub key: AttributeKey,
}

/// Discards an attribute of the caller's tenant and its values.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }

    /// Discards every value stored under the attribute, then its
    /// declaration, returning how many values went.
    ///
    /// The values go first. Were the order reversed and the second step to
    /// fail, the rows would remain with nothing left to say what they meant.
    async fn discard(
        &self,
        tenant: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<u64, AppError> {
        let values_discarded = self
            .ports
            .metadata_store
            .purge_attribute(tenant, namespace, key)
            .await
            .or_internal()?;
        self.ports
            .attribute_store
            .delete(tenant, namespace, key)
            .await
            .or_internal()?;
        Ok(values_discarded)
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = DeleteRequest;
    type Output = Result<u64, AppError>;

    /// Discards a withdrawn attribute and every value stored under it, for a
    /// caller who may change the schema, returning how many values went.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the schema.
    /// - `AppError::NotFound` if nothing is declared under that name.
    /// - `AppError::Conflict` if the attribute is still in use.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DeleteRequest,
    ) -> Result<u64, AppError> {
        let DeleteRequest { namespace, key } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_may_change_schema()
            .map_err(AppError::from_domain)?;
        let mut definition = existing_attribute(
            self.ports.attribute_store.as_ref(),
            &tenant,
            namespace,
            &key,
        )
        .await?;
        ensure_withdrawn(&definition)?;

        let values_discarded = self.discard(&tenant, namespace, &key).await?;
        definition
            .delete(values_discarded, &authority)
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), definition.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(values_discarded)
    }
}

/// Refuses deleting an attribute that is still in use: it must be withdrawn
/// first, which keeps what people stored under it.
fn ensure_withdrawn(definition: &AttributeDefinition<ResolvedTenant>) -> Result<(), AppError> {
    if definition.archived() {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "identity-is-still-in-use-withdraw-it",
        format!(
            "'{}' is still in use; withdraw it first, which keeps what people stored under it",
            definition.key()
        )
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::attribute::AttributeKind;
    use ianua_domain::domains::identity::metadata_value::MetadataValue;
    use ianua_domain::test_support::authority::user_editor;
    use ianua_domain::types::{Label, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{
        FakeMetadataStore, FakeUserAttributeStore, declaration, declared,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A tenant declaring `tier`, withdrawn or not, Bob holding gold.
    struct Tier {
        bob: UserId,
        attributes: Arc<FakeUserAttributeStore>,
        values: Arc<FakeMetadataStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tier {
        fn in_use() -> Self {
            Self::declaring(declared(declaration(
                "tier",
                AttributeNamespace::App,
                AttributeKind::Text,
            )))
        }

        fn withdrawn() -> Self {
            let mut tier = declared(declaration(
                "tier",
                AttributeNamespace::App,
                AttributeKind::Text,
            ));
            tier.archive(user_editor()).unwrap();
            Self::declaring(tier)
        }

        fn declaring(tier: AttributeDefinition<ResolvedTenant>) -> Self {
            let bob = UserId::new();
            let values = Arc::new(FakeMetadataStore::empty());
            values.insert_app_value(
                &bob,
                Label::new("attribute_key", "tier").unwrap(),
                MetadataValue::from("gold"),
            );
            Self {
                bob,
                attributes: Arc::new(FakeUserAttributeStore::holding(vec![tier])),
                values,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> DeletePorts {
            DeletePorts {
                attribute_store: self.attributes.clone(),
                metadata_store: self.values.clone(),
                ..DeletePorts::fakes()
            }
        }

        fn delete(&self, ports: DeletePorts) -> Result<u64, AppError> {
            block_on(DeleteUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                DeleteRequest {
                    namespace: AttributeNamespace::App,
                    key: AttributeKey::new("tier").unwrap(),
                },
            ))
        }

        fn bob_holds_tier(&self) -> bool {
            self.values
                .has_app_value(&self.bob, &Label::new("attribute_key", "tier").unwrap())
        }
    }

    /// Ann deletes the withdrawn `tier`. Bob's value and the declaration go,
    /// and she is told one value was discarded.
    #[test]
    fn a_withdrawn_attribute_is_deleted_with_its_values() {
        let tier = Tier::withdrawn();

        let discarded = tier.delete(tier.ports()).unwrap();

        assert_eq!(discarded, 1);
        assert!(!tier.bob_holds_tier());
        assert_eq!(tier.attributes.count_declared(), 0);
        assert_eq!(
            tier.sink.records.lock().unwrap().as_slice(),
            ["identity.attribute_deleted"]
        );
    }

    /// Ann deletes `tier` while it is in use. It is refused and Bob keeps his
    /// value.
    #[test]
    fn an_attribute_in_use_is_not_deleted() {
        let tier = Tier::in_use();

        let result = tier.delete(tier.ports());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(tier.bob_holds_tier());
    }

    /// User-viewing rights do not permit deleting a withdrawn attribute.
    /// Bob keeps his tier value after the refusal.
    #[test]
    fn a_caller_who_may_not_change_the_schema_is_refused() {
        let tier = Tier::withdrawn();
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..tier.ports()
        };

        let result = tier.delete(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tier.bob_holds_tier());
    }

    /// A signed-out caller cannot delete the withdrawn tier attribute.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tier = Tier::withdrawn();
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tier.ports()
        };

        let result = tier.delete(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
