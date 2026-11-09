//! Get metadata: the user and app values a caller may read for one user.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::identity::attribute::{
    AttributeClearance, AttributeNamespace, MetadataSchema, SchemaControlCheck,
};
use ianua_domain::domains::identity::metadata_value::MetadataValue;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Label, UserId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{MetadataStore, UserAttributeStore};
use crate::use_case::Query;
use crate::use_cases::identity::attributes::declared_schema::declared_schema;
use crate::use_cases::identity::whose::Whose;

/// The ports [`GetMetadataUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetMetadataPorts {
    /// Loads values.
    pub metadata_store: Arc<dyn MetadataStore>,
    /// The tenant's declared fields, which decide what a caller may read.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// One value a caller may read: its namespace, key and value.
pub type ReadableValue = (AttributeNamespace, String, MetadataValue);

/// Reads the values a caller may see for one user.
pub struct GetMetadataUseCase {
    ports: GetMetadataPorts,
}

impl GetMetadataUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetMetadataPorts) -> Self {
        Self { ports }
    }

    /// Whose values are read, and how much of them the caller may see.
    async fn reader(
        &self,
        ctx: &CallerContext,
        whose: Whose,
    ) -> Result<(UserId, AttributeClearance), AppError> {
        match whose {
            Whose::Own => {
                let person = self.ports.tenant_authorities.signed_in(ctx).await?;
                Ok((*person.account.id(), AttributeClearance::Sensitive))
            }
            Whose::OnBehalfOf(user_id) => {
                let authority = self.ports.tenant_authorities.authority(ctx).await?;
                authority
                    .ensure_holds(SystemPermission::Users(UserAction::View))
                    .map_err(AppError::from_domain)?;
                Ok((user_id, authority.clearance()))
            }
        }
    }
}

impl Query for GetMetadataUseCase {
    type Caller = CallerContext;
    type Input = Whose;
    type Output = Result<Vec<ReadableValue>, AppError>;

    /// The values of `whose` the caller may read, as
    /// `(namespace, key, value)`.
    ///
    /// A person reads all of their own declared values. Someone else needs
    /// the right to view users, and sees a sensitive value only with the
    /// clearance for it. A value the caller may not see is left out rather
    /// than emptied, so its absence says nothing about whether the person
    /// holds one.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when someone else may not view users.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        whose: Whose,
    ) -> Result<Vec<ReadableValue>, AppError> {
        let (user_id, clearance) = self.reader(ctx, whose).await?;
        let tenant = ctx.tenant();
        let schema = declared_schema(self.ports.attribute_store.as_ref(), &tenant).await?;
        let (user_values, app_values) = self
            .ports
            .metadata_store
            .find_by_user(&tenant, &user_id)
            .await
            .or_internal()?;
        let mut readable = readable_in(&schema, clearance, AttributeNamespace::User, &user_values);
        readable.extend(readable_in(
            &schema,
            clearance,
            AttributeNamespace::App,
            &app_values,
        ));
        Ok(readable)
    }
}

/// The values in `namespace` the schema shows a caller with `clearance`.
fn readable_in(
    schema: &MetadataSchema<ResolvedTenant>,
    clearance: AttributeClearance,
    namespace: AttributeNamespace,
    values: &HashMap<Label, MetadataValue>,
) -> Vec<ReadableValue> {
    values
        .iter()
        .filter(|(key, _)| schema.shows(namespace, key.as_str(), clearance))
        .map(|(key, value)| (namespace, key.as_str().to_owned(), value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::attribute::definition::AttributeSensitivity;
    use ianua_domain::domains::identity::attribute::{AttributeKind, AttributeVisibility};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{
        FakeMetadataStore, FakeUserAttributeStore, declaration, declared,
    };
    use crate::test_support::{block_on, test_ctx};

    /// A tenant declaring an ordinary `tier` and a sensitive `salary`, and
    /// Bob, who holds both.
    struct Bob {
        bob: UserId,
        attributes: Arc<FakeUserAttributeStore>,
        values: Arc<FakeMetadataStore>,
    }

    impl Bob {
        fn new() -> Self {
            let mut salary = declaration("salary", AttributeNamespace::App, AttributeKind::Text);
            salary.visibility = AttributeVisibility {
                sensitive: AttributeSensitivity::Sensitive,
                ..AttributeVisibility::default()
            };
            let tier = declaration("tier", AttributeNamespace::App, AttributeKind::Text);
            let bob = UserId::new();
            let values = Arc::new(FakeMetadataStore::empty());
            for (key, value) in [("tier", "gold"), ("salary", "high")] {
                values.insert_app_value(
                    &bob,
                    Label::new("attribute_key", key).unwrap(),
                    MetadataValue::from(value),
                );
            }
            Self {
                bob,
                attributes: Arc::new(FakeUserAttributeStore::holding(vec![
                    declared(tier),
                    declared(salary),
                ])),
                values,
            }
        }

        fn read_as(&self, holding: &[SystemPermission]) -> Result<Vec<String>, AppError> {
            let use_case = GetMetadataUseCase::new(GetMetadataPorts {
                metadata_store: self.values.clone(),
                attribute_store: self.attributes.clone(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holding)),
            });
            let mut keys: Vec<String> =
                block_on(use_case.execute(&test_ctx(), Whose::OnBehalfOf(self.bob)))?
                    .into_iter()
                    .map(|(_, key, _)| key)
                    .collect();
            keys.sort();
            Ok(keys)
        }
    }

    /// Ann reads Bob's values with the right to view users. She sees his
    /// tier but not his salary.
    #[test]
    fn a_sensitive_value_is_left_out_without_clearance() {
        let bob = Bob::new();

        let seen = bob
            .read_as(&[SystemPermission::Users(UserAction::View)])
            .unwrap();

        assert_eq!(seen, ["tier"]);
    }

    /// Ann may manage users. She sees Bob's salary too.
    #[test]
    fn a_cleared_caller_reads_the_sensitive_value() {
        let bob = Bob::new();

        let seen = bob.read_as(&[SystemPermission::ManageUsers]).unwrap();

        assert_eq!(seen, ["salary", "tier"]);
    }

    /// Carol holds no values. Reading hers finds nothing.
    #[test]
    fn a_user_without_values_reads_as_nothing() {
        let bob = Bob::new();
        let use_case = GetMetadataUseCase::new(GetMetadataPorts {
            metadata_store: bob.values.clone(),
            attribute_store: bob.attributes.clone(),
            ..GetMetadataPorts::fakes()
        });

        let seen =
            block_on(use_case.execute(&test_ctx(), Whose::OnBehalfOf(UserId::new()))).unwrap();

        assert!(seen.is_empty());
    }

    /// A caller without user-viewing rights cannot read Bob's attribute values.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let bob = Bob::new();

        let result = bob.read_as(&[]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot read their own attribute values.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = GetMetadataUseCase::new(GetMetadataPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..GetMetadataPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), Whose::Own));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
