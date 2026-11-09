//! List user attributes: the shape of a tenant's own user directory.
//!
//! What a client reads to show a form, a filter bar or a column chooser. It
//! is the schema, not anybody's values, so it is the same answer for every
//! caller with the same clearance.

use std::sync::Arc;

use ianua_domain::domains::identity::attribute::{AttributeDefinition, SchemaControlCheck};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserAttributeStore;
use crate::use_case::Query;

/// Which declarations a listing returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttributeListing {
    /// Only the attributes still in use. A form has no use for withdrawn
    /// ones.
    #[default]
    InUse,
    /// Every attribute, the ones withdrawn from use included.
    WithArchived,
}

impl AttributeListing {
    /// Whether `attribute` belongs in this listing.
    fn admits(self, attribute: &AttributeDefinition<ResolvedTenant>) -> bool {
        match self {
            Self::InUse => !attribute.archived(),
            Self::WithArchived => true,
        }
    }
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Reads declarations.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// What the caller holds in their tenant, and so may see.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the caller's tenant's declared user attributes.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = AttributeListing;
    type Output = Result<Vec<AttributeDefinition<ResolvedTenant>>, AppError>;

    /// The attributes in `listing` the caller is cleared to see, the
    /// clearance worked out from what they hold.
    ///
    /// A caller who may not read sensitive attributes is not told they
    /// exist: listing them and refusing to fill them in would tell that the
    /// tenant records a salary, which is most of what a sensitive field
    /// hides.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        listing: AttributeListing,
    ) -> Result<Vec<AttributeDefinition<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let clearance = SchemaControlCheck::clearance(&authority);
        let declared = self
            .ports
            .attribute_store
            .load_schema(&ctx.tenant())
            .await
            .or_internal()?;
        Ok(declared
            .into_iter()
            .filter(|attribute| listing.admits(attribute))
            .filter(|attribute| clearance.admits_sensitive() || !attribute.sensitive())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::attribute::definition::AttributeSensitivity;
    use ianua_domain::domains::identity::attribute::{
        AttributeKind, AttributeNamespace, AttributeVisibility,
    };
    use ianua_domain::test_support::authority::user_editor;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeUserAttributeStore, declaration, declared};
    use crate::test_support::{block_on, test_ctx};

    fn ordinary(name: &str) -> AttributeDefinition<ResolvedTenant> {
        declared(declaration(
            name,
            AttributeNamespace::App,
            AttributeKind::Text,
        ))
    }

    fn sensitive(name: &str) -> AttributeDefinition<ResolvedTenant> {
        let mut params = declaration(name, AttributeNamespace::App, AttributeKind::Text);
        params.visibility = AttributeVisibility {
            sensitive: AttributeSensitivity::Sensitive,
            ..AttributeVisibility::default()
        };
        declared(params)
    }

    fn withdrawn(name: &str) -> AttributeDefinition<ResolvedTenant> {
        let mut attribute = ordinary(name);
        attribute.archive(user_editor()).unwrap();
        attribute
    }

    fn keys_seen(
        attributes: Vec<AttributeDefinition<ResolvedTenant>>,
        holding: &[SystemPermission],
        listing: AttributeListing,
    ) -> Vec<String> {
        let use_case = ListUseCase::new(ListPorts {
            attribute_store: Arc::new(FakeUserAttributeStore::holding(attributes)),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holding)),
        });
        block_on(use_case.execute(&test_ctx(), listing))
            .unwrap()
            .iter()
            .map(|attribute| attribute.key().as_str().to_owned())
            .collect()
    }

    fn viewer() -> Vec<SystemPermission> {
        vec![SystemPermission::Users(UserAction::View)]
    }

    /// A tenant that declared nothing lists nothing.
    #[test]
    fn a_tenant_that_declared_nothing_lists_nothing() {
        assert!(keys_seen(Vec::new(), &viewer(), AttributeListing::InUse).is_empty());
    }

    /// The tenant declared `tier` and `team`. Both are listed.
    #[test]
    fn the_declared_attributes_are_listed() {
        let seen = keys_seen(
            vec![ordinary("tier"), ordinary("team")],
            &viewer(),
            AttributeListing::InUse,
        );

        assert_eq!(seen, ["tier", "team"]);
    }

    /// Sam may only view users. The tenant's sensitive `salary` is not
    /// listed to him, so he does not learn it is recorded.
    #[test]
    fn a_caller_without_clearance_is_not_told_a_sensitive_field_exists() {
        let seen = keys_seen(
            vec![ordinary("tier"), sensitive("salary")],
            &viewer(),
            AttributeListing::InUse,
        );

        assert_eq!(seen, ["tier"]);
    }

    /// Ann may manage users. She sees `salary` too.
    #[test]
    fn a_cleared_caller_sees_the_sensitive_fields_too() {
        let seen = keys_seen(
            vec![ordinary("tier"), sensitive("salary")],
            &[SystemPermission::ManageUsers],
            AttributeListing::InUse,
        );

        assert_eq!(seen, ["tier", "salary"]);
    }

    /// The withdrawn `old` is left out unless withdrawn ones are asked for.
    #[test]
    fn withdrawn_attributes_are_left_out_unless_asked_for() {
        let attributes = || vec![ordinary("tier"), withdrawn("old")];

        assert_eq!(
            keys_seen(attributes(), &viewer(), AttributeListing::InUse),
            ["tier"]
        );
        assert_eq!(
            keys_seen(attributes(), &viewer(), AttributeListing::WithArchived),
            ["tier", "old"]
        );
    }

    /// Including archived attributes does not expose the sensitive salary
    /// declaration to a caller with only user-viewing rights.
    #[test]
    fn asking_for_withdrawn_attributes_does_not_lift_clearance() {
        let seen = keys_seen(
            vec![sensitive("salary")],
            &viewer(),
            AttributeListing::WithArchived,
        );

        assert!(seen.is_empty());
    }

    /// A signed-out caller cannot list attribute declarations.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ListPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), AttributeListing::InUse));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
