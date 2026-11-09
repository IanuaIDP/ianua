//! Get users metadata: the named attributes for a page of users, in one
//! query.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::identity::attribute::{
    AttributeKey, AttributeNamespace, SchemaControlCheck,
};
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{MetadataStore, StoredAttribute, UserAttributeStore};
use crate::use_case::Query;
use crate::use_cases::identity::attributes::declared_schema::declared_schema;

/// The ports [`GetUsersMetadataUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetUsersMetadataPorts {
    /// Loads values.
    pub metadata_store: Arc<dyn MetadataStore>,
    /// The tenant's declared fields, which decide what a caller may read.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which users, and which of their attributes, to load.
pub struct GetUsersMetadataRequest {
    /// The users on the page.
    pub user_ids: Vec<UserId>,
    /// The attributes the listing shows.
    pub keys: Vec<(AttributeNamespace, AttributeKey)>,
}

/// Loads attributes for a page of the caller's tenant's users.
pub struct GetUsersMetadataUseCase {
    ports: GetUsersMetadataPorts,
}

impl GetUsersMetadataUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetUsersMetadataPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUsersMetadataUseCase {
    type Caller = CallerContext;
    type Input = GetUsersMetadataRequest;
    type Output = Result<HashMap<UserId, Vec<StoredAttribute>>, AppError>;

    /// The named attributes for a page of users, in one query, for a caller
    /// who may view users.
    ///
    /// Only the attributes the schema shows the caller are read: a key
    /// nobody declared, or a sensitive one the caller has no clearance for,
    /// is dropped from what is asked. Asking per user would turn one page
    /// into a query per row, which is why this exists apart from reading one
    /// user's values.
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
        request: GetUsersMetadataRequest,
    ) -> Result<HashMap<UserId, Vec<StoredAttribute>>, AppError> {
        let GetUsersMetadataRequest { user_ids, keys } = request;
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Users(UserAction::View))
            .map_err(AppError::from_domain)?;
        if user_ids.is_empty() || keys.is_empty() {
            return Ok(HashMap::new());
        }
        let tenant = ctx.tenant();
        let schema = declared_schema(self.ports.attribute_store.as_ref(), &tenant).await?;
        let clearance = authority.clearance();
        let shown: Vec<_> = keys
            .into_iter()
            .filter(|(namespace, key)| schema.shows(*namespace, key.as_str(), clearance))
            .collect();
        if shown.is_empty() {
            return Ok(HashMap::new());
        }
        self.ports
            .metadata_store
            .find_for_users(&tenant, &user_ids, &shown)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::attribute::definition::AttributeSensitivity;
    use ianua_domain::domains::identity::attribute::{AttributeKind, AttributeVisibility};
    use ianua_domain::domains::identity::metadata_value::MetadataValue;
    use ianua_domain::types::Label;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{
        FakeMetadataStore, FakeUserAttributeStore, declaration, declared,
    };
    use crate::test_support::{block_on, test_ctx};

    fn key(name: &str) -> (AttributeNamespace, AttributeKey) {
        (AttributeNamespace::App, AttributeKey::new(name).unwrap())
    }

    /// Bob and Carol, each holding a `theme` and a sensitive `salary`.
    struct Page {
        people: Vec<UserId>,
        ports: GetUsersMetadataPorts,
    }

    impl Page {
        fn as_holder_of(holding: &[SystemPermission]) -> Self {
            let mut salary = declaration("salary", AttributeNamespace::App, AttributeKind::Text);
            salary.visibility = AttributeVisibility {
                sensitive: AttributeSensitivity::Sensitive,
                ..AttributeVisibility::default()
            };
            let theme = declaration("theme", AttributeNamespace::App, AttributeKind::Text);
            let values = Arc::new(FakeMetadataStore::empty());
            let people = vec![UserId::new(), UserId::new()];
            for person in &people {
                for (name, value) in [("theme", "dark"), ("salary", "high")] {
                    values.insert_app_value(
                        person,
                        Label::new("attribute_key", name).unwrap(),
                        MetadataValue::from(value),
                    );
                }
            }
            Self {
                people,
                ports: GetUsersMetadataPorts {
                    metadata_store: values,
                    attribute_store: Arc::new(FakeUserAttributeStore::holding(vec![
                        declared(theme),
                        declared(salary),
                    ])),
                    tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holding)),
                },
            }
        }

        fn load(
            self,
            keys: Vec<(AttributeNamespace, AttributeKey)>,
        ) -> Result<HashMap<UserId, Vec<StoredAttribute>>, AppError> {
            let request = GetUsersMetadataRequest {
                user_ids: self.people,
                keys,
            };
            block_on(GetUsersMetadataUseCase::new(self.ports).execute(&test_ctx(), request))
        }
    }

    fn viewer() -> Vec<SystemPermission> {
        vec![SystemPermission::Users(UserAction::View)]
    }

    /// Ann's page shows `theme`. Each person's theme comes back.
    #[test]
    fn the_named_attributes_of_each_user_are_loaded() {
        let loaded = Page::as_holder_of(&viewer())
            .load(vec![key("theme")])
            .unwrap();

        assert_eq!(loaded.len(), 2);
        assert!(loaded.values().all(|held| held.len() == 1));
    }

    /// A page with no people loads nothing.
    #[test]
    fn an_empty_page_loads_nothing() {
        let mut page = Page::as_holder_of(&viewer());
        page.people.clear();

        let loaded = page.load(vec![key("theme")]).unwrap();

        assert!(loaded.is_empty());
    }

    /// A page request for sensitive salaries returns no values to a caller
    /// with only user-viewing rights.
    #[test]
    fn a_sensitive_attribute_is_not_read_without_clearance() {
        let loaded = Page::as_holder_of(&viewer())
            .load(vec![key("salary")])
            .unwrap();

        assert!(loaded.is_empty());
    }

    /// A caller without user-viewing rights cannot load a page of attribute values.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let result = Page::as_holder_of(&[]).load(vec![key("theme")]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot load a page of attribute values.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut page = Page::as_holder_of(&viewer());
        page.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = page.load(vec![key("theme")]);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
