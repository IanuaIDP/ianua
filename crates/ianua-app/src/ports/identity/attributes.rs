//! A user's metadata and the custom attributes a tenant declares for it.

use std::collections::HashMap;

use async_trait::async_trait;
use ianua_domain::domains::identity::attribute::{
    AttributeDefinition, AttributeKey, AttributeNamespace,
};
use ianua_domain::domains::identity::metadata_value::MetadataValue;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, UserId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting and retrieving user metadata.
///
/// Two namespaces: `user` (user-writable) and `app` (admin-only).
/// Returns `(user_metadata, app_metadata)` pairs.
#[async_trait]
pub trait MetadataStore: Send + Sync + TenantScoped {
    /// Loads all metadata for a user.
    ///
    /// Returns `(user_metadata, app_metadata)`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(HashMap<Label, MetadataValue>, HashMap<Label, MetadataValue>), DomainError>;

    /// Saves a single user-namespace metadata key-value pair.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn set_user_value(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        key: &Label,
        value: &MetadataValue,
    ) -> Result<(), DomainError>;

    /// Saves a single app-namespace metadata key-value pair.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn set_app_value(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        key: &Label,
        value: &MetadataValue,
    ) -> Result<(), DomainError>;

    /// Deletes all metadata for a user (both namespaces).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError>;

    /// Loads the named attributes for several users at once.
    ///
    /// A listing carries its tenant's custom attributes with every row, so
    /// asking per user would turn one page into a query per person. `keys`
    /// names only the attributes the listing shows, so a directory does not
    /// pay for the ones it hides.
    ///
    /// Users with no values are absent from the result rather than present
    /// and empty.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_for_users(
        &self,
        tenant_id: &ScopedTenant,
        user_ids: &[UserId],
        keys: &[(AttributeNamespace, AttributeKey)],
    ) -> Result<HashMap<UserId, Vec<StoredAttribute>>, DomainError>;

    /// Removes one value, leaving the rest of the user's metadata alone.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete_value(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<(), DomainError>;

    /// Counts the users holding a value for an attribute.
    ///
    /// Answers the questions an aggregate cannot: whether withdrawing an
    /// option would strand somebody, and whether making an attribute required
    /// would leave users failing it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn count_holders(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
        held: HeldValues<'_>,
    ) -> Result<u64, DomainError>;

    /// Removes every value stored under an attribute, for when a tenant
    /// discards the attribute itself.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn purge_attribute(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<u64, DomainError>;
}

/// Which holders of an attribute a count is asking about.
#[derive(Debug, Clone, Copy)]
pub enum HeldValues<'a> {
    /// Every user holding any value at all.
    Any,
    /// Users whose value is one of these options, for finding who would be
    /// stranded by withdrawing one.
    OneOf(&'a [Label]),
    /// Users whose text is longer than this, for finding who would be
    /// stranded by shortening a limit.
    LongerThan(u32),
    /// Users whose number is below this, for finding who would be stranded
    /// by raising a lowest value.
    Below(f64),
    /// Users whose number is above this, for finding who would be stranded
    /// by lowering a highest value.
    Above(f64),
}

/// One stored value, with the attribute it belongs to.
#[derive(Debug, Clone)]
pub struct StoredAttribute {
    /// Which namespace the value is in.
    pub namespace: AttributeNamespace,
    /// The attribute the value belongs to.
    pub key: AttributeKey,
    /// The value itself.
    pub value: MetadataValue,
}

/// Dyn-safe port for a tenant's declared custom user attributes.
///
/// Separate from [`MetadataStore`], which holds the values: one is the shape
/// of the tenant's directory and changes rarely, the other is per-person data
/// and changes constantly. Reading the shape to render a form should not drag
/// anybody's values along with it.
#[async_trait]
pub trait UserAttributeStore: Send + Sync + TenantScoped {
    /// Loads every declared attribute, archived ones included.
    ///
    /// Archived attributes are returned because the schema has to recognise a
    /// key to refuse it for the right reason, and because restoring
    /// one has to find it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn load_schema(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AttributeDefinition<ResolvedTenant>>, DomainError>;

    /// Finds one declaration by namespace and key.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<Option<AttributeDefinition<ResolvedTenant>>, DomainError>;

    /// Saves a new or changed declaration.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        definition: &AttributeDefinition<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Permanently removes a declaration.
    ///
    /// The values stored under it are removed by
    /// [`MetadataStore::purge_attribute`] rather than by cascade, so that
    /// discarding a tenant's data is always something a use case did on
    /// purpose and can report the size of.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<(), DomainError>;

    /// Counts the declarations a tenant holds, for the plan limit.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn count(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError>;
}
