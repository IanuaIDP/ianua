//! In-memory stores for a user's metadata and the custom attributes a
//! tenant declares.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::attribute::{
    AttributeDefinition, AttributeKey, AttributeKind, AttributeNamespace, AttributeVisibility,
    DeclareAttribute,
};
use ianua_domain::domains::identity::metadata_value::MetadataValue;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::test_support::authority::user_editor;
use ianua_domain::types::{Label, Preference, TenantId, UserId};

use crate::ports::TenantScoped;
use crate::ports::identity::{HeldValues, MetadataStore, StoredAttribute, UserAttributeStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::identity::held::{TenantRows, seeded_tenant};

/// A declaration of `name` in `namespace`, holding `kind`, with everything
/// else at its least surprising setting, for a test to vary one facet of.
///
/// # Panics
///
/// If `name` is not a valid attribute key. Tests pass literals that are.
#[must_use]
pub fn declaration(
    name: &str,
    namespace: AttributeNamespace,
    kind: AttributeKind,
) -> DeclareAttribute {
    DeclareAttribute {
        key: AttributeKey::new(name).expect("a valid attribute key"),
        namespace,
        kind,
        control: Preference::Inherited,
        display_name: Label::new("display_name", name).expect("a valid name"),
        description: None,
        options: Vec::new(),
        max_length: Restriction::Unrestricted,
        minimum: Restriction::Unrestricted,
        maximum: Restriction::Unrestricted,
        visibility: AttributeVisibility::default(),
    }
}

/// `params`, declared by someone who may change the schema.
///
/// # Panics
///
/// If the declaration contradicts its kind. Tests pass ones that do not.
#[must_use]
pub fn declared(params: DeclareAttribute) -> AttributeDefinition<ResolvedTenant> {
    AttributeDefinition::declare(params, user_editor()).expect("a valid declaration")
}

/// One user's metadata: the user namespace, then the app namespace.
type MetadataEntry = (HashMap<Label, MetadataValue>, HashMap<Label, MetadataValue>);

/// In-memory metadata store: each user's values kept under their tenant.
///
/// Its seeding helpers file values under the tenant [`test_ctx`] carries.
///
/// [`test_ctx`]: crate::test_support::test_ctx
#[derive(Default)]
pub struct FakeMetadataStore {
    data: Mutex<HashMap<(TenantId, UserId), MetadataEntry>>,
}

impl TenantScoped for FakeMetadataStore {}

impl FakeMetadataStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Stores a user-namespace value for `user_id`.
    pub fn insert_user_value(&self, user_id: &UserId, key: Label, value: MetadataValue) {
        self.write(
            (seeded_tenant(), *user_id),
            AttributeNamespace::User,
            key,
            value,
        );
    }

    /// Stores an app-namespace value for `user_id`.
    pub fn insert_app_value(&self, user_id: &UserId, key: Label, value: MetadataValue) {
        self.write(
            (seeded_tenant(), *user_id),
            AttributeNamespace::App,
            key,
            value,
        );
    }

    /// Whether `user_id` holds a user-namespace value under `key`.
    #[must_use]
    pub fn has_user_value(&self, user_id: &UserId, key: &Label) -> bool {
        self.holds_key(user_id, AttributeNamespace::User, key)
    }

    /// Whether `user_id` holds an app-namespace value under `key`.
    #[must_use]
    pub fn has_app_value(&self, user_id: &UserId, key: &Label) -> bool {
        self.holds_key(user_id, AttributeNamespace::App, key)
    }

    /// Whether `user_id` holds no metadata at all.
    #[must_use]
    pub fn is_empty_for(&self, user_id: &UserId) -> bool {
        self.data
            .lock()
            .unwrap()
            .get(&(seeded_tenant(), *user_id))
            .is_none_or(|(user, app)| user.is_empty() && app.is_empty())
    }

    fn holds_key(&self, user_id: &UserId, namespace: AttributeNamespace, key: &Label) -> bool {
        self.data
            .lock()
            .unwrap()
            .get(&(seeded_tenant(), *user_id))
            .is_some_and(|entry| side(entry, namespace).contains_key(key))
    }

    fn write(
        &self,
        owner: (TenantId, UserId),
        namespace: AttributeNamespace,
        key: Label,
        value: MetadataValue,
    ) {
        let mut data = self.data.lock().unwrap();
        let entry = data.entry(owner).or_default();
        side_mut(entry, namespace).insert(key, value);
    }
}

#[async_trait]
impl MetadataStore for FakeMetadataStore {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<MetadataEntry, DomainError> {
        let data = self.data.lock().unwrap();
        Ok(data
            .get(&(**tenant_id, *user_id))
            .cloned()
            .unwrap_or_default())
    }

    async fn set_user_value(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        key: &Label,
        value: &MetadataValue,
    ) -> Result<(), DomainError> {
        let owner = (**tenant_id, *user_id);
        self.write(owner, AttributeNamespace::User, key.clone(), value.clone());
        Ok(())
    }

    async fn set_app_value(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        key: &Label,
        value: &MetadataValue,
    ) -> Result<(), DomainError> {
        let owner = (**tenant_id, *user_id);
        self.write(owner, AttributeNamespace::App, key.clone(), value.clone());
        Ok(())
    }

    async fn delete_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        self.data.lock().unwrap().remove(&(**tenant_id, *user_id));
        Ok(())
    }

    async fn find_for_users(
        &self,
        tenant_id: &ScopedTenant,
        user_ids: &[UserId],
        keys: &[(AttributeNamespace, AttributeKey)],
    ) -> Result<HashMap<UserId, Vec<StoredAttribute>>, DomainError> {
        let data = self.data.lock().unwrap();
        let found = user_ids
            .iter()
            .filter_map(|user_id| {
                let entry = data.get(&(**tenant_id, *user_id))?;
                let values = attributes_in(entry, keys);
                (!values.is_empty()).then_some((*user_id, values))
            })
            .collect();
        Ok(found)
    }

    async fn delete_value(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<(), DomainError> {
        let mut data = self.data.lock().unwrap();
        let Some(entry) = data.get_mut(&(**tenant_id, *user_id)) else {
            return Ok(());
        };
        side_mut(entry, namespace).remove(&as_label(key));
        Ok(())
    }

    async fn count_holders(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
        held: HeldValues<'_>,
    ) -> Result<u64, DomainError> {
        let data = self.data.lock().unwrap();
        let label = as_label(key);
        let matching = data
            .iter()
            .filter(|((tenant, _), _)| tenant == &**tenant_id)
            .filter_map(|(_, entry)| side(entry, namespace).get(&label))
            .filter(|value| holds(value, held))
            .count();
        Ok(matching as u64)
    }

    async fn purge_attribute(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<u64, DomainError> {
        let mut data = self.data.lock().unwrap();
        let label = as_label(key);
        let removed = data
            .iter_mut()
            .filter(|((tenant, _), _)| tenant == &**tenant_id)
            .filter_map(|(_, entry)| side_mut(entry, namespace).remove(&label))
            .count();
        Ok(removed as u64)
    }
}

impl Fake for Arc<dyn MetadataStore> {
    fn fake() -> Self {
        Arc::new(FakeMetadataStore::empty())
    }
}

/// The values `entry` holds under `keys`, each with its attribute.
fn attributes_in(
    entry: &MetadataEntry,
    keys: &[(AttributeNamespace, AttributeKey)],
) -> Vec<StoredAttribute> {
    keys.iter()
        .filter_map(|(namespace, key)| {
            let value = side(entry, *namespace).get(&as_label(key))?;
            Some(StoredAttribute {
                namespace: *namespace,
                key: key.clone(),
                value: value.clone(),
            })
        })
        .collect()
}

fn side(entry: &MetadataEntry, namespace: AttributeNamespace) -> &HashMap<Label, MetadataValue> {
    match namespace {
        AttributeNamespace::User => &entry.0,
        AttributeNamespace::App => &entry.1,
    }
}

fn side_mut(
    entry: &mut MetadataEntry,
    namespace: AttributeNamespace,
) -> &mut HashMap<Label, MetadataValue> {
    match namespace {
        AttributeNamespace::User => &mut entry.0,
        AttributeNamespace::App => &mut entry.1,
    }
}

/// `key` as the label the values are kept under: every attribute key is
/// also a valid label.
fn as_label(key: &AttributeKey) -> Label {
    Label::new("attribute_key", key.as_str()).expect("an attribute key is always a valid label")
}

/// Whether a stored value is one the count is asking about.
fn holds(value: &MetadataValue, held: HeldValues<'_>) -> bool {
    let texts = texts_of(value);
    match held {
        HeldValues::Any => true,
        HeldValues::OneOf(wanted) => texts
            .iter()
            .any(|text| wanted.iter().any(|option| option.as_str() == *text)),
        HeldValues::LongerThan(limit) => texts
            .iter()
            .any(|text| text.chars().count() > limit as usize),
        HeldValues::Below(floor) => number_of(value).is_some_and(|number| number < floor),
        HeldValues::Above(ceiling) => number_of(value).is_some_and(|number| number > ceiling),
    }
}

/// The texts a stored value holds, none for a value that is not text.
fn texts_of(value: &MetadataValue) -> Vec<&str> {
    match value {
        MetadataValue::String(text) => vec![text.as_str()],
        MetadataValue::StringArray(items) => items.iter().map(String::as_str).collect(),
        MetadataValue::Integer(_)
        | MetadataValue::Number(_)
        | MetadataValue::Bool(_)
        | MetadataValue::Null => Vec::new(),
    }
}

/// The number a stored value holds, if it is one.
fn number_of(value: &MetadataValue) -> Option<f64> {
    match value {
        MetadataValue::Integer(number) => Some(*number as f64),
        MetadataValue::Number(number) => Some(*number),
        MetadataValue::String(_)
        | MetadataValue::StringArray(_)
        | MetadataValue::Bool(_)
        | MetadataValue::Null => None,
    }
}

/// In-memory declared attributes: each tenant's declarations, in the order
/// they were first saved.
#[derive(Default)]
pub struct FakeUserAttributeStore {
    declared: TenantRows<AttributeDefinition<ResolvedTenant>>,
}

impl TenantScoped for FakeUserAttributeStore {}

impl FakeUserAttributeStore {
    /// A tenant that has declared nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The tenant [`test_ctx`] carries, having already declared
    /// `definitions`.
    ///
    /// [`test_ctx`]: crate::test_support::test_ctx
    #[must_use]
    pub fn holding(definitions: Vec<AttributeDefinition<ResolvedTenant>>) -> Self {
        let store = Self::empty();
        let tenant = seeded_tenant();
        definitions
            .into_iter()
            .for_each(|definition| store.declared.insert(tenant, definition));
        store
    }

    /// How many declarations are held, across every tenant.
    #[must_use]
    pub fn count_declared(&self) -> usize {
        self.declared.count()
    }
}

#[async_trait]
impl UserAttributeStore for FakeUserAttributeStore {
    async fn load_schema(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AttributeDefinition<ResolvedTenant>>, DomainError> {
        Ok(self
            .declared
            .collect(tenant_id, |_| true, AttributeDefinition::clone))
    }

    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<Option<AttributeDefinition<ResolvedTenant>>, DomainError> {
        Ok(self.declared.find(
            tenant_id,
            |definition| names(definition, namespace, key),
            AttributeDefinition::clone,
        ))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        definition: &AttributeDefinition<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let same = |held: &AttributeDefinition<ResolvedTenant>| {
            names(held, definition.namespace(), definition.key())
        };
        self.declared.upsert(**tenant_id, same, definition.clone());
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<(), DomainError> {
        self.declared
            .remove(tenant_id, |definition| names(definition, namespace, key));
        Ok(())
    }

    async fn count(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        Ok(self.declared.collect(tenant_id, |_| true, |_| ()).len() as u64)
    }
}

impl Fake for Arc<dyn UserAttributeStore> {
    fn fake() -> Self {
        Arc::new(FakeUserAttributeStore::empty())
    }
}

/// Whether `definition` declares the attribute `key` in `namespace`.
fn names(
    definition: &AttributeDefinition<ResolvedTenant>,
    namespace: AttributeNamespace,
    key: &AttributeKey,
) -> bool {
    definition.namespace() == namespace && definition.key() == key
}
