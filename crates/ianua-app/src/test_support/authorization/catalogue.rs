//! An in-memory permission catalogue: the resource types a tenant declares.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::authorization::resource_type::{
    ActionDefinition, ResourceType, ResourceTypeRow,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, ResourceTypeId, TenantId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authorization::{ResourceTypeSortField, ResourceTypeStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::listing::page;

/// In-memory catalogue that keeps every resource type it is handed, tenant
/// by tenant, and says as many roles use a key as the test set.
#[derive(Default)]
pub struct FakeResourceTypeStore {
    items: Mutex<Vec<(TenantId, ResourceType<ResolvedTenant>)>>,
    roles_using: u64,
}

impl TenantScoped for FakeResourceTypeStore {}

impl FakeResourceTypeStore {
    /// An empty catalogue.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// An empty catalogue that says `count` roles use any key.
    #[must_use]
    pub fn with_roles_using(count: u64) -> Self {
        Self {
            roles_using: count,
            ..Self::default()
        }
    }

    /// A catalogue declaring, in `tenant_id`, `key` holding data of `class`.
    #[must_use]
    pub fn declaring(tenant_id: TenantId, key: &str, class: DataClassLevel) -> Self {
        let store = Self::default();
        store
            .items
            .lock()
            .unwrap()
            .push((tenant_id, declared_as(key, key, class)));
        store
    }

    /// A catalogue declaring, in `tenant_id`, the resource types other tests
    /// grant: `project` and `billing`, each with `read` and a `write` that
    /// brings `read`.
    ///
    /// For any test that grants an app permission without being about the
    /// catalogue, which would otherwise fail the declaration check for a
    /// reason unrelated to what it shows.
    #[must_use]
    pub fn seeded(tenant_id: TenantId) -> Self {
        let store = Self::default();
        store.items.lock().unwrap().extend(
            [("project", "Project"), ("billing", "Billing")]
                .into_iter()
                .map(|(key, name)| (tenant_id, declared(key, name))),
        );
        store
    }

    /// How many resource types are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.items.lock().unwrap().len()
    }

    /// Every resource type `tenant_id` declares.
    pub(crate) fn of_tenant(&self, tenant_id: TenantId) -> Vec<ResourceType<ResolvedTenant>> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, _)| *tenant == tenant_id)
            .map(|(_, item)| item.clone())
            .collect()
    }
}

/// A resource type under `key`, named `name`, with `read` and a `write`
/// that brings `read`, holding internal data.
fn declared(key: &str, name: &str) -> ResourceType<ResolvedTenant> {
    declared_as(key, name, DataClassLevel::Internal)
}

/// A resource type under `key`, named `name`, with `read` and a `write`
/// that brings `read`, holding data of `class`.
fn declared_as(key: &str, name: &str, class: DataClassLevel) -> ResourceType<ResolvedTenant> {
    let now = clock::now();
    ResourceType::reconstitute(ResourceTypeRow {
        id: ResourceTypeId::new(),
        key: segment(key),
        display_name: label(name),
        description: None,
        actions: vec![
            ActionDefinition::new(segment("read"), label("read"), Vec::new()),
            ActionDefinition::new(segment("write"), label("write"), vec![segment("read")]),
        ],
        data_class: class,
        created_at: now,
        updated_at: now,
    })
    .expect("a declared resource type is a consistent row")
}

fn segment(value: &str) -> PermissionSegment {
    PermissionSegment::new("test", value).expect("a valid segment")
}

fn label(value: &str) -> Label {
    Label::new("test", value).expect("a valid label")
}

#[async_trait]
impl ResourceTypeStore for FakeResourceTypeStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ResourceTypeId,
    ) -> Result<Option<ResourceType<ResolvedTenant>>, DomainError> {
        Ok(self
            .of_tenant(**tenant_id)
            .into_iter()
            .find(|item| item.id() == id))
    }

    async fn find_by_key(
        &self,
        tenant_id: &ScopedTenant,
        key: &PermissionSegment,
    ) -> Result<Option<ResourceType<ResolvedTenant>>, DomainError> {
        Ok(self
            .of_tenant(**tenant_id)
            .into_iter()
            .find(|item| item.key() == key))
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ResourceTypeSortField>,
        request: &PageRequest,
    ) -> Result<Page<ResourceType<ResolvedTenant>>, DomainError> {
        let items = self.of_tenant(**tenant_id);
        page(items, sort, request)
    }

    async fn list_every(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ResourceType<ResolvedTenant>>, DomainError> {
        Ok(self.of_tenant(**tenant_id))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        resource_type: &ResourceType<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut items = self.items.lock().unwrap();
        let held = items
            .iter_mut()
            .find(|(tenant, held)| *tenant == **tenant_id && held.id() == resource_type.id());
        match held {
            Some((_, held)) => *held = resource_type.clone(),
            None => items.push((**tenant_id, resource_type.clone())),
        }
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &ResourceTypeId,
    ) -> Result<(), DomainError> {
        self.items
            .lock()
            .unwrap()
            .retain(|(tenant, item)| !(*tenant == **tenant_id && item.id() == id));
        Ok(())
    }

    async fn count_roles_using(
        &self,
        _tenant_id: &ScopedTenant,
        _key: &PermissionSegment,
    ) -> Result<u64, DomainError> {
        Ok(self.roles_using)
    }
}

impl Fake for Arc<dyn ResourceTypeStore> {
    fn fake() -> Self {
        Arc::new(FakeResourceTypeStore::empty())
    }
}
