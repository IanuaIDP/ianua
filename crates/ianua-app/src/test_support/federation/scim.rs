//! Fakes for SCIM provisioning: the endpoint's configuration and its bearer
//! tokens.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::federation::scim::{ScimEndpoint, ScimEndpointRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Enablement, Setting, TenantId, TokenHash};

use crate::ports::TenantScoped;
use crate::ports::federation::{ScimStore, ScimTokenGenerator};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// In-memory SCIM store, one endpoint per tenant.
#[derive(Default)]
pub struct FakeScimStore {
    endpoints: Mutex<HashMap<TenantId, ScimEndpoint<ResolvedTenant>>>,
}

impl TenantScoped for FakeScimStore {}

impl FakeScimStore {
    /// A store holding no endpoint.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `endpoint` for `tenant`.
    #[must_use]
    pub fn holding(tenant: &ScopedTenant, endpoint: ScimEndpoint<ResolvedTenant>) -> Self {
        Self {
            endpoints: Mutex::new(HashMap::from([(**tenant, endpoint)])),
        }
    }
}

#[async_trait]
impl ScimStore for FakeScimStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ScimEndpoint<ResolvedTenant>>, DomainError> {
        self.endpoints
            .lock()
            .unwrap()
            .get(&**tenant_id)
            .map(copy_endpoint)
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        endpoint: &ScimEndpoint<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_endpoint(endpoint)?;
        self.endpoints.lock().unwrap().insert(**tenant_id, copy);
        Ok(())
    }

    async fn save_last_sync(
        &self,
        tenant_id: &ScopedTenant,
        endpoint: &ScimEndpoint<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut endpoints = self.endpoints.lock().unwrap();
        let Some(stored) = endpoints.get(&**tenant_id) else {
            return Ok(());
        };
        let synced = ScimEndpoint::reconstitute(ScimEndpointRow {
            last_sync_at: endpoint.last_sync_at(),
            ..row_of(stored)
        })?;
        endpoints.insert(**tenant_id, synced);
        Ok(())
    }
}

impl Fake for Arc<dyn ScimStore> {
    fn fake() -> Self {
        Arc::new(FakeScimStore::empty())
    }
}

/// `endpoint` written out and read back, as storage would return it.
fn copy_endpoint(
    endpoint: &ScimEndpoint<ResolvedTenant>,
) -> Result<ScimEndpoint<ResolvedTenant>, DomainError> {
    ScimEndpoint::reconstitute(row_of(endpoint))
}

/// `endpoint` as storage writes it.
fn row_of(endpoint: &ScimEndpoint<ResolvedTenant>) -> ScimEndpointRow {
    ScimEndpointRow {
        bearer_token_hash: endpoint.bearer_token_hash().clone(),
        enabled: Enablement::from(endpoint.enabled()),
        default_role_id: Setting::from_stored(endpoint.default_role_id().copied()),
        auto_activate: endpoint.auto_activate(),
        deactivate_on_remove: endpoint.deactivate_on_remove(),
        last_sync_at: endpoint.last_sync_at(),
        created_at: endpoint.created_at(),
    }
}

/// SCIM token generator that counts the tokens it makes, `scim-token-1`
/// first, and recognises a token by the hash it made for it.
#[derive(Default)]
pub struct FakeScimTokenGenerator {
    made: Mutex<u32>,
}

impl FakeScimTokenGenerator {
    /// A generator that has made no token yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ScimTokenGenerator for FakeScimTokenGenerator {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        let raw = format!("scim-token-{made}");
        let hash = token_hash(&raw);
        Ok((Secret::new(raw), hash))
    }

    fn verify(&self, presented: &Secret, hash: &TokenHash) -> bool {
        token_hash(presented.expose()) == *hash
    }
}

impl Fake for Arc<dyn ScimTokenGenerator> {
    fn fake() -> Self {
        Arc::new(FakeScimTokenGenerator::new())
    }
}

/// The hash the fake generator keeps for the raw token `raw`.
fn token_hash(raw: &str) -> TokenHash {
    TokenHash::from_stored(format!("hash:{raw}"))
}
