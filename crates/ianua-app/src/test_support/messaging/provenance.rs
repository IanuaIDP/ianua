//! Fakes for the provenance a relayed agent message carries: its payload
//! hash and the signed claim of who wrote it.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::provenance::{
    MessageProvenance, PayloadHash, SealedProvenance,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::ports::broker::{MessageProvenanceSigner, MessageProvenanceVerifier, PayloadHasher};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// Hashes a payload to 32 copies of its first byte: payloads that differ in
/// their first byte never share a hash.
pub struct FirstByteHasher;

#[async_trait]
impl PayloadHasher for FirstByteHasher {
    async fn hash(&self, payload: &[u8]) -> PayloadHash {
        PayloadHash::from_bytes([payload.first().copied().unwrap_or(0); 32])
    }
}

/// Signs provenance by handing out an opaque token and remembering it under
/// its tenant; verifies only the tokens it handed out, in the tenant it
/// handed them out in.
#[derive(Default)]
pub struct MapProvenanceStore {
    by_token: Mutex<HashMap<(TenantId, String), MessageProvenance>>,
}

impl MapProvenanceStore {
    /// A store that has signed nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MessageProvenanceSigner for MapProvenanceStore {
    async fn sign(
        &self,
        tenant_id: &ScopedTenant,
        provenance: &MessageProvenance,
    ) -> Result<SealedProvenance, DomainError> {
        let mut by_token = self.by_token.lock().unwrap();
        let token = format!("sealed-provenance-{:04}", by_token.len());
        by_token.insert((**tenant_id, token.clone()), provenance.clone());
        Ok(SealedProvenance::new(&token).expect("a fake token has a sealed token's shape"))
    }
}

#[async_trait]
impl MessageProvenanceVerifier for MapProvenanceStore {
    async fn verify(
        &self,
        tenant_id: &ScopedTenant,
        token: &SealedProvenance,
    ) -> Result<MessageProvenance, DomainError> {
        self.by_token
            .lock()
            .unwrap()
            .get(&(**tenant_id, token.as_str().to_owned()))
            .cloned()
            .ok_or_else(|| DomainError::unauthorized("unknown provenance token"))
    }
}

impl Fake for std::sync::Arc<dyn PayloadHasher> {
    fn fake() -> Self {
        std::sync::Arc::new(FirstByteHasher)
    }
}

impl Fake for std::sync::Arc<dyn MessageProvenanceSigner> {
    fn fake() -> Self {
        std::sync::Arc::new(MapProvenanceStore::new())
    }
}

impl Fake for std::sync::Arc<dyn MessageProvenanceVerifier> {
    fn fake() -> Self {
        std::sync::Arc::new(MapProvenanceStore::new())
    }
}
