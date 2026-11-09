//! Fakes for the assertion key ports: one store that keeps each tenant's
//! set as storage would, a signer that signs nothing, and a verifier that
//! checks only what it issued.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::crypto::assertion_key::{
    AssertionKey, AssertionKeyRow, AssertionKeySet, AssertionSigningKey, PrivateHalf,
};
use ianua_domain::domains::proxy::assertion::{AssertedCaller, UpstreamAssertion};
use ianua_domain::domains::proxy::exchange::ExchangedToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::TenantId;
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::crypto::{
    AssertionKeyStore, AssertionSigner, AssertionSigningKeys, AssertionVerifier,
    CrossTenantAssertionKeys,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::crypto::stores::tenants_holding_rotated;
use crate::test_support::{Fake, test_ctx};

/// In-memory assertion keys, kept as storage keeps them: a set found again
/// holds no private half, and the private halves are kept apart, by tenant
/// and kid, for the gateway's read.
#[derive(Default)]
pub struct FakeAssertionKeyStore {
    sets: Mutex<HashMap<TenantId, AssertionKeySet<ResolvedTenant>>>,
    private_halves: Mutex<HashMap<(TenantId, String), Secret>>,
    active: Mutex<Vec<TenantId>>,
}

impl TenantScoped for FakeAssertionKeyStore {}

impl FakeAssertionKeyStore {
    /// No tenant has assertion keys.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The test tenant holds `set`, saved as storage would keep it.
    #[must_use]
    pub fn holding(set: &AssertionKeySet<ResolvedTenant>) -> Self {
        let store = Self::default();
        store.put(test_ctx().tenant_id(), set);
        store
    }

    /// `tenant_id` holds `set`, beside whatever other tenants hold.
    ///
    /// # Panics
    ///
    /// When a key of `set` cannot be kept, as a store would refuse it.
    pub fn put(&self, tenant_id: TenantId, set: &AssertionKeySet<ResolvedTenant>) {
        self.kept(tenant_id, set).unwrap();
    }

    /// `tenant_id` is active, holding keys or not: one holding none is due
    /// its first, as a tenant made before assertion keys were.
    pub fn activate(&self, tenant_id: TenantId) {
        self.active.lock().unwrap().push(tenant_id);
    }

    /// The set `tenant_id` holds, as last saved.
    #[must_use]
    pub fn set_of(&self, tenant_id: TenantId) -> Option<AssertionKeySet<ResolvedTenant>> {
        self.sets.lock().unwrap().get(&tenant_id).cloned()
    }

    /// Keeps `set` for `tenant_id`: each fresh private half apart, each key
    /// as it reads back from storage. A key new to the tenant with no
    /// private half to write is refused, as the store refuses it.
    fn kept(
        &self,
        tenant_id: TenantId,
        set: &AssertionKeySet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut private_halves = self.private_halves.lock().unwrap();
        let mut stored = Vec::with_capacity(set.keys().len());
        for key in set.keys() {
            let place = (tenant_id, key.kid().as_str().to_owned());
            match key.private_half() {
                PrivateHalf::Fresh(secret) => {
                    private_halves.insert(place, secret.clone());
                }
                PrivateHalf::Stored if !private_halves.contains_key(&place) => {
                    return Err(DomainError::infra_msg("a new key holds no private half"));
                }
                PrivateHalf::Stored => {}
            }
            stored.push(as_stored(key)?);
        }
        let set = AssertionKeySet::from_keys(stored)?;
        self.sets.lock().unwrap().insert(tenant_id, set);
        Ok(())
    }
}

/// `key` as it reads back from storage, without its private half.
fn as_stored(key: &AssertionKey) -> Result<AssertionKey, DomainError> {
    AssertionKey::reconstitute(AssertionKeyRow {
        kid: key.kid().clone(),
        algorithm: key.algorithm(),
        public_key: key.public_key().clone(),
        state: key.state(),
        created_at: key.created_at(),
    })
}

#[async_trait]
impl AssertionKeyStore for FakeAssertionKeyStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AssertionKeySet<ResolvedTenant>>, DomainError> {
        Ok(self.set_of(**tenant_id))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        keys: &AssertionKeySet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.kept(**tenant_id, keys)
    }
}

#[async_trait]
impl AssertionSigningKeys for FakeAssertionKeyStore {
    async fn signing(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AssertionSigningKey>, DomainError> {
        let Some(set) = self.set_of(**tenant_id) else {
            return Ok(None);
        };
        let Some(key) = set.signing_key() else {
            return Ok(None);
        };
        let place = (**tenant_id, key.kid().as_str().to_owned());
        let private = self
            .private_halves
            .lock()
            .unwrap()
            .get(&place)
            .cloned()
            .ok_or_else(|| DomainError::infra_msg("the private half is missing"))?;
        Ok(AssertionSigningKey::of(&set, private))
    }
}

#[async_trait]
impl CrossTenantAssertionKeys for FakeAssertionKeyStore {
    async fn tenants_with_rotated_keys(&self) -> Result<Vec<TenantId>, DomainError> {
        let sets = self.sets.lock().unwrap();
        Ok(tenants_holding_rotated(
            sets.iter(),
            AssertionKeySet::keys,
            AssertionKey::status,
        ))
    }

    async fn tenants_due(&self, cutoff: OffsetDateTime) -> Result<Vec<TenantId>, DomainError> {
        let sets = self.sets.lock().unwrap();
        let keyless: Vec<TenantId> = self
            .active
            .lock()
            .unwrap()
            .iter()
            .filter(|tenant_id| !sets.contains_key(tenant_id))
            .copied()
            .collect();
        Ok(sets
            .iter()
            .filter(|(_, set)| {
                !set.keys()
                    .iter()
                    .any(|key| key.is_active() && key.created_at() >= cutoff)
            })
            .map(|(tenant_id, _)| *tenant_id)
            .chain(keyless)
            .collect())
    }
}

/// Signs nothing: answers `assertion.{kid}.{sub}` or `exchanged.{kid}.{sub}`
/// and records each assertion and exchanged token it was asked to sign.
#[derive(Default)]
pub struct FakeAssertionSigner {
    /// The assertions it was asked to sign, in order.
    pub signed: Mutex<Vec<UpstreamAssertion>>,
    /// The exchanged tokens it was asked to sign, in order.
    pub exchanged: Mutex<Vec<ExchangedToken>>,
}

#[async_trait]
impl AssertionSigner for FakeAssertionSigner {
    async fn sign(
        &self,
        assertion: &UpstreamAssertion,
        key: &AssertionSigningKey,
    ) -> Result<Secret, DomainError> {
        self.signed.lock().unwrap().push(assertion.clone());
        Ok(Secret::new(format!(
            "assertion.{}.{}",
            key.kid(),
            assertion.caller().subject()
        )))
    }

    async fn sign_exchanged(
        &self,
        token: &ExchangedToken,
        key: &AssertionSigningKey,
    ) -> Result<Secret, DomainError> {
        self.exchanged.lock().unwrap().push(token.clone());
        Ok(Secret::new(format!(
            "exchanged.{}.{}",
            key.kid(),
            token.caller().subject()
        )))
    }
}

/// Checks only the assertions it issued, each for the tenant it issued it
/// for: anything else does not check, as a forged one would not.
#[derive(Default)]
pub struct FakeAssertionVerifier {
    issued: Mutex<Vec<(TenantId, String, AssertedCaller)>>,
}

impl TenantScoped for FakeAssertionVerifier {}

impl FakeAssertionVerifier {
    /// An assertion of `tenant_id` saying `caller` made the request.
    #[must_use]
    pub fn issue(&self, tenant_id: TenantId, caller: AssertedCaller) -> Secret {
        let mut issued = self.issued.lock().unwrap();
        let value = format!("assertion-{}", issued.len());
        issued.push((tenant_id, value.clone(), caller));
        Secret::new(value)
    }
}

#[async_trait]
impl AssertionVerifier for FakeAssertionVerifier {
    async fn caller(
        &self,
        tenant_id: &ScopedTenant,
        assertion: &Secret,
    ) -> Result<AssertedCaller, DomainError> {
        self.issued
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, value, _)| tenant == &**tenant_id && value == assertion.expose())
            .map(|(_, _, caller)| caller.clone())
            .ok_or_else(|| DomainError::unauthorized("the assertion does not check"))
    }
}

impl Fake for Arc<dyn AssertionVerifier> {
    fn fake() -> Self {
        Arc::new(FakeAssertionVerifier::default())
    }
}

impl Fake for Arc<dyn AssertionKeyStore> {
    fn fake() -> Self {
        Arc::new(FakeAssertionKeyStore::empty())
    }
}

impl Fake for Arc<dyn AssertionSigningKeys> {
    fn fake() -> Self {
        Arc::new(FakeAssertionKeyStore::empty())
    }
}

impl Fake for Arc<dyn CrossTenantAssertionKeys> {
    fn fake() -> Self {
        Arc::new(FakeAssertionKeyStore::empty())
    }
}

impl Fake for Arc<dyn AssertionSigner> {
    fn fake() -> Self {
        Arc::new(FakeAssertionSigner::default())
    }
}
