//! A fake for what connections' group mappings gave each person.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::federation::connection::{MappedHoldings, MappedHoldingsRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, TenantId, UserId};

use crate::ports::TenantScoped;
use crate::ports::federation::MappedHoldingsStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// In-memory store of mapped holdings, each record kept under its tenant.
#[derive(Default)]
pub struct FakeMappedHoldings {
    records: Mutex<Vec<(TenantId, MappedHoldings<ResolvedTenant>)>>,
}

impl TenantScoped for FakeMappedHoldings {}

impl FakeMappedHoldings {
    /// A store holding no record.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Every record kept in `tenant`.
    #[must_use]
    pub fn all(&self, tenant: &ScopedTenant) -> Vec<MappedHoldings<ResolvedTenant>> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|(kept_in, _)| kept_in == &**tenant)
            .map(|(_, holdings)| copy_holdings(holdings))
            .collect()
    }
}

#[async_trait]
impl MappedHoldingsStore for FakeMappedHoldings {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<Option<MappedHoldings<ResolvedTenant>>, DomainError> {
        Ok(self
            .all(tenant_id)
            .into_iter()
            .find(|held| held.connection_id() == connection_id && held.user_id() == user_id))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        holdings: &MappedHoldings<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut records = self.records.lock().unwrap();
        records.retain(|(kept_in, held)| {
            !(kept_in == &**tenant_id
                && held.connection_id() == holdings.connection_id()
                && held.user_id() == holdings.user_id())
        });
        records.push((**tenant_id, copy_holdings(holdings)));
        Ok(())
    }
}

impl Fake for Arc<dyn MappedHoldingsStore> {
    fn fake() -> Self {
        Arc::new(FakeMappedHoldings::empty())
    }
}

/// `holdings` written out and read back, as storage would return them.
fn copy_holdings(holdings: &MappedHoldings<ResolvedTenant>) -> MappedHoldings<ResolvedTenant> {
    MappedHoldings::reconstitute(MappedHoldingsRow {
        connection_id: *holdings.connection_id(),
        user_id: *holdings.user_id(),
        roles: holdings.roles().to_vec(),
        groups: holdings.groups().to_vec(),
    })
    .expect("a record the domain made reads back")
}
