//! The tenant whose provisioning a live stream follows.

use ianua_domain::types::TenantId;
use serde::Deserialize;
use uuid::Uuid;

/// `.../ws/workflow/{reference_id}`: the tenant being set up or torn down.
#[derive(Deserialize)]
pub(crate) struct ProvisioningPath {
    reference_id: Uuid,
}

impl ProvisioningPath {
    /// The tenant named.
    #[must_use]
    pub(crate) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.reference_id)
    }
}
