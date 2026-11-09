//! Recording that a tenant's directory reached it, so the tenant can see
//! when its directory last synced.

use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::ScimStore;
use crate::tenancy::ScopedTenant;

/// Records that the directory synced through `endpoint` now. Only the time
/// is written, so a settings change made meanwhile is kept.
///
/// # Errors
///
/// - `AppError::Internal` when the time cannot be written.
pub(in crate::use_cases::scim) async fn record_sync(
    store: &dyn ScimStore,
    tenant: &ScopedTenant,
    mut endpoint: ScimEndpoint<ResolvedTenant>,
) -> Result<(), AppError> {
    endpoint.record_sync();
    store.save_last_sync(tenant, &endpoint).await.or_internal()
}

/// Records the sync through `endpoint`, then `events` as done by the
/// system, which is who acts for a directory.
///
/// # Errors
///
/// - `AppError::Internal` when the time or the events cannot be written.
pub(in crate::use_cases::scim) async fn record_synced(
    store: &dyn ScimStore,
    tenant: &ScopedTenant,
    endpoint: ScimEndpoint<ResolvedTenant>,
    auditor: &RequestAuditor,
    events: Vec<DomainEvent>,
) -> Result<(), AppError> {
    record_sync(store, tenant, endpoint).await?;
    auditor
        .dispatch_by(&ActorRef::System, events)
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::scim::ScimEndpointRow;
    use ianua_domain::types::Enablement;

    use super::*;
    use crate::test_support::federation::FakeScimStore;
    use crate::test_support::scim::directory_row;
    use crate::test_support::{block_on, test_ctx};

    fn endpoint_of(row: ScimEndpointRow) -> ScimEndpoint<ResolvedTenant> {
        ScimEndpoint::reconstitute(row).unwrap()
    }

    /// Okta's call went through. Acme sees when its directory last synced,
    /// and the endpoint's settings stay as stored.
    #[test]
    fn a_sync_is_recorded_without_touching_the_settings() {
        let tenant = test_ctx().tenant();
        let store = FakeScimStore::holding(&tenant, endpoint_of(directory_row()));
        let endpoint = block_on(store.find(&tenant)).unwrap().unwrap();
        let switched_off = endpoint_of(ScimEndpointRow {
            enabled: Enablement::Disabled,
            ..directory_row()
        });
        block_on(store.save(&tenant, &switched_off)).unwrap();

        block_on(record_sync(&store, &tenant, endpoint)).unwrap();

        let stored = block_on(store.find(&tenant)).unwrap().unwrap();
        assert!(stored.last_sync_at().is_some());
        assert!(!stored.enabled());
    }
}
