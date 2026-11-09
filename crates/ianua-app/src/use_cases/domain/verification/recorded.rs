//! Saving a registration whose proof changed, and recording the change.

use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::RegisteredDomainStore;
use crate::tenancy::ScopedTenant;

/// Saves `domain` in `tenant`, then dispatches what it raised, followed by
/// `then`, the record of what changed alongside it.
///
/// # Errors
///
/// `AppError::Internal` when the domain cannot be saved or the events
/// cannot be recorded.
pub(super) async fn save_and_record(
    store: &dyn RegisteredDomainStore,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    domain: &mut RegisteredDomain<ResolvedTenant>,
    then: Vec<DomainEvent>,
) -> Result<(), AppError> {
    store.save(tenant, domain).await.or_internal()?;
    let events: Vec<DomainEvent> = domain.take_events(tenant).into_iter().chain(then).collect();
    auditor.dispatch(&events).await.or_internal()
}
