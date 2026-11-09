//! Shipping finished requests to the log stores tenants chose.
//!
//! Queued and batched like the request records; each batch is split by
//! tenant and handed to the app's ship use case, which sends every target
//! of the tenant what it takes. A store that is slow or gone costs records
//! in somebody else's log store, never a request's time.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use ianua_app::ports::runtime::{DroppedRecords, RequestObserver};
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::proxy::log_shipping::ShipRequestRecordsUseCase;
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::proxy::observation::RequestObservation;
use ianua_domain::types::{Fact, TenantId};

use crate::observability::batching::{BatchLimits, Batched, Deliver, Queueing};

/// The longest shipping one tenant's share of a batch may take.
const SHIP_TIMEOUT: Duration = Duration::from_secs(15);

/// Ships each finished request that resolved a tenant to that tenant's log
/// stores.
pub(crate) struct ShippedLog {
    queue: Batched<RequestObservation>,
}

impl ShippedLog {
    /// Starts shipping through `ship` until `shutdown` stops, counting what
    /// the queue drops into `dropped`.
    #[must_use]
    pub(crate) fn start(
        ship: Arc<ShipRequestRecordsUseCase>,
        dropped: Arc<dyn DroppedRecords>,
        shutdown: &Shutdown,
    ) -> Self {
        let queueing = Queueing::new(BatchLimits::DEFAULT, dropped);
        Self {
            queue: Batched::start(Shipper { ship }, queueing, shutdown),
        }
    }
}

impl RequestObserver for ShippedLog {
    fn observe(&self, observation: &RequestObservation) {
        if matches!(observation.tenant_id, Fact::Unknown) {
            return;
        }
        self.queue.record(observation.clone());
    }
}

/// The use case a batch is shipped through.
struct Shipper {
    ship: Arc<ShipRequestRecordsUseCase>,
}

impl Shipper {
    /// Ships `records`, all `tenant`'s, giving up after the timeout.
    async fn ship_tenant(&self, tenant: TenantId, records: Vec<RequestObservation>) {
        let scope = ScopedTenant::from_request_host(tenant);
        let count = records.len();
        match tokio::time::timeout(SHIP_TIMEOUT, self.ship.execute(&scope, records)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::warn!(%tenant, records = count, %error, "request records not shipped");
            }
            Err(_) => {
                tracing::warn!(%tenant, records = count, "request records not shipped in time");
            }
        }
    }
}

impl Deliver<RequestObservation> for Shipper {
    async fn deliver(&self, batch: Vec<RequestObservation>) {
        let by_tenant = by_tenant(batch);
        join_all(
            by_tenant
                .into_iter()
                .map(|(tenant, records)| self.ship_tenant(tenant, records)),
        )
        .await;
    }

    fn name(&self) -> &'static str {
        "log shipping"
    }
}

/// `batch` split by the tenant each request resolved to.
fn by_tenant(batch: Vec<RequestObservation>) -> HashMap<TenantId, Vec<RequestObservation>> {
    let mut split: HashMap<TenantId, Vec<RequestObservation>> = HashMap::new();
    for observation in batch {
        let Fact::Known(tenant) = observation.tenant_id else {
            continue;
        };
        split.entry(tenant).or_default().push(observation);
    }
    split
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::request_observation;
    use ianua_domain::domains::proxy::observation::RequestOutcome;

    use super::*;

    fn of(tenant: Fact<TenantId>) -> RequestObservation {
        RequestObservation {
            tenant_id: tenant,
            ..request_observation(RequestOutcome::Undecided)
        }
    }

    /// A mixed batch groups two records under Acme and one under Globex,
    /// omitting the record with no known tenant.
    #[test]
    fn a_mixed_batch_is_split_by_tenant() {
        let acme = TenantId::new();
        let globex = TenantId::new();

        let split = by_tenant(vec![
            of(Fact::Known(acme)),
            of(Fact::Known(globex)),
            of(Fact::Known(acme)),
            of(Fact::Unknown),
        ]);

        assert_eq!(split.len(), 2);
        assert_eq!(split[&acme].len(), 2);
        assert_eq!(split[&globex].len(), 1);
    }
}
