//! Ship request records: send a tenant's finished requests to every place
//! it ships them to.
//!
//! The gateway batches its observations per tenant and hands each batch
//! here. Every active target gets the records its selection takes, signed in
//! with its own credential, opened only for the send. One destination that
//! is down does not stop the others.

use std::sync::Arc;

use ianua_domain::domains::proxy::log_shipping::LogShippingTarget;
use ianua_domain::domains::proxy::observation::RequestObservation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Fact, LogShippingTargetId};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::proxy::{LogShipper, LogShippingStore, Shipment};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::proxy::log_shipping::credential::{credential_place, opened_credential};

/// What came of shipping a batch to one target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShipmentResult {
    /// This many records were sent.
    Shipped {
        /// How many.
        records: usize,
    },
    /// The target took none of the records, or is paused.
    NothingToShip,
    /// The records could not be sent. The failure is logged; the batch is
    /// not retried.
    Failed,
}

/// What came of shipping a batch to one of the tenant's targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetShipment {
    /// The destination that received this batch's delivery attempt.
    pub target_id: LogShippingTargetId,
    /// What came of it.
    pub result: ShipmentResult,
}

/// The ports [`ShipRequestRecordsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ShipRequestRecordsPorts {
    /// Keeps the tenant's log shipping targets.
    pub log_shipping_store: Arc<dyn LogShippingStore>,
    /// Sends a batch to a destination, refusing internal addresses.
    pub shipper: Arc<dyn LogShipper>,
    /// Opens each target's sealed credential for the send.
    pub encryptor: Arc<dyn SecretEncryptor>,
}

/// Ships a tenant's request records to its log shipping targets.
pub struct ShipRequestRecordsUseCase {
    ports: ShipRequestRecordsPorts,
}

impl ShipRequestRecordsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ShipRequestRecordsPorts) -> Self {
        Self { ports }
    }

    /// Sends `tenant`'s `target` the records of `observed` it takes.
    async fn ship_to(
        &self,
        tenant: &ScopedTenant,
        target: &LogShippingTarget<ResolvedTenant>,
        observed: &[&RequestObservation],
    ) -> ShipmentResult {
        let records = selected_for(target, observed);
        if records.is_empty() {
            return ShipmentResult::NothingToShip;
        }
        let place = credential_place(tenant, target.id());
        let opened =
            opened_credential(self.ports.encryptor.as_ref(), target.credential(), &place).await;
        let credential = match opened {
            Ok(credential) => credential,
            Err(error) => return failed(target, &error),
        };
        let shipment = Shipment {
            destination: target.destination(),
            credential: credential.as_ref(),
            format: target.format(),
            records: &records,
        };
        match self.ports.shipper.ship(shipment).await {
            Ok(()) => ShipmentResult::Shipped {
                records: records.len(),
            },
            Err(error) => failed(target, &error),
        }
    }
}

impl Query for ShipRequestRecordsUseCase {
    type Caller = ScopedTenant;
    type Input = Vec<RequestObservation>;
    type Output = Result<Vec<TargetShipment>, AppError>;

    /// Ships the batch to each of the tenant's targets, and says what came
    /// of each. Only the tenant's own requests are shipped, whatever else
    /// the batch holds. It keeps nothing and records nothing, so a failed
    /// send changes no target.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the targets cannot be read.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        observed: Vec<RequestObservation>,
    ) -> Result<Vec<TargetShipment>, AppError> {
        let targets = self
            .ports
            .log_shipping_store
            .list(tenant)
            .await
            .or_internal()?;
        let own = of_tenant(tenant, &observed);
        let mut shipped = Vec::with_capacity(targets.len());
        for target in &targets {
            shipped.push(TargetShipment {
                target_id: *target.id(),
                result: self.ship_to(tenant, target, &own).await,
            });
        }
        Ok(shipped)
    }
}

/// The requests of `observed` that `tenant` made, so a mixed batch never
/// sends one tenant's records to another's destination.
fn of_tenant<'a>(
    tenant: &ScopedTenant,
    observed: &'a [RequestObservation],
) -> Vec<&'a RequestObservation> {
    observed
        .iter()
        .filter(|request| request.tenant_id == Fact::Known(**tenant))
        .collect()
}

/// The records of `observed` that `target` ships.
fn selected_for(
    target: &LogShippingTarget<ResolvedTenant>,
    observed: &[&RequestObservation],
) -> Vec<RequestObservation> {
    observed
        .iter()
        .filter(|request| target.ships(request))
        .copied()
        .cloned()
        .collect()
}

/// Logs a failed send to `target`, naming the target but never its address
/// or credential.
fn failed(
    target: &LogShippingTarget<ResolvedTenant>,
    error: &dyn std::fmt::Display,
) -> ShipmentResult {
    tracing::warn!(
        target_id = %target.id(),
        destination = target.destination().kind(),
        %error,
        "request records not shipped"
    );
    ShipmentResult::Failed
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::proxy::log_shipping::{LogTargetSettings, ShippedRecords};
    use ianua_domain::domains::proxy::observation::{
        DecidingRule, DecidingStage, GatewayCheck, RequestOutcome,
    };
    use ianua_domain::domains::routing::control::RoutingControl;
    use ianua_domain::shared::events::raised::Raises as _;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::proxy::{
        FakeLogShipper, FakeLogShippingStore, ShippedBatch, TEST_SHIPPING_KEY, siem_settings,
        test_log_target,
    };
    use crate::test_support::{block_on, request_observation, test_ctx};

    /// A request in the test tenant, decided as `outcome`.
    fn observed(outcome: RequestOutcome) -> RequestObservation {
        RequestObservation {
            tenant_id: Fact::Known(test_ctx().tenant_id()),
            ..request_observation(outcome)
        }
    }

    /// A request forwarded and answered with 200.
    fn allowed() -> RequestObservation {
        observed(RequestOutcome::Allowed {
            upstream_status: 200,
        })
    }

    /// A request refused for want of a route.
    fn refused() -> RequestObservation {
        observed(RequestOutcome::Denied {
            status: 404,
            reason: "no route".to_owned(),
            decided_by: DecidingStage::Gateway(GatewayCheck::Route),
            rule: DecidingRule::Unnamed,
        })
    }

    /// The routing control of an admin, for seeding targets.
    fn admin() -> RoutingControl<'static> {
        RoutingControl::new(anyone_holding(SystemPermission::all()))
    }

    /// Ships `batch` to the targets `store` holds, through `shipper`.
    fn ship(
        store: FakeLogShippingStore,
        shipper: &Arc<FakeLogShipper>,
        batch: Vec<RequestObservation>,
    ) -> Vec<TargetShipment> {
        let use_case = ShipRequestRecordsUseCase::new(ShipRequestRecordsPorts {
            log_shipping_store: Arc::new(store),
            shipper: shipper.clone(),
            ..ShipRequestRecordsPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx().tenant(), batch)).unwrap()
    }

    /// Ann's SIEM takes every record. Both requests are sent, signed in with
    /// her key opened for the send.
    #[test]
    fn every_record_goes_to_a_target_taking_all() {
        let store = FakeLogShippingStore::holding(test_ctx().tenant_id(), test_log_target());
        let shipper = Arc::new(FakeLogShipper::accepting());

        let shipped = ship(store, &shipper, vec![allowed(), refused()]);

        assert_eq!(shipped[0].result, ShipmentResult::Shipped { records: 2 });
        assert_eq!(
            shipper.batches(),
            [ShippedBatch {
                destination: "https",
                credential: Some(TEST_SHIPPING_KEY.to_owned()),
                records: 2,
            }]
        );
    }

    /// Ann's SIEM takes refusals only. Only the refused request is sent.
    #[test]
    fn a_target_taking_refusals_gets_only_refusals() {
        let mut target = test_log_target();
        let refusals = LogTargetSettings {
            records: ShippedRecords::DeniedOnly,
            ..siem_settings(target.id())
        };
        target.change_settings(refusals, &admin()).unwrap();
        let store = FakeLogShippingStore::holding(test_ctx().tenant_id(), target);
        let shipper = Arc::new(FakeLogShipper::accepting());

        let shipped = ship(store, &shipper, vec![allowed(), refused()]);

        assert_eq!(shipped[0].result, ShipmentResult::Shipped { records: 1 });
    }

    /// Ann paused her SIEM target. Nothing is sent to it.
    #[test]
    fn a_paused_target_gets_nothing() {
        let mut target = test_log_target();
        target.pause(&admin()).unwrap();
        let _ = target.take_events(&test_ctx().tenant());
        let store = FakeLogShippingStore::holding(test_ctx().tenant_id(), target);
        let shipper = Arc::new(FakeLogShipper::accepting());

        let shipped = ship(store, &shipper, vec![allowed(), refused()]);

        assert_eq!(shipped[0].result, ShipmentResult::NothingToShip);
        assert!(shipper.batches().is_empty());
    }

    /// A batch containing one foreign request and one local request ships
    /// only the local record to the tenant's SIEM.
    #[test]
    fn another_tenants_records_are_never_shipped() {
        let store = FakeLogShippingStore::holding(test_ctx().tenant_id(), test_log_target());
        let shipper = Arc::new(FakeLogShipper::accepting());
        let elsewhere = RequestObservation {
            tenant_id: Fact::Known(TenantId::new()),
            ..allowed()
        };

        let shipped = ship(store, &shipper, vec![elsewhere, refused()]);

        assert_eq!(shipped[0].result, ShipmentResult::Shipped { records: 1 });
    }

    /// Ann's SIEM is down. The send fails and is reported as failed, not as
    /// an error for the whole batch.
    #[test]
    fn a_destination_that_is_down_fails_alone() {
        let store = FakeLogShippingStore::holding(test_ctx().tenant_id(), test_log_target());
        let shipper = Arc::new(FakeLogShipper::failing());

        let shipped = ship(store, &shipper, vec![refused()]);

        assert_eq!(shipped[0].result, ShipmentResult::Failed);
    }
}
