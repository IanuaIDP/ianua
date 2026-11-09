//! Fakes for log shipping: the targets a tenant keeps and the shipper that
//! sends records to them.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::proxy::log_shipping::{
    LogDestination, LogFormat, LogShippingTarget, LogTargetSettings, ShippedRecords,
    ShippingCredential,
};
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::test_support::authority::anyone_holding;
use ianua_domain::types::{Label, LogShippingTargetId, PublicHttpsUrl, TenantId};

use crate::ports::TenantScoped;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor};
use crate::ports::proxy::{LogShipper, LogShippingStore, Shipment};
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::FakeEncryptor;
use crate::test_support::{Fake, rivals, test_ctx};

/// The API key Ann's SIEM takes, as she typed it.
pub const TEST_SHIPPING_KEY: &str = "siem-key-1";

/// The name `name`, as a target name.
///
/// # Panics
///
/// Panics if `name` is not a valid label.
#[must_use]
pub fn log_target_name(name: &str) -> Label {
    Label::new("name", name).expect("a valid target name")
}

/// Where the test tenant's target `id` keeps its credential.
#[must_use]
pub fn shipping_key_place(id: &LogShippingTargetId) -> SealedFor {
    SealedFor::new(
        SealOwner::Tenant(test_ctx().tenant_id()),
        SealedField::LogShippingCredential,
        id,
    )
}

/// Ann's SIEM collector, taking every record as JSON lines with
/// [`TEST_SHIPPING_KEY`] sealed by the fake encryptor for the test
/// tenant's target `id`.
///
/// # Panics
///
/// Never in practice: the address is a public HTTPS one.
#[must_use]
pub fn siem_settings(id: &LogShippingTargetId) -> LogTargetSettings {
    LogTargetSettings {
        destination: LogDestination::Https(
            PublicHttpsUrl::new("https://siem.example.com/ingest").expect("a public address"),
        ),
        credential: ShippingCredential::Sealed(FakeEncryptor::sealed_for(
            TEST_SHIPPING_KEY,
            &shipping_key_place(id),
        )),
        records: ShippedRecords::All,
        format: LogFormat::JsonLines,
    }
}

/// A target named `siem` shipping to Ann's SIEM, its creation already
/// taken out.
///
/// # Panics
///
/// Never in practice: an admin creates a valid target.
#[must_use]
pub fn test_log_target() -> LogShippingTarget<ResolvedTenant> {
    let admin = RoutingControl::new(anyone_holding(SystemPermission::all()));
    let id = LogShippingTargetId::new();
    let mut target =
        LogShippingTarget::create(id, log_target_name("siem"), siem_settings(&id), &admin)
            .expect("an admin creates a target");
    let _ = target.take_events(&test_ctx().tenant());
    target
}

/// In-memory log shipping store for tests.
///
/// Keeps each target under its tenant and refuses a second target by the
/// same name in one tenant, as the Postgres store does.
#[derive(Default)]
pub struct FakeLogShippingStore {
    targets: Mutex<Vec<(TenantId, LogShippingTarget<ResolvedTenant>)>>,
}

impl FakeLogShippingStore {
    /// A store holding `target` in `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, target: LogShippingTarget<ResolvedTenant>) -> Self {
        Self {
            targets: Mutex::new(vec![(tenant, target)]),
        }
    }

    /// The tenant's target with `id`, as stored.
    #[must_use]
    pub fn stored(
        &self,
        tenant: TenantId,
        id: &LogShippingTargetId,
    ) -> Option<LogShippingTarget<ResolvedTenant>> {
        self.targets
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, target)| *owner == tenant && target.id() == id)
            .map(|(_, target)| target.clone())
    }

    /// How many targets the store holds, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.targets.lock().unwrap().len()
    }
}

impl TenantScoped for FakeLogShippingStore {}

#[async_trait]
impl LogShippingStore for FakeLogShippingStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        target_id: &LogShippingTargetId,
    ) -> Result<Option<LogShippingTarget<ResolvedTenant>>, DomainError> {
        Ok(self.stored(**tenant_id, target_id))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<LogShippingTarget<ResolvedTenant>>, DomainError> {
        let mut all: Vec<_> = self
            .targets
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, target)| target.clone())
            .collect();
        all.sort_by(|a, b| a.name().as_str().cmp(b.name().as_str()));
        Ok(all)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        target: &LogShippingTarget<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut targets = self.targets.lock().unwrap();
        let by_name = |kept: &LogShippingTarget<ResolvedTenant>| (kept.name().clone(), *kept.id());
        if targets
            .iter()
            .any(|entry| rivals(entry, tenant_id, target, by_name))
        {
            return Err(DomainError::conflict(
                "a log shipping target by that name already exists",
            ));
        }
        targets.retain(|(owner, held)| !(owner == &**tenant_id && held.id() == target.id()));
        targets.push((**tenant_id, target.clone()));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        target_id: &LogShippingTargetId,
    ) -> Result<(), DomainError> {
        self.targets
            .lock()
            .unwrap()
            .retain(|(owner, held)| !(owner == &**tenant_id && held.id() == target_id));
        Ok(())
    }
}

/// One batch a [`FakeLogShipper`] was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShippedBatch {
    /// The kind of destination it went to.
    pub destination: &'static str,
    /// The opened credential it was sent with, when there was one.
    pub credential: Option<String>,
    /// How many records it held.
    pub records: usize,
}

/// What a [`FakeLogShipper`] does with a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShipperMood {
    /// Takes it.
    Accepting,
    /// Fails it, as a destination that cannot be reached does.
    Failing,
}

/// In-memory log shipper for tests, remembering every batch it took.
pub struct FakeLogShipper {
    mood: ShipperMood,
    batches: Mutex<Vec<ShippedBatch>>,
}

impl FakeLogShipper {
    /// A shipper that takes every batch.
    #[must_use]
    pub fn accepting() -> Self {
        Self {
            mood: ShipperMood::Accepting,
            batches: Mutex::new(Vec::new()),
        }
    }

    /// A shipper whose every destination cannot be reached.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            mood: ShipperMood::Failing,
            batches: Mutex::new(Vec::new()),
        }
    }

    /// Every batch taken, in order.
    #[must_use]
    pub fn batches(&self) -> Vec<ShippedBatch> {
        self.batches.lock().unwrap().clone()
    }
}

#[async_trait]
impl LogShipper for FakeLogShipper {
    async fn ship(&self, shipment: Shipment<'_>) -> Result<(), DomainError> {
        if self.mood == ShipperMood::Failing {
            return Err(DomainError::infra_msg("the destination did not answer"));
        }
        self.batches.lock().unwrap().push(ShippedBatch {
            destination: shipment.destination.kind(),
            credential: shipment.credential.map(|key| key.expose().to_owned()),
            records: shipment.records.len(),
        });
        Ok(())
    }
}

impl Fake for Arc<dyn LogShippingStore> {
    fn fake() -> Self {
        Arc::new(FakeLogShippingStore::default())
    }
}

impl Fake for Arc<dyn LogShipper> {
    fn fake() -> Self {
        Arc::new(FakeLogShipper::accepting())
    }
}
