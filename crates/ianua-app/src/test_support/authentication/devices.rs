//! Fakes for trusted devices, of tenant users and organization members.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::device_status::DeviceStatus;
use ianua_domain::domains::authentication::device_trust::{TrustedDevice, TrustedDeviceRow};
use ianua_domain::isolation::SecurityScope;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::builders::label;
use ianua_domain::types::{
    IpAddress, OrgUserId, PrincipalId, TokenHash, TrustedDeviceId, UserAgent, UserId,
};

use crate::ports::TenantScoped;
use crate::ports::authentication::TrustedDeviceStore;
use crate::ports::organization::OrgTrustedDeviceStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authentication::{Holder, Plane};

/// The digest of the secret [`known_device`] presents.
pub const KNOWN_DEVICE_HASH: &str = "known-device-hash";

/// One device whose secret hashes to [`KNOWN_DEVICE_HASH`], owned by
/// `subject`, in `status`, on the plane `S`.
///
/// # Panics
///
/// Never in practice: the device's fields are fixed and valid.
#[must_use]
pub fn known_device<S: SecurityScope>(
    subject: impl Into<PrincipalId>,
    status: DeviceStatus,
) -> TrustedDevice<S> {
    stored_device(subject.into(), KNOWN_DEVICE_HASH, "Test Device", status)
}

/// A device trusted a moment ago, as storage would hold it.
fn stored_device<S: SecurityScope>(
    subject: PrincipalId,
    secret_hash: &str,
    name: &str,
    status: DeviceStatus,
) -> TrustedDevice<S> {
    let now = clock::now();
    TrustedDevice::reconstitute(TrustedDeviceRow {
        id: TrustedDeviceId::new(),
        subject_id: subject,
        secret_hash: TokenHash::from_stored(secret_hash.to_owned()),
        device_name: label(name),
        last_user_agent: UserAgent::new("Mozilla/5.0").expect("a fixed user agent is valid"),
        last_ip: IpAddress::new("10.0.0.1").expect("a fixed address is valid"),
        status,
        last_seen_at: now,
        created_at: now,
    })
    .expect("a fresh device row rebuilds")
}

/// `count` trusted devices of `subject`, their secrets hashing to `fp_0`,
/// `fp_1` and so on.
fn numbered_devices<S: SecurityScope>(
    subject: PrincipalId,
    count: u8,
) -> impl Iterator<Item = TrustedDevice<S>> {
    (0..count).map(move |i| {
        stored_device(
            subject,
            &format!("fp_{i}"),
            &format!("dev_{i}"),
            DeviceStatus::Trusted,
        )
    })
}

/// In-memory trusted-device store for tenant users and organization members
/// alike, keeping each device on its plane as it was last saved.
#[derive(Default)]
pub struct FakeTrustedDeviceStore {
    devices: Mutex<Vec<(Plane, TrustedDevice<ResolvedTenant>)>>,
    member_devices: Mutex<Vec<TrustedDevice<ResolvedOrganization>>>,
}

impl FakeTrustedDeviceStore {
    /// Nobody has a trusted device.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Holds `devices` in the test tenant.
    #[must_use]
    pub fn holding(devices: impl IntoIterator<Item = TrustedDevice<ResolvedTenant>>) -> Self {
        Self::holding_on(Plane::test_tenant(), devices)
    }

    /// Holds `devices` on `plane`.
    #[must_use]
    pub fn holding_on(
        plane: Plane,
        devices: impl IntoIterator<Item = TrustedDevice<ResolvedTenant>>,
    ) -> Self {
        let store = Self::default();
        store
            .devices
            .lock()
            .unwrap()
            .extend(devices.into_iter().map(|device| (plane, device)));
        store
    }

    /// Holds the organization members' `devices`.
    #[must_use]
    pub fn holding_members(
        devices: impl IntoIterator<Item = TrustedDevice<ResolvedOrganization>>,
    ) -> Self {
        let store = Self::default();
        store.member_devices.lock().unwrap().extend(devices);
        store
    }

    /// Holds `count` trusted devices for `holder`, their secrets hashing to
    /// `fp_0`, `fp_1` and so on.
    #[must_use]
    pub fn with_devices(holder: impl Into<Holder>, count: u8) -> Self {
        let holder = holder.into();
        match holder.plane() {
            Plane::Organization => Self::holding_members(numbered_devices(holder.subject(), count)),
            plane @ Plane::Tenant(_) => {
                Self::holding_on(plane, numbered_devices(holder.subject(), count))
            }
        }
    }

    /// How many devices are held, across planes.
    #[must_use]
    pub fn count(&self) -> usize {
        self.devices.lock().unwrap().len() + self.member_devices.lock().unwrap().len()
    }

    fn select(
        &self,
        plane: Plane,
        matches: impl Fn(&TrustedDevice<ResolvedTenant>) -> bool,
    ) -> Vec<TrustedDevice<ResolvedTenant>> {
        self.devices
            .lock()
            .unwrap()
            .iter()
            .filter(|(held_on, device)| *held_on == plane && matches(device))
            .map(|(_, device)| copy_device(device))
            .collect()
    }

    fn select_members(
        &self,
        matches: impl Fn(&TrustedDevice<ResolvedOrganization>) -> bool,
    ) -> Vec<TrustedDevice<ResolvedOrganization>> {
        self.member_devices
            .lock()
            .unwrap()
            .iter()
            .filter(|device| matches(device))
            .map(copy_device)
            .collect()
    }

    fn put(&self, plane: Plane, device: &TrustedDevice<ResolvedTenant>) {
        let mut devices = self.devices.lock().unwrap();
        devices.retain(|(held_on, held)| !(*held_on == plane && held.id() == device.id()));
        devices.push((plane, copy_device(device)));
    }
}

/// A copy of `device`, which does not implement `Clone`.
fn copy_device<S: SecurityScope>(device: &TrustedDevice<S>) -> TrustedDevice<S> {
    TrustedDevice::reconstitute(TrustedDeviceRow {
        id: *device.id(),
        subject_id: device.subject_id(),
        secret_hash: device.secret_hash().clone(),
        device_name: device.device_name().clone(),
        last_user_agent: device.last_user_agent().clone(),
        last_ip: device.last_ip().clone(),
        status: device.status(),
        last_seen_at: device.last_seen_at(),
        created_at: device.created_at(),
    })
    .expect("a live device's own row rebuilds")
}

impl TenantScoped for FakeTrustedDeviceStore {}

#[async_trait]
impl TrustedDeviceStore for FakeTrustedDeviceStore {
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<TrustedDevice<ResolvedTenant>>, DomainError> {
        let owner = PrincipalId::from(*user_id);
        Ok(self.select(Plane::of(tenant_id), |device| device.subject_id() == owner))
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &TrustedDeviceId,
    ) -> Result<Option<TrustedDevice<ResolvedTenant>>, DomainError> {
        Ok(self
            .select(Plane::of(tenant_id), |device| device.id() == id)
            .pop())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        device: &TrustedDevice<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.put(Plane::of(tenant_id), device);
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &TrustedDeviceId,
    ) -> Result<(), DomainError> {
        let plane = Plane::of(tenant_id);
        self.devices
            .lock()
            .unwrap()
            .retain(|(held_on, device)| !(*held_on == plane && device.id() == id));
        Ok(())
    }
}

#[async_trait]
impl OrgTrustedDeviceStore for FakeTrustedDeviceStore {
    async fn list_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<TrustedDevice<ResolvedOrganization>>, DomainError> {
        let owner = PrincipalId::from(*org_user_id);
        Ok(self.select_members(|device| device.subject_id() == owner))
    }

    async fn find_by_id(
        &self,
        org_user_id: &OrgUserId,
        id: &TrustedDeviceId,
    ) -> Result<Option<TrustedDevice<ResolvedOrganization>>, DomainError> {
        let owner = PrincipalId::from(*org_user_id);
        Ok(self
            .select_members(|device| device.id() == id && device.subject_id() == owner)
            .pop())
    }

    async fn save(
        &self,
        org_user_id: &OrgUserId,
        device: &TrustedDevice<ResolvedOrganization>,
    ) -> Result<(), DomainError> {
        let owner = PrincipalId::from(*org_user_id);
        if device.subject_id() != owner {
            return Err(DomainError::invalid(
                "a device is saved for the member who trusted it",
            ));
        }
        let mut devices = self.member_devices.lock().unwrap();
        if devices
            .iter()
            .any(|held| held.id() == device.id() && held.subject_id() != owner)
        {
            return Err(DomainError::conflict(
                "this device is already kept for another member",
            ));
        }
        devices.retain(|held| held.id() != device.id());
        devices.push(copy_device(device));
        Ok(())
    }
}

impl Fake for Arc<dyn TrustedDeviceStore> {
    fn fake() -> Self {
        Arc::new(FakeTrustedDeviceStore::empty())
    }
}

impl Fake for Arc<dyn OrgTrustedDeviceStore> {
    fn fake() -> Self {
        Arc::new(FakeTrustedDeviceStore::empty())
    }
}
