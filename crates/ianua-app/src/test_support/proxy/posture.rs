//! A posture provider that answers as a test tells it to, and the
//! standings of the devices a test remembers.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::authentication::device_trust::{DeviceStanding, TrustedDevice};
use ianua_domain::domains::proxy::stages::posture::DevicePosture;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Fact, TrustedDeviceId};

use crate::ports::TenantScoped;
use crate::ports::proxy::{DeviceInQuestion, DeviceStandings, PostureProvider};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// What a [`FakePostureProvider`] answers every question with.
enum Answer {
    /// Returns this posture assessment for every device.
    Reports(DevicePosture),
    /// That it knows nothing of the device.
    KnowsNothing,
    /// An error, as a provider that cannot be reached gives.
    Unreachable,
}

/// In-memory posture provider for tests, giving one answer for every device.
pub struct FakePostureProvider {
    answer: Answer,
}

impl FakePostureProvider {
    /// A provider that reports `posture` for every device.
    #[must_use]
    pub fn reporting(posture: DevicePosture) -> Self {
        Self {
            answer: Answer::Reports(posture),
        }
    }

    /// A provider that knows nothing of any device.
    #[must_use]
    pub fn knowing_nothing() -> Self {
        Self {
            answer: Answer::KnowsNothing,
        }
    }

    /// A provider that cannot be reached.
    #[must_use]
    pub fn unreachable() -> Self {
        Self {
            answer: Answer::Unreachable,
        }
    }
}

impl TenantScoped for FakePostureProvider {}

#[async_trait]
impl PostureProvider for FakePostureProvider {
    async fn posture_of(
        &self,
        _tenant_id: &ScopedTenant,
        _device: &DeviceInQuestion,
    ) -> Result<Fact<DevicePosture>, DomainError> {
        match &self.answer {
            Answer::Reports(posture) => Ok(Fact::Known(posture.clone())),
            Answer::KnowsNothing => Ok(Fact::Unknown),
            Answer::Unreachable => Err(DomainError::infra_msg(
                "the posture provider did not answer in time",
            )),
        }
    }
}

impl Fake for Arc<dyn PostureProvider> {
    fn fake() -> Self {
        Arc::new(FakePostureProvider::knowing_nothing())
    }
}

/// In-memory standings of remembered devices, read from the devices a test
/// hands it.
#[derive(Default)]
pub struct FakeDeviceStandings {
    standings: HashMap<TrustedDeviceId, DeviceStanding>,
}

impl FakeDeviceStandings {
    /// The standings of `devices`, as their records hold them.
    #[must_use]
    pub fn of<'a>(devices: impl IntoIterator<Item = &'a TrustedDevice<ResolvedTenant>>) -> Self {
        Self {
            standings: devices
                .into_iter()
                .map(|device| (*device.id(), device.standing()))
                .collect(),
        }
    }
}

impl TenantScoped for FakeDeviceStandings {}

#[async_trait]
impl DeviceStandings for FakeDeviceStandings {
    async fn standing_of(
        &self,
        _tenant_id: &ScopedTenant,
        device: &TrustedDeviceId,
    ) -> Result<Option<DeviceStanding>, DomainError> {
        Ok(self.standings.get(device).copied())
    }
}

impl Fake for Arc<dyn DeviceStandings> {
    fn fake() -> Self {
        Arc::new(FakeDeviceStandings::default())
    }
}
