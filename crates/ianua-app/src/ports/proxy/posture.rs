//! Device posture: asking an outside provider what it knows of a device,
//! and whether the device it names is one the person still trusts.

use async_trait::async_trait;
use ianua_domain::domains::authentication::device_trust::DeviceStanding;
use ianua_domain::domains::proxy::request::device::RequestDevice;
use ianua_domain::domains::proxy::stages::posture::DevicePosture;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Fact, TrustedDeviceId, UserId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// The device a request came from, as the gateway knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInQuestion {
    /// The person signed in on it.
    pub person: UserId,
    /// What names the device: a verified device certificate, the trusted
    /// device the person's session was signed in from, or nothing.
    pub device: RequestDevice,
}

/// Dyn-safe port for asking a device agent or device manager about a device.
///
/// The provider is outside the deployment, such as an MDM or an endpoint
/// agent's service. It is asked only about a device something names: by
/// the fingerprint of its verified device certificate, or by the trusted
/// device the session was signed in from. The adapter must give up after a
/// short timeout, so a slow provider holds no request, and reports that as
/// an error. The caller tells an error apart from a device nobody reported
/// on, and refuses both.
#[async_trait]
pub trait PostureProvider: Send + Sync + TenantScoped {
    /// What the provider last reported about `device`, or
    /// [`Fact::Unknown`] when it knows nothing of it.
    ///
    /// A report may name a trusted device only when it is the one the
    /// session names, or the one the certificate's device is enrolled as;
    /// the caller still holds that device to the person's own records.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the provider cannot be
    /// reached, does not answer in time, or answers with something it cannot
    /// read.
    async fn posture_of(
        &self,
        tenant_id: &ScopedTenant,
        device: &DeviceInQuestion,
    ) -> Result<Fact<DevicePosture>, DomainError>;
}

/// Dyn-safe port reading whose a remembered device is and whether it is
/// still trusted, and nothing else of it: the gateway, which asks, never
/// reads the digest of a device's secret.
#[async_trait]
pub trait DeviceStandings: Send + Sync + TenantScoped {
    /// The standing of `device`, or `None` when the tenant keeps no such
    /// device.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the device cannot be
    /// read.
    async fn standing_of(
        &self,
        tenant_id: &ScopedTenant,
        device: &TrustedDeviceId,
    ) -> Result<Option<DeviceStanding>, DomainError>;
}
