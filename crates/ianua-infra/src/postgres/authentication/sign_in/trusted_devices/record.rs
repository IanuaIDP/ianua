//! A trusted device as its row holds it: read back into the aggregate, and
//! written out from it.
//!
//! The words of a device's status are the ones the organization's devices
//! are stored with.

use ianua_domain::domains::authentication::device_trust::{
    DeviceStanding, TrustedDevice, TrustedDeviceRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    IpAddress, Label, PrincipalId, TokenHash, TrustedDeviceId, UserAgent, UserId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const DEVICE: Stored = Stored("trusted device");

/// A trusted device as it is read. The store's checked queries fill it.
pub(super) struct DeviceRecord {
    pub(super) id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) secret_hash: String,
    pub(super) device_name: String,
    pub(super) last_user_agent: String,
    pub(super) last_ip: String,
    pub(super) status: String,
    pub(super) last_seen_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
}

impl DeviceRecord {
    /// The device the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the device
    /// keeps.
    pub(super) fn into_device(self) -> Result<TrustedDevice<ResolvedTenant>, DomainError> {
        TrustedDevice::reconstitute(TrustedDeviceRow {
            id: TrustedDeviceId::from_uuid(self.id),
            subject_id: PrincipalId::from(UserId::from_uuid(self.user_id)),
            secret_hash: TokenHash::from_stored(self.secret_hash),
            device_name: DEVICE
                .value("device name", Label::new("device_name", self.device_name))?,
            last_user_agent: DEVICE.value("user agent", UserAgent::new(self.last_user_agent))?,
            last_ip: DEVICE.value("ip address", IpAddress::new(self.last_ip))?,
            status: DEVICE.choice(&self.status)?,
            last_seen_at: self.last_seen_at,
            created_at: self.created_at,
        })
    }
}

/// Whose a trusted device is and whether it is still trusted, as read for
/// a check away from the sign-in.
pub(super) struct StandingRecord {
    pub(super) user_id: Uuid,
    pub(super) status: String,
}

impl StandingRecord {
    /// The standing the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the status word is
    /// unknown.
    pub(super) fn into_standing(self) -> Result<DeviceStanding, DomainError> {
        Ok(DeviceStanding::new(
            PrincipalId::from(UserId::from_uuid(self.user_id)),
            DEVICE.choice(&self.status)?,
        ))
    }
}

/// A trusted device's columns, as they are written.
pub(super) struct DeviceColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) user_id: Uuid,
    pub(super) secret_hash: &'a str,
    pub(super) device_name: &'a str,
    pub(super) last_user_agent: &'a str,
    pub(super) last_ip: &'a str,
    pub(super) status: &'static str,
    pub(super) last_seen_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> DeviceColumns<'a> {
    /// The columns `device` is written to, as its holder's.
    pub(super) fn of(device: &'a TrustedDevice<ResolvedTenant>) -> Self {
        Self {
            id: device.id().as_uuid(),
            user_id: *device.subject_id().as_uuid(),
            secret_hash: device.secret_hash().as_str(),
            device_name: device.device_name().as_str(),
            last_user_agent: device.last_user_agent().as_str(),
            last_ip: device.last_ip().as_str(),
            status: device.status().word(),
            last_seen_at: device.last_seen_at(),
            created_at: device.created_at(),
        }
    }
}
