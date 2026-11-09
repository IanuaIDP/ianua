//! A device authorization as its row holds it: read back into the
//! aggregate, and written out from it. The user code is kept sealed, so the
//! store opens it before the row is rebuilt, and seals it before it is
//! written.

use ianua_domain::domains::oauth::grants::device_authorization::{
    DeviceAuthRow, DeviceAuthState, DeviceAuthorization, LastPoll, PollInterval,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DeviceUserCode, OAuthClientId, TenantId, TokenHash, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::oauth::scopes::{scopes_column, scopes_from};

/// What a device authorization row is, so a refusal names it.
pub(super) const DEVICE: Stored = Stored("device authorization");

/// A device authorization as it is read, with its tenant. The store's
/// checked queries fill it.
pub(super) struct DeviceAuthRecord {
    pub(super) tenant_id: Uuid,
    pub(super) device_code_hash: String,
    pub(super) user_code_sealed: String,
    pub(super) client_id: Uuid,
    pub(super) scopes: Vec<String>,
    pub(super) status: String,
    pub(super) approved_by: Option<Uuid>,
    pub(super) interval_secs: i32,
    pub(super) last_polled_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl DeviceAuthRecord {
    /// The authorization the record holds, showing `user_code` once opened,
    /// rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, the status does not fit its approver, or the row breaks a
    /// rule the authorization keeps.
    pub(super) fn into_device(
        self,
        user_code: DeviceUserCode,
    ) -> Result<DeviceAuthorization<ResolvedTenant>, DomainError> {
        let seconds = u16::try_from(self.interval_secs)
            .map_err(|_| DomainError::corrupt_row(DEVICE.0, "a poll interval out of range"))?;
        DeviceAuthorization::reconstitute(DeviceAuthRow {
            device_code_hash: TokenHash::from_stored(self.device_code_hash),
            user_code,
            client_id: OAuthClientId::from_uuid(self.client_id),
            scopes: scopes_from(DEVICE, self.scopes)?,
            state: DeviceAuthState::from_stored(
                DEVICE.choice(&self.status)?,
                self.approved_by.map(UserId::from_uuid),
            )?,
            interval: DEVICE.value("interval", PollInterval::seconds(seconds))?,
            last_poll: LastPoll::from_stored(self.last_polled_at),
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }

    /// The tenant the authorization belongs to.
    pub(super) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }
}

/// A device authorization's columns, as they are written, but for its user
/// code, which the store hashes and seals.
pub(super) struct DeviceAuthColumns<'a> {
    pub(super) device_code_hash: &'a str,
    pub(super) client_id: &'a Uuid,
    pub(super) scopes: Vec<String>,
    pub(super) status: &'static str,
    pub(super) approved_by: Option<Uuid>,
    pub(super) interval_secs: i32,
    pub(super) last_polled_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl<'a> DeviceAuthColumns<'a> {
    /// The columns `auth` is written to.
    pub(super) fn of(auth: &'a DeviceAuthorization<ResolvedTenant>) -> Self {
        Self {
            device_code_hash: auth.device_code_hash().as_str(),
            client_id: auth.client_id().as_uuid(),
            scopes: scopes_column(auth.scopes()),
            status: auth.status().word(),
            approved_by: auth.approved_by().map(|person| *person.as_uuid()),
            interval_secs: i32::from(auth.interval().as_secs()),
            last_polled_at: auth.last_poll().at(),
            created_at: auth.created_at(),
            expires_at: auth.expires_at(),
        }
    }
}
