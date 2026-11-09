//! A passkey ceremony as its row holds it: read back into the ceremony, and
//! written out from it.
//!
//! The words of a ceremony's purpose are the ones the organization's
//! ceremonies are stored with.

use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
    CeremonySubject, PasskeyCeremony, PasskeyCeremonyRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CeremonyId, TenantId, Usage, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const CEREMONY: Stored = Stored("passkey ceremony");

/// A ceremony as it is read. The store's checked queries fill it.
pub(super) struct CeremonyRecord {
    pub(super) id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) user_id: Option<Uuid>,
    pub(super) purpose: String,
    pub(super) state: Vec<u8>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl CeremonyRecord {
    /// The ceremony the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the purpose is unknown, or
    /// the row breaks a rule the ceremony keeps.
    pub(super) fn into_ceremony(self) -> Result<PasskeyCeremony, DomainError> {
        PasskeyCeremony::reconstitute(PasskeyCeremonyRow {
            id: CeremonyId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            subject: CeremonySubject::from_stored(self.user_id.map(UserId::from_uuid)),
            purpose: CEREMONY.choice(&self.purpose)?,
            state: self.state,
            created_at: self.created_at,
            expires_at: self.expires_at,
            usage: Usage::from_stored(self.consumed_at),
        })
    }
}

/// A ceremony's columns, as they are written.
pub(super) struct CeremonyColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) tenant_id: &'a Uuid,
    pub(super) user_id: Option<Uuid>,
    pub(super) purpose: &'static str,
    pub(super) state: &'a [u8],
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl<'a> CeremonyColumns<'a> {
    /// The columns `ceremony` is written to.
    pub(super) fn of(ceremony: &'a PasskeyCeremony) -> Self {
        Self {
            id: ceremony.id().as_uuid(),
            tenant_id: ceremony.tenant_id().as_uuid(),
            user_id: ceremony.user_id().map(|user| *user.as_uuid()),
            purpose: ceremony.purpose().word(),
            state: ceremony.state_for_storage(),
            created_at: ceremony.created_at(),
            expires_at: ceremony.expires_at(),
            consumed_at: ceremony.consumed_at(),
        }
    }
}
