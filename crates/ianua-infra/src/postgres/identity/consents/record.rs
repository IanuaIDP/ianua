//! A consent record as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::identity::privacy::consent::{
    ConsentDecision, ConsentRecord, ConsentRecordRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConsentId, Fact, IpAddress, Label, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const CONSENT: Stored = Stored("consent record");

/// A consent record as it is read. The store's checked queries fill it.
pub(super) struct DecisionRecord {
    pub(super) id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) consent_type: String,
    pub(super) granted: bool,
    pub(super) version: String,
    pub(super) ip_address: Option<String>,
    pub(super) recorded_at: OffsetDateTime,
}

impl DecisionRecord {
    /// The decision the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules or a word is unknown.
    pub(super) fn into_consent(self) -> Result<ConsentRecord<ResolvedTenant>, DomainError> {
        let ip_address = self
            .ip_address
            .map(|address| CONSENT.value("ip address", IpAddress::new(address)))
            .transpose()?;
        ConsentRecord::reconstitute(ConsentRecordRow {
            id: ConsentId::from_uuid(self.id),
            user_id: UserId::from_uuid(self.user_id),
            consent_type: CONSENT.choice(&self.consent_type)?,
            granted: ConsentDecision::from(self.granted),
            version: CONSENT.value("version", Label::new("version", self.version))?,
            ip_address: Fact::from_option(ip_address),
            recorded_at: self.recorded_at,
        })
    }
}

/// A consent record's columns, as they are written.
pub(super) struct ConsentColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) consent_type: &'static str,
    pub(super) granted: bool,
    pub(super) version: &'a str,
    pub(super) ip_address: Option<&'a str>,
    pub(super) recorded_at: OffsetDateTime,
}

impl<'a> ConsentColumns<'a> {
    /// The columns `record` is written to.
    pub(super) fn of(record: &'a ConsentRecord<ResolvedTenant>) -> Self {
        Self {
            id: record.id().as_uuid(),
            user_id: record.user_id().as_uuid(),
            consent_type: record.consent_type().word(),
            granted: record.granted(),
            version: record.version().as_str(),
            ip_address: record.ip_address().known().copied().map(IpAddress::as_str),
            recorded_at: record.recorded_at(),
        }
    }
}
