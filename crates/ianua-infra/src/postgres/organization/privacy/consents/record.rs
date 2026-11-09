//! A member's consent record as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::identity::privacy::consent::ConsentDecision;
use ianua_domain::domains::organization::members::privacy::consent::{
    OrgConsentRecord, OrgConsentRecordRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConsentId, Fact, IpAddress, Label, OrgUserId, OrganizationId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const CONSENT: Stored = Stored("organization consent record");

/// A consent record as it is read. The store's checked queries fill it.
pub(super) struct ConsentRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) org_user_id: Uuid,
    pub(super) consent_type: String,
    pub(super) granted: bool,
    pub(super) version: String,
    pub(super) ip_address: Option<String>,
    pub(super) recorded_at: OffsetDateTime,
}

impl ConsentRecord {
    /// The record the row holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules or the kind of consent is unknown.
    pub(super) fn into_record(self) -> Result<OrgConsentRecord, DomainError> {
        let ip_address = self
            .ip_address
            .map(|ip| CONSENT.value("ip address", IpAddress::new(ip)))
            .transpose()?;
        OrgConsentRecord::reconstitute(OrgConsentRecordRow {
            id: ConsentId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            org_user_id: OrgUserId::from_uuid(self.org_user_id),
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
    pub(super) organization_id: &'a Uuid,
    pub(super) org_user_id: &'a Uuid,
    pub(super) consent_type: &'static str,
    pub(super) granted: bool,
    pub(super) version: &'a str,
    pub(super) ip_address: Option<&'a str>,
    pub(super) recorded_at: OffsetDateTime,
}

impl<'a> ConsentColumns<'a> {
    /// The columns `record` is written to.
    pub(super) fn of(record: &'a OrgConsentRecord) -> Self {
        let ip_address = match record.ip_address() {
            Fact::Known(ip) => Some(ip.as_str()),
            Fact::Unknown => None,
        };
        Self {
            id: record.id().as_uuid(),
            organization_id: record.organization_id().as_uuid(),
            org_user_id: record.org_user_id().as_uuid(),
            consent_type: record.consent_type().word(),
            granted: bool::from(record.decision()),
            version: record.version().as_str(),
            ip_address,
            recorded_at: record.recorded_at(),
        }
    }
}
