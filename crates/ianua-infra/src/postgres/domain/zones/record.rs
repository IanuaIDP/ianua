//! A DNS zone and its record sets as their rows hold them: read back into
//! the domain's zone and record sets, and a record set written out.

use std::collections::HashMap;

use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    HeldZone, RecordKind, RecordName, RecordSet, RecordValue, Serial, Ttl, Zone, ZoneStanding,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const DNS_ZONE: Stored = Stored("DNS zone");

const DNS_RECORD: Stored = Stored("DNS record");

/// Who holds a zone, and the nameservers it answers with. The store's
/// checked queries fill it.
pub(super) struct HolderRecord {
    pub(super) tenant_id: Uuid,
    pub(super) nameservers: Vec<String>,
}

impl HolderRecord {
    /// The nameservers of the zone, when `tenant` is the one holding it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when another tenant holds the zone,
    /// and `DomainError::Infrastructure` when a stored nameserver is not a
    /// domain name.
    pub(super) fn into_nameservers_of(
        self,
        tenant: &TenantId,
    ) -> Result<Vec<DomainName>, DomainError> {
        if self.tenant_id != *tenant.as_uuid() {
            return Err(DomainError::conflict(message!(
                "infra-the-zone-is-held-by-another",
                "the zone is held by another tenant"
            )));
        }
        nameservers_from(self.nameservers)
    }
}

/// A zone as it is read, with the tenant holding it and whether its name
/// was proved. The store's checked queries fill it.
pub(super) struct ZoneRecord {
    pub(super) hostname: String,
    pub(super) tenant_id: Uuid,
    pub(super) nameservers: Vec<String>,
    pub(super) changed_at: OffsetDateTime,
    pub(super) verified: bool,
}

impl ZoneRecord {
    /// The zone the record holds, answering with the sets `sets` keeps
    /// under its hostname, its serial read from when it last changed, with
    /// its holder and its standing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a stored name is not a
    /// domain name, or a set lies outside the zone.
    pub(super) fn into_held(
        self,
        sets: &mut HashMap<String, Vec<RecordSet>>,
    ) -> Result<HeldZone, DomainError> {
        let held = sets.remove(&self.hostname).unwrap_or_default();
        let apex = DNS_ZONE.value("hostname", DomainName::new(self.hostname))?;
        let zone = Zone::new(
            apex,
            Serial::at(self.changed_at),
            held,
            nameservers_from(self.nameservers)?,
        )
        .map_err(DomainError::infra)?;
        Ok(HeldZone {
            zone,
            owner: TenantId::from_uuid(self.tenant_id),
            standing: match self.verified {
                true => ZoneStanding::Proven,
                false => ZoneStanding::Unproven,
            },
        })
    }
}

/// The stored nameservers, each read back as a domain name.
fn nameservers_from(stored: Vec<String>) -> Result<Vec<DomainName>, DomainError> {
    stored
        .into_iter()
        .map(|name| DNS_ZONE.value("nameserver", DomainName::new(name)))
        .collect()
}

/// One record set as it is read, with the zone it is in. The store's
/// checked queries fill it.
pub(super) struct RecordSetRecord {
    pub(super) hostname: String,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) ttl: i32,
    pub(super) record_values: Vec<String>,
}

impl RecordSetRecord {
    /// The hostname of the zone the set is in, and the record set the
    /// record holds, each value read back from the spelling a zone file
    /// gives it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the type is unknown, a
    /// value does not read as its type, or the set breaks a rule a set
    /// keeps.
    pub(super) fn into_held(self) -> Result<(String, RecordSet), DomainError> {
        let kind: RecordKind = DNS_RECORD.choice(&self.kind)?;
        let values = self
            .record_values
            .iter()
            .map(|value| RecordValue::parse(kind, value).map_err(DomainError::infra))
            .collect::<Result<Vec<_>, _>>()?;
        let seconds = u32::try_from(self.ttl)
            .map_err(|_| DomainError::corrupt_row(DNS_RECORD.0, "a negative time to live"))?;
        let ttl = Ttl::seconds(seconds).map_err(DomainError::infra)?;
        let name = DNS_RECORD.value("name", RecordName::new(self.name))?;
        let set = RecordSet::new(name, ttl, values).map_err(DomainError::infra)?;
        Ok((self.hostname, set))
    }
}

/// A record set's columns, as they are written.
pub(super) struct RecordSetColumns<'a> {
    pub(super) name: &'a str,
    pub(super) kind: &'static str,
    pub(super) ttl: i32,
    pub(super) record_values: Vec<String>,
}

impl<'a> RecordSetColumns<'a> {
    /// The columns `set` is written to, each value spelled as a zone file
    /// spells it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the time to live does not
    /// fit its column.
    pub(super) fn of(set: &'a RecordSet) -> Result<Self, DomainError> {
        Ok(Self {
            name: set.name().as_str(),
            kind: set.kind().word(),
            ttl: i32::try_from(set.ttl().as_seconds()).map_err(DomainError::infra)?,
            record_values: set
                .values()
                .iter()
                .map(RecordValue::as_presentation)
                .collect(),
        })
    }
}
