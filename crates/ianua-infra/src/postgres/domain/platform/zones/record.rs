//! Platform zones reconstructed from public columns only.

use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    HeldZone, RecordName, RecordSet, RecordValue, Serial, Ttl, TxtValue, Zone, ZoneStanding,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, IpAddress, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const PLATFORM: Stored = Stored("platform zone");

/// Public columns only; the nameserver has no privilege on sealed keys.
pub(super) struct ZoneRecord {
    pub(super) root: String,
    pub(super) tenant_id: Uuid,
    pub(super) nameservers: Vec<String>,
    pub(super) address: String,
    pub(super) changed_at: OffsetDateTime,
    pub(super) proofs: Vec<String>,
}

impl ZoneRecord {
    /// Builds root and wildcard address records plus only unexpired proofs.
    pub(super) fn into_held(self) -> Result<HeldZone, DomainError> {
        let root = PLATFORM.value("root", DomainName::new(self.root))?;
        let address = PLATFORM.value("address", IpAddress::new(self.address))?;
        let nameservers = self
            .nameservers
            .into_iter()
            .map(|name| PLATFORM.value("nameserver", DomainName::new(name)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut records = vec![
            record(root.as_str(), vec![RecordValue::Address(address.clone())])?,
            record(&format!("*.{root}"), vec![RecordValue::Address(address)])?,
        ];
        if !self.proofs.is_empty() {
            records.push(proofs(&root, self.proofs)?);
        }
        let zone = Zone::new(root, Serial::at(self.changed_at), records, nameservers)
            .map_err(DomainError::infra)?;
        Ok(HeldZone {
            zone,
            owner: TenantId::from_uuid(self.tenant_id),
            standing: ZoneStanding::Proven,
        })
    }
}

/// Groups simultaneous authorizations into one TXT record without dropping either proof.
fn proofs(root: &DomainName, proofs: Vec<String>) -> Result<RecordSet, DomainError> {
    let values = proofs
        .into_iter()
        .map(|value| {
            PLATFORM
                .value("proof", TxtValue::new(value))
                .map(RecordValue::Text)
        })
        .collect::<Result<Vec<_>, _>>()?;
    record(&format!("_acme-challenge.{root}"), values)
}

/// Uses short DNS caching so consent withdrawal and challenge changes propagate promptly.
fn record(name: &str, values: Vec<RecordValue>) -> Result<RecordSet, DomainError> {
    let name = PLATFORM.value("record name", RecordName::new(name))?;
    RecordSet::new(name, Ttl::shortest(), values).map_err(DomainError::infra)
}
