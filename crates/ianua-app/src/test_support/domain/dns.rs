//! DNS fakes: resolvers that answer a proof one way, a zone manager that
//! keeps what it is told to serve, and a zone reader the nameservers load
//! from.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    DelegationLabel, HeldZone, RecordKind, RecordName, RecordSet, TxtValue,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, TenantId};

use crate::ports::domain::{DnsResolver, DnsZoneReader, DnsZoneWriter};
use crate::test_support::Fake;

/// DNS resolver that finds every record it is asked about.
pub struct AcceptingDnsResolver;

#[async_trait]
impl DnsResolver for AcceptingDnsResolver {
    async fn verify_txt_record(
        &self,
        _name: &RecordName,
        _expected: &TxtValue,
    ) -> Result<bool, DomainError> {
        Ok(true)
    }

    async fn verify_cname(
        &self,
        _domain: &DomainName,
        _expected_target: &DomainName,
    ) -> Result<bool, DomainError> {
        Ok(true)
    }

    async fn verify_delegation(
        &self,
        _domain: &DomainName,
        _expected_nameservers: &[DomainName],
    ) -> Result<bool, DomainError> {
        Ok(true)
    }
}

/// DNS resolver that finds no record it is asked about.
pub struct RejectingDnsResolver;

#[async_trait]
impl DnsResolver for RejectingDnsResolver {
    async fn verify_txt_record(
        &self,
        _name: &RecordName,
        _expected: &TxtValue,
    ) -> Result<bool, DomainError> {
        Ok(false)
    }

    async fn verify_cname(
        &self,
        _domain: &DomainName,
        _expected_target: &DomainName,
    ) -> Result<bool, DomainError> {
        Ok(false)
    }

    async fn verify_delegation(
        &self,
        _domain: &DomainName,
        _expected_nameservers: &[DomainName],
    ) -> Result<bool, DomainError> {
        Ok(false)
    }
}

/// In-memory zone manager for use case tests.
///
/// Records what was opened and written, so a test can prove a delegated
/// registration actually made the name answerable rather than only
/// labelling it delegated.
#[derive(Default)]
pub struct FakeDnsZoneWriter {
    zones: Mutex<Vec<(TenantId, DomainName)>>,
    sets: Mutex<Vec<(TenantId, DomainName, RecordSet)>>,
    nameservers: Vec<DomainName>,
}

impl FakeDnsZoneWriter {
    /// A zone writer advertising `nameservers` for each created zone.
    #[must_use]
    pub fn with_nameservers(nameservers: Vec<DomainName>) -> Self {
        Self {
            nameservers,
            ..Self::default()
        }
    }

    /// Zones opened so far.
    #[must_use]
    pub fn opened(&self) -> Vec<DomainName> {
        self.zones
            .lock()
            .unwrap()
            .iter()
            .map(|(_, zone)| zone.clone())
            .collect()
    }

    /// Record sets written so far, paired with the zone holding them.
    #[must_use]
    pub fn written(&self) -> Vec<(DomainName, RecordSet)> {
        self.sets
            .lock()
            .unwrap()
            .iter()
            .map(|(_, zone, set)| (zone.clone(), set.clone()))
            .collect()
    }

    fn holder_of(&self, hostname: &DomainName) -> Option<TenantId> {
        self.zones
            .lock()
            .unwrap()
            .iter()
            .find(|(_, zone)| zone == hostname)
            .map(|(holder, _)| *holder)
    }
}

fn in_zone(
    held: &(TenantId, DomainName, RecordSet),
    tenant_id: &TenantId,
    hostname: &DomainName,
) -> bool {
    held.0 == *tenant_id && held.1 == *hostname
}

#[async_trait]
impl DnsZoneWriter for FakeDnsZoneWriter {
    async fn create_zone(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        label: &DelegationLabel,
    ) -> Result<Vec<DomainName>, DomainError> {
        match self.holder_of(hostname) {
            Some(holder) if holder != *tenant_id => {
                return Err(DomainError::conflict("zone is held by another tenant"));
            }
            Some(_) => {}
            None => self
                .zones
                .lock()
                .unwrap()
                .push((*tenant_id, hostname.clone())),
        }
        label.nameservers(&self.nameservers)
    }

    async fn replace_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        set: &RecordSet,
    ) -> Result<(), DomainError> {
        if self.holder_of(hostname) != Some(*tenant_id) {
            return Err(DomainError::NotFound);
        }
        let mut sets = self.sets.lock().unwrap();
        sets.retain(|held| !(in_zone(held, tenant_id, hostname) && held.2.answers_same_as(set)));
        sets.push((*tenant_id, hostname.clone(), set.clone()));
        Ok(())
    }

    async fn add_to_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        addition: &RecordSet,
    ) -> Result<(), DomainError> {
        if self.holder_of(hostname) != Some(*tenant_id) {
            return Err(DomainError::NotFound);
        }
        let mut sets = self.sets.lock().unwrap();
        let held = sets.iter().position(|held| {
            in_zone(held, tenant_id, hostname) && held.2.answers_same_as(addition)
        });
        let Some(index) = held else {
            sets.push((*tenant_id, hostname.clone(), addition.clone()));
            return Ok(());
        };
        sets[index].2 = sets[index].2.merged_with(addition)?;
        Ok(())
    }

    async fn remove_from_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        removal: &RecordSet,
    ) -> Result<(), DomainError> {
        let mut sets = self.sets.lock().unwrap();
        let held = sets
            .iter()
            .position(|held| in_zone(held, tenant_id, hostname) && held.2.answers_same_as(removal));
        let Some(index) = held else {
            return Ok(());
        };
        match sets[index].2.without_values_of(removal) {
            Some(rest) => sets[index].2 = rest,
            None => {
                sets.remove(index);
            }
        }
        Ok(())
    }

    async fn remove_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        name: &RecordName,
        kind: RecordKind,
    ) -> Result<(), DomainError> {
        self.sets.lock().unwrap().retain(|held| {
            !(in_zone(held, tenant_id, hostname) && held.2.name() == name && held.2.kind() == kind)
        });
        Ok(())
    }

    async fn record_sets(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
    ) -> Result<Vec<RecordSet>, DomainError> {
        let mut found: Vec<RecordSet> = self
            .sets
            .lock()
            .unwrap()
            .iter()
            .filter(|held| in_zone(held, tenant_id, hostname))
            .map(|(_, _, set)| set.clone())
            .collect();
        found.sort_by(|a, b| a.name().cmp(b.name()).then_with(|| a.kind().cmp(&b.kind())));
        Ok(found)
    }

    async fn delete_zone(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
    ) -> Result<(), DomainError> {
        self.zones
            .lock()
            .unwrap()
            .retain(|(holder, zone)| !(holder == tenant_id && zone == hostname));
        self.sets
            .lock()
            .unwrap()
            .retain(|held| !in_zone(held, tenant_id, hostname));
        Ok(())
    }

    async fn transfer_zone(
        &self,
        from: &TenantId,
        to: &TenantId,
        hostname: &DomainName,
    ) -> Result<(), DomainError> {
        self.zones
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|(holder, zone)| holder == from && zone == hostname)
            .for_each(|(holder, _)| *holder = *to);
        self.sets
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|held| in_zone(held, from, hostname))
            .for_each(|held| held.0 = *to);
        Ok(())
    }
}

/// Zone reader answering with the zones it was given, or failing as a
/// database that is down does.
pub enum FakeDnsZoneReader {
    /// Answers with these zones on every load.
    Holding(Vec<HeldZone>),
    /// Fails every load.
    Unreachable,
}

#[async_trait]
impl DnsZoneReader for FakeDnsZoneReader {
    async fn load_all_zones(&self) -> Result<Vec<HeldZone>, DomainError> {
        match self {
            Self::Holding(zones) => Ok(zones.clone()),
            Self::Unreachable => Err(DomainError::infra_msg("the zone store is unreachable")),
        }
    }
}

impl Fake for Arc<dyn DnsResolver> {
    fn fake() -> Self {
        Arc::new(AcceptingDnsResolver)
    }
}

impl Fake for Arc<dyn DnsZoneReader> {
    fn fake() -> Self {
        Arc::new(FakeDnsZoneReader::Holding(Vec::new()))
    }
}

impl Fake for Arc<dyn DnsZoneWriter> {
    fn fake() -> Self {
        Arc::new(FakeDnsZoneWriter::default())
    }
}
