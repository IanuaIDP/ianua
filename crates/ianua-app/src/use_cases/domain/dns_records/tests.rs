//! Fixtures shared by the DNS record use case tests.
//!
//! All three operations start from the same place, a delegated domain of
//! the test tenant and the zone behind it, so the setup lives here once.

use std::sync::Arc;

use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    DelegationLabel, RecordName, RecordSet, RecordValue, Ttl, TxtValue,
};
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{DomainId, DomainName, IpAddress};

use crate::acting::TenantAuthorities;
use crate::ports::domain::DnsZoneWriter;
use crate::test_support::acting::FakeTenantAuthorities;
use crate::test_support::domain::{DomainSeed, FakeDnsZoneWriter, FakeDomainStore};
use crate::test_support::{FakeEventDispatcher, block_on, test_ctx};
use crate::use_cases::domain::dns_records::zone::ZonePorts;

/// The hostname every fixture delegates.
pub(super) const DELEGATED_HOST: &str = "auth.acme.test";

/// The delegated hostname as a [`DomainName`].
pub(super) fn host() -> DomainName {
    DomainName::new(DELEGATED_HOST).unwrap()
}

/// A record owner name.
pub(super) fn record_name(value: &str) -> RecordName {
    RecordName::new(value).unwrap()
}

/// An address set with one value.
pub(super) fn address_set(name: &str, address: &str) -> RecordSet {
    RecordSet::new(
        record_name(name),
        Ttl::standard(),
        vec![RecordValue::Address(IpAddress::new(address).unwrap())],
    )
    .unwrap()
}

/// A text set with one value.
pub(super) fn text_set(name: &str, value: &str) -> RecordSet {
    RecordSet::new(
        record_name(name),
        Ttl::standard(),
        vec![RecordValue::Text(TxtValue::new(value).unwrap())],
    )
    .unwrap()
}

/// Builds one DNS alias value with the standard TTL for record tests.
pub(super) fn alias_set(name: &str, target: &str) -> RecordSet {
    RecordSet::new(
        record_name(name),
        Ttl::standard(),
        vec![RecordValue::Alias(DomainName::new(target).unwrap())],
    )
    .unwrap()
}

/// The test tenant's domain [`DELEGATED_HOST`], its zone, and what the
/// caller holds.
pub(super) struct ZoneFixture {
    pub(super) domains: Arc<FakeDomainStore>,
    pub(super) zones: Arc<FakeDnsZoneWriter>,
    pub(super) audit: Arc<FakeEventDispatcher>,
    pub(super) id: DomainId,
    authorities: Arc<dyn TenantAuthorities>,
}

impl ZoneFixture {
    /// `domain`, registered by the test tenant, with its zone opened as
    /// registration opens it. The zone is opened whatever the connection,
    /// so a test proves the use cases go by the domain, not by a missing
    /// zone.
    fn of(domain: RegisteredDomain<ResolvedTenant>) -> Self {
        let id = *domain.id();
        let zones = Arc::new(FakeDnsZoneWriter::with_nameservers(vec![
            DomainName::new("ns1.ianua.test").unwrap(),
        ]));
        block_on(DnsZoneWriter::create_zone(
            zones.as_ref(),
            &test_ctx().tenant_id(),
            &host(),
            &DelegationLabel::for_registration(&id),
        ))
        .unwrap();
        Self {
            domains: Arc::new(FakeDomainStore::holding(test_ctx().tenant_id(), [domain])),
            zones,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
            authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        }
    }

    /// The same domain and zone as `other`, with a fresh audit record.
    pub(super) fn sharing(other: &Self) -> Self {
        Self {
            domains: other.domains.clone(),
            zones: other.zones.clone(),
            audit: Arc::new(FakeEventDispatcher::new()),
            id: other.id,
            authorities: other.authorities.clone(),
        }
    }

    /// The caller holding what `authorities` says instead.
    pub(super) fn with_authorities(self, authorities: FakeTenantAuthorities) -> Self {
        Self {
            authorities: Arc::new(authorities),
            ..self
        }
    }

    /// The ports the record use cases share, over these fakes.
    pub(super) fn ports(&self) -> ZonePorts {
        ZonePorts {
            domain_store: self.domains.clone(),
            dns_zones: self.zones.clone(),
            tenant_authorities: self.authorities.clone(),
        }
    }

    /// Every set the zone answers with now.
    pub(super) fn held(&self) -> Vec<RecordSet> {
        let zones: &dyn DnsZoneWriter = self.zones.as_ref();
        block_on(zones.record_sets(&test_ctx().tenant_id(), &host())).unwrap()
    }

    /// Writes `set` into the zone directly, as if it was already there.
    pub(super) fn holding(self, set: &RecordSet) -> Self {
        let zones: &dyn DnsZoneWriter = self.zones.as_ref();
        block_on(zones.replace_record_set(&test_ctx().tenant_id(), &host(), set)).unwrap();
        self
    }
}

/// [`DELEGATED_HOST`], delegated to us and verified.
pub(super) fn delegated_zone() -> ZoneFixture {
    ZoneFixture::of(DomainSeed::verified(DELEGATED_HOST).delegated().build())
}

/// [`DELEGATED_HOST`], delegated to us but not yet verified.
pub(super) fn unverified_zone() -> ZoneFixture {
    ZoneFixture::of(DomainSeed::pending(DELEGATED_HOST).delegated().build())
}

/// [`DELEGATED_HOST`], verified but run at the tenant's own DNS provider.
pub(super) fn self_managed() -> ZoneFixture {
    ZoneFixture::of(DomainSeed::verified(DELEGATED_HOST).build())
}
