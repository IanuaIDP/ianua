//! A change to a zone that
//! [`ZonePolicy`](crate::domains::tenant::custom_domains::dns_zone::ZonePolicy)
//! allowed, and the record it leaves.
//!
//! The zone lives on the nameservers, not in a store of ours, so no
//! aggregate is saved when a record set changes. The allowed change itself
//! raises the record, and the application takes it once the zone holds the
//! change. A change the zone never received is dropped with its record.

use crate::domains::tenant::custom_domains::dns_zone::kind::RecordKind;
use crate::domains::tenant::custom_domains::dns_zone::name::RecordName;
use crate::domains::tenant::custom_domains::dns_zone::record_set::RecordSet;
use crate::domains::tenant::events::custom_domains::{
    TenantDnsRecordSetChanged, TenantDnsRecordSetRemoved,
};
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::types::{DomainName, TenantId};

/// The zone a change is made in: whose it is, and the hostname it answers
/// for.
#[derive(Clone, Copy)]
pub(super) struct ZoneOf<'a> {
    /// The tenant holding the zone, whose record the change is.
    pub(super) tenant: TenantId,
    /// The delegated hostname, the zone's apex.
    pub(super) apex: &'a DomainName,
}

/// A write of one record set that
/// [`ZonePolicy::permits_write`](crate::domains::tenant::custom_domains::dns_zone::ZonePolicy::permits_write)
/// allowed.
///
/// Raises `tenant.dns_record_set_changed` with the set as written and the
/// values of the set it replaces, empty when the set is new.
#[derive(Debug)]
pub struct RecordSetWrite {
    effect: WriteEffect,
    raised: RaisedEvents,
}

/// What a write does to the zone's count of record sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteEffect {
    /// No set answered the same question, so the zone holds one more.
    AddsASet,
    /// A set answering the same question is replaced, so the zone does not
    /// grow.
    ReplacesASet,
}

impl RecordSetWrite {
    /// The write of `incoming` into `zone`, which holds `existing`.
    pub(super) fn new(zone: ZoneOf<'_>, incoming: &RecordSet, existing: &[RecordSet]) -> Self {
        let previous = existing.iter().find(|held| held.answers_same_as(incoming));
        let mut raised = RaisedEvents::default();
        raised.raise_tenant(
            zone.tenant,
            TenantDnsRecordSetChanged {
                zone: zone.apex.clone(),
                name: incoming.name().clone(),
                kind: incoming.kind().as_str(),
                values: incoming.values().to_vec(),
                previous_values: previous
                    .map(|held| held.values().to_vec())
                    .unwrap_or_default(),
                occurred_at: crate::shared::clock::now(),
            },
        );
        let effect = match previous {
            Some(_) => WriteEffect::ReplacesASet,
            None => WriteEffect::AddsASet,
        };
        Self { effect, raised }
    }

    /// Whether the write adds a set to the zone or replaces one it held.
    #[must_use]
    pub fn effect(&self) -> WriteEffect {
        self.effect
    }
}

impl RaisesComplete for RecordSetWrite {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// A removal of the set at one name and type that
/// [`ZonePolicy::permits_removal`](crate::domains::tenant::custom_domains::dns_zone::ZonePolicy::permits_removal)
/// allowed, before the zone is read.
#[derive(Debug)]
pub struct RecordSetRemoval {
    tenant: TenantId,
    apex: DomainName,
    name: RecordName,
    kind: RecordKind,
}

impl RecordSetRemoval {
    /// The removal of the set at `name`/`kind` from `zone`.
    pub(super) fn new(zone: ZoneOf<'_>, name: &RecordName, kind: RecordKind) -> Self {
        Self {
            tenant: zone.tenant,
            apex: zone.apex.clone(),
            name: name.clone(),
            kind,
        }
    }

    /// The set this removal takes out of a zone holding `existing`, or
    /// `None` when the zone holds no such set. Removing a set that is not
    /// there records nothing.
    #[must_use]
    pub fn of_held(self, existing: &[RecordSet]) -> Option<RemovedRecordSet> {
        let held = existing
            .iter()
            .find(|held| held.name() == &self.name && held.kind() == self.kind)?;
        let mut raised = RaisedEvents::default();
        raised.raise_tenant(
            self.tenant,
            TenantDnsRecordSetRemoved {
                zone: self.apex,
                name: self.name,
                kind: self.kind.as_str(),
                previous_values: held.values().to_vec(),
                occurred_at: crate::shared::clock::now(),
            },
        );
        Some(RemovedRecordSet { raised })
    }
}

/// A record set the zone holds and a removal takes out.
///
/// Raises `tenant.dns_record_set_removed` with the values the set held,
/// since nothing else keeps them once it is gone.
#[derive(Debug)]
pub struct RemovedRecordSet {
    raised: RaisedEvents,
}

impl RaisesComplete for RemovedRecordSet {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::custom_domains::dns_zone::ttl::Ttl;
    use crate::domains::tenant::custom_domains::dns_zone::value::RecordValue;
    use crate::test_support::builders::record_name;
    use crate::types::IpAddress;

    fn apex() -> DomainName {
        DomainName::new("auth.acme.com").unwrap()
    }

    fn www(address: &str) -> RecordSet {
        RecordSet::new(
            record_name("www.auth.acme.com"),
            Ttl::standard(),
            vec![RecordValue::Address(IpAddress::new(address).unwrap())],
        )
        .unwrap()
    }

    fn zone(apex: &DomainName, tenant: TenantId) -> ZoneOf<'_> {
        ZoneOf { tenant, apex }
    }

    /// Acme points `www` at a new address. The write replaces the set the
    /// zone held, and raises the change with the old value, filed under
    /// Acme.
    #[test]
    fn a_write_raises_the_change_with_the_values_it_replaced() {
        let (acme, apex) = (TenantId::new(), apex());

        let mut write = RecordSetWrite::new(
            zone(&apex, acme),
            &www("203.0.113.10"),
            &[www("203.0.113.1")],
        );

        let events = write.take_events();
        assert_eq!(write.effect(), WriteEffect::ReplacesASet);
        assert_eq!(
            events[0].event_type().to_string(),
            "tenant.dns_record_set_changed"
        );
        assert_eq!(events[0].tenant_id(), Some(&acme));
        assert_eq!(
            events[0].payload().get("previous_values"),
            Some("203.0.113.1")
        );
    }

    /// Acme adds `www` to a zone that held none. The write adds a set.
    #[test]
    fn a_write_to_a_new_name_adds_a_set() {
        let apex = apex();

        let write = RecordSetWrite::new(zone(&apex, TenantId::new()), &www("203.0.113.10"), &[]);

        assert_eq!(write.effect(), WriteEffect::AddsASet);
    }

    /// Acme removes `www`, which the zone holds. The removal raises what
    /// the set answered, filed under Acme.
    #[test]
    fn removing_a_held_set_raises_its_values() {
        let (acme, apex) = (TenantId::new(), apex());
        let removal = RecordSetRemoval::new(
            zone(&apex, acme),
            &record_name("www.auth.acme.com"),
            RecordKind::A,
        );

        let mut removed = removal.of_held(&[www("203.0.113.1")]).unwrap();

        let events = removed.take_events();
        assert_eq!(
            events[0].event_type().to_string(),
            "tenant.dns_record_set_removed"
        );
        assert_eq!(events[0].tenant_id(), Some(&acme));
        assert_eq!(
            events[0].payload().get("previous_values"),
            Some("203.0.113.1")
        );
    }

    /// Acme removes `www` from a zone that holds no such set. Nothing is
    /// removed, and nothing is raised.
    #[test]
    fn removing_a_set_that_is_not_there_raises_nothing() {
        let apex = apex();
        let removal = RecordSetRemoval::new(
            zone(&apex, TenantId::new()),
            &record_name("www.auth.acme.com"),
            RecordKind::A,
        );

        assert!(removal.of_held(&[]).is_none());
    }
}
