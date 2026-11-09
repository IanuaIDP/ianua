//! Every zone the nameservers hold, and which one answers a given name.

use std::collections::{HashMap, HashSet};

use crate::domains::tenant::custom_domains::dns_zone::name::RecordName;
use crate::domains::tenant::custom_domains::dns_zone::resolution::{
    QueryKind, Resolution, resolve,
};
use crate::domains::tenant::custom_domains::dns_zone::zone::{Authority, Zone};
use crate::types::TenantId;

/// Whether a zone's delegation has been proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneStanding {
    /// The parent delegates the name to us, and the proof saw it.
    Proven,
    /// Registered but not yet proved. It is never served: the proof reads
    /// the parent's own referral and needs no answer from us.
    Unproven,
}

/// A zone, with the tenant it belongs to and whether it is proven.
///
/// The catalog needs all three to decide between two tenants' zones that
/// nest inside each other.
#[derive(Debug, Clone)]
pub struct HeldZone {
    /// The authoritative records considered when choosing the most specific owned zone.
    pub zone: Zone,
    /// The tenant whose registration it serves.
    pub owner: TenantId,
    /// Whether its delegation has been proved.
    pub standing: ZoneStanding,
}

/// Every zone the nameservers hold, as of one moment.
///
/// It is replaced whole, never edited. A nameserver changing its zones under
/// live queries would answer half from one version and half from another.
/// That happens just when a tenant is checking whether their change took
/// effect.
#[derive(Debug, Clone)]
pub struct ZoneCatalog {
    zones: Vec<Zone>,
    authority: Authority,
}

impl ZoneCatalog {
    /// The catalog holding the [`served_zones`] of `zones`, answered for by
    /// `authority`.
    #[must_use]
    pub fn new(zones: Vec<HeldZone>, authority: Authority) -> Self {
        Self {
            zones: served_zones(zones),
            authority,
        }
    }

    /// The catalog holding `zones` as they are, answered for by
    /// `authority`: zones the control plane already settled with
    /// [`served_zones`] and sent a nameserver outside the cluster over the
    /// link both ends authenticate. They carry no holder or standing, so
    /// they cannot be settled again here, and need not be.
    #[must_use]
    pub fn from_served(zones: Vec<Zone>, authority: Authority) -> Self {
        Self { zones, authority }
    }

    /// A catalog holding nothing, which refuses every query.
    ///
    /// The nameservers serve this before their first load. We hold no zones
    /// yet and know nothing about any name, so we refuse. A resolver retries
    /// a refusal. A made-up `NXDOMAIN` it would cache, and the name would
    /// stay unreachable for the whole negative TTL.
    #[must_use]
    pub fn empty(authority: Authority) -> Self {
        Self {
            zones: Vec::new(),
            authority,
        }
    }

    /// How many zones the catalog holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// Whether the catalog holds no zones at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// The zone answering for `name`, if we hold one.
    ///
    /// The longest apex wins. Two zones enclose one name only when one tenant
    /// holds both, such as `acme.com` and `auth.acme.com`. The deeper
    /// delegation is the more specific, so it answers.
    #[must_use]
    pub fn zone_for(&self, name: &RecordName) -> Option<&Zone> {
        self.zones
            .iter()
            .filter(|zone| name.is_within(zone.apex()))
            .max_by_key(|zone| zone.apex().as_str().len())
    }

    /// What we answer for `name` and `kind`.
    ///
    /// A name in no zone we hold is [`Resolution::Refused`], never a name
    /// error. We cannot say whether a name outside our zones exists, and
    /// claiming it does not would harm whoever really answers for it.
    #[must_use]
    pub fn answer(&self, name: &RecordName, kind: QueryKind) -> Resolution {
        match self.zone_for(name) {
            Some(zone) => resolve(zone, &self.authority, name, kind),
            None => Resolution::Refused,
        }
    }
}

/// The zones of `zones` that any nameserver of ours may serve.
///
/// An unproven zone is never served. Say Acme removed its registration
/// of `auth.acme.com` but left the delegation at its provider pointing at
/// our nameservers. Eve registers the name. Serving her zone before it is
/// proved would answer for Acme's name with her records, and any certificate
/// authority would then issue her a certificate for it. Her proof never
/// passes, because the parent still names the nameservers of Acme's old
/// registration.
///
/// When two tenants' proven zones nest, one inside the other, the enclosing
/// one keeps answering. Its parent delegated it to us, so a zone nested
/// inside one we serve can only have been "proved" by our own answers. Zones
/// of one tenant nest freely.
#[must_use]
pub fn served_zones(zones: Vec<HeldZone>) -> Vec<Zone> {
    let proven: Vec<HeldZone> = zones
        .into_iter()
        .filter(|held| held.standing == ZoneStanding::Proven)
        .collect();
    let nested = nested_in_another_tenants(&proven);
    proven
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !nested.contains(index))
        .map(|(_, held)| held.zone)
        .collect()
}

/// The positions in `zones` of every zone nested inside, or at the apex
/// of, another tenant's zone.
fn nested_in_another_tenants(zones: &[HeldZone]) -> HashSet<usize> {
    let mut by_apex: HashMap<RecordName, Vec<usize>> = HashMap::new();
    for (index, held) in zones.iter().enumerate() {
        by_apex
            .entry(RecordName::from(held.zone.apex()))
            .or_default()
            .push(index);
    }
    zones
        .iter()
        .enumerate()
        .filter(|(inner, held)| {
            enclosing(held, &by_apex).any(|outer| {
                outer != *inner
                    && zones
                        .get(outer)
                        .is_some_and(|other| other.owner != held.owner)
            })
        })
        .map(|(inner, _)| inner)
        .collect()
}

/// Every zone whose apex is `held`'s apex or one of its ancestors.
fn enclosing<'a>(
    held: &HeldZone,
    by_apex: &'a HashMap<RecordName, Vec<usize>>,
) -> impl Iterator<Item = usize> + 'a {
    std::iter::successors(Some(RecordName::from(held.zone.apex())), RecordName::parent)
        .filter_map(|name| by_apex.get(&name))
        .flatten()
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::custom_domains::dns_zone::kind::RecordKind;
    use crate::domains::tenant::custom_domains::dns_zone::record_set::RecordSet;
    use crate::domains::tenant::custom_domains::dns_zone::ttl::Ttl;
    use crate::domains::tenant::custom_domains::dns_zone::value::RecordValue;
    use crate::domains::tenant::custom_domains::dns_zone::zone::Serial;
    use crate::test_support::builders::record_name;
    use crate::types::{DomainName, IpAddress};

    fn authority() -> Authority {
        Authority::new(record_name("hostmaster.ianua.test"))
    }

    fn nameservers() -> Vec<DomainName> {
        vec![DomainName::new("abc123.ns1.ianua.test").unwrap()]
    }

    fn zone(apex: &str, owner: &str, address: &str) -> Zone {
        zone_at(apex, owner, address)
    }

    fn zone_at(apex: &str, owner: &str, address: &str) -> Zone {
        Zone::new(
            DomainName::new(apex).unwrap(),
            Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()),
            vec![
                RecordSet::new(
                    record_name(owner),
                    Ttl::standard(),
                    vec![RecordValue::Address(IpAddress::new(address).unwrap())],
                )
                .unwrap(),
            ],
            nameservers(),
        )
        .unwrap()
    }

    fn held(zone: Zone, owner: TenantId, standing: ZoneStanding) -> HeldZone {
        HeldZone {
            zone,
            owner,
            standing,
        }
    }

    fn one_tenant(zones: Vec<Zone>) -> Vec<HeldZone> {
        let owner = TenantId::new();
        zones
            .into_iter()
            .map(|zone| held(zone, owner, ZoneStanding::Proven))
            .collect()
    }

    fn address_of(catalog: &ZoneCatalog, name: &str) -> Vec<String> {
        addresses(&catalog.answer(&record_name(name), QueryKind::Record(RecordKind::A)))
    }

    fn addresses(resolution: &Resolution) -> Vec<String> {
        let Resolution::Found { answers, .. } = resolution else {
            return Vec::new();
        };

        answers
            .iter()
            .filter_map(|a| match &a.value {
                crate::domains::tenant::custom_domains::dns_zone::AnswerValue::Record(value) => {
                    Some(value.as_presentation())
                }
                _ => None,
            })
            .collect()
    }

    /// The catalog holds zones for `auth.acme.com` and `auth.other.com`. A
    /// query for `api.auth.other.com` gets the address from the second.
    #[test]
    fn a_query_is_answered_by_the_zone_holding_it() {
        let catalog = ZoneCatalog::new(
            one_tenant(vec![
                zone("auth.acme.com", "api.auth.acme.com", "198.51.100.1"),
                zone("auth.other.com", "api.auth.other.com", "198.51.100.2"),
            ]),
            authority(),
        );

        let found = catalog.answer(
            &record_name("api.auth.other.com"),
            QueryKind::Record(RecordKind::A),
        );

        assert_eq!(addresses(&found), ["198.51.100.2"]);
    }

    /// Acme holds both `acme.com` and `auth.acme.com`. A query for
    /// `api.auth.acme.com` is answered by the deeper `auth.acme.com`.
    #[test]
    fn the_longest_matching_zone_of_one_tenant_answers() {
        let catalog = ZoneCatalog::new(
            one_tenant(vec![
                zone("acme.com", "api.auth.acme.com", "198.51.100.1"),
                zone("auth.acme.com", "api.auth.acme.com", "198.51.100.2"),
            ]),
            authority(),
        );

        let found = catalog.answer(
            &record_name("api.auth.acme.com"),
            QueryKind::Record(RecordKind::A),
        );

        assert_eq!(addresses(&found), ["198.51.100.2"]);
    }

    /// A query for `evil.example.com`, in no zone we hold, is refused rather
    /// than answered as nonexistent.
    #[test]
    fn a_name_in_no_zone_is_refused() {
        let catalog = ZoneCatalog::new(
            one_tenant(vec![zone(
                "auth.acme.com",
                "api.auth.acme.com",
                "198.51.100.1",
            )]),
            authority(),
        );

        assert_eq!(
            catalog.answer(
                &record_name("evil.example.com"),
                QueryKind::Record(RecordKind::A)
            ),
            Resolution::Refused
        );
    }

    /// A nameserver outside the cluster is sent the zones the control plane
    /// settled, and answers from them as sent.
    #[test]
    fn zones_settled_at_the_control_plane_answer_as_sent() {
        let catalog = ZoneCatalog::from_served(
            vec![zone("auth.acme.com", "api.auth.acme.com", "198.51.100.1")],
            authority(),
        );

        assert_eq!(address_of(&catalog, "api.auth.acme.com"), ["198.51.100.1"]);
        assert_eq!(catalog.len(), 1);
    }

    /// Before the first load the catalog is empty and refuses every query. A
    /// resolver retries a refusal, but would cache a made-up `NXDOMAIN` for
    /// the whole negative TTL.
    #[test]
    fn an_empty_catalog_refuses_rather_than_denying() {
        let catalog = ZoneCatalog::empty(authority());

        assert_eq!(
            catalog.answer(
                &record_name("api.auth.acme.com"),
                QueryKind::Record(RecordKind::A)
            ),
            Resolution::Refused
        );
        assert!(catalog.is_empty());
    }

    /// A catalog of two zones counts two and is not empty. An empty one
    /// counts zero. Startup and health checks read these numbers.
    #[test]
    fn a_catalog_counts_the_zones_it_holds() {
        let catalog = ZoneCatalog::new(
            one_tenant(vec![
                zone("auth.acme.com", "api.auth.acme.com", "198.51.100.1"),
                zone("auth.globex.com", "api.auth.globex.com", "198.51.100.2"),
            ]),
            authority(),
        );

        assert_eq!(catalog.len(), 2);
        assert!(!catalog.is_empty());
        assert_eq!(ZoneCatalog::empty(authority()).len(), 0);
    }

    /// Another tenant's nested zone is excluded whether proven or unproven.
    /// The catalog keeps only the enclosing proven zone and answers with its
    /// address.
    #[test]
    fn another_tenants_nested_zone_cannot_take_over_names_in_a_zone() {
        let (victim, attacker) = (TenantId::new(), TenantId::new());
        for standing in [ZoneStanding::Proven, ZoneStanding::Unproven] {
            let catalog = ZoneCatalog::new(
                vec![
                    held(
                        zone_at("auth.acme.com", "api.auth.acme.com", "198.51.100.1"),
                        victim,
                        ZoneStanding::Proven,
                    ),
                    held(
                        zone_at("api.auth.acme.com", "api.auth.acme.com", "203.0.113.66"),
                        attacker,
                        standing,
                    ),
                ],
                authority(),
            );

            assert_eq!(address_of(&catalog, "api.auth.acme.com"), ["198.51.100.1"]);
            assert_eq!(catalog.len(), 1);
        }
    }

    /// An unproven enclosing zone from another tenant does not replace the
    /// address answered by the proven inner zone.
    #[test]
    fn an_unproven_enclosing_zone_cannot_take_over_a_proven_one() {
        let (victim, attacker) = (TenantId::new(), TenantId::new());
        let catalog = ZoneCatalog::new(
            vec![
                held(
                    zone_at("acme.com", "api.auth.acme.com", "203.0.113.66"),
                    attacker,
                    ZoneStanding::Unproven,
                ),
                held(
                    zone_at("auth.acme.com", "api.auth.acme.com", "198.51.100.1"),
                    victim,
                    ZoneStanding::Proven,
                ),
            ],
            authority(),
        );

        assert_eq!(address_of(&catalog, "api.auth.acme.com"), ["198.51.100.1"]);
    }

    /// Nested unproven zones from different tenants are both excluded. The
    /// catalog is empty and refuses a query within them.
    #[test]
    fn an_unproven_enclosing_zone_cannot_answer_for_another_unproven_zone() {
        let (squatter, owner) = (TenantId::new(), TenantId::new());
        let catalog = ZoneCatalog::new(
            vec![
                held(
                    zone_at("acme.com", "www.shop.acme.com", "203.0.113.66"),
                    squatter,
                    ZoneStanding::Unproven,
                ),
                held(
                    zone_at("shop.acme.com", "www.shop.acme.com", "198.51.100.1"),
                    owner,
                    ZoneStanding::Unproven,
                ),
            ],
            authority(),
        );

        assert_eq!(
            catalog.answer(
                &record_name("www.shop.acme.com"),
                QueryKind::Record(RecordKind::A)
            ),
            Resolution::Refused
        );
        assert!(catalog.is_empty(), "neither unproven claim answers");
    }

    /// Eve's unproven `acme.com` sits above Acme's proven `shop.acme.com`
    /// and a third tenant's proven `blog.acme.com`. Hers answers nothing,
    /// and both proven zones keep answering.
    #[test]
    fn an_unproven_zone_displaces_nothing() {
        let (squatter, owner, third) = (TenantId::new(), TenantId::new(), TenantId::new());
        let catalog = ZoneCatalog::new(
            vec![
                held(
                    zone_at("acme.com", "www.acme.com", "203.0.113.66"),
                    squatter,
                    ZoneStanding::Unproven,
                ),
                held(
                    zone_at("shop.acme.com", "www.shop.acme.com", "198.51.100.1"),
                    owner,
                    ZoneStanding::Proven,
                ),
                held(
                    zone_at("blog.acme.com", "www.blog.acme.com", "198.51.100.2"),
                    third,
                    ZoneStanding::Proven,
                ),
            ],
            authority(),
        );

        assert_eq!(address_of(&catalog, "www.shop.acme.com"), ["198.51.100.1"]);
        assert_eq!(address_of(&catalog, "www.blog.acme.com"), ["198.51.100.2"]);
        assert!(address_of(&catalog, "www.acme.com").is_empty());
        assert_eq!(catalog.len(), 2);
    }

    /// An unproven zone is omitted from the catalog, leaving it empty and
    /// refusing a query for the zone's stored address.
    #[test]
    fn an_unproven_zone_is_never_served() {
        let catalog = ZoneCatalog::new(
            vec![held(
                zone_at("auth.acme.com", "api.auth.acme.com", "203.0.113.66"),
                TenantId::new(),
                ZoneStanding::Unproven,
            )],
            authority(),
        );

        assert_eq!(
            catalog.answer(
                &record_name("api.auth.acme.com"),
                QueryKind::Record(RecordKind::A)
            ),
            Resolution::Refused
        );
        assert!(catalog.is_empty());
    }

    /// One tenant holds `acme.com` and another `notacme.com`. They only end
    /// alike and do not nest, so both keep answering.
    #[test]
    fn zones_that_only_end_alike_do_not_conflict() {
        let catalog = ZoneCatalog::new(
            vec![
                held(
                    zone_at("acme.com", "www.acme.com", "198.51.100.1"),
                    TenantId::new(),
                    ZoneStanding::Proven,
                ),
                held(
                    zone_at("notacme.com", "www.notacme.com", "198.51.100.2"),
                    TenantId::new(),
                    ZoneStanding::Proven,
                ),
            ],
            authority(),
        );

        assert_eq!(catalog.len(), 2);
        assert_eq!(address_of(&catalog, "www.notacme.com"), ["198.51.100.2"]);
    }
}
