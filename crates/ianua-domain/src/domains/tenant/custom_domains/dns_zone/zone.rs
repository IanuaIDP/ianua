//! A zone as the nameservers see it, and the authority they answer with.

use crate::domains::tenant::custom_domains::dns_zone::kind::RecordKind;
use crate::domains::tenant::custom_domains::dns_zone::name::RecordName;
use crate::domains::tenant::custom_domains::dns_zone::record_set::RecordSet;
use crate::domains::tenant::custom_domains::dns_zone::ttl::Ttl;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::ValidationError;
use crate::types::DomainName;

/// A zone's version number, as `SOA` carries it.
///
/// A secondary nameserver compares serials to decide whether to fetch a zone
/// again. So the serial must rise whenever the zone changes and never fall.
/// It comes from the newest record's time, not a counter. A counter would
/// need storage of its own and would reset when that storage was rebuilt.
/// The record times already say when the zone last changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Serial(u32);

impl Serial {
    /// The serial for a zone whose newest record is `changed_at`.
    ///
    /// It is the seconds since the epoch, cut to 32 bits. `SOA` carries that
    /// width, and every implementation compares it with the wrap-around
    /// arithmetic of RFC 1982.
    #[must_use]
    pub fn at(changed_at: time::OffsetDateTime) -> Self {
        Self(u32::try_from(changed_at.unix_timestamp().max(0)).unwrap_or(u32::MAX))
    }

    /// The number as the wire carries it.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// How long secondaries and resolvers wait, as `SOA` carries it.
///
/// Every zone we hold uses the same timers. They are short, because each
/// zone is small, changes only through us and has no secondary to keep in
/// step. The ones that matter are `minimum`, which limits how long a
/// negative answer is cached, and `expire`, the only one a resolver never
/// sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoaTimers {
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

impl SoaTimers {
    /// The timers every zone we hold answers with.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            refresh: 3_600,
            retry: 600,
            expire: 1_209_600,
            minimum: 300,
        }
    }

    /// How often a secondary re-checks the serial.
    #[must_use]
    pub fn refresh(self) -> u32 {
        self.refresh
    }

    /// How soon a secondary retries a failed check.
    #[must_use]
    pub fn retry(self) -> u32 {
        self.retry
    }

    /// When a secondary stops answering for a zone it cannot reach.
    #[must_use]
    pub fn expire(self) -> u32 {
        self.expire
    }

    /// How long a resolver may cache "this name does not exist".
    ///
    /// A mistake here shows. Too long, and a name a tenant just created
    /// keeps reading as missing.
    #[must_use]
    pub fn minimum(self) -> u32 {
        self.minimum
    }
}

/// The `SOA` record at a zone's apex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartOfAuthority {
    primary: DomainName,
    hostmaster: RecordName,
    serial: Serial,
    timers: SoaTimers,
}

impl StartOfAuthority {
    /// The nameserver named as the zone's primary.
    #[must_use]
    pub fn primary(&self) -> &DomainName {
        &self.primary
    }

    /// The address to write to about the zone, spelled as DNS spells one,
    /// with the `@` as a dot.
    #[must_use]
    pub fn hostmaster(&self) -> &RecordName {
        &self.hostmaster
    }

    /// The zone's version.
    #[must_use]
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// How long secondaries and resolvers wait.
    #[must_use]
    pub fn timers(&self) -> SoaTimers {
        self.timers
    }
}

/// The parts of `SOA` and `NS` answers that every zone shares.
///
/// These are deployment settings, not tenant data. No tenant may write an
/// `NS` or `SOA` of their own, so no tenant can forge those two records.
///
/// The nameserver *names* are not here, because they are not shared. Each
/// delegated zone answers with its own, which ties a delegation to the
/// registration that asked for it. See
/// [`DelegationLabel`](crate::domains::tenant::custom_domains::dns_zone::DelegationLabel).
#[derive(Debug, Clone)]
pub struct Authority {
    hostmaster: RecordName,
    timers: SoaTimers,
}

impl Authority {
    /// The authority every zone answers under.
    #[must_use]
    pub fn new(hostmaster: RecordName) -> Self {
        Self {
            hostmaster,
            timers: SoaTimers::standard(),
        }
    }

    /// The `SOA` for `zone`.
    ///
    /// The zone's first nameserver is named as primary. Which one matters
    /// little while no secondary copies from us. It must still be one of
    /// them, since a primary outside the zone's own `NS` set leads to a
    /// broken delegation.
    #[must_use]
    pub fn start_of_authority(&self, zone: &Zone) -> StartOfAuthority {
        StartOfAuthority {
            primary: zone.primary.clone(),
            hostmaster: self.hostmaster.clone(),
            serial: zone.serial(),
            timers: self.timers,
        }
    }

    /// How long a resolver may cache the `NS` and `SOA` we build.
    #[must_use]
    pub fn ttl(&self) -> Ttl {
        Ttl::standard()
    }
}

/// A zone and everything it answers with, as of one moment.
///
/// It is built for reading. The control plane changes zones. The
/// nameservers hold this in memory and replace it whole, so it has no
/// mutators and every lookup depends only on what it was built with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    apex: DomainName,
    serial: Serial,
    sets: Vec<RecordSet>,
    primary: DomainName,
    nameservers: Vec<DomainName>,
}

impl Zone {
    /// A zone rooted at `apex`, answering with `sets`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a set answers for a name outside
    ///   the zone. Answering for a name not delegated to us would attack
    ///   somebody else's domain, so it is refused when the zone is built.
    /// - [`DomainError::Validation`] when `nameservers` is empty.
    pub fn new(
        apex: DomainName,
        serial: Serial,
        sets: Vec<RecordSet>,
        nameservers: Vec<DomainName>,
    ) -> Result<Self, DomainError> {
        if let Some(stray) = sets.iter().find(|set| !set.name().is_within(&apex)) {
            return Err(DomainError::invalid(message!(
                "tenant-is-outside-the-zone-rooted-at",
                format!(
                    "{} is outside the zone rooted at {}",
                    stray.name(),
                    apex.as_str()
                )
            )));
        }

        let Some(primary) = nameservers.first().cloned() else {
            return Err(ValidationError::Count {
                field: "nameservers",
                min: 1,
                max: usize::MAX,
                actual: 0,
            }
            .into());
        };

        Ok(Self {
            apex,
            serial,
            sets,
            primary,
            nameservers,
        })
    }

    /// The names this zone answers with for `NS`, and the ones its parent
    /// must delegate to.
    ///
    /// They are the zone's own, not the deployment's. A resolver asking a
    /// zone for its `NS` records is answered by the zone, so a delegation is
    /// checked against these.
    #[must_use]
    pub fn nameservers(&self) -> &[DomainName] {
        &self.nameservers
    }

    /// The hostname this zone is delegated for.
    #[must_use]
    pub fn apex(&self) -> &DomainName {
        &self.apex
    }

    /// The zone's version.
    #[must_use]
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// Every set the zone holds.
    #[must_use]
    pub fn sets(&self) -> &[RecordSet] {
        &self.sets
    }

    /// The set answering `name` for `kind`, if the zone holds one.
    #[must_use]
    pub fn record_set_at(&self, name: &RecordName, kind: RecordKind) -> Option<&RecordSet> {
        self.sets
            .iter()
            .find(|set| set.name() == name && set.kind() == kind)
    }

    /// Every set answering `name`, whatever the type.
    pub fn sets_at<'a>(&'a self, name: &'a RecordName) -> impl Iterator<Item = &'a RecordSet> {
        self.sets.iter().filter(move |set| set.name() == name)
    }

    /// Whether the zone has a node at `name`.
    ///
    /// It is true for a name with records, and also for one that only has
    /// names beneath it, an *empty non-terminal*. If `a.b.zone` exists, so
    /// does `b.zone`. A query for `b.zone` must then answer "no records of
    /// that type", not "no such name".
    #[must_use]
    pub fn has_node(&self, name: &RecordName) -> bool {
        name.is_apex_of(&self.apex)
            || self
                .sets
                .iter()
                .any(|set| set.name() == name || set.name().is_beneath(name))
    }

    /// The longest ancestor of `name` that the zone has a node at.
    ///
    /// A wildcard search starts here, per RFC 4592. A wildcard may only
    /// answer for names beneath the closest name that exists. So `*.zone`
    /// never answers for a name a real record already covers further down.
    #[must_use]
    pub fn closest_encloser(&self, name: &RecordName) -> RecordName {
        let apex = RecordName::from(&self.apex);
        let mut candidate = name.clone();

        while candidate != apex {
            if self.has_node(&candidate) {
                return candidate;
            }

            let Some(parent) = candidate.parent() else {
                return apex;
            };
            candidate = parent;
        }

        apex
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::custom_domains::dns_zone::value::RecordValue;
    use crate::test_support::builders::record_name;
    use crate::types::IpAddress;

    fn apex() -> DomainName {
        DomainName::new("auth.acme.com").unwrap()
    }

    fn address_set(owner: &str, value: &str) -> RecordSet {
        RecordSet::new(
            record_name(owner),
            Ttl::standard(),
            vec![RecordValue::Address(IpAddress::new(value).unwrap())],
        )
        .unwrap()
    }

    fn serial() -> Serial {
        Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap())
    }

    /// This zone's own names, as a delegated zone has.
    fn nameservers() -> Vec<DomainName> {
        vec![DomainName::new("abc123.ns1.ianua.test").unwrap()]
    }

    fn zone(sets: Vec<RecordSet>) -> Zone {
        Zone::new(apex(), serial(), sets, nameservers()).unwrap()
    }

    /// Zone construction rejects a record set whose name lies outside the
    /// zone's apex.
    #[test]
    fn a_zone_refuses_a_set_outside_it() {
        let result = Zone::new(
            apex(),
            serial(),
            vec![address_set("elsewhere.example.com", "198.51.100.1")],
            nameservers(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A zone holds sets for its apex and for names one and two labels below.
    /// It is built.
    #[test]
    fn a_zone_accepts_its_apex_and_everything_beneath() {
        let result = Zone::new(
            apex(),
            serial(),
            vec![
                address_set("auth.acme.com", "203.0.113.10"),
                address_set("api.auth.acme.com", "198.51.100.1"),
                address_set("a.b.auth.acme.com", "198.51.100.2"),
            ],
            nameservers(),
        );

        assert!(result.is_ok());
    }

    /// A zone with an `A` at `api.auth.acme.com` finds it there. It finds no
    /// `AAAA` at that name and no `A` at another.
    #[test]
    fn a_set_is_found_by_name_and_type() {
        let zone = zone(vec![address_set("api.auth.acme.com", "198.51.100.1")]);

        assert!(
            zone.record_set_at(&record_name("api.auth.acme.com"), RecordKind::A)
                .is_some()
        );
        assert!(
            zone.record_set_at(&record_name("api.auth.acme.com"), RecordKind::Aaaa)
                .is_none()
        );
        assert!(
            zone.record_set_at(&record_name("other.auth.acme.com"), RecordKind::A)
                .is_none()
        );
    }

    /// A zone with no records still has a node at its apex. It answers
    /// `NODATA` there, not that its own name does not exist.
    #[test]
    fn the_apex_is_a_node_of_an_empty_zone() {
        assert!(zone(Vec::new()).has_node(&record_name("auth.acme.com")));
    }

    /// A zone with a record only at `a.b.auth.acme.com` has nodes there and
    /// at `b.auth.acme.com`. It has none at `c.auth.acme.com`.
    #[test]
    fn a_name_with_only_descendants_is_still_a_node() {
        let zone = zone(vec![address_set("a.b.auth.acme.com", "198.51.100.1")]);

        assert!(zone.has_node(&record_name("b.auth.acme.com")));
        assert!(zone.has_node(&record_name("a.b.auth.acme.com")));
        assert!(!zone.has_node(&record_name("c.auth.acme.com")));
    }

    /// For `api.auth.acme.com`, which has a record, the closest encloser is
    /// the name itself.
    #[test]
    fn the_closest_encloser_of_an_existing_name_is_itself() {
        let zone = zone(vec![address_set("api.auth.acme.com", "198.51.100.1")]);

        assert_eq!(
            zone.closest_encloser(&record_name("api.auth.acme.com"))
                .as_str(),
            "api.auth.acme.com"
        );
    }

    /// For `missing.b.auth.acme.com`, the closest encloser is
    /// `b.auth.acme.com`, the nearest name above it that exists.
    #[test]
    fn the_closest_encloser_of_a_missing_name_is_its_nearest_existing_ancestor() {
        let zone = zone(vec![address_set("a.b.auth.acme.com", "198.51.100.1")]);

        assert_eq!(
            zone.closest_encloser(&record_name("missing.b.auth.acme.com"))
                .as_str(),
            "b.auth.acme.com"
        );
    }

    /// In an empty zone, the closest encloser of a deep name is the apex. The
    /// walk always ends there, which keeps a wildcard search finite.
    #[test]
    fn the_closest_encloser_falls_back_to_the_apex() {
        let zone = zone(Vec::new());

        assert_eq!(
            zone.closest_encloser(&record_name("deep.down.auth.acme.com"))
                .as_str(),
            "auth.acme.com"
        );
    }

    /// A zone built with no nameservers is refused. A parent delegating to
    /// it would find nothing to delegate to.
    #[test]
    fn a_zone_with_no_nameservers_is_refused() {
        let result = Zone::new(apex(), serial(), Vec::new(), Vec::new());

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The `SOA` built for a zone names one of the zone's own nameservers as
    /// primary, so the delegation does not break.
    #[test]
    fn the_soa_names_one_of_the_zones_own_nameservers_as_primary() {
        let zone = zone(Vec::new());

        let soa = Authority::new(record_name("hostmaster.ianua.test")).start_of_authority(&zone);

        assert!(
            zone.nameservers().contains(soa.primary()),
            "the primary must be one of the zone's own nameservers"
        );
    }

    /// A zone built with `abc123.ns1.ianua.test` answers `NS` with exactly
    /// that name, not the deployment's shared ones. That ties the delegation
    /// to one registration.
    #[test]
    fn a_zone_answers_with_its_own_nameservers() {
        let zone = zone(Vec::new());

        assert_eq!(
            zone.nameservers()
                .iter()
                .map(DomainName::as_str)
                .collect::<Vec<_>>(),
            ["abc123.ns1.ianua.test"]
        );
    }

    /// A change one second later gives a higher serial, so a secondary sees
    /// the zone changed.
    #[test]
    fn a_later_change_produces_a_higher_serial() {
        let earlier = Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap());
        let later = Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap());

        assert!(later > earlier);
    }

    /// A serial taken at Unix time 1,700,000,000 goes on the wire as that
    /// number. A serial stuck at zero would stop every secondary updating.
    #[test]
    fn a_serial_goes_on_the_wire_as_the_moment_it_was_taken_from() {
        assert_eq!(serial().as_u32(), 1_700_000_000);
    }

    /// The standard timers read back as 3600, 600, 1,209,600 and 300
    /// seconds. Mixing them up would flood us with refreshes or keep a new
    /// name cached as missing.
    #[test]
    fn each_soa_timer_reports_its_own_number() {
        let timers = SoaTimers::standard();

        assert_eq!(timers.refresh(), 3_600);
        assert_eq!(timers.retry(), 600);
        assert_eq!(timers.expire(), 1_209_600);
        assert_eq!(timers.minimum(), 300);
    }

    /// A zone built with two sets holds both. Zone transfers and lookups read
    /// this list.
    #[test]
    fn a_zone_holds_the_sets_it_was_built_with() {
        let zone = zone(vec![
            address_set("auth.acme.com", "10.0.0.1"),
            address_set("api.auth.acme.com", "10.0.0.2"),
        ]);

        assert_eq!(zone.sets().len(), 2);
    }

    /// The apex gets back its own one set and not the set on
    /// `api.auth.acme.com`. A name with no sets gets none.
    #[test]
    fn every_set_on_a_name_is_returned_and_nothing_from_another_name() {
        let zone = zone(vec![
            address_set("auth.acme.com", "10.0.0.1"),
            address_set("api.auth.acme.com", "10.0.0.2"),
        ]);

        let apex_name = record_name("auth.acme.com");
        let at_apex: Vec<_> = zone.sets_at(&apex_name).collect();
        assert_eq!(at_apex.len(), 1);
        assert_eq!(at_apex[0].name(), &apex_name);

        let missing = record_name("nothing.auth.acme.com");
        assert_eq!(zone.sets_at(&missing).count(), 0);
    }
}
