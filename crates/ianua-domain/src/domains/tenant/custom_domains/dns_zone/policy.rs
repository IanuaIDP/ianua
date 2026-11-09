//! What a tenant may and may not write into a zone we hold for them.
//!
//! The tenant hands over a hostname and gets a zone they can fill. We keep
//! the few records that make the hostname work at all. Everything not named
//! here is theirs, since a DNS provider that second-guesses its users is
//! worse than one that lets them make ordinary mistakes.
//!
//! What we keep is short, and each entry has its reason. The rules are pure
//! functions over records the caller has already read. So they are tested
//! without a database and stay out of handlers. Every change also names the
//! person making it, who needs the right to change the tenant's domains.

use crate::domains::tenant::control::{TenantArea, TenantControl};
use crate::domains::tenant::custom_domains::dns_zone::change::{
    RecordSetRemoval, RecordSetWrite, ZoneOf,
};
use crate::domains::tenant::custom_domains::dns_zone::kind::RecordKind;
use crate::domains::tenant::custom_domains::dns_zone::name::RecordName;
use crate::domains::tenant::custom_domains::dns_zone::record_set::RecordSet;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{DomainName, TenantId};

/// The label a certificate authority reads a DNS-01 challenge from.
const CHALLENGE_LABEL: &str = "_acme-challenge";

/// What a tenant may change in a zone we hold on their behalf.
///
/// It is built from the tenant that holds the zone and the delegated
/// hostname, the zone's apex. Only the apex tells a name in this zone from
/// a name in somebody else's, and only the tenant says whose admins may
/// change it.
#[derive(Debug, Clone)]
pub struct ZonePolicy {
    tenant: TenantId,
    apex: DomainName,
}

impl ZonePolicy {
    /// The policy for `tenant`'s zone rooted at `apex`.
    #[must_use]
    pub fn new(tenant: TenantId, apex: DomainName) -> Self {
        Self { tenant, apex }
    }

    /// The hostname this zone answers for.
    #[must_use]
    pub fn apex(&self) -> &DomainName {
        &self.apex
    }

    /// The write of `incoming` into the tenant's zone, once `by` may make
    /// it, given what the zone already holds. The write raises
    /// `tenant.dns_record_set_changed`, taken once the zone holds the set.
    ///
    /// `existing` is every set now in the zone. Whether a `CNAME` may be
    /// written depends on what else sits at its name, so one record alone
    /// cannot answer it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` was worked out for another
    ///   tenant, or may not change the tenant's domains.
    /// - [`DomainError::Validation`] when the name is outside the zone. We
    ///   answer for one hostname and what is beneath it, and no resolver
    ///   would ask us for anything else.
    /// - [`DomainError::Forbidden`] when the set is one we keep: the apex
    ///   address, which routes the hostname to the proxy, or a name a
    ///   certificate challenge is read from.
    /// - [`DomainError::Validation`] when the set is a `CNAME` on the apex.
    ///   An apex carries its zone's `NS` and `SOA` records, and a `CNAME` may
    ///   not sit beside any other record.
    /// - [`DomainError::Validation`] when a `CNAME` would sit beside another
    ///   type, in either direction.
    pub fn permits_write(
        &self,
        incoming: &RecordSet,
        existing: &[RecordSet],
        by: TenantControl<'_>,
    ) -> Result<RecordSetWrite, DomainError> {
        by.ensure_may(&self.tenant, TenantArea::Domains)?;
        self.ensure_the_tenants(incoming.name(), incoming.kind())?;

        if incoming.kind() == RecordKind::Cname && incoming.name().is_apex_of(&self.apex) {
            return Err(DomainError::invalid(message!(
                "tenant-is-this-zone-s-apex-and",
                format!(
                    "{} is this zone's apex and carries its NS records, which a \
                 CNAME may not coexist with; point it with an A record instead",
                    self.apex.as_str()
                )
            )));
        }

        let clash = existing
            .iter()
            .filter(|held| held.name() == incoming.name())
            .find(|held| held.conflicts_with(incoming.kind()));

        if let Some(clash) = clash {
            return Err(DomainError::invalid(message!(
                "tenant-already-holds-a-record-which-a",
                format!(
                    "{} already holds a {} record, which a {} record may not sit \
                 beside; a CNAME replaces a name rather than adding to it",
                    incoming.name(),
                    clash.kind(),
                    incoming.kind()
                )
            )));
        }

        Ok(RecordSetWrite::new(self.zone(), incoming, existing))
    }

    /// Authorizes removing `name`/`kind` from the tenant's zone.
    /// [`RecordSetRemoval::of_held`] raises `tenant.dns_record_set_removed` when the set is found.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another tenant's authority or missing domain-update rights.
    /// Also propagates [`ZonePolicy::permits_write`] errors for protected sets or names outside the zone.
    pub fn permits_removal(
        &self,
        name: &RecordName,
        kind: RecordKind,
        by: TenantControl<'_>,
    ) -> Result<RecordSetRemoval, DomainError> {
        by.ensure_may(&self.tenant, TenantArea::Domains)?;
        self.ensure_the_tenants(name, kind)?;
        Ok(RecordSetRemoval::new(self.zone(), name, kind))
    }

    /// The zone this policy governs, for the change it allows.
    fn zone(&self) -> ZoneOf<'_> {
        ZoneOf {
            tenant: self.tenant,
            apex: &self.apex,
        }
    }

    /// Refuses the set at `name`/`kind` unless it is the tenant's to write
    /// or remove.
    ///
    /// Two things are ours:
    ///
    /// The **apex address** makes the delegated hostname reach the proxy. We
    /// wrote it when the zone was opened. A tenant who edits or removes it
    /// takes their own login page offline, with no error anywhere, because
    /// on our side nothing failed.
    ///
    /// The **`_acme-challenge` names** show a certificate authority that the
    /// hostname is ours to certify. They appear and vanish within a minute
    /// during a renewal. A tenant editing one would race a process they
    /// cannot see, and losing means an expired certificate.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the name is outside the zone.
    /// - [`DomainError::Forbidden`] when the set is one of the two above.
    fn ensure_the_tenants(&self, name: &RecordName, kind: RecordKind) -> Result<(), DomainError> {
        self.ensure_within_zone(name)?;
        if is_challenge(name) {
            return Err(DomainError::forbidden(message!(
                "tenant-is-written-and-withdrawn-automatically-while",
                format!(
                    "{name} is written and withdrawn automatically while a \
                 certificate is issued for {}",
                    self.apex.as_str()
                )
            )));
        }

        if name.is_apex_of(&self.apex) && is_address(kind) {
            return Err(DomainError::forbidden(message!(
                "tenant-the-record-on-is-what-routes",
                format!(
                    "the {kind} record on {} is what routes traffic to the proxy; \
                 editing it would take the hostname off the air",
                    self.apex.as_str()
                )
            )));
        }

        Ok(())
    }

    /// Refuses a name outside the zone.
    fn ensure_within_zone(&self, name: &RecordName) -> Result<(), DomainError> {
        if name.is_within(&self.apex) {
            return Ok(());
        }
        Err(DomainError::invalid(message!(
            "tenant-is-outside-the-zone-this-zone",
            format!(
                "{name} is outside the zone; this zone answers for {} and the \
                 names beneath it",
                self.apex.as_str()
            )
        )))
    }

    /// Whether a set is one we maintain rather than the tenant.
    ///
    /// It is for display. A reserved set is still shown, marked as ours,
    /// since hiding records that exist would make the zone look wrong.
    #[must_use]
    pub fn is_reserved(&self, name: &RecordName, kind: RecordKind) -> bool {
        is_challenge(name) || (name.is_apex_of(&self.apex) && is_address(kind))
    }
}

/// Whether `name` is one of the names a certificate challenge is read from.
pub(super) fn is_challenge(name: &RecordName) -> bool {
    name.as_str()
        .split('.')
        .any(|label| label == CHALLENGE_LABEL)
}

/// Whether `kind` is one of the two types that point a name at a machine.
fn is_address(kind: RecordKind) -> bool {
    matches!(kind, RecordKind::A | RecordKind::Aaaa)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{DomainAction, SystemPermission};
    use crate::domains::tenant::custom_domains::dns_zone::ttl::Ttl;
    use crate::domains::tenant::custom_domains::dns_zone::value::RecordValue;
    use crate::domains::tenant::fixtures::person;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::builders::{record_name, txt_record};
    use crate::types::IpAddress;

    /// Acme, whose zone every test changes.
    fn acme() -> TenantId {
        TenantId::from_uuid(uuid::Uuid::from_u128(1))
    }

    fn policy() -> ZonePolicy {
        ZonePolicy::new(acme(), DomainName::new("auth.acme.com").unwrap())
    }

    /// `address`, holding `system` in `tenant`.
    fn holding(
        address: &str,
        tenant: TenantId,
        system: &[SystemPermission],
    ) -> TenantControl<'static> {
        TenantControl::new(assumed_authority(&person(address), tenant, system, &[]))
    }

    /// Ann, an admin of Acme who may change its domains.
    fn ann() -> TenantControl<'static> {
        holding(
            "ann@acme.test",
            acme(),
            &[SystemPermission::Domains(DomainAction::Update)],
        )
    }

    /// Domain viewers and administrators of another tenant cannot write or
    /// remove zone records. Domain update rights in this tenant allow removal.
    #[test]
    fn only_someone_who_may_change_the_tenants_domains_changes_its_zone() {
        let view = [SystemPermission::Domains(DomainAction::View)];
        let manage = [SystemPermission::ManageDomains];
        let sam = holding("sam@acme.test", acme(), &view);
        let mallory = holding("mallory@evil.test", TenantId::new(), &manage);
        let incoming = set("api.auth.acme.com", vec![txt_record("v=spf1 -all")]);
        let name = record_name("api.auth.acme.com");

        for by in [sam, mallory] {
            let written = policy().permits_write(&incoming, &[], by);
            let removed = policy().permits_removal(&name, RecordKind::Txt, by);

            assert!(matches!(written, Err(DomainError::Forbidden(_))));
            assert!(matches!(removed, Err(DomainError::Forbidden(_))));
        }
        let by_ann = policy().permits_removal(&name, RecordKind::Txt, ann());
        assert!(by_ann.is_ok());
    }

    fn set(owner: &str, values: Vec<RecordValue>) -> RecordSet {
        RecordSet::new(record_name(owner), Ttl::standard(), values).unwrap()
    }

    fn address(value: &str) -> RecordValue {
        RecordValue::Address(IpAddress::new(value).unwrap())
    }

    fn alias(value: &str) -> RecordValue {
        RecordValue::Alias(DomainName::new(value).unwrap())
    }

    /// Acme writes an `A` record for `api.auth.acme.com` in its delegated
    /// zone. It is allowed.
    #[test]
    fn a_record_beneath_the_apex_is_permitted() {
        let incoming = set("api.auth.acme.com", vec![address("198.51.100.1")]);

        assert!(policy().permits_write(&incoming, &[], ann()).is_ok());
    }

    /// Acme writes an SPF `TXT` record on the apex itself. It is allowed,
    /// since only the apex's address is ours.
    #[test]
    fn a_non_address_record_on_the_apex_is_permitted() {
        let incoming = set("auth.acme.com", vec![txt_record("v=spf1 -all")]);

        assert!(policy().permits_write(&incoming, &[], ann()).is_ok());
    }

    /// Acme writes `*.auth.acme.com`. A wildcard inside the zone is ordinary
    /// DNS and is allowed.
    #[test]
    fn a_wildcard_beneath_the_apex_is_permitted() {
        let incoming = set("*.auth.acme.com", vec![address("198.51.100.1")]);

        assert!(policy().permits_write(&incoming, &[], ann()).is_ok());
    }

    /// Acme points `www.auth.acme.com` at another host with a `CNAME`. It
    /// is allowed.
    #[test]
    fn an_alias_beneath_the_apex_is_permitted() {
        let incoming = set("www.auth.acme.com", vec![alias("elsewhere.example.com")]);

        assert!(policy().permits_write(&incoming, &[], ann()).is_ok());
    }

    /// Zone writes reject records for the apex's parent, sibling and an
    /// unrelated domain.
    #[test]
    fn a_record_outside_the_zone_is_refused() {
        for outside in ["acme.com", "other.acme.com", "evil.com"] {
            let incoming = set(outside, vec![address("198.51.100.1")]);

            assert!(
                matches!(
                    policy().permits_write(&incoming, &[], ann()),
                    Err(DomainError::Validation(_))
                ),
                "{outside} should be outside the zone"
            );
        }
    }

    /// A record name that only starts with the apex's text is outside the
    /// zone and cannot be written.
    #[test]
    fn a_name_that_only_shares_a_prefix_with_the_apex_is_outside_it() {
        let incoming = set("auth.acme.com.evil.example", vec![address("198.51.100.1")]);

        assert!(policy().permits_write(&incoming, &[], ann()).is_err());
    }

    /// An admin at Acme writes an IPv4 or IPv6 address on the apex. Both are
    /// forbidden, since that would take the login page offline with no error.
    #[test]
    fn the_apex_address_is_ours() {
        for family in [address("198.51.100.1"), address("2001:db8::99")] {
            let incoming = set("auth.acme.com", vec![family]);

            assert!(matches!(
                policy().permits_write(&incoming, &[], ann()),
                Err(DomainError::Forbidden(_))
            ));
        }
    }

    /// An admin at Acme removes the apex `A` record. It is forbidden too.
    #[test]
    fn the_apex_address_cannot_be_removed_either() {
        assert!(matches!(
            policy().permits_removal(&record_name("auth.acme.com"), RecordKind::A, ann()),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Domain update rights do not allow writing the platform's certificate
    /// challenge TXT record.
    #[test]
    fn a_certificate_challenge_name_is_ours() {
        let incoming = set("_acme-challenge.auth.acme.com", vec![txt_record("proof")]);

        assert!(matches!(
            policy().permits_write(&incoming, &[], ann()),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A TXT at `_acme-challenge.api.auth.acme.com` is forbidden as well.
    /// The rule follows the label, not one fixed name.
    #[test]
    fn a_challenge_name_deeper_in_the_zone_is_also_ours() {
        let incoming = set(
            "_acme-challenge.api.auth.acme.com",
            vec![txt_record("proof")],
        );

        assert!(matches!(
            policy().permits_write(&incoming, &[], ann()),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Acme writes `_acme-challenge-notes.auth.acme.com`. The label only
    /// contains the text, so the name is Acme's to write.
    #[test]
    fn a_name_merely_resembling_a_challenge_is_the_tenants() {
        let incoming = set(
            "_acme-challenge-notes.auth.acme.com",
            vec![txt_record("mine")],
        );

        assert!(policy().permits_write(&incoming, &[], ann()).is_ok());
    }

    /// The apex `A` and the challenge `TXT` read as ours. An apex `MX` and an
    /// `A` on `api.auth.acme.com` read as the tenant's.
    #[test]
    fn reserved_sets_are_identifiable_for_presentation() {
        let policy = policy();

        assert!(policy.is_reserved(&record_name("auth.acme.com"), RecordKind::A));
        assert!(policy.is_reserved(
            &record_name("_acme-challenge.auth.acme.com"),
            RecordKind::Txt
        ));
        assert!(!policy.is_reserved(&record_name("auth.acme.com"), RecordKind::Mx));
        assert!(!policy.is_reserved(&record_name("api.auth.acme.com"), RecordKind::A));
    }

    /// Acme writes a `CNAME` on its apex. It is refused, since the apex
    /// carries the zone's `NS` and `SOA` records and a `CNAME` must stand
    /// alone.
    #[test]
    fn an_alias_on_the_apex_is_refused() {
        let incoming = set("auth.acme.com", vec![alias("elsewhere.example.com")]);

        assert!(matches!(
            policy().permits_write(&incoming, &[], ann()),
            Err(DomainError::Validation(_))
        ));
    }

    /// `api.auth.acme.com` already has an `A` record and Acme adds a
    /// `CNAME` there. It is refused.
    #[test]
    fn an_alias_beside_an_existing_record_is_refused() {
        let held = set("api.auth.acme.com", vec![address("198.51.100.1")]);
        let incoming = set("api.auth.acme.com", vec![alias("elsewhere.example.com")]);

        assert!(policy().permits_write(&incoming, &[held], ann()).is_err());
    }

    /// `www.auth.acme.com` already has a `CNAME` and Acme adds an `A` record
    /// there. It is refused.
    #[test]
    fn a_record_beside_an_existing_alias_is_refused() {
        let held = set("www.auth.acme.com", vec![alias("elsewhere.example.com")]);
        let incoming = set("www.auth.acme.com", vec![address("198.51.100.1")]);

        assert!(policy().permits_write(&incoming, &[held], ann()).is_err());
    }

    /// Acme points the `CNAME` on `www.auth.acme.com` at a new host. The
    /// replacement is allowed, not taken as a clash with the old one.
    #[test]
    fn replacing_an_existing_alias_is_permitted() {
        let held = set("www.auth.acme.com", vec![alias("old.example.com")]);
        let incoming = set("www.auth.acme.com", vec![alias("new.example.com")]);

        assert!(policy().permits_write(&incoming, &[held], ann()).is_ok());
    }

    /// A `CNAME` sits on `www.auth.acme.com` and Acme adds an `A` on
    /// `api.auth.acme.com`. It is allowed, since the rule applies per name.
    #[test]
    fn an_alias_on_another_name_does_not_block_a_record() {
        let held = set("www.auth.acme.com", vec![alias("elsewhere.example.com")]);
        let incoming = set("api.auth.acme.com", vec![address("198.51.100.1")]);

        assert!(policy().permits_write(&incoming, &[held], ann()).is_ok());
    }

    /// `api.auth.acme.com` has an `A` record and Acme adds a `TXT` beside it.
    /// It is allowed.
    #[test]
    fn two_types_that_are_not_aliases_coexist() {
        let held = set("api.auth.acme.com", vec![address("198.51.100.1")]);
        let incoming = set("api.auth.acme.com", vec![txt_record("v=spf1 -all")]);

        assert!(policy().permits_write(&incoming, &[held], ann()).is_ok());
    }
}
