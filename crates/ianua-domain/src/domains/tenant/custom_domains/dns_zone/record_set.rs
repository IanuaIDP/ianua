//! Every answer a zone gives to one question.

use crate::domains::tenant::custom_domains::dns_zone::kind::RecordKind;
use crate::domains::tenant::custom_domains::dns_zone::name::RecordName;
use crate::domains::tenant::custom_domains::dns_zone::ttl::Ttl;
use crate::domains::tenant::custom_domains::dns_zone::value::RecordValue;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;

/// The most values one set may hold.
///
/// That is more than a DNS answer can usefully carry. A set this large
/// already overflows a UDP response and forces every resolver onto TCP. The
/// limit also keeps checking a set cheap, whatever a caller sends.
pub(super) const MAX_VALUES: usize = 100;

/// Every answer a zone gives to one question.
///
/// DNS looks up a name and a type together and gets back a *set*. Two `A`
/// records share the load, two `MX` records are a primary and a backup, and
/// two `CAA` records allow two issuers. A resolver holding a cached set
/// replaces it whole, so the set is also what changes at once.
///
/// The set has one TTL, not one per value. A resolver caches the answer it
/// received as a whole, and RFC 2181 requires the values to agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSet {
    name: RecordName,
    kind: RecordKind,
    ttl: Ttl,
    values: Vec<RecordValue>,
}

impl RecordSet {
    /// Assembles the answers to one question.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `values` is empty. "No record" is
    ///   said by removing the set, not by an empty one.
    /// - [`DomainError::Validation`] when the values are not all one type. A
    ///   resolver asks for one type and must get answers of that type.
    /// - [`DomainError::Validation`] when a `CNAME` set holds more than one
    ///   value. A `CNAME` says this name *is* that name, so a second one
    ///   would contradict it.
    /// - [`DomainError::Validation`] when the same value appears twice.
    /// - [`DomainError::Validation`] when there are more than 100 values,
    ///   more than a DNS answer can usefully carry.
    pub fn new(name: RecordName, ttl: Ttl, values: Vec<RecordValue>) -> Result<Self, DomainError> {
        validate_count("values", values.len(), 0..=MAX_VALUES)?;
        let kind = one_kind(&values)?;
        ensure_distinct(&values)?;
        Ok(Self {
            name,
            kind,
            ttl,
            values,
        })
    }

    /// The name these answers are for.
    #[must_use]
    pub fn name(&self) -> &RecordName {
        &self.name
    }

    /// The type these answers are.
    #[must_use]
    pub fn kind(&self) -> RecordKind {
        self.kind
    }

    /// How long a resolver may cache the set.
    #[must_use]
    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// The answers themselves.
    #[must_use]
    pub fn values(&self) -> &[RecordValue] {
        &self.values
    }

    /// Whether this set answers the same question as `other`.
    ///
    /// A zone holds one set per name and type. So writing an address set over
    /// an address set replaces it, while a text set beside it stays.
    #[must_use]
    pub fn answers_same_as(&self, other: &Self) -> bool {
        self.name == other.name && self.kind == other.kind
    }

    /// This set with the values of `addition` added after its own, at the
    /// time to live of `addition`. A value it holds already is kept where it
    /// is.
    ///
    /// Several writers may each own one value of a set, such as two
    /// certificate orders proving one name. Each adds its own and takes away
    /// its own, so neither replaces the other's. A full set lets go of its
    /// oldest values to make room, so values left behind by writers stopped
    /// half way can never fill it for good.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `addition` answers another
    ///   question, or the merged values break a rule of [`RecordSet::new`],
    ///   such as a second `CNAME`.
    pub fn merged_with(&self, addition: &Self) -> Result<Self, DomainError> {
        if !self.answers_same_as(addition) {
            return Err(DomainError::invalid(message!(
                "tenant-only-a-set-answering-the-same",
                "only a set answering the same name and type can be added to another"
            )));
        }
        let added: Vec<&RecordValue> = addition
            .values
            .iter()
            .filter(|value| !self.values.contains(value))
            .collect();
        let room = self
            .values
            .len()
            .saturating_add(added.len())
            .saturating_sub(MAX_VALUES);
        let values = self
            .values
            .iter()
            .skip(room)
            .chain(added)
            .cloned()
            .collect();
        Self::new(self.name.clone(), addition.ttl, values)
    }

    /// This set without the values of `removal`, or none once nothing is
    /// left of it. Values of `removal` this set does not hold change
    /// nothing.
    #[must_use]
    pub fn without_values_of(&self, removal: &Self) -> Option<Self> {
        let values: Vec<RecordValue> = self
            .values
            .iter()
            .filter(|value| !removal.values.contains(value))
            .cloned()
            .collect();
        if values.is_empty() {
            return None;
        }
        Some(Self {
            name: self.name.clone(),
            kind: self.kind,
            ttl: self.ttl,
            values,
        })
    }

    /// Whether this set may not sit beside a set of `kind` on the same name.
    ///
    /// A `CNAME` clashes with every other type, in both directions. RFC 1034
    /// forbids the pairing, so resolvers never pick between two answers that
    /// contradict each other.
    #[must_use]
    pub fn conflicts_with(&self, kind: RecordKind) -> bool {
        if self.kind == kind {
            return false;
        }

        self.kind.is_exclusive() || kind.is_exclusive()
    }
}

/// The one type every value in a set has, when that type allows this many
/// values.
fn one_kind(values: &[RecordValue]) -> Result<RecordKind, DomainError> {
    let Some(first) = values.first() else {
        return Err(DomainError::invalid(message!(
            "tenant-a-record-set-needs-at-least",
            "a record set needs at least one value; remove the set instead"
        )));
    };
    let kind = first.kind();
    if let Some(odd) = values.iter().find(|value| value.kind() != kind) {
        return Err(DomainError::invalid(message!(
            "tenant-a-record-set-answers-one-type",
            format!(
                "a record set answers one type; found {kind} beside {}",
                odd.kind()
            )
        )));
    }
    if !kind.allows_multiple() && values.len() > 1 {
        return Err(DomainError::invalid(message!(
            "tenant-a-record-holds-exactly-one-value",
            format!(
                "a {kind} record holds exactly one value, got {}",
                values.len()
            )
        )));
    }
    Ok(kind)
}

/// Refuses a set that holds one value twice.
fn ensure_distinct(values: &[RecordValue]) -> Result<(), DomainError> {
    let Some(duplicate) = first_repeat(values) else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "tenant-appears-twice-in-the-same-record",
        format!(
            "'{}' appears twice in the same record set",
            duplicate.as_presentation()
        )
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::custom_domains::dns_zone::CaaHandling;
    use crate::domains::tenant::custom_domains::dns_zone::value::{
        CaaProperty, CaaTag, MailExchange, TxtValue,
    };
    use crate::test_support::builders::{record_name, txt_record};
    use crate::types::{DomainName, IpAddress};

    fn address(value: &str) -> RecordValue {
        RecordValue::Address(IpAddress::new(value).unwrap())
    }

    fn alias(value: &str) -> RecordValue {
        RecordValue::Alias(DomainName::new(value).unwrap())
    }

    fn mail(priority: u16, host: &str) -> RecordValue {
        RecordValue::Mail(MailExchange::new(priority, DomainName::new(host).unwrap()))
    }

    fn set(values: Vec<RecordValue>) -> Result<RecordSet, DomainError> {
        RecordSet::new(record_name("hello.acme.com"), Ttl::standard(), values)
    }

    /// A set of one IPv4 address for `hello.acme.com` is an `A` set, with the
    /// name and TTL it was given.
    #[test]
    fn a_set_takes_its_type_from_its_values() {
        let addresses = set(vec![address("203.0.113.10")]).unwrap();

        assert_eq!(addresses.kind(), RecordKind::A);
        assert_eq!(addresses.name().as_str(), "hello.acme.com");
        assert_eq!(addresses.ttl(), Ttl::standard());
    }

    /// A set holds two IPv4 addresses for one name. Both are kept, as for any
    /// site served from two machines.
    #[test]
    fn a_set_holds_several_answers_of_the_same_type() {
        let addresses = set(vec![address("203.0.113.10"), address("203.0.113.11")]).unwrap();

        assert_eq!(addresses.values().len(), 2);
    }

    /// A mail set holds `mx1` at priority 10 and `mx2` at 20. It is an `MX`
    /// set with both values.
    #[test]
    fn a_mail_set_holds_a_primary_and_a_backup() {
        let mail = set(vec![mail(10, "mx1.acme.com"), mail(20, "mx2.acme.com")]).unwrap();

        assert_eq!(mail.kind(), RecordKind::Mx);
        assert_eq!(mail.values().len(), 2);
    }

    /// A `CAA` set allows both Let's Encrypt and DigiCert to issue. Both
    /// values are kept.
    #[test]
    fn a_certificate_authorisation_set_may_name_several_issuers() {
        let caa = set(vec![
            RecordValue::Authority(CaaProperty::new(
                CaaHandling::NonCritical,
                CaaTag::Issue,
                TxtValue::new("letsencrypt.org").unwrap(),
            )),
            RecordValue::Authority(CaaProperty::new(
                CaaHandling::NonCritical,
                CaaTag::Issue,
                TxtValue::new("digicert.com").unwrap(),
            )),
        ])
        .unwrap();

        assert_eq!(caa.values().len(), 2);
    }

    /// A set with no values is refused. "No record" is said by removing the
    /// set.
    #[test]
    fn an_empty_set_is_refused() {
        assert!(set(Vec::new()).is_err());
    }

    /// A set holds an address and an SPF text. It is refused, since a
    /// resolver asks for one type and must get only that type.
    #[test]
    fn a_set_mixing_types_is_refused() {
        assert!(set(vec![address("203.0.113.10"), txt_record("v=spf1 -all")]).is_err());
    }

    /// A set holds an IPv4 and an IPv6 address. It is refused, since `A` and
    /// `AAAA` are separate types on the wire.
    #[test]
    fn addresses_of_different_families_are_different_sets() {
        assert!(set(vec![address("203.0.113.10"), address("2001:db8::1")]).is_err());
    }

    /// A set holds two `CNAME` targets. It is refused, since a name cannot
    /// be two other names at once.
    #[test]
    fn a_set_of_two_aliases_is_refused() {
        assert!(set(vec![alias("a.acme.com"), alias("b.acme.com")]).is_err());
    }

    /// A set holds one `CNAME` target. It is accepted as a `CNAME` set.
    #[test]
    fn a_single_alias_is_accepted() {
        assert_eq!(
            set(vec![alias("target.acme.com")]).unwrap().kind(),
            RecordKind::Cname
        );
    }

    /// A set holds `203.0.113.10` twice. It is refused, and the message names
    /// the repeated address.
    #[test]
    fn a_repeated_value_is_refused() {
        let err = set(vec![address("203.0.113.10"), address("203.0.113.10")]).unwrap_err();

        let DomainError::Validation(error) = err else {
            panic!("expected a validation error");
        };
        let message = error.to_string();
        assert!(message.contains("203.0.113.10"), "{message}");
    }

    /// A `CNAME` set clashes with each of the six other types.
    #[test]
    fn an_alias_conflicts_with_every_other_type() {
        let aliased = set(vec![alias("target.acme.com")]).unwrap();

        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| *k != RecordKind::Cname)
        {
            assert!(aliased.conflicts_with(kind), "CNAME should exclude {kind}");
        }
    }

    /// An `A` set clashes with a `CNAME`, so the rule holds in both
    /// directions.
    #[test]
    fn every_other_type_conflicts_with_an_alias() {
        let addresses = set(vec![address("203.0.113.10")]).unwrap();

        assert!(addresses.conflicts_with(RecordKind::Cname));
    }

    /// An `A` set may sit beside `TXT`, `MX`, `CAA` and `AAAA` sets.
    #[test]
    fn types_that_are_not_aliases_coexist_freely() {
        let addresses = set(vec![address("203.0.113.10")]).unwrap();

        for kind in [
            RecordKind::Txt,
            RecordKind::Mx,
            RecordKind::Caa,
            RecordKind::Aaaa,
        ] {
            assert!(!addresses.conflicts_with(kind), "A should allow {kind}");
        }
    }

    /// A `CNAME` set does not clash with another `CNAME`. Replacing a set is
    /// how it is edited, so it must not count as a clash.
    #[test]
    fn a_set_does_not_conflict_with_its_own_type() {
        let aliased = set(vec![alias("target.acme.com")]).unwrap();

        assert!(!aliased.conflicts_with(RecordKind::Cname));
    }

    /// Two `A` sets on one name answer the same question, even with
    /// different addresses. An `A` and a `TXT` set on that name do not.
    #[test]
    fn sets_answer_the_same_question_when_name_and_type_agree() {
        let first = set(vec![address("203.0.113.10")]).unwrap();
        let second = set(vec![address("203.0.113.11")]).unwrap();
        let other_type = set(vec![txt_record("v=spf1 -all")]).unwrap();

        assert!(first.answers_same_as(&second));
        assert!(!first.answers_same_as(&other_type));
    }

    /// An ACME challenge set is written with the shortest TTL and keeps it,
    /// while an ordinary set keeps the standard one. So a withdrawn challenge
    /// does not linger in caches.
    #[test]
    fn a_set_answers_with_the_ttl_it_was_written_with() {
        let brief = RecordSet::new(
            record_name("_acme-challenge.acme.com"),
            Ttl::shortest(),
            vec![txt_record("token")],
        )
        .unwrap();

        assert_eq!(brief.ttl(), Ttl::shortest());
        assert_ne!(brief.ttl(), Ttl::standard());
        assert_eq!(
            set(vec![address("203.0.113.10")]).unwrap().ttl(),
            Ttl::standard()
        );
    }

    /// A record set with 101 distinct addresses exceeds the value limit and
    /// is rejected.
    #[test]
    fn a_set_with_more_values_than_an_answer_carries_is_refused() {
        let values: Vec<RecordValue> = (0..=MAX_VALUES)
            .map(|i| address(&format!("10.0.{}.{}", i / 250, i % 250)))
            .collect();

        assert!(RecordSet::new(record_name("api.acme.com"), Ttl::standard(), values).is_err());
    }

    fn proofs(values: &[&str]) -> RecordSet {
        RecordSet::new(
            record_name("_acme-challenge.auth.acme.com"),
            Ttl::shortest(),
            values.iter().map(|value| txt_record(value)).collect(),
        )
        .unwrap()
    }

    /// Merging challenge values preserves both proofs. Removing one leaves
    /// the other, and removing the final value removes the set.
    #[test]
    fn a_value_added_and_taken_away_leaves_the_others() {
        let first = proofs(&["one"]);

        let both = first.merged_with(&proofs(&["two"])).unwrap();
        let left = both.without_values_of(&proofs(&["one"]));

        assert_eq!(both, proofs(&["one", "two"]));
        assert_eq!(left, Some(proofs(&["two"])));
        assert_eq!(left.unwrap().without_values_of(&proofs(&["two"])), None);
    }

    /// A value the set holds already is not added twice.
    #[test]
    fn a_value_held_already_is_kept_once() {
        let held = proofs(&["one"]);

        assert_eq!(held.merged_with(&proofs(&["one"])).unwrap(), held);
    }

    /// Adding a fresh proof to a full set removes the oldest value and appends
    /// the new one while keeping the set at its size limit.
    #[test]
    fn a_full_set_lets_its_oldest_value_go() {
        let names: Vec<String> = (0..MAX_VALUES).map(|i| format!("left-{i}")).collect();
        let full = proofs(&names.iter().map(String::as_str).collect::<Vec<_>>());

        let merged = full.merged_with(&proofs(&["fresh"])).unwrap();

        assert_eq!(merged.values().len(), MAX_VALUES);
        assert_eq!(merged.values().first(), Some(&txt_record("left-1")));
        assert_eq!(merged.values().last(), Some(&txt_record("fresh")));
    }

    /// A set answering another name cannot be added to this one.
    #[test]
    fn a_set_for_another_name_cannot_be_added() {
        let elsewhere = RecordSet::new(
            record_name("hello.acme.com"),
            Ttl::shortest(),
            vec![txt_record("x")],
        )
        .unwrap();

        assert!(proofs(&["one"]).merged_with(&elsewhere).is_err());
    }
}
