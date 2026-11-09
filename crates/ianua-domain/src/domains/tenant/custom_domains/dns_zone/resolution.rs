//! What a nameserver answers, decided without touching a socket.
//!
//! Every decision our nameservers make lives here. The rest of the data
//! plane only moves bytes on and off the wire. These are pure functions over
//! a zone, so they are tested fully without a server, a port or a resolver.
//!
//! # Refusing is not the same as denying
//!
//! Three different "no" answers matter, and mixing them up is a common bug
//! in authoritative servers:
//!
//! - [`Resolution::Refused`]: the name is not in a zone we hold. We say
//!   nothing about whether it exists, because it is not ours to say.
//!   Answering `NXDOMAIN` would claim authority over a name somebody else
//!   runs.
//! - [`Resolution::NoData`]: the name exists in our zone, but not with the
//!   type asked for.
//! - [`Resolution::NameError`]: the name does not exist in our zone, and we
//!   may say so.
//!
//! A resolver treats the three very differently. A server that merges them
//! either claims authority it does not have, or breaks negative caching for
//! names it does hold.

use crate::domains::tenant::custom_domains::dns_zone::kind::RecordKind;
use crate::domains::tenant::custom_domains::dns_zone::name::RecordName;
use crate::domains::tenant::custom_domains::dns_zone::policy::is_challenge;
use crate::domains::tenant::custom_domains::dns_zone::record_set::RecordSet;
use crate::domains::tenant::custom_domains::dns_zone::ttl::Ttl;
use crate::domains::tenant::custom_domains::dns_zone::value::RecordValue;
use crate::domains::tenant::custom_domains::dns_zone::zone::{Authority, StartOfAuthority, Zone};
use crate::types::DomainName;

/// How many `CNAME` hops we follow inside one zone before giving up.
///
/// A chain that long is a mistake. Following it without end would let one
/// query take the nameserver down.
const MAX_ALIAS_HOPS: usize = 8;

/// What a resolver asked for.
///
/// It covers more than [`RecordKind`], which is what a *tenant may write*. A
/// query may ask for `SOA` and `NS`, which only we produce, and for types we
/// do not serve at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind {
    /// One of the types a tenant writes.
    Record(RecordKind),
    /// The zone's own start of authority.
    StartOfAuthority,
    /// The zone's own nameservers.
    Nameservers,
    /// Everything at the name. It is answered as not implemented, see
    /// [`resolve`].
    Any,
    /// A type we do not serve.
    Unsupported,
}

/// One record in an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The name the record answers for.
    ///
    /// For a wildcard match this is the name that was *asked for*, never the
    /// `*` that matched. A resolver caching the literal `*` would go on to
    /// answer for names we never meant to cover.
    pub name: RecordName,
    /// How long the answer may be cached.
    pub ttl: Ttl,
    /// The answer itself.
    pub value: AnswerValue,
}

/// The content of an answer.
///
/// It is apart from [`RecordValue`] because two of these are ours alone. A
/// tenant can write an address. Only the nameserver produces the `SOA` and
/// `NS` that say who holds the zone, so nobody can forge them through the
/// record API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerValue {
    /// A record a tenant wrote.
    Record(RecordValue),
    /// The zone's start of authority.
    StartOfAuthority(Box<StartOfAuthority>),
    /// One of the zone's nameservers.
    Nameserver(DomainName),
}

/// What the nameserver answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The name is not in a zone we hold, so we say nothing about it.
    Refused,
    /// Here are the answers, with the zone's authority behind them.
    Found {
        /// The records answering the question.
        answers: Vec<Answer>,
        /// The zone's nameservers, for the authority section.
        authority: Vec<Answer>,
    },
    /// The name exists here, but not with the type asked for.
    NoData {
        /// The zone's `SOA`, which tells a resolver how long to remember it.
        soa: Answer,
    },
    /// The name does not exist in this zone.
    NameError {
        /// The zone's `SOA`, which tells a resolver how long to remember it.
        soa: Answer,
    },
    /// We do not serve this kind of question.
    NotImplemented,
}

/// What this zone answers for `name` and `kind`.
///
/// `ANY` is answered as [`Resolution::NotImplemented`], not with every
/// record at the name. Per RFC 8482, the full answer turns one small query
/// into a large response, which is how DNS amplification attacks work.
#[must_use]
pub fn resolve(
    zone: &Zone,
    authority: &Authority,
    name: &RecordName,
    kind: QueryKind,
) -> Resolution {
    if !name.is_within(zone.apex()) {
        return Resolution::Refused;
    }

    if matches!(kind, QueryKind::Unsupported | QueryKind::Any) {
        return Resolution::NotImplemented;
    }

    resolve_own_records(zone, authority, name, kind)
        .unwrap_or_else(|| resolve_stored_records(zone, authority, name, kind))
}

/// What the zone's stored records answer for `name` and `kind`.
///
/// The records at the name come first, following aliases, then a wildcard
/// covering it. With neither, the answer says whether the name exists at
/// all.
fn resolve_stored_records(
    zone: &Zone,
    authority: &Authority,
    name: &RecordName,
    kind: QueryKind,
) -> Resolution {
    let found = follow(zone, name, kind, MAX_ALIAS_HOPS);

    if !found.is_empty() {
        return Resolution::Found {
            answers: found,
            authority: nameserver_answers(zone, authority),
        };
    }

    if zone.has_node(name) {
        return Resolution::NoData {
            soa: soa_answer(zone, authority),
        };
    }

    match wildcard_answers(zone, name, kind) {
        Some(answers) => Resolution::Found {
            answers,
            authority: nameserver_answers(zone, authority),
        },
        None => Resolution::NameError {
            soa: soa_answer(zone, authority),
        },
    }
}

/// The two records the zone produces for itself, when asked for them.
///
/// They exist only at the apex. A resolver asking for the `SOA` of a name
/// inside the zone is answered as for any missing type, with `NODATA`.
fn resolve_own_records(
    zone: &Zone,
    authority: &Authority,
    name: &RecordName,
    kind: QueryKind,
) -> Option<Resolution> {
    if !matches!(kind, QueryKind::StartOfAuthority | QueryKind::Nameservers) {
        return None;
    }

    if !name.is_apex_of(zone.apex()) {
        return Some(if zone.has_node(name) {
            Resolution::NoData {
                soa: soa_answer(zone, authority),
            }
        } else {
            Resolution::NameError {
                soa: soa_answer(zone, authority),
            }
        });
    }

    let answers = match kind {
        QueryKind::StartOfAuthority => vec![soa_answer(zone, authority)],
        QueryKind::Record(_) | QueryKind::Nameservers | QueryKind::Any | QueryKind::Unsupported => {
            nameserver_answers(zone, authority)
        }
    };

    Some(Resolution::Found {
        answers,
        authority: nameserver_answers(zone, authority),
    })
}

/// The records at `name`, following any alias in the way.
///
/// A `CNAME` is returned whatever was asked for. It says the name *is*
/// another name, and the resolver must learn that first. When the target is
/// inside this zone we follow it ourselves, which saves the resolver a round
/// trip.
fn follow(zone: &Zone, name: &RecordName, kind: QueryKind, hops: usize) -> Vec<Answer> {
    if let Some(direct) = zone.record_set_at(name, as_record_kind(kind)) {
        return records_of(direct, name);
    }

    let Some(alias) = zone.record_set_at(name, RecordKind::Cname) else {
        return Vec::new();
    };

    let mut answers = records_of(alias, name);

    let Some(RecordValue::Alias(target)) = alias.values().first() else {
        return answers;
    };

    let target = RecordName::from(target);

    let Some(remaining) = hops.checked_sub(1) else {
        return answers;
    };
    if !target.is_within(zone.apex()) {
        return answers;
    }

    answers.extend(follow(zone, &target, kind, remaining));
    answers
}

/// The records a wildcard would answer `name` with, if one covers it.
///
/// The wildcard is looked for only beneath the closest ancestor that
/// exists, per RFC 4592. Searching from the name itself would let `*.zone`
/// answer for a name a real record already covers further down.
///
/// A certificate challenge name is never answered from a wildcard. A
/// certificate authority takes whatever it finds at `_acme-challenge` as the
/// zone's word. So a tenant's `*` alias would let whoever runs the target
/// zone get certificates for the hostname.
///
/// Only the wildcard's own records take the asked-for name. Records reached
/// by following its alias keep their own names, as for any other alias.
fn wildcard_answers(zone: &Zone, name: &RecordName, kind: QueryKind) -> Option<Vec<Answer>> {
    if is_challenge(name) {
        return None;
    }

    let encloser = zone.closest_encloser(name);

    if &encloser == name {
        return None;
    }

    let wildcard = RecordName::new(format!("*.{}", encloser.as_str())).ok()?;
    let answers = follow(zone, &wildcard, kind, MAX_ALIAS_HOPS);

    if answers.is_empty() {
        return None;
    }

    Some(
        answers
            .into_iter()
            .map(|answer| owned_by_asked_name(answer, &wildcard, name))
            .collect(),
    )
}

/// `answer` under the asked-for name when the wildcard itself owns it.
fn owned_by_asked_name(answer: Answer, wildcard: &RecordName, asked: &RecordName) -> Answer {
    if &answer.name != wildcard {
        return answer;
    }
    Answer {
        name: asked.clone(),
        ..answer
    }
}

/// A set's values as answers, owned by `name`.
fn records_of(set: &RecordSet, name: &RecordName) -> Vec<Answer> {
    set.values()
        .iter()
        .map(|value| Answer {
            name: name.clone(),
            ttl: set.ttl(),
            value: AnswerValue::Record(value.clone()),
        })
        .collect()
}

/// The zone's `SOA`, as an answer.
fn soa_answer(zone: &Zone, authority: &Authority) -> Answer {
    Answer {
        name: RecordName::from(zone.apex()),
        ttl: authority.ttl(),
        value: AnswerValue::StartOfAuthority(Box::new(authority.start_of_authority(zone))),
    }
}

/// The zone's own `NS` records, as answers.
///
/// They are the zone's own, not the deployment's. Each delegated zone
/// answers with the names its parent was told to point at, which ties it to
/// the registration that asked for it.
fn nameserver_answers(zone: &Zone, authority: &Authority) -> Vec<Answer> {
    zone.nameservers()
        .iter()
        .map(|nameserver| Answer {
            name: RecordName::from(zone.apex()),
            ttl: authority.ttl(),
            value: AnswerValue::Nameserver(nameserver.clone()),
        })
        .collect()
}

/// The record type a question is asking for.
///
/// `SOA`, `NS`, `ANY` and unsupported types never reach here, since they are
/// answered before the zone is searched. They map to `CNAME` only so the
/// match is complete.
fn as_record_kind(kind: QueryKind) -> RecordKind {
    match kind {
        QueryKind::Record(kind) => kind,
        QueryKind::StartOfAuthority
        | QueryKind::Nameservers
        | QueryKind::Any
        | QueryKind::Unsupported => RecordKind::Cname,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::custom_domains::dns_zone::zone::Serial;
    use crate::test_support::builders::record_name;
    use crate::types::IpAddress;

    fn apex() -> DomainName {
        DomainName::new("auth.acme.com").unwrap()
    }

    fn authority() -> Authority {
        Authority::new(record_name("hostmaster.ianua.test"))
    }

    /// This zone's own names, as a delegated zone has.
    fn nameservers() -> Vec<DomainName> {
        vec![
            DomainName::new("abc123.ns1.ianua.test").unwrap(),
            DomainName::new("abc123.ns2.ianua.test").unwrap(),
        ]
    }

    fn set(owner: &str, values: Vec<RecordValue>) -> RecordSet {
        RecordSet::new(record_name(owner), Ttl::standard(), values).unwrap()
    }

    fn address(value: &str) -> RecordValue {
        RecordValue::Address(IpAddress::new(value).unwrap())
    }

    fn alias(target: &str) -> RecordValue {
        RecordValue::Alias(DomainName::new(target).unwrap())
    }

    fn zone(sets: Vec<RecordSet>) -> Zone {
        Zone::new(
            apex(),
            Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()),
            sets,
            nameservers(),
        )
        .unwrap()
    }

    fn ask(zone: &Zone, name_str: &str, kind: QueryKind) -> Resolution {
        resolve(zone, &authority(), &record_name(name_str), kind)
    }

    fn addresses(resolution: &Resolution) -> Vec<String> {
        let Resolution::Found { answers, .. } = resolution else {
            return Vec::new();
        };

        answers
            .iter()
            .filter_map(|a| match &a.value {
                AnswerValue::Record(value) => Some(value.as_presentation()),
                _ => None,
            })
            .collect()
    }

    /// Queries for the zone's parent, a sibling and an unrelated domain return
    /// a refusal because the zone has no authority over those names.
    #[test]
    fn a_name_outside_the_zone_is_refused_not_denied() {
        let zone = zone(vec![set("auth.acme.com", vec![address("203.0.113.10")])]);

        for outside in ["acme.com", "other.acme.com", "evil.example.com"] {
            assert_eq!(
                ask(&zone, outside, QueryKind::Record(RecordKind::A)),
                Resolution::Refused,
                "{outside} is not ours to answer for"
            );
        }
    }

    /// A query for `auth.acme.com.evil.example` only starts with the apex.
    /// It belongs to somebody else and is refused.
    #[test]
    fn a_name_sharing_only_a_prefix_with_the_apex_is_refused() {
        let zone = zone(Vec::new());

        assert_eq!(
            ask(
                &zone,
                "auth.acme.com.evil.example",
                QueryKind::Record(RecordKind::A)
            ),
            Resolution::Refused
        );
    }

    /// A query for the `A` at `api.auth.acme.com` gets its address.
    #[test]
    fn a_record_at_a_name_is_answered() {
        let zone = zone(vec![set(
            "api.auth.acme.com",
            vec![address("198.51.100.1")],
        )]);

        let found = ask(&zone, "api.auth.acme.com", QueryKind::Record(RecordKind::A));

        assert_eq!(addresses(&found), ["198.51.100.1"]);
    }

    /// A name with two addresses answers with both, in order, so clients
    /// spread across the two machines.
    #[test]
    fn every_value_in_a_set_is_answered() {
        let zone = zone(vec![set(
            "api.auth.acme.com",
            vec![address("198.51.100.1"), address("198.51.100.2")],
        )]);

        let found = ask(&zone, "api.auth.acme.com", QueryKind::Record(RecordKind::A));

        assert_eq!(addresses(&found), ["198.51.100.1", "198.51.100.2"]);
    }

    /// An answer carries the zone's two nameservers in its authority part.
    /// A resolver learns whom to ask next time without a second query.
    #[test]
    fn an_answer_carries_the_zones_authority() {
        let zone = zone(vec![set(
            "api.auth.acme.com",
            vec![address("198.51.100.1")],
        )]);

        let Resolution::Found { authority, .. } =
            ask(&zone, "api.auth.acme.com", QueryKind::Record(RecordKind::A))
        else {
            panic!("expected an answer");
        };

        assert_eq!(authority.len(), 2);
        assert!(
            authority
                .iter()
                .all(|a| matches!(a.value, AnswerValue::Nameserver(_)))
        );
    }

    /// A query asks for `MX` at a name that has only an `A`. It gets
    /// `NODATA`, so the resolver does not cache the name as missing.
    #[test]
    fn a_name_without_the_type_asked_for_is_nodata() {
        let zone = zone(vec![set(
            "api.auth.acme.com",
            vec![address("198.51.100.1")],
        )]);

        let answer = ask(
            &zone,
            "api.auth.acme.com",
            QueryKind::Record(RecordKind::Mx),
        );

        assert!(matches!(answer, Resolution::NoData { .. }), "{answer:?}");
    }

    /// A query for `missing.auth.acme.com`, which the zone does not hold,
    /// gets a name error.
    #[test]
    fn a_name_the_zone_does_not_hold_is_a_name_error() {
        let zone = zone(vec![set(
            "api.auth.acme.com",
            vec![address("198.51.100.1")],
        )]);

        let answer = ask(
            &zone,
            "missing.auth.acme.com",
            QueryKind::Record(RecordKind::A),
        );

        assert!(matches!(answer, Resolution::NameError { .. }), "{answer:?}");
    }

    /// Only `a.b.auth.acme.com` has a record, and a query asks for
    /// `b.auth.acme.com`. It gets `NODATA`, since `NXDOMAIN` would tell the
    /// resolver everything beneath is gone.
    #[test]
    fn a_name_with_only_descendants_is_nodata_not_a_name_error() {
        let zone = zone(vec![set(
            "a.b.auth.acme.com",
            vec![address("198.51.100.1")],
        )]);

        let answer = ask(&zone, "b.auth.acme.com", QueryKind::Record(RecordKind::A));

        assert!(matches!(answer, Resolution::NoData { .. }), "{answer:?}");
    }

    /// A query for the `A` at the apex of an empty zone gets `NODATA`. The
    /// zone never denies its own name.
    #[test]
    fn an_empty_zones_apex_is_nodata_not_a_name_error() {
        let answer = ask(
            &zone(Vec::new()),
            "auth.acme.com",
            QueryKind::Record(RecordKind::A),
        );

        assert!(matches!(answer, Resolution::NoData { .. }), "{answer:?}");
    }

    /// A `NODATA` and a name error both carry the zone's `SOA` at the apex.
    /// Only the `SOA` tells a resolver how long to remember them.
    #[test]
    fn both_negative_answers_carry_the_soa() {
        let zone = zone(vec![set(
            "api.auth.acme.com",
            vec![address("198.51.100.1")],
        )]);

        for answer in [
            ask(
                &zone,
                "api.auth.acme.com",
                QueryKind::Record(RecordKind::Mx),
            ),
            ask(
                &zone,
                "missing.auth.acme.com",
                QueryKind::Record(RecordKind::A),
            ),
        ] {
            let (Resolution::NoData { soa } | Resolution::NameError { soa }) = answer else {
                panic!("expected a negative answer");
            };
            assert!(matches!(soa.value, AnswerValue::StartOfAuthority(_)));
            assert_eq!(soa.name.as_str(), "auth.acme.com");
        }
    }

    /// A query for the `SOA` at the apex gets exactly one `SOA` answer.
    #[test]
    fn the_apex_answers_for_its_own_soa() {
        let found = ask(
            &zone(Vec::new()),
            "auth.acme.com",
            QueryKind::StartOfAuthority,
        );

        let Resolution::Found { answers, .. } = found else {
            panic!("expected an answer");
        };
        assert_eq!(answers.len(), 1);
        assert!(matches!(answers[0].value, AnswerValue::StartOfAuthority(_)));
    }

    /// A query for `NS` at the apex gets both of the zone's nameservers.
    #[test]
    fn the_apex_answers_for_its_own_nameservers() {
        let found = ask(&zone(Vec::new()), "auth.acme.com", QueryKind::Nameservers);

        let Resolution::Found { answers, .. } = found else {
            panic!("expected an answer");
        };
        assert_eq!(answers.len(), 2);
        assert!(
            answers
                .iter()
                .all(|a| matches!(a.value, AnswerValue::Nameserver(_)))
        );
    }

    /// A query for the `SOA` at `api.auth.acme.com` gets `NODATA`, not a copy
    /// of the zone's. Only the apex has one.
    #[test]
    fn a_name_inside_the_zone_has_no_soa_of_its_own() {
        let zone = zone(vec![set(
            "api.auth.acme.com",
            vec![address("198.51.100.1")],
        )]);

        let answer = ask(&zone, "api.auth.acme.com", QueryKind::StartOfAuthority);

        assert!(matches!(answer, Resolution::NoData { .. }), "{answer:?}");
    }

    /// A query for `NS` gets the zone's own two names, not names every zone
    /// shares. A delegation is checked against these, so any other answer
    /// would fail a correct delegation for good.
    #[test]
    fn a_zone_answers_with_its_own_nameservers() {
        let Resolution::Found { answers, .. } =
            ask(&zone(Vec::new()), "auth.acme.com", QueryKind::Nameservers)
        else {
            panic!("expected an answer");
        };

        let names: Vec<String> = answers
            .iter()
            .filter_map(|a| match &a.value {
                AnswerValue::Nameserver(host) => Some(host.as_str().to_owned()),
                _ => None,
            })
            .collect();

        assert_eq!(names, ["abc123.ns1.ianua.test", "abc123.ns2.ianua.test"]);
    }

    /// A query asks for `A` at a name holding a `CNAME` to another domain.
    /// It gets the `CNAME`, since the resolver must learn the name is an
    /// alias.
    #[test]
    fn an_alias_is_answered_even_when_another_type_was_asked_for() {
        let zone = zone(vec![set(
            "www.auth.acme.com",
            vec![alias("elsewhere.example.com")],
        )]);

        let Resolution::Found { answers, .. } =
            ask(&zone, "www.auth.acme.com", QueryKind::Record(RecordKind::A))
        else {
            panic!("expected the alias");
        };

        assert_eq!(answers.len(), 1);
        assert_eq!(
            answers[0].value,
            AnswerValue::Record(alias("elsewhere.example.com"))
        );
    }

    /// `www` aliases `api` in the same zone. A query for `www` gets the alias
    /// and `api`'s address together, saving the resolver a round trip.
    #[test]
    fn an_alias_inside_the_zone_is_followed() {
        let zone = zone(vec![
            set("www.auth.acme.com", vec![alias("api.auth.acme.com")]),
            set("api.auth.acme.com", vec![address("198.51.100.1")]),
        ]);

        let found = ask(&zone, "www.auth.acme.com", QueryKind::Record(RecordKind::A));

        assert_eq!(
            addresses(&found),
            ["api.auth.acme.com", "198.51.100.1"],
            "the alias and what it resolves to"
        );
    }

    /// `www` aliases `elsewhere.example.com`. Only the alias is returned,
    /// since an authoritative server does not chase names outside its zones.
    #[test]
    fn an_alias_leaving_the_zone_is_not_followed() {
        let zone = zone(vec![set(
            "www.auth.acme.com",
            vec![alias("elsewhere.example.com")],
        )]);

        let found = ask(&zone, "www.auth.acme.com", QueryKind::Record(RecordKind::A));

        assert_eq!(addresses(&found), ["elsewhere.example.com"]);
    }

    /// A two-name alias cycle returns a bounded answer of at most nine records.
    #[test]
    fn an_alias_loop_terminates() {
        let zone = zone(vec![
            set("a.auth.acme.com", vec![alias("b.auth.acme.com")]),
            set("b.auth.acme.com", vec![alias("a.auth.acme.com")]),
        ]);

        let found = ask(&zone, "a.auth.acme.com", QueryKind::Record(RecordKind::A));

        let Resolution::Found { answers, .. } = found else {
            panic!("expected the alias chain");
        };
        assert!(answers.len() <= MAX_ALIAS_HOPS + 1, "{}", answers.len());
    }

    /// A query asks for the `CNAME` at `www` itself. It gets only the alias,
    /// not the address it leads to.
    #[test]
    fn asking_for_the_alias_itself_does_not_follow_it() {
        let zone = zone(vec![
            set("www.auth.acme.com", vec![alias("api.auth.acme.com")]),
            set("api.auth.acme.com", vec![address("198.51.100.1")]),
        ]);

        let found = ask(
            &zone,
            "www.auth.acme.com",
            QueryKind::Record(RecordKind::Cname),
        );

        assert_eq!(addresses(&found), ["api.auth.acme.com"]);
    }

    /// The zone holds `*.auth.acme.com`. A query for
    /// `anything.auth.acme.com` gets the wildcard's address.
    #[test]
    fn a_wildcard_answers_for_a_name_that_does_not_exist() {
        let zone = zone(vec![set("*.auth.acme.com", vec![address("198.51.100.9")])]);

        let found = ask(
            &zone,
            "anything.auth.acme.com",
            QueryKind::Record(RecordKind::A),
        );

        assert_eq!(addresses(&found), ["198.51.100.9"]);
    }

    /// A wildcard answer for `anything.auth.acme.com` is named
    /// `anything.auth.acme.com`, not `*`. A resolver caching `*` would cover
    /// names we never meant to.
    #[test]
    fn a_wildcard_answers_under_the_name_that_was_asked_for() {
        let zone = zone(vec![set("*.auth.acme.com", vec![address("198.51.100.9")])]);

        let Resolution::Found { answers, .. } = ask(
            &zone,
            "anything.auth.acme.com",
            QueryKind::Record(RecordKind::A),
        ) else {
            panic!("expected the wildcard");
        };

        assert_eq!(answers[0].name.as_str(), "anything.auth.acme.com");
    }

    /// A wildcard alias to an external domain does not answer a certificate
    /// challenge lookup, which returns a name error.
    #[test]
    fn a_wildcard_never_answers_for_a_certificate_challenge() {
        let zone = zone(vec![set(
            "*.auth.acme.com",
            vec![alias("evil.example.net")],
        )]);

        let found = ask(
            &zone,
            "_acme-challenge.auth.acme.com",
            QueryKind::Record(RecordKind::Txt),
        );

        assert!(matches!(found, Resolution::NameError { .. }), "{found:?}");
    }

    /// A wildcard aliases `api.auth.acme.com`. The alias is named as asked,
    /// while `api`'s address keeps its own name.
    #[test]
    fn a_wildcard_alias_target_keeps_its_own_name() {
        let zone = zone(vec![
            set("*.auth.acme.com", vec![alias("api.auth.acme.com")]),
            set("api.auth.acme.com", vec![address("198.51.100.1")]),
        ]);

        let Resolution::Found { answers, .. } = ask(
            &zone,
            "anything.auth.acme.com",
            QueryKind::Record(RecordKind::A),
        ) else {
            panic!("expected the wildcard");
        };

        let names: Vec<&str> = answers.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["anything.auth.acme.com", "api.auth.acme.com"]);
    }

    /// The zone holds both a wildcard and a real `api` record. A query for
    /// `api` gets the real record's address.
    #[test]
    fn a_real_record_beats_a_wildcard() {
        let zone = zone(vec![
            set("*.auth.acme.com", vec![address("198.51.100.9")]),
            set("api.auth.acme.com", vec![address("198.51.100.1")]),
        ]);

        let found = ask(&zone, "api.auth.acme.com", QueryKind::Record(RecordKind::A));

        assert_eq!(addresses(&found), ["198.51.100.1"]);
    }

    /// `b.auth.acme.com` exists through `a.b`, and a query asks for
    /// `missing.b`. The higher `*.auth.acme.com` does not reach past `b`, so
    /// the answer is a name error.
    #[test]
    fn a_wildcard_does_not_answer_past_a_closer_name() {
        let zone = zone(vec![
            set("*.auth.acme.com", vec![address("198.51.100.9")]),
            set("a.b.auth.acme.com", vec![address("198.51.100.1")]),
        ]);

        let answer = ask(
            &zone,
            "missing.b.auth.acme.com",
            QueryKind::Record(RecordKind::A),
        );

        assert!(matches!(answer, Resolution::NameError { .. }), "{answer:?}");
    }

    /// A wildcard holds only an `A`, and a query asks for `MX`. The answer is
    /// a name error.
    #[test]
    fn a_wildcard_without_the_type_asked_for_is_a_name_error() {
        let zone = zone(vec![set("*.auth.acme.com", vec![address("198.51.100.9")])]);

        let answer = ask(
            &zone,
            "anything.auth.acme.com",
            QueryKind::Record(RecordKind::Mx),
        );

        assert!(matches!(answer, Resolution::NameError { .. }), "{answer:?}");
    }

    /// A query for the `A` at the apex gets `NODATA`. The apex exists, so the
    /// wildcard beneath it never answers for it.
    #[test]
    fn a_wildcard_does_not_answer_for_the_apex() {
        let zone = zone(vec![set("*.auth.acme.com", vec![address("198.51.100.9")])]);

        let answer = ask(&zone, "auth.acme.com", QueryKind::Record(RecordKind::A));

        assert!(matches!(answer, Resolution::NoData { .. }), "{answer:?}");
    }

    /// An `ANY` query for an existing address returns not implemented.
    #[test]
    fn an_any_query_is_not_answered() {
        let zone = zone(vec![set(
            "api.auth.acme.com",
            vec![address("198.51.100.1")],
        )]);

        assert_eq!(
            ask(&zone, "api.auth.acme.com", QueryKind::Any),
            Resolution::NotImplemented
        );
    }

    /// A query for a type we do not serve gets "not implemented".
    #[test]
    fn an_unsupported_type_is_not_answered() {
        let zone = zone(Vec::new());

        assert_eq!(
            ask(&zone, "auth.acme.com", QueryKind::Unsupported),
            Resolution::NotImplemented
        );
    }

    /// An `ANY` query for `evil.example.com`, a name we do not hold, is
    /// refused. The refusal comes before the type is looked at.
    #[test]
    fn a_name_outside_the_zone_is_refused_before_the_type_is_considered() {
        assert_eq!(
            ask(&zone(Vec::new()), "evil.example.com", QueryKind::Any),
            Resolution::Refused
        );
    }
}
