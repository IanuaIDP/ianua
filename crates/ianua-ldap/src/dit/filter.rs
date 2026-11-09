//! LDAP search-filter evaluation against synthetic entries.
//!
//! Matching is case-insensitive, mirroring the `caseIgnoreMatch` rules the
//! exposed attributes use. Constructs the facade does not support —
//! ordering, approximate, and extensible matches — match nothing:
//! deny-by-default, an unsupported assertion never widens a result set.

use ldap3_proto::proto::{LdapFilter, LdapSubstringFilter};

use crate::dit::entries::Entry;

/// Whether `entry` satisfies `filter`.
#[must_use]
pub fn matches(filter: &LdapFilter, entry: &Entry) -> bool {
    match filter {
        LdapFilter::And(inner) => inner.iter().all(|f| matches(f, entry)),
        LdapFilter::Or(inner) => inner.iter().any(|f| matches(f, entry)),
        LdapFilter::Not(inner) => !matches(inner, entry),
        LdapFilter::Equality(attr, value) => entry
            .values(attr)
            .is_some_and(|vals| vals.iter().any(|v| v.eq_ignore_ascii_case(value))),
        LdapFilter::Present(attr) => entry.values(attr).is_some(),
        LdapFilter::Substring(attr, pattern) => entry
            .values(attr)
            .is_some_and(|vals| vals.iter().any(|v| substring_matches(v, pattern))),
        LdapFilter::GreaterOrEqual(..)
        | LdapFilter::LessOrEqual(..)
        | LdapFilter::Approx(..)
        | LdapFilter::Extensible(_) => false,
    }
}

fn substring_matches(value: &str, pattern: &LdapSubstringFilter) -> bool {
    let value = value.to_ascii_lowercase();
    let mut position = 0;

    if let Some(initial) = &pattern.initial {
        let initial = initial.to_ascii_lowercase();
        if !value.starts_with(&initial) {
            return false;
        }
        position = initial.len();
    }

    for any in &pattern.any {
        let any = any.to_ascii_lowercase();
        let Some(found) = value[position..].find(&any) else {
            return false;
        };
        position += found + any.len();
    }

    if let Some(last) = &pattern.final_ {
        let last = last.to_ascii_lowercase();
        return value.len() >= position + last.len() && value.ends_with(&last);
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            dn: "uid=ada@acme.com,ou=users,ou=prod,o=acme,dc=ianua".to_owned(),
            attrs: vec![
                (
                    "objectClass".to_owned(),
                    vec!["top".to_owned(), "inetOrgPerson".to_owned()],
                ),
                ("mail".to_owned(), vec!["ada@acme.com".to_owned()]),
                ("cn".to_owned(), vec!["Ada Lovelace".to_owned()]),
            ],
        }
    }

    #[test]
    fn equality_is_case_insensitive_on_attribute_and_value() {
        let f = LdapFilter::Equality("MAIL".to_owned(), "ADA@ACME.COM".to_owned());
        assert!(matches(&f, &entry()));
    }

    #[test]
    fn presence_and_boolean_composition_work() {
        let f = LdapFilter::And(vec![
            LdapFilter::Present("objectClass".to_owned()),
            LdapFilter::Or(vec![
                LdapFilter::Equality("cn".to_owned(), "nobody".to_owned()),
                LdapFilter::Equality("cn".to_owned(), "ada lovelace".to_owned()),
            ]),
            LdapFilter::Not(Box::new(LdapFilter::Present("member".to_owned()))),
        ]);
        assert!(matches(&f, &entry()));
    }

    #[test]
    fn substring_matches_initial_any_and_final() {
        let f = LdapFilter::Substring(
            "mail".to_owned(),
            LdapSubstringFilter {
                initial: Some("ada".to_owned()),
                any: vec!["@".to_owned()],
                final_: Some(".com".to_owned()),
            },
        );
        assert!(matches(&f, &entry()));

        let miss = LdapFilter::Substring(
            "mail".to_owned(),
            LdapSubstringFilter {
                initial: Some("bob".to_owned()),
                any: vec![],
                final_: None,
            },
        );
        assert!(!matches(&miss, &entry()));
    }

    #[test]
    fn unsupported_assertions_match_nothing() {
        let f = LdapFilter::GreaterOrEqual("cn".to_owned(), "a".to_owned());
        assert!(!matches(&f, &entry()));
        let not_wrapped = LdapFilter::Not(Box::new(f));
        assert!(
            matches(&not_wrapped, &entry()),
            "negation of an unsupported assertion is still boolean"
        );
    }
}
