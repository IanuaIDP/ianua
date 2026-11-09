//! The values a provider sends under a claim or an attribute, one or
//! several each, as it sent them.
//!
//! An OIDC `groups` claim is a list, and a SAML attribute carries one
//! `AttributeValue` per value. Each value is kept on its own: a provider
//! that puts Ann in `engineering` and `ops` sends two values, and a group
//! named by a DN such as `cn=ops,ou=groups,dc=acme,dc=com` stays one name,
//! commas and all.

use std::collections::HashMap;

/// What a provider sent under each claim or attribute name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderValues {
    by_name: HashMap<String, Vec<String>>,
}

impl ProviderValues {
    /// The values `by_name` holds: each name with every value sent under
    /// it, in the order sent.
    #[must_use]
    pub fn new(by_name: HashMap<String, Vec<String>>) -> Self {
        Self { by_name }
    }

    /// Every value sent under `name`, in order. Empty when nothing was sent
    /// under it.
    #[must_use]
    pub fn values(&self, name: &str) -> &[String] {
        self.by_name
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The first value sent under `name`, for a claim that holds one, such
    /// as `department`.
    #[must_use]
    pub fn first(&self, name: &str) -> Option<&str> {
        self.values(name).first().map(String::as_str)
    }

    /// How many names carry values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the provider sent nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(name: &str, values: &[&str]) -> ProviderValues {
        ProviderValues::new(HashMap::from([(
            name.to_owned(),
            values.iter().map(|value| (*value).to_owned()).collect(),
        )]))
    }

    /// Okta puts Ann in two groups and sends each as its own value. Both
    /// are kept, in order, and the first is the one a single-valued claim
    /// reads.
    #[test]
    fn every_value_sent_under_a_name_is_kept() {
        let values = sent("groups", &["engineering", "ops"]);

        assert_eq!(values.values("groups"), ["engineering", "ops"]);
        assert_eq!(values.first("groups"), Some("engineering"));
    }

    /// A group named by its DN keeps its commas: it is one value, not three.
    #[test]
    fn a_value_holding_commas_stays_one_value() {
        let values = sent("memberOf", &["cn=ops,ou=groups,dc=acme,dc=com"]);

        assert_eq!(values.values("memberOf").len(), 1);
    }

    /// A name nobody sent holds no value.
    #[test]
    fn a_name_not_sent_holds_nothing() {
        let values = sent("groups", &["engineering"]);

        assert!(values.values("department").is_empty());
        assert_eq!(values.first("department"), None);
    }
}
