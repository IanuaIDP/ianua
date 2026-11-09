//! Domains the operator of an installation vouches for.

use crate::message;
use crate::shared::errors::DomainError;
use crate::types::DomainName;

/// Parent domains whose names need no DNS proof of ownership.
///
/// A tenant normally proves a domain is theirs by publishing a token or
/// delegating it. On a shared deployment a name is claimed globally, and the
/// tenant asking may not own it. An installation with one organization has no
/// stranger to guard against. Whoever configured it already owns these names.
/// A proof would only add a DNS round trip, on a network that may never reach
/// a public resolver.
///
/// A name is covered when it is a listed parent or any name beneath one, at any
/// depth. `corp.com` covers `corp.com`, `app.corp.com` and `a.b.corp.com`, and
/// does not cover `evilcorp.com`.
///
/// It is empty by default, as on every shared deployment. Listing a parent
/// there would let any tenant take any name under it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedDomains(Vec<DomainName>);

impl TrustedDomains {
    /// Trusts every name at or beneath each of `parents`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a parent is a wildcard. A parent
    ///   already covers every depth beneath it, so a wildcard would say the
    ///   same thing less clearly.
    pub fn new(parents: impl IntoIterator<Item = DomainName>) -> Result<Self, DomainError> {
        let parents: Vec<DomainName> = parents.into_iter().collect();

        if let Some(wildcard) = parents.iter().find(|parent| parent.is_wildcard()) {
            return Err(DomainError::invalid(message!(
                "tenant-trusted-domain-is-a-wildcard-list",
                format!(
                    "trusted domain '{wildcard}' is a wildcard; list the parent \
                 without '*.', which already covers every name beneath it"
                )
            )));
        }

        Ok(Self(parents))
    }

    /// Whether no parent is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The trusted parents, in the order they were listed.
    #[must_use]
    pub fn parents(&self) -> &[DomainName] {
        &self.0
    }

    /// Whether `domain` is one of the trusted parents or beneath one.
    ///
    /// A wildcard is judged by the name it stands in front of, so
    /// `*.app.corp.com` is covered exactly when `app.corp.com` is.
    #[must_use]
    pub fn covers(&self, domain: &DomainName) -> bool {
        let name = domain.wildcard_parent().unwrap_or_else(|| domain.clone());

        self.0.iter().any(|parent| is_at_or_beneath(&name, parent))
    }
}

fn is_at_or_beneath(name: &DomainName, parent: &DomainName) -> bool {
    let Some(prefix) = name.as_str().strip_suffix(parent.as_str()) else {
        return false;
    };

    prefix.is_empty() || prefix.ends_with('.')
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::test_support::builders::domain_name;

    fn trusting(parents: &[&str]) -> TrustedDomains {
        TrustedDomains::new(parents.iter().map(|p| domain_name(p))).unwrap()
    }

    /// An installation trusts `corp.com`. `corp.com` itself is covered.
    #[test]
    fn a_listed_parent_covers_itself() {
        assert!(trusting(&["corp.com"]).covers(&domain_name("corp.com")));
    }

    /// An installation trusts `corp.com`. `app.corp.com` and `a.b.corp.com`
    /// are covered too.
    #[test]
    fn a_listed_parent_covers_names_at_any_depth_beneath_it() {
        let trusted = trusting(&["corp.com"]);

        assert!(trusted.covers(&domain_name("app.corp.com")));
        assert!(trusted.covers(&domain_name("a.b.corp.com")));
    }

    /// Trusting `corp.com` does not cover `evilcorp.com`, which shares only its
    /// ending letters.
    #[test]
    fn a_name_that_only_ends_in_the_same_letters_is_not_covered() {
        assert!(!trusting(&["corp.com"]).covers(&domain_name("evilcorp.com")));
    }

    /// An installation trusts `app.corp.com`. `corp.com` above it is not
    /// covered.
    #[test]
    fn a_parent_does_not_cover_the_domain_above_it() {
        assert!(!trusting(&["app.corp.com"]).covers(&domain_name("corp.com")));
    }

    /// An installation trusts `corp.com`. `*.app.corp.com` is covered, while
    /// `*.other.com` is not.
    #[test]
    fn a_wildcard_is_covered_when_the_name_it_stands_in_front_of_is() {
        let trusted = trusting(&["corp.com"]);

        assert!(trusted.covers(&domain_name("*.app.corp.com")));
        assert!(!trusted.covers(&domain_name("*.other.com")));
    }

    /// A shared deployment trusts no parent. `corp.com` is not covered, so
    /// every claim needs a DNS proof.
    #[test]
    fn nothing_is_covered_when_nothing_is_trusted() {
        assert!(!TrustedDomains::default().covers(&domain_name("corp.com")));
    }

    /// An installation trusts `corp.com` and `internal.example.org`.
    /// `vpn.internal.example.org` is covered by the second.
    #[test]
    fn any_of_several_parents_is_enough() {
        let trusted = trusting(&["corp.com", "internal.example.org"]);

        assert!(trusted.covers(&domain_name("vpn.internal.example.org")));
    }

    /// An operator lists `*.corp.com` as trusted. It is refused, since
    /// `corp.com` already covers every name beneath it.
    #[test]
    fn a_wildcard_parent_is_refused() {
        let result = TrustedDomains::new([domain_name("*.corp.com")]);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    fn label() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{0,10}"
    }

    proptest! {
        /// Any one to three random labels in front of `corp.com` give a name
        /// that is covered when `corp.com` is trusted.
        #[test]
        fn every_subdomain_of_a_trusted_parent_is_covered(
            labels in proptest::collection::vec(label(), 1..4),
        ) {
            let hostname = format!("{}.corp.com", labels.join("."));

            prop_assert!(trusting(&["corp.com"]).covers(&domain_name(&hostname)));
        }

        /// Adding random letters directly before a trusted parent without a
        /// dot never produces a covered name.
        #[test]
        fn gluing_letters_onto_a_trusted_parent_is_never_covered(glued in label()) {
            let hostname = format!("{glued}corp.com");

            prop_assert!(!trusting(&["corp.com"]).covers(&domain_name(&hostname)));
        }
    }
}
