//! Which hosts are on one site, by the public suffix list compiled into the
//! build.
//!
//! The list comes with the `psl` crate, so an answer makes no call out and
//! cannot hang. A name the list cannot place is on no site, so two such
//! names are never taken for one site.

use ianua_app::ports::shared::SiteRules;
use ianua_domain::types::DomainName;

/// Site rules from the public suffix list bundled with the build: two hosts
/// are on one site when they share a registrable domain.
#[derive(Debug, Clone, Copy, Default)]
pub struct BundledSiteRules;

impl SiteRules for BundledSiteRules {
    fn same_site(&self, a: &DomainName, b: &DomainName) -> bool {
        psl::domain_str(a.as_str())
            .zip(psl::domain_str(b.as_str()))
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    fn is_public_suffix(&self, name: &DomainName) -> bool {
        psl::suffix_str(name.as_str())
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(name.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(a: &str, b: &str) -> bool {
        BundledSiteRules.same_site(&DomainName::new(a).unwrap(), &DomainName::new(b).unwrap())
    }

    fn suffix(name: &str) -> bool {
        BundledSiteRules.is_public_suffix(&DomainName::new(name).unwrap())
    }

    /// Hosts under one registrable domain are one site, however deep they
    /// sit and whatever suffix they end in.
    #[test]
    fn hosts_under_one_registrable_domain_are_one_site() {
        assert!(same("shop.example.com", "api.shop.example.com"));
        assert!(same("shop.example.co.uk", "api.example.co.uk"));
    }

    /// Hosts with different registrable domains are separate sites, including
    /// distinct tenants hosted under github.io.
    #[test]
    fn hosts_sharing_only_a_public_suffix_are_not_one_site() {
        assert!(!same("shop.example.co.uk", "api.other.co.uk"));
        assert!(!same("alice.github.io", "bob.github.io"));
        assert!(!same("shop.example.com", "api.example.net"));
    }

    /// A wildcard is on the site of the name it stands in front of.
    #[test]
    fn a_wildcard_is_on_the_site_of_its_parent() {
        assert!(same("*.auth.example.com", "example.com"));
    }

    /// Names anyone may register under are public suffixes; names someone
    /// registered are not.
    #[test]
    fn a_public_suffix_is_told_from_a_registered_name() {
        assert!(suffix("co.uk"));
        assert!(suffix("github.io"));
        assert!(!suffix("example.co.uk"));
        assert!(!suffix("alice.github.io"));
    }
}
