//! What the public suffix list says about hosts.

use ianua_domain::types::DomainName;

/// Port answering from the public suffix list: which hosts share a site,
/// and which names anyone may register under.
pub trait SiteRules: Send + Sync {
    /// Whether `a` and `b` share a registrable domain: `shop.example.com`
    /// and `api.shop.example.com` do; `a.github.io` and `b.github.io` do not.
    /// A browser sends a host's cookie from the pages of another host only
    /// when both are on one site.
    fn same_site(&self, a: &DomainName, b: &DomainName) -> bool;

    /// Whether `name` is itself a public suffix, such as `com`, `co.uk` or
    /// `github.io`: one under which anyone may register a name, so no one
    /// holds it.
    fn is_public_suffix(&self, name: &DomainName) -> bool;
}
