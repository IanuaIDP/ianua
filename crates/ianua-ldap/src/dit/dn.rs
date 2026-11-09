//! Distinguished names in the directory the LDAP server shows.
//!
//! The tree is rooted at `dc=ianua`:
//!
//! ```text
//! dc=ianua
//! └── o=<org-slug>
//!     └── ou=<tenant-slug>
//!         ├── ou=users     → uid=<email>,ou=users,ou=<tenant>,o=<org>,dc=ianua
//!         ├── ou=groups    → cn=<name>,ou=groups,ou=<tenant>,o=<org>,dc=ianua
//!         └── ou=services  → cn=<name>,ou=services,ou=<tenant>,o=<org>,dc=ianua
//! ```
//!
//! People bind as their `ou=users` entry, applications as their service
//! account under `ou=services`, which has no entries a search returns.
//!
//! DN comparisons are case-insensitive and whitespace-tolerant, per LDAP
//! convention; values keep RFC 4514 escapes only long enough to parse.

/// The root naming context the directory serves.
pub(crate) const ROOT_DN: &str = "dc=ianua";

/// The organization and tenant a DN lies in, by their slugs as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPath {
    /// The organization slug from the `o=` RDN.
    pub org_slug: String,
    /// The tenant slug from the `ou=` RDN under it.
    pub tenant_slug: String,
}

impl TenantPath {
    /// The DN of the tenant's subtree.
    #[must_use]
    pub fn base(&self) -> String {
        format!(
            "ou={},o={},{ROOT_DN}",
            escape_value(&self.tenant_slug),
            escape_value(&self.org_slug)
        )
    }

    /// The DN of the container its users sit in.
    #[must_use]
    pub fn users(&self) -> String {
        format!("ou=users,{}", self.base())
    }

    /// The DN of the container its groups sit in.
    #[must_use]
    pub fn groups(&self) -> String {
        format!("ou=groups,{}", self.base())
    }

    /// The DN of the user entry named by `email`.
    #[must_use]
    pub fn user_dn(&self, email: &str) -> String {
        format!("uid={},{}", escape_value(email), self.users())
    }

    /// The DN of the group entry named `name`.
    #[must_use]
    pub fn group_dn(&self, name: &str) -> String {
        format!("cn={},{}", escape_value(name), self.groups())
    }

    /// The DN of the service account named `name`.
    #[must_use]
    pub fn service_dn(&self, name: &str) -> String {
        format!("cn={},ou=services,{}", escape_value(name), self.base())
    }
}

/// Who a bind DN names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindDn {
    /// A person: `uid=<email>,ou=users,ou=<tenant>,o=<org>,dc=ianua`.
    Person {
        /// The tenant the DN lies in.
        tenant: TenantPath,
        /// The address from the `uid=` RDN.
        email: String,
    },
    /// An application's service account:
    /// `cn=<name>,ou=services,ou=<tenant>,o=<org>,dc=ianua`.
    Service {
        /// The tenant the DN lies in.
        tenant: TenantPath,
        /// The account's name from the `cn=` RDN.
        name: String,
    },
}

impl BindDn {
    /// The canonical DN a bind as this identity is known by.
    #[must_use]
    pub fn to_dn(&self) -> String {
        match self {
            Self::Person { tenant, email } => tenant.user_dn(email),
            Self::Service { tenant, name } => tenant.service_dn(name),
        }
    }
}

/// Reads a bind DN: a person's entry under `ou=users` or a service
/// account under `ou=services`, in a tenant.
///
/// Returns `None` for anything else, deny by default: the caller answers
/// `invalidCredentials` without saying which part was wrong.
#[must_use]
pub fn parse_bind_dn(dn: &str) -> Option<BindDn> {
    let rdns = parse_rdns(dn)?;
    let [(naming, value), (container_attr, container), rest @ ..] = rdns.as_slice() else {
        return None;
    };
    if container_attr != "ou" || rest.len() != 3 {
        return None;
    }
    let tenant = tenant_in(rest)?;
    match (naming.as_str(), container.as_str()) {
        ("uid", "users") => Some(BindDn::Person {
            tenant,
            email: value.clone(),
        }),
        ("cn", "services") => Some(BindDn::Service {
            tenant,
            name: value.clone(),
        }),
        _ => None,
    }
}

/// The tenant `dn` lies in, when its last three RDNs are
/// `ou=<tenant>,o=<org>,dc=ianua`: the tenant's subtree itself or anything
/// under it. `None` for a DN above every tenant, outside the tree, or
/// malformed.
#[must_use]
pub fn tenant_of(dn: &str) -> Option<TenantPath> {
    tenant_in(&parse_rdns(dn)?)
}

/// The tenant whose subtree `rdns` end in.
fn tenant_in(rdns: &[(String, String)]) -> Option<TenantPath> {
    let [.., (tenant_attr, tenant), (org_attr, org), (dc_attr, dc)] = rdns else {
        return None;
    };
    let in_a_tenant = tenant_attr == "ou" && org_attr == "o" && dc_attr == "dc" && dc == "ianua";
    in_a_tenant.then(|| TenantPath {
        org_slug: org.clone(),
        tenant_slug: tenant.clone(),
    })
}

/// A DN's leading (leftmost) RDN, the one that names the entry, as its
/// attribute and value: `uid` and an address for users, `cn` and a name
/// for groups. Both lowercased, like the rest of DN comparison; fine for an
/// address (matching is case-insensitive anyway) but wrong for a display
/// value, see [`leading_rdn_value_exact`] for that. `None` for a malformed
/// DN.
#[must_use]
pub(crate) fn leading_rdn(dn: &str) -> Option<(String, String)> {
    parse_rdns(dn)?.into_iter().next()
}

/// The value of a DN's leading RDN, case preserved.
///
/// For values that carry meaning beyond DN matching, such as a group's
/// display name, where [`leading_rdn`]'s lowercasing would silently rewrite
/// whatever case the client sent, on every lookup and every rename.
#[must_use]
pub(crate) fn leading_rdn_value_exact(dn: &str) -> Option<String> {
    let dn = trim_unescaped(dn);
    if dn.is_empty() {
        return None;
    }
    let rdn = split_unescaped(dn, ',').into_iter().next()?;
    let mut parts = split_unescaped(&rdn, '=').into_iter();
    let _attr = parts.next()?;
    let value = unescape(trim_unescaped(&parts.next()?));
    if value.is_empty() { None } else { Some(value) }
}

/// Normalizes a DN for comparison: lowercased, no whitespace around RDN
/// separators.
#[must_use]
pub fn normalize(dn: &str) -> String {
    parse_rdns(dn)
        .map(|rdns| {
            rdns.iter()
                .map(|(a, v)| format!("{}={}", escape_value(a), escape_value(v)))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_else(|| trim_unescaped(dn).to_ascii_lowercase())
}

/// Whether `dn` lies inside the subtree rooted at `base` (inclusive).
#[must_use]
pub fn within(dn: &str, base: &str) -> bool {
    let dn = normalize(dn);
    let base = normalize(base);
    dn == base || dn.ends_with(&format!(",{base}"))
}

/// Whether `dn` is a direct child of `base`.
#[must_use]
pub fn is_child_of(dn: &str, base: &str) -> bool {
    let dn = normalize(dn);
    let base = normalize(base);
    let Some(rest) = dn.strip_suffix(&format!(",{base}")) else {
        return false;
    };
    parse_rdns(rest).is_some_and(|rdns| rdns.len() == 1)
}

/// Splits a DN into lowercased `(attribute, value)` pairs, honoring RFC 4514
/// backslash escapes. Returns `None` for malformed input.
fn parse_rdns(dn: &str) -> Option<Vec<(String, String)>> {
    let dn = trim_unescaped(dn);
    if dn.is_empty() {
        return None;
    }
    split_unescaped(dn, ',')
        .into_iter()
        .map(|rdn| {
            let mut parts = split_unescaped(&rdn, '=').into_iter();
            let attr = unescape(trim_unescaped(&parts.next()?)).to_ascii_lowercase();
            let value = unescape(trim_unescaped(&parts.next()?)).to_ascii_lowercase();
            let extra = parts.next();
            if attr.is_empty() || value.is_empty() || extra.is_some() {
                return None;
            }
            Some((attr, value))
        })
        .collect()
}

/// Trims the whitespace surrounding a written value, leaving escaped
/// whitespace where it is.
///
/// The trim has to happen before unescaping, because that is where the padding
/// a client wrote around an RDN lives. But `str::trim` cannot see escapes: it
/// would take the space off a value ending `\ ` and leave the backslash
/// dangling, which `unescape` then swallows along with whatever followed. The
/// value would come back shorter every pass, and [`normalize`] would stop being
/// a fixed point.
///
/// A leading whitespace character can never be escaped — an escape begins with
/// the backslash — so only the trailing end needs the care.
fn trim_unescaped(value: &str) -> &str {
    let value = value.trim_start();
    let mut end = value.len();
    while let Some(c) = value[..end].chars().next_back() {
        if !c.is_whitespace() {
            break;
        }
        let preceding = &value[..end - c.len_utf8()];
        let escapes = preceding.chars().rev().take_while(|&b| b == '\\').count();
        if escapes % 2 == 1 {
            break;
        }
        end -= c.len_utf8();
    }
    &value[..end]
}

/// Splits on `separator`, treating backslash-escaped separators as literal.
fn split_unescaped(input: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for c in input.chars() {
        if escaped {
            current.push('\\');
            current.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == separator {
            parts.push(std::mem::take(&mut current));
            continue;
        }
        current.push(c);
    }
    if escaped {
        current.push('\\');
    }
    parts.push(current);
    parts
}

/// Removes RFC 4514 backslash escapes from a value.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        out.push(c);
    }
    out
}

/// Escapes the RFC 4514 special characters in a value, plus the whitespace at
/// either end.
///
/// The edge whitespace is what makes [`normalize`] a canonical form rather than
/// merely a tidier spelling. [`parse_rdns`] trims each half of an RDN before
/// unescaping it, so a value emitted with a bare leading or trailing space
/// would come back shorter the next time it was parsed — and `normalize` is
/// applied to both sides of every DN comparison that decides access. Escaping
/// the edges puts a backslash where the trim would otherwise bite.
///
/// Interior whitespace is left alone: `cn=Ada Lovelace` survives a round trip
/// unchanged, because nothing trims the middle of a value.
fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let last = value.chars().count().saturating_sub(1);
    for (i, c) in value.chars().enumerate() {
        let at_edge = i == 0 || i == last;
        if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=')
            || (at_edge && c.is_whitespace())
        {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression, found by the `ldap_dn` fuzz target.
    ///
    /// [`normalize`] is the canonical form applied to both sides of every DN
    /// comparison that acts as a boundary — search scope, the container a
    /// modify-DN may move into, and `within`. A second pass that changes the
    /// answer means it is not canonical, and two spellings of one DN can
    /// compare unequal.
    ///
    /// The break was whitespace: [`parse_rdns`] trims each half of an RDN, and
    /// `escape_value` did not escape the whitespace it would trim, so a value
    /// that survived one pass was shortened by the next.
    #[test]
    fn normalize_is_idempotent() {
        for dn in [
            "\n\n\n\0\n=\n\n\n\\\n\n\\\\",
            "uid=ada@acme.com,ou=users,ou=prod,o=acme,dc=ianua",
            " cn = ada , dc = ianua ",
            "cn=\n,dc=ianua",
            "cn=a\nb,dc=ianua",
            "cn= ada ,dc=ianua",
            "",
            "\\",
            "=",
        ] {
            let once = normalize(dn);
            let twice = normalize(&once);
            assert_eq!(twice, once, "normalize is not idempotent for {dn:?}");
        }
    }

    /// The other half of the same invariant: `within` composes a normalized
    /// base into a suffix match against a normalized DN, so a value carrying
    /// whitespace must not be able to slide across a tenant boundary.
    #[test]
    fn a_dn_cannot_lie_inside_two_tenants_at_once() {
        let tenant = |slug: &str| TenantPath {
            org_slug: "acme".to_owned(),
            tenant_slug: slug.to_owned(),
        };
        let alpha = tenant("alpha").base();
        let beta = tenant("beta").base();

        for dn in [
            "\n\n\n\0\n=\n\n\n\\\n\n\\\\",
            "uid=ada,ou=alpha,o=acme,dc=ianua",
            "uid=ada\\,ou=beta\\,o=acme\\,dc=ianua,ou=alpha,o=acme,dc=ianua",
            "uid= ,ou=alpha,o=acme,dc=ianua",
        ] {
            assert!(
                !(within(dn, &alpha) && within(dn, &beta)),
                "{dn:?} is inside two tenants"
            );
        }
    }

    fn prod() -> TenantPath {
        TenantPath {
            org_slug: "acme".to_owned(),
            tenant_slug: "prod".to_owned(),
        }
    }

    #[test]
    fn parse_reads_a_persons_bind_dn() {
        let dn = "uid=ada@acme.com,ou=users,ou=prod,o=acme,dc=ianua";

        assert_eq!(
            parse_bind_dn(dn),
            Some(BindDn::Person {
                tenant: prod(),
                email: "ada@acme.com".to_owned(),
            })
        );
    }

    #[test]
    fn parse_reads_a_service_accounts_bind_dn() {
        let dn = "cn=jira,ou=services,ou=prod,o=acme,dc=ianua";

        assert_eq!(
            parse_bind_dn(dn),
            Some(BindDn::Service {
                tenant: prod(),
                name: "jira".to_owned(),
            })
        );
    }

    #[test]
    fn parse_is_case_and_whitespace_insensitive() {
        let dn = "UID=Ada@Acme.com, OU=users, OU=Prod, O=Acme, DC=Ianua";

        assert_eq!(
            parse_bind_dn(dn),
            Some(BindDn::Person {
                tenant: prod(),
                email: "ada@acme.com".to_owned(),
            })
        );
    }

    #[test]
    fn a_bind_dn_renders_back_to_its_canonical_form() {
        let dn = "cn=jira,ou=services,ou=prod,o=acme,dc=ianua";

        assert_eq!(
            parse_bind_dn(dn).map(|bind| bind.to_dn()),
            Some(dn.to_owned())
        );
    }

    #[test]
    fn parse_returns_none_on_wrong_shapes() {
        for dn in [
            "",
            "uid=a@b.c",
            "cn=admin,dc=ianua",
            "uid=a@b.c,ou=groups,ou=t,o=o,dc=ianua",
            "cn=jira,ou=users,ou=t,o=o,dc=ianua",
            "uid=a@b.c,ou=services,ou=t,o=o,dc=ianua",
            "uid=a@b.c,ou=users,ou=t,o=o,dc=elsewhere",
            "uid=a@b.c,ou=users,ou=x,ou=t,o=o,dc=ianua",
            "uid=,ou=users,ou=t,o=o,dc=ianua",
        ] {
            assert!(parse_bind_dn(dn).is_none(), "{dn} must not parse");
        }
    }

    #[test]
    fn tenant_of_reads_the_tenant_any_dn_inside_it_lies_in() {
        for dn in [
            "ou=prod,o=acme,dc=ianua",
            "ou=users,ou=prod,o=acme,dc=ianua",
            "cn=Engineering,ou=groups,ou=prod,o=acme,dc=ianua",
        ] {
            assert_eq!(tenant_of(dn), Some(prod()), "{dn}");
        }
    }

    #[test]
    fn tenant_of_is_none_above_every_tenant_and_outside_the_tree() {
        for dn in [
            "dc=ianua",
            "o=acme,dc=ianua",
            "ou=prod,o=acme,dc=elsewhere",
            "",
        ] {
            assert_eq!(tenant_of(dn), None, "{dn}");
        }
    }

    #[test]
    fn within_matches_subtree_inclusively() {
        let base = "ou=prod,o=acme,dc=ianua";
        assert!(within("OU=Prod,O=Acme,DC=Ianua", base));
        assert!(within("uid=a@b.c,ou=users,ou=prod,o=acme,dc=ianua", base));
        assert!(!within("ou=other,o=acme,dc=ianua", base));
        assert!(!within("ou=prod,o=globex,dc=ianua", base));
    }

    #[test]
    fn is_child_of_matches_exactly_one_level() {
        let base = "ou=prod,o=acme,dc=ianua";
        assert!(is_child_of("ou=users,ou=prod,o=acme,dc=ianua", base));
        assert!(!is_child_of(
            "uid=a@b.c,ou=users,ou=prod,o=acme,dc=ianua",
            base
        ));
        assert!(!is_child_of(base, base));
    }

    #[test]
    fn escaped_separators_survive_a_round_trip() {
        let dn = prod().user_dn("weird,name@acme.com");
        assert!(within(&dn, "ou=prod,o=acme,dc=ianua"));
        assert!(is_child_of(&dn, "ou=users,ou=prod,o=acme,dc=ianua"));
    }

    #[test]
    fn leading_rdn_reads_whichever_attribute_names_the_entry() {
        assert_eq!(
            leading_rdn("uid=ada@acme.com,ou=users,ou=prod,o=acme,dc=ianua"),
            Some(("uid".to_owned(), "ada@acme.com".to_owned()))
        );
        assert_eq!(
            leading_rdn("CN=Engineering,ou=groups,ou=prod,o=acme,dc=ianua"),
            Some(("cn".to_owned(), "engineering".to_owned())),
            "lowercased, like the rest of DN comparison"
        );
        assert_eq!(leading_rdn(""), None);
    }

    #[test]
    fn leading_rdn_value_exact_preserves_case() {
        assert_eq!(
            leading_rdn_value_exact("cn=Engineering,ou=groups,ou=prod,o=acme,dc=ianua"),
            Some("Engineering".to_owned())
        );
        assert_eq!(leading_rdn_value_exact(""), None);
    }
}
