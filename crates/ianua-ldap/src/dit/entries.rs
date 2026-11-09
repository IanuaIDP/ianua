//! A tenant's directory listing as LDAP entries.

use ianua_app::use_cases::directory::{DirectoryGroup, DirectoryListing, DirectoryUser};
use ldap3_proto::proto::{LdapPartialAttribute, LdapSearchResultEntry, LdapSearchScope};

use crate::dit::dn::{self, ROOT_DN, TenantPath};

/// An entry of the directory: a DN plus named multi-valued attributes.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The entry's distinguished name.
    pub dn: String,
    /// The entry's attributes, in render order.
    pub attrs: Vec<(String, Vec<String>)>,
}

impl Entry {
    /// The values of `attr`, case-insensitively.
    #[must_use]
    pub fn values(&self, attr: &str) -> Option<&[String]> {
        self.attrs
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(attr))
            .map(|(_, v)| v.as_slice())
    }

    /// Whether the entry lies in `scope` relative to `base`.
    #[must_use]
    pub fn in_scope(&self, base: &str, scope: &LdapSearchScope) -> bool {
        match scope {
            LdapSearchScope::Base => dn::normalize(&self.dn) == dn::normalize(base),
            LdapSearchScope::OneLevel => dn::is_child_of(&self.dn, base),
            LdapSearchScope::Subtree => dn::within(&self.dn, base),
            LdapSearchScope::Children => {
                dn::within(&self.dn, base) && dn::normalize(&self.dn) != dn::normalize(base)
            }
        }
    }

    /// Renders the entry as a search result, keeping only `requested`
    /// attributes (all when empty or `*`; none when `1.1`).
    #[must_use]
    pub fn to_result(&self, requested: &[String]) -> LdapSearchResultEntry {
        let all = requested.is_empty() || requested.iter().any(|a| a == "*");
        let attributes = self
            .attrs
            .iter()
            .filter(|(name, _)| all || requested.iter().any(|r| r.eq_ignore_ascii_case(name)))
            .map(|(name, vals)| LdapPartialAttribute {
                atype: name.clone(),
                vals: vals.iter().map(|v| v.clone().into_bytes()).collect(),
            })
            .collect();
        LdapSearchResultEntry {
            dn: self.dn.clone(),
            attributes,
        }
    }
}

/// The tenant's subtree: the base node, the `users` and `groups`
/// organizational units, one entry per user, and one per group.
#[must_use]
pub(crate) fn build_entries(tenant: &TenantPath, listing: &DirectoryListing) -> Vec<Entry> {
    let mut entries = vec![
        node(&tenant.base(), "organizationalUnit", &tenant.tenant_slug),
        node(&tenant.users(), "organizationalUnit", "users"),
        node(&tenant.groups(), "organizationalUnit", "groups"),
    ];
    entries.extend(
        listing
            .users
            .iter()
            .map(|user| user_entry(tenant, listing, user)),
    );
    entries.extend(
        listing
            .groups
            .iter()
            .map(|group| group_entry(tenant, listing, group)),
    );
    entries
}

/// A user's entry, naming the groups they are in.
fn user_entry(tenant: &TenantPath, listing: &DirectoryListing, user: &DirectoryUser) -> Entry {
    let member_of: Vec<String> = listing
        .groups
        .iter()
        .filter(|g| g.members.contains(&user.id))
        .map(|g| tenant.group_dn(&g.name))
        .collect();
    let mut attrs = vec![
        (
            "objectClass".to_owned(),
            vec![
                "top".to_owned(),
                "person".to_owned(),
                "organizationalPerson".to_owned(),
                "inetOrgPerson".to_owned(),
            ],
        ),
        ("uid".to_owned(), vec![user.email.clone()]),
        ("mail".to_owned(), vec![user.email.clone()]),
        ("cn".to_owned(), vec![user.display_name.clone()]),
        ("sn".to_owned(), vec![surname(&user.display_name)]),
        ("entryUUID".to_owned(), vec![user.id.to_string()]),
    ];
    if !member_of.is_empty() {
        attrs.push(("memberOf".to_owned(), member_of));
    }
    Entry {
        dn: tenant.user_dn(&user.email),
        attrs,
    }
}

/// A group's entry, naming its members by their DNs.
fn group_entry(tenant: &TenantPath, listing: &DirectoryListing, group: &DirectoryGroup) -> Entry {
    let members: Vec<String> = group
        .members
        .iter()
        .filter_map(|id| listing.users.iter().find(|u| u.id == *id))
        .map(|u| tenant.user_dn(&u.email))
        .collect();
    let mut attrs = vec![
        (
            "objectClass".to_owned(),
            vec!["top".to_owned(), "groupOfNames".to_owned()],
        ),
        ("cn".to_owned(), vec![group.name.clone()]),
        ("entryUUID".to_owned(), vec![group.id.to_string()]),
    ];
    if !members.is_empty() {
        attrs.push(("member".to_owned(), members));
    }
    Entry {
        dn: tenant.group_dn(&group.name),
        attrs,
    }
}

/// The root DSE, the only entry visible without a bind. It names the
/// naming context and nothing about any tenant.
#[must_use]
pub(crate) fn root_dse() -> Entry {
    Entry {
        dn: String::new(),
        attrs: vec![
            ("objectClass".to_owned(), vec!["top".to_owned()]),
            ("namingContexts".to_owned(), vec![ROOT_DN.to_owned()]),
            ("supportedLDAPVersion".to_owned(), vec!["3".to_owned()]),
            ("vendorName".to_owned(), vec!["Ianua".to_owned()]),
        ],
    }
}

fn node(dn: &str, object_class: &str, ou: &str) -> Entry {
    Entry {
        dn: dn.to_owned(),
        attrs: vec![
            (
                "objectClass".to_owned(),
                vec!["top".to_owned(), object_class.to_owned()],
            ),
            ("ou".to_owned(), vec![ou.to_owned()]),
        ],
    }
}

fn surname(display_name: &str) -> String {
    display_name
        .rsplit(' ')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(display_name)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{GroupId, UserId};

    use super::*;

    fn prod() -> TenantPath {
        TenantPath {
            org_slug: "acme".to_owned(),
            tenant_slug: "prod".to_owned(),
        }
    }

    fn listing() -> DirectoryListing {
        let ada = UserId::new();
        DirectoryListing {
            users: vec![DirectoryUser {
                id: ada,
                email: "ada@acme.com".to_owned(),
                display_name: "Ada Lovelace".to_owned(),
            }],
            groups: vec![DirectoryGroup {
                id: GroupId::new(),
                name: "Engineering".to_owned(),
                members: vec![ada],
            }],
        }
    }

    #[test]
    fn users_carry_identity_attributes_and_membership() {
        let entries = build_entries(&prod(), &listing());
        let user = entries
            .iter()
            .find(|e| e.dn.starts_with("uid="))
            .expect("user entry");
        assert_eq!(user.values("mail").unwrap(), ["ada@acme.com"]);
        assert_eq!(user.values("cn").unwrap(), ["Ada Lovelace"]);
        assert_eq!(user.values("sn").unwrap(), ["Lovelace"]);
        assert_eq!(
            user.values("memberOf").unwrap(),
            ["cn=Engineering,ou=groups,ou=prod,o=acme,dc=ianua"]
        );
    }

    #[test]
    fn groups_name_their_members_by_dn() {
        let entries = build_entries(&prod(), &listing());
        let group = entries
            .iter()
            .find(|e| e.dn.starts_with("cn="))
            .expect("group entry");
        assert_eq!(
            group.values("member").unwrap(),
            ["uid=ada@acme.com,ou=users,ou=prod,o=acme,dc=ianua"]
        );
    }

    #[test]
    fn scope_filters_relative_to_the_base() {
        let entries = build_entries(&prod(), &listing());
        let base = "ou=users,ou=prod,o=acme,dc=ianua";
        let in_one_level: Vec<_> = entries
            .iter()
            .filter(|e| e.in_scope(base, &LdapSearchScope::OneLevel))
            .collect();
        assert_eq!(in_one_level.len(), 1);
        assert!(in_one_level[0].dn.starts_with("uid="));
    }

    #[test]
    fn attribute_selection_honors_the_request() {
        let entries = build_entries(&prod(), &listing());
        let user = entries.iter().find(|e| e.dn.starts_with("uid=")).unwrap();
        let only_mail = user.to_result(&["mail".to_owned()]);
        assert_eq!(only_mail.attributes.len(), 1);
        let none = user.to_result(&["1.1".to_owned()]);
        assert!(none.attributes.is_empty());
        let all = user.to_result(&[]);
        assert!(all.attributes.len() >= 5);
    }
}
