//! What a directory service account is called and what it may read: only
//! under the base DNs it was given. Writing the directory is a person's,
//! bound as themselves, so no service account writes.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{
    Boundary, Charset, Rule, TextValue, ValidationError, Validator, text_value,
};

/// The most base DNs one service account may be given.
pub(crate) const MAX_BASE_DNS: usize = 16;

/// The longest base DN taken, in bytes.
const MAX_BASE_DN_BYTES: usize = 512;

text_value! {
    /// The name a service account binds with, such as `jira` or
    /// `sssd-web-01`: 2 to 64 lowercase letters, digits and hyphens,
    /// starting and ending with a letter or digit.
    ///
    /// It is unique within the tenant. The LDAP interface names the account
    /// in its bind DN by it.
    pub struct ServiceAccountName;
}

impl TextValue for ServiceAccountName {
    const FIELD: &'static str = "service_account_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .identifier(
                2..=64,
                Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN,
            )
            .boundaries(Boundary::LowercaseAlphanumeric)
            .no_consecutive(b'-')
    }

    fn normalized(value: String) -> String {
        value.to_ascii_lowercase()
    }
}

text_value! {
    /// A subtree of the tenant's directory, by its distinguished name, such
    /// as `ou=people,dc=acme,dc=com`.
    ///
    /// It is kept lower-cased with no spaces around its commas, so two
    /// spellings of one DN compare equal. Each part is an `attribute=value`
    /// pair.
    pub struct BaseDn;
}

impl TextValue for BaseDn {
    const FIELD: &'static str = "base_dn";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .ascii_only()
            .max_bytes(MAX_BASE_DN_BYTES)
            .no_control_chars()
            .rule(&AttributeValuePairs)
    }

    fn normalized(value: String) -> String {
        canonical_dn(&value)
    }
}

/// `dn` lower-cased, with the spaces around its commas and at its ends
/// dropped.
fn canonical_dn(dn: &str) -> String {
    dn.split(',')
        .map(|part| part.trim().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

/// Every comma-separated part of a DN is `attribute=value`, both sides
/// filled.
struct AttributeValuePairs;

impl Rule for AttributeValuePairs {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let well_formed = value.split(',').all(|part| {
            part.split_once('=')
                .is_some_and(|(attribute, value)| !attribute.is_empty() && !value.is_empty())
        });
        if well_formed {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "not_a_dn".to_owned(),
            message: message!(
                "authentication-must-be-attribute-value-pairs-separated",
                "must be attribute=value pairs separated by commas"
            ),
        })
    }
}

impl BaseDn {
    /// Whether the entry named `entry_dn` is this subtree's root or sits
    /// under it. The entry is compared in the same canonical form.
    #[must_use]
    pub fn covers(&self, entry_dn: &str) -> bool {
        let entry = canonical_dn(entry_dn);
        entry == self.as_str() || entry.ends_with(&format!(",{}", self.as_str()))
    }
}

/// What a service account may do in the subtrees it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DirectoryAccess {
    /// Bind, search and compare.
    ReadOnly,
}

impl DirectoryAccess {
    /// The stable name records carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
        }
    }
}

/// What a service account may do, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccountScope {
    access: DirectoryAccess,
    base_dns: Vec<BaseDn>,
}

impl ServiceAccountScope {
    /// `access` under each of `base_dns`.
    ///
    /// A service account with no subtree could reach nothing, and one listed
    /// twice reads as two grants where there is one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when no base DN is given, more than
    ///   `MAX_BASE_DNS` are, or one is given twice.
    pub fn new(access: DirectoryAccess, base_dns: Vec<BaseDn>) -> Result<Self, DomainError> {
        validate_count("base_dns", base_dns.len(), 1..=MAX_BASE_DNS)?;
        if first_repeat(&base_dns).is_some() {
            return Err(DomainError::invalid(message!(
                "authentication-a-base-dn-is-listed-twice",
                "a base DN is listed twice"
            )));
        }
        Ok(Self { access, base_dns })
    }

    /// What the account may do.
    #[must_use]
    pub fn access(&self) -> DirectoryAccess {
        self.access
    }

    /// The subtrees it may do it in.
    #[must_use]
    pub fn base_dns(&self) -> &[BaseDn] {
        &self.base_dns
    }

    /// Whether the entry `entry_dn` lies under one of its subtrees.
    #[must_use]
    pub fn reaches(&self, entry_dn: &str) -> bool {
        self.base_dns.iter().any(|base| base.covers(entry_dn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(dn: &str) -> BaseDn {
        BaseDn::new(dn).unwrap()
    }

    /// `OU=People, DC=Acme, DC=com` is kept as `ou=people,dc=acme,dc=com`,
    /// so both spellings name one subtree.
    #[test]
    fn a_base_dn_is_kept_in_one_spelling() {
        assert_eq!(
            base("OU=People, DC=Acme, DC=com").as_str(),
            "ou=people,dc=acme,dc=com"
        );
    }

    /// Text that is not attribute=value pairs, or has an empty side, is
    /// refused as a base DN.
    #[test]
    fn a_base_dn_must_be_attribute_value_pairs() {
        for value in [
            "",
            "people",
            "ou=,dc=acme",
            "=people,dc=acme",
            "ou=people,,dc=acme",
        ] {
            assert!(BaseDn::new(value).is_err(), "{value}");
        }
    }

    /// An entry under `ou=people` and the subtree root are covered. An
    /// entry under `ou=admins`, or one whose last part only ends the same
    /// way, is not.
    #[test]
    fn a_base_dn_covers_its_subtree_only() {
        let people = base("ou=people,dc=acme,dc=com");

        assert!(people.covers("uid=ann,ou=people,dc=acme,dc=com"));
        assert!(people.covers("OU=People,DC=acme,DC=com"));
        assert!(!people.covers("uid=root,ou=admins,dc=acme,dc=com"));
        assert!(!people.covers("ou=otherpeople,dc=acme,dc=com"));
    }

    /// A service name of lowercase letters, digits and single hyphens is
    /// taken. A space, a leading hyphen or a double hyphen is refused.
    #[test]
    fn a_service_account_name_is_a_simple_identifier() {
        assert!(ServiceAccountName::new("sssd-web-01").is_ok());
        for value in ["jira bot", "-jira", "jira--bot", "j"] {
            assert!(ServiceAccountName::new(value).is_err(), "{value}");
        }
    }

    /// A scope reaches the entries under its subtrees and no others.
    #[test]
    fn a_scope_reaches_only_its_subtrees() {
        let scope = ServiceAccountScope::new(
            DirectoryAccess::ReadOnly,
            vec![base("ou=hosts,dc=acme,dc=com")],
        )
        .unwrap();

        assert!(scope.reaches("cn=web1,ou=hosts,dc=acme,dc=com"));
        assert!(!scope.reaches("uid=root,ou=admins,dc=acme,dc=com"));
    }

    /// A scope with no subtree, or one subtree twice, is refused.
    #[test]
    fn a_scope_names_each_subtree_once_and_at_least_one() {
        let people = base("ou=people,dc=acme");

        assert!(ServiceAccountScope::new(DirectoryAccess::ReadOnly, Vec::new()).is_err());
        assert!(
            ServiceAccountScope::new(DirectoryAccess::ReadOnly, vec![people.clone(), people])
                .is_err()
        );
    }
}
