//! Attribute extraction shared by Add and Modify.

use ldap3_proto::proto::LdapPartialAttribute;

/// The first UTF-8 value of `name`, matched case-insensitively.
pub(super) fn value(attributes: &[LdapPartialAttribute], name: &str) -> Option<String> {
    attributes
        .iter()
        .find(|a| a.atype.eq_ignore_ascii_case(name))
        .and_then(|a| a.vals.first())
        .and_then(|v| String::from_utf8(v.clone()).ok())
}
