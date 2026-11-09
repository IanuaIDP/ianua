//! The claims about a person that a grant's scopes let out (OIDC Core 5.4),
//! the same in an ID token and from `userinfo`.
//!
//! The address and whether it is verified come only with `email`; the
//! name, locale and timezone only with `profile`; the roles only with
//! `roles`. An app that asked for none of them learns who signed in and
//! nothing more about them.

use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::types::{DisplayName, Email, Label, Locale, Preference, Scope, Timezone};

/// The scope that asks for the address claims.
const EMAIL: &str = "email";
/// The scope that asks for the profile claims.
const PROFILE: &str = "profile";
/// The scope that asks for the roles the person holds.
const ROLES: &str = "roles";

/// Whether `scopes` include the one named `name`.
pub(crate) fn names(scopes: &[Scope], name: &str) -> bool {
    scopes.iter().any(|scope| scope.as_str() == name)
}

/// The claims about a person a grant's scopes let out.
///
/// Only the ID token and `userinfo` builders make them, from the account as
/// it is, so `email_verified` is read from the address and never set by
/// hand.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ScopedClaims {
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    email: Option<Email>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    email_verified: Option<bool>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    name: Option<DisplayName>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    locale: Option<Locale>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    zoneinfo: Option<Timezone>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    roles: Option<Vec<Label>>,
}

impl ScopedClaims {
    /// What `scopes` let out about `account`, who holds the roles named
    /// `roles`.
    pub(crate) fn for_scopes<T: TenantScope>(
        scopes: &[Scope],
        account: &User<T>,
        roles: &[Label],
    ) -> Self {
        let address = account.address();
        let email = names(scopes, EMAIL);
        let profile = names(scopes, PROFILE);
        Self {
            email: email.then(|| address.email().clone()),
            email_verified: email.then(|| address.is_verified()),
            name: profile.then(|| account.display_name().clone()),
            locale: profile.then(|| own(account.locale())).flatten(),
            zoneinfo: profile.then(|| own(account.timezone())).flatten(),
            roles: names(scopes, ROLES).then(|| roles.to_vec()),
        }
    }

    /// The person's email address, with the `email` scope.
    #[must_use]
    pub fn email(&self) -> Option<&Email> {
        self.email.as_ref()
    }

    /// Whether the person proved they hold the address, with the `email`
    /// scope. It comes from their
    /// [`AccountAddress`](crate::domains::identity::account::address::AccountAddress).
    #[must_use]
    pub fn email_verified(&self) -> Option<bool> {
        self.email_verified
    }

    /// The person's display name, with the `profile` scope.
    #[must_use]
    pub fn name(&self) -> Option<&DisplayName> {
        self.name.as_ref()
    }

    /// The person's own locale, with the `profile` scope, when they set
    /// one.
    #[must_use]
    pub fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }

    /// The person's own timezone, `zoneinfo`, with the `profile` scope,
    /// when they set one.
    #[must_use]
    pub fn zoneinfo(&self) -> Option<&Timezone> {
        self.zoneinfo.as_ref()
    }

    /// The names of the roles the person holds, with the `roles` scope.
    #[must_use]
    pub fn roles(&self) -> Option<&[Label]> {
        self.roles.as_deref()
    }
}

/// The person's own `preference`, when they set one: an inherited one is
/// the tenant's, not theirs to report.
fn own<V: Clone>(preference: &Preference<V>) -> Option<V> {
    match preference {
        Preference::Own(value) => Some(value.clone()),
        Preference::Inherited => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::{label, user};
    use crate::types::UserId;

    /// `names` as scopes.
    fn scopes(names: &[&str]) -> Vec<Scope> {
        names
            .iter()
            .map(|name| Scope::new(*name).unwrap())
            .collect()
    }

    /// Ann, who proved her address.
    fn ann() -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), "ann@acme.com");
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// An app that asked only for `openid` learns nothing about Ann.
    #[test]
    fn no_scope_lets_out_nothing() {
        let claims = ScopedClaims::for_scopes(&scopes(&["openid"]), &ann(), &[label("Editor")]);

        assert_eq!(claims.email(), None);
        assert_eq!(claims.email_verified(), None);
        assert_eq!(claims.name(), None);
        assert_eq!(claims.roles(), None);
    }

    /// With `email` and `roles`, the app reads Ann's proven address and
    /// her roles, but not her name.
    #[test]
    fn each_scope_lets_out_its_own_claims() {
        let held = [label("Editor")];

        let claims = ScopedClaims::for_scopes(&scopes(&["email", "roles"]), &ann(), &held);

        assert_eq!(claims.email().map(Email::as_str), Some("ann@acme.com"));
        assert_eq!(claims.email_verified(), Some(true));
        assert_eq!(claims.roles(), Some(held.as_slice()));
        assert_eq!(claims.name(), None);
    }
}
