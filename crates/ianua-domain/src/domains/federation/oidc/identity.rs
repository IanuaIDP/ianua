//! The identity claims read from a validated OIDC ID token.

use crate::domains::federation::provider_values::ProviderValues;
use crate::domains::federation::vouched_identity::{
    ProviderEmailVerification, ProviderFactor, VouchedFacts, VouchedIdentity,
};
use crate::shared::config::DisplayNameLimits;
use crate::types::{ConnectionId, DisplayName, Email, FederatedSubject, HttpsUrl, Locale};

/// Parameters for building an [`OidcIdentityClaims`].
///
/// The profile claims are the provider's raw text. [`OidcIdentityClaims::new`]
/// reads each into its own type.
pub struct OidcIdentityParams {
    /// The federation connection this identity came from.
    pub connection_id: ConnectionId,
    /// The subject identifier. Unique at one IdP and the same on every sign-in.
    pub sub: FederatedSubject,
    /// The authenticated user's email.
    pub email: Email,
    /// The `email_verified` claim, when the provider sent one.
    pub email_verified: Option<bool>,
    /// The `amr` claim, which says how the person signed in at the provider.
    pub amr: Vec<String>,
    /// The user's display name.
    pub name: Option<String>,
    /// The user's given name, usually the first name.
    pub given_name: Option<String>,
    /// The user's family name, usually the last name.
    pub family_name: Option<String>,
    /// URL of the user's profile picture.
    pub picture: Option<String>,
    /// The user's locale.
    pub locale: Option<String>,
    /// Every other claim holding text or a list of text, such as `groups`,
    /// each with every value it held.
    pub claims: ProviderValues,
}

/// Identity claims extracted from a validated OIDC ID token.
#[derive(Debug, Clone)]
pub struct OidcIdentityClaims {
    connection_id: ConnectionId,
    sub: FederatedSubject,
    email: Email,
    email_verification: ProviderEmailVerification,
    factor: ProviderFactor,
    name: Option<DisplayName>,
    given_name: Option<DisplayName>,
    family_name: Option<DisplayName>,
    picture: Option<HttpsUrl>,
    locale: Option<Locale>,
    claims: ProviderValues,
}

impl OidcIdentityClaims {
    /// Builds an OIDC identity from validated claims. Email verification is
    /// read from `email_verified` and the sign-in factor from `amr`.
    ///
    /// A profile claim that does not read as its type is dropped, not
    /// refused. The sign-in still goes ahead, and a name with control
    /// characters, a picture not served over HTTPS or an unknown locale
    /// never reaches an account.
    #[must_use]
    pub fn new(params: OidcIdentityParams) -> Self {
        Self {
            connection_id: params.connection_id,
            sub: params.sub,
            email: params.email,
            email_verification: ProviderEmailVerification::from_claim(params.email_verified),
            factor: ProviderFactor::from_oidc_amr(&params.amr),
            name: params.name.and_then(name_from),
            given_name: params.given_name.and_then(name_from),
            family_name: params.family_name.and_then(name_from),
            picture: params.picture.and_then(|url| HttpsUrl::new(url).ok()),
            locale: params.locale.and_then(|tag| Locale::new(tag).ok()),
            claims: params.claims,
        }
    }

    /// The connection this identity came from.
    #[must_use]
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// The subject identifier. Unique at one IdP and the same on every sign-in.
    #[must_use]
    pub fn sub(&self) -> &FederatedSubject {
        &self.sub
    }

    /// The authenticated user's email.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// What the provider vouched for: who the person is there, their address,
    /// whether it verified that address, and whether it reports a second
    /// factor.
    #[must_use]
    pub fn vouched(&self) -> VouchedIdentity {
        VouchedIdentity::new(VouchedFacts {
            connection_id: self.connection_id,
            subject: self.sub.clone(),
            email: self.email.clone(),
            email_verification: self.email_verification,
            factor: self.factor,
        })
    }

    /// The user's display name.
    #[must_use]
    pub fn name(&self) -> Option<&DisplayName> {
        self.name.as_ref()
    }

    /// The user's given name, usually the first name.
    #[must_use]
    pub fn given_name(&self) -> Option<&DisplayName> {
        self.given_name.as_ref()
    }

    /// The user's family name, usually the last name.
    #[must_use]
    pub fn family_name(&self) -> Option<&DisplayName> {
        self.family_name.as_ref()
    }

    /// URL of the user's profile picture.
    #[must_use]
    pub fn picture(&self) -> Option<&HttpsUrl> {
        self.picture.as_ref()
    }

    /// The user's locale.
    #[must_use]
    pub fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }

    /// The other claims the token held as text or lists of text, such as
    /// `groups`, which a connection's group mapping reads.
    #[must_use]
    pub fn claims(&self) -> &ProviderValues {
        &self.claims
    }
}

/// A name the provider sent, or nothing when it is not a valid one.
fn name_from(raw: String) -> Option<DisplayName> {
    DisplayName::new(raw, &DisplayNameLimits::default()).ok()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn subject() -> FederatedSubject {
        FederatedSubject::new("google-oauth2|1234567890").unwrap()
    }

    fn claims(connection_id: ConnectionId) -> OidcIdentityClaims {
        OidcIdentityClaims::new(OidcIdentityParams {
            connection_id,
            sub: subject(),
            email: Email::new("alice@acme.com").unwrap(),
            email_verified: Some(true),
            amr: vec!["pwd".to_owned(), "mfa".to_owned()],
            name: Some("Alice Smith".to_owned()),
            given_name: Some("Alice".to_owned()),
            family_name: Some("Smith".to_owned()),
            picture: Some("https://cdn.acme.com/alice.png".to_owned()),
            locale: Some("en-GB".to_owned()),
            claims: ProviderValues::new(HashMap::from([(
                "groups".to_owned(),
                vec!["engineering".to_owned(), "ops".to_owned()],
            )])),
        })
    }

    /// Alice's token from Google carries her `sub`. The claims give back that
    /// `sub` and that connection unchanged, since the same `sub` at another
    /// provider is someone else.
    #[test]
    fn the_subject_and_its_connection_are_what_an_account_is_linked_by() {
        let connection = ConnectionId::new();
        let claims = claims(connection);

        assert_eq!(claims.sub(), &subject());
        assert_eq!(*claims.connection_id(), connection);
    }

    /// Alice's token says `email_verified: true` and `amr` holds `mfa`. What
    /// it vouches for is her confirmed address and a second factor.
    #[test]
    fn the_vouched_identity_carries_the_verified_email_and_the_providers_second_factor() {
        let vouched = claims(ConnectionId::new()).vouched();

        assert_eq!(vouched.subject(), &subject());
        assert_eq!(vouched.email().as_str(), "alice@acme.com");
        assert_eq!(
            vouched.email_verification(),
            ProviderEmailVerification::Confirmed
        );
        assert_eq!(vouched.factor(), ProviderFactor::Performed);
    }

    /// Alice's token carries her name, picture and locale. Each comes back as
    /// sent, since a new account is filled from them.
    #[test]
    fn every_profile_claim_is_reported_as_the_provider_sent_it() {
        let claims = claims(ConnectionId::new());

        assert_eq!(claims.name().map(DisplayName::as_str), Some("Alice Smith"));
        assert_eq!(claims.given_name().map(DisplayName::as_str), Some("Alice"));
        assert_eq!(claims.family_name().map(DisplayName::as_str), Some("Smith"));
        assert_eq!(
            claims.picture().map(HttpsUrl::as_str),
            Some("https://cdn.acme.com/alice.png")
        );
        assert_eq!(claims.locale().map(Locale::as_str), Some("en-GB"));
    }

    /// Alice's token lists her groups in `groups`. Each comes back, so a
    /// connection's group mapping reads them.
    #[test]
    fn the_groups_claim_comes_back_with_every_group() {
        let claims = claims(ConnectionId::new());

        assert_eq!(claims.claims().values("groups"), ["engineering", "ops"]);
    }

    /// A token carries only `sub` and an email. Every profile claim stays
    /// empty instead of getting a made-up value.
    #[test]
    fn a_claim_the_provider_omitted_stays_absent() {
        let minimal = OidcIdentityClaims::new(OidcIdentityParams {
            connection_id: ConnectionId::new(),
            sub: subject(),
            email: Email::new("alice@acme.com").unwrap(),
            email_verified: None,
            amr: Vec::new(),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            claims: ProviderValues::default(),
        });

        assert_eq!(minimal.name(), None);
        assert_eq!(minimal.given_name(), None);
        assert_eq!(minimal.family_name(), None);
        assert_eq!(minimal.picture(), None);
        assert_eq!(minimal.locale(), None);
    }

    /// Mallory's provider sends a name with a line break, a picture over
    /// plain HTTP and a made-up locale. Each is dropped, and the sign-in
    /// still carries her subject and address.
    #[test]
    fn a_profile_claim_that_does_not_read_as_its_type_is_dropped() {
        let claims = OidcIdentityClaims::new(OidcIdentityParams {
            connection_id: ConnectionId::new(),
            sub: subject(),
            email: Email::new("mallory@acme.com").unwrap(),
            email_verified: None,
            amr: Vec::new(),
            name: Some("Mallory\nAdmin".to_owned()),
            given_name: Some(String::new()),
            family_name: Some("\u{202e}nimda".to_owned()),
            picture: Some("http://cdn.acme.com/mallory.png".to_owned()),
            locale: Some("xx-XX".to_owned()),
            claims: ProviderValues::default(),
        });

        assert_eq!(claims.sub(), &subject());
        assert!(claims.name().is_none());
        assert!(claims.given_name().is_none());
        assert!(claims.family_name().is_none());
        assert!(claims.picture().is_none());
        assert!(claims.locale().is_none());
    }
}
