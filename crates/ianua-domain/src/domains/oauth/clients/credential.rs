//! How a client proves itself at the token endpoint (RFC 6749 2.3, RFC 7523
//! for keys, RFC 8705 for certificates).
//!
//! The way is fixed when the client is registered, and only that way is
//! taken. Mallory learns the client id of an app that signs its requests
//! with a key; if the token endpoint also took a secret for it, she would
//! only have to guess one. A public client proves nothing, so it holds
//! nothing here.

use time::{Duration, OffsetDateTime};

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{HttpsUrl, RotationOverlap, TokenHash};

/// The longest an old secret keeps working after a rotation: thirty days.
const LONGEST_OVERLAP: Duration = Duration::days(30);

/// How a client proves itself when it swaps a grant for tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCredential {
    /// A confidential client holding a secret, kept here as hashes.
    Secret(ClientSecret),
    /// A confidential client signing a JWT with its own private key
    /// (`private_key_jwt`); the public keys it is checked with.
    PrivateKeyJwt(ClientKeys),
    /// A confidential client presenting a TLS client certificate
    /// (`tls_client_auth`) with this subject.
    TlsClientAuth(CertificateSubject),
    /// A public client, such as a single-page app, a mobile app or a CLI:
    /// whatever ships to people's devices can be read off them, so it holds
    /// no secret. PKCE, required for every code, binds its codes instead.
    Public,
}

impl ClientCredential {
    /// A confidential client's secret, kept as `hash`, sent in the
    /// `Authorization: Basic` header, the usual way.
    #[must_use]
    pub fn secret(hash: TokenHash) -> Self {
        Self::Secret(ClientSecret::new(hash, SecretSentBy::Basic))
    }

    /// The `token_endpoint_auth_method` this is (RFC 7591 2).
    #[must_use]
    pub fn method(&self) -> TokenEndpointAuthMethod {
        match self {
            Self::Secret(secret) => match secret.sent_by {
                SecretSentBy::Basic => TokenEndpointAuthMethod::ClientSecretBasic,
                SecretSentBy::Post => TokenEndpointAuthMethod::ClientSecretPost,
            },
            Self::PrivateKeyJwt(_) => TokenEndpointAuthMethod::PrivateKeyJwt,
            Self::TlsClientAuth(_) => TokenEndpointAuthMethod::TlsClientAuth,
            Self::Public => TokenEndpointAuthMethod::None,
        }
    }

    /// Whether the client proves itself with nothing.
    #[must_use]
    pub fn is_public(&self) -> bool {
        *self == Self::Public
    }

    /// Whether `presented`, the way a request at the token endpoint proved
    /// the client, is the way it registered. Any other way is refused.
    #[must_use]
    pub fn accepts_method(&self, presented: TokenEndpointAuthMethod) -> bool {
        self.method() == presented
    }

    /// The hash of the current secret, for a client holding one.
    #[must_use]
    pub fn secret_hash(&self) -> Option<&TokenHash> {
        match self {
            Self::Secret(secret) => Some(&secret.current),
            Self::PrivateKeyJwt(_) | Self::TlsClientAuth(_) | Self::Public => None,
        }
    }

    /// The hashes a presented secret may match at `now`: the current one,
    /// and the one before it while its overlap lasts. A client holding no
    /// secret accepts none.
    #[must_use]
    pub fn secrets_accepted_at(&self, now: OffsetDateTime) -> Vec<&TokenHash> {
        match self {
            Self::Secret(secret) => secret.accepted_at(now),
            Self::PrivateKeyJwt(_) | Self::TlsClientAuth(_) | Self::Public => Vec::new(),
        }
    }

    /// Whether this holds a secret before the current one: only a rotation
    /// leaves one, never a registration.
    pub(crate) fn has_previous_secret(&self) -> bool {
        matches!(
            self,
            Self::Secret(ClientSecret {
                previous: PreviousSecret::AcceptedUntil { .. },
                ..
            })
        )
    }
}

/// How a confidential client sends its secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSentBy {
    /// In the `Authorization: Basic` header (`client_secret_basic`).
    Basic,
    /// In the form body (`client_secret_post`).
    Post,
}

/// The secret before the current one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviousSecret {
    /// None works: the client was never rotated, or the overlap ended or was
    /// not given.
    Retired,
    /// The old secret, still accepted until a time, so the app's servers can
    /// move to the new one without an outage.
    AcceptedUntil {
        /// The old secret's hash.
        hash: TokenHash,
        /// When it stops working.
        until: OffsetDateTime,
    },
}

/// A confidential client's secret, kept as the hashes of the current one
/// and the one before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecret {
    current: TokenHash,
    previous: PreviousSecret,
    sent_by: SecretSentBy,
}

impl ClientSecret {
    /// A secret kept as `current`, sent `sent_by`, with none before it.
    #[must_use]
    pub fn new(current: TokenHash, sent_by: SecretSentBy) -> Self {
        Self {
            current,
            previous: PreviousSecret::Retired,
            sent_by,
        }
    }

    /// A secret as storage keeps it.
    #[must_use]
    pub fn from_stored(
        current: TokenHash,
        previous: PreviousSecret,
        sent_by: SecretSentBy,
    ) -> Self {
        Self {
            current,
            previous,
            sent_by,
        }
    }

    /// The hash of the current secret.
    #[must_use]
    pub fn current(&self) -> &TokenHash {
        &self.current
    }

    /// The secret before it.
    #[must_use]
    pub fn previous(&self) -> &PreviousSecret {
        &self.previous
    }

    /// How the client sends it.
    #[must_use]
    pub fn sent_by(&self) -> SecretSentBy {
        self.sent_by
    }

    /// The hashes accepted at `now`.
    fn accepted_at(&self, now: OffsetDateTime) -> Vec<&TokenHash> {
        let mut accepted = vec![&self.current];
        match &self.previous {
            PreviousSecret::AcceptedUntil { hash, until } if now < *until => accepted.push(hash),
            PreviousSecret::AcceptedUntil { .. } | PreviousSecret::Retired => {}
        }
        accepted
    }

    /// This secret replaced by `next` at `now`, the current one kept for
    /// `overlap`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `overlap` is longer than thirty
    ///   days.
    pub(crate) fn rotated(
        &self,
        next: TokenHash,
        overlap: RotationOverlap,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let previous = match overlap.ends(now, LONGEST_OVERLAP, "an old client secret")? {
            None => PreviousSecret::Retired,
            Some(until) => PreviousSecret::AcceptedUntil {
                hash: self.current.clone(),
                until,
            },
        };
        Ok(Self {
            current: next,
            previous,
            sent_by: self.sent_by,
        })
    }
}

/// Where the public keys of a `private_key_jwt` client are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKeys {
    /// Registered with the client, as its JWK Set (`jwks`).
    Listed(ClientJwks),
    /// Published by the client at this address (`jwks_uri`), fetched when
    /// a signature is checked, so it can roll its keys on its own.
    Published(HttpsUrl),
}

text_value! {
    /// A client's JWK Set (RFC 7517 5), as the JSON it registered. An
    /// adapter reads the keys out of it when it checks a signed assertion.
    /// At most 16 KiB.
    pub struct ClientJwks;
}

impl TextValue for ClientJwks {
    const FIELD: &'static str = "jwks";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_blank()
            .max_bytes(16_384)
            .no_control_chars_but_line_breaks()
    }
}

text_value! {
    /// The subject distinguished name a `tls_client_auth` client's
    /// certificate must carry (RFC 8705 2.1.2), such as
    /// `CN=billing,O=Acme`.
    pub struct CertificateSubject;
}

impl TextValue for CertificateSubject {
    const FIELD: &'static str = "tls_client_auth_subject_dn";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(1024)
    }
}

/// The ways a client may prove itself at the token endpoint, by their
/// registered names (RFC 7591 2, RFC 8705 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEndpointAuthMethod {
    /// Proves the shared secret through HTTP Basic authentication.
    ClientSecretBasic,
    /// Proves the shared secret through fields in the token request body.
    ClientSecretPost,
    /// Proves possession of a private key by signing a client assertion.
    PrivateKeyJwt,
    /// Proves the client identity with its TLS certificate.
    TlsClientAuth,
    /// `none`, for a public client.
    None,
}

impl TokenEndpointAuthMethod {
    /// Every method, for discovery to list.
    pub const ALL: [Self; 5] = [
        Self::ClientSecretBasic,
        Self::ClientSecretPost,
        Self::PrivateKeyJwt,
        Self::TlsClientAuth,
        Self::None,
    ];

    /// Its registered name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::TlsClientAuth => "tls_client_auth",
            Self::None => "none",
        }
    }

    /// The method registered under `name`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `name` is not one of the five.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|method| method.as_str() == name)
            .ok_or_else(|| {
                DomainError::invalid(message!(
                    "oauth-is-not-a-client-authentication-method",
                    format!("{name} is not a client authentication method this server offers")
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Lifetime;

    fn hash(value: &str) -> TokenHash {
        TokenHash::from_stored(value.to_owned())
    }

    /// Supplies the allowed overlap while tests retire the previous client secret.
    fn week() -> Lifetime {
        Lifetime::seconds(7 * 86_400).unwrap()
    }

    /// The billing server's secret is rotated with a week's overlap. Both
    /// secrets work for the week, then only the new one.
    #[test]
    fn a_rotated_secret_keeps_the_old_one_for_its_overlap() {
        let now = crate::shared::clock::now();
        let secret = ClientSecret::new(hash("old"), SecretSentBy::Basic);

        let rotated = secret
            .rotated(hash("new"), RotationOverlap::For(week()), now)
            .unwrap();
        let credential = ClientCredential::Secret(rotated);

        assert_eq!(
            credential.secrets_accepted_at(now),
            vec![&hash("new"), &hash("old")]
        );
        assert_eq!(
            credential.secrets_accepted_at(now + Duration::days(7)),
            vec![&hash("new")]
        );
    }

    /// Rotating a secret without overlap immediately leaves only the new
    /// secret among the accepted hashes.
    #[test]
    fn an_immediate_rotation_drops_the_old_secret() {
        let now = crate::shared::clock::now();
        let secret = ClientSecret::new(hash("leaked"), SecretSentBy::Post);

        let rotated = secret
            .rotated(hash("new"), RotationOverlap::Immediate, now)
            .unwrap();

        assert_eq!(
            ClientCredential::Secret(rotated).secrets_accepted_at(now),
            vec![&hash("new")]
        );
    }

    /// An overlap of two months is refused: an old secret lives at most
    /// thirty days.
    #[test]
    fn an_overlap_longer_than_thirty_days_is_refused() {
        let secret = ClientSecret::new(hash("old"), SecretSentBy::Basic);
        let two_months = Lifetime::seconds(60 * 86_400).unwrap();

        let result = secret.rotated(
            hash("new"),
            RotationOverlap::For(two_months),
            crate::shared::clock::now(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A client registered for private-key JWT accepts that method, rejects
    /// a posted secret, and offers no accepted secret hashes.
    #[test]
    fn a_client_is_proved_only_the_way_it_registered() {
        let url = HttpsUrl::new("https://app.acme.com/jwks.json").unwrap();
        let credential = ClientCredential::PrivateKeyJwt(ClientKeys::Published(url));

        assert!(credential.accepts_method(TokenEndpointAuthMethod::PrivateKeyJwt));
        assert!(!credential.accepts_method(TokenEndpointAuthMethod::ClientSecretPost));
        assert!(
            credential
                .secrets_accepted_at(crate::shared::clock::now())
                .is_empty()
        );
    }

    /// Each credential names the method it is registered as, and a public
    /// client names `none`.
    #[test]
    fn each_credential_names_its_registered_method() {
        let subject = CertificateSubject::new("CN=billing,O=Acme").unwrap();

        assert_eq!(
            ClientCredential::secret(hash("s")).method().as_str(),
            "client_secret_basic"
        );
        assert_eq!(
            ClientCredential::TlsClientAuth(subject).method().as_str(),
            "tls_client_auth"
        );
        assert_eq!(ClientCredential::Public.method().as_str(), "none");
    }

    /// Every method reads back from its registered name; an unknown name is
    /// refused.
    #[test]
    fn methods_read_back_from_their_names() {
        for method in TokenEndpointAuthMethod::ALL {
            assert_eq!(
                TokenEndpointAuthMethod::parse(method.as_str()).unwrap(),
                method
            );
        }
        assert!(TokenEndpointAuthMethod::parse("client_secret_jwt").is_err());
    }
}
