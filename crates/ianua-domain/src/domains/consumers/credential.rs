//! How a consumer signs in.

use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{
    CertificateFingerprint, FederatedSubject, HttpsUrl, Issuer, KeyPrefix, TokenHash,
};

/// How a consumer proves its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConsumerCredentialKind {
    /// An API key, kept as a hash, with a visible prefix to tell keys apart.
    ApiKey {
        /// The first characters of the key, such as `"sk_live_abc"`.
        prefix: KeyPrefix,
        /// HMAC hash of the full key.
        key_hash: TokenHash,
    },

    /// An X.509 client certificate, known by its SHA-256 fingerprint.
    ClientCert {
        /// The certificate's SHA-256 fingerprint.
        fingerprint: CertificateFingerprint,
    },

    /// A JWT the consumer signs itself, with a known issuer and subject.
    ///
    /// The proxy checks the signature against the consumer's keys at
    /// `jwks_uri`, with the algorithm each key names. It then matches the
    /// `iss` and `sub` claims to find the consumer. The tenant's own issuer
    /// is never a consumer's, because its tokens belong to people.
    JwtBearer {
        /// The expected `iss` claim: the consumer's token issuer URL.
        issuer: Issuer,
        /// The expected `sub` claim: the consumer's subject.
        subject: FederatedSubject,
        /// Where the consumer publishes the keys its tokens are signed with.
        jwks_uri: HttpsUrl,
    },
}

impl ConsumerCredentialKind {
    /// Refuses a JWT credential naming `tenant_issuer`, the tenant's own
    /// token issuer.
    ///
    /// Without this, Ann's access token from the tenant would be read as
    /// the consumer's. Ann would then act with the machine's roles.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the credential trusts tokens from
    ///   `tenant_issuer`.
    pub fn ensure_foreign_to(&self, tenant_issuer: &Issuer) -> Result<(), DomainError> {
        match self {
            Self::JwtBearer { issuer, .. } if issuer == tenant_issuer => {
                Err(DomainError::forbidden(message!(
                    "consumers-a-consumer-s-tokens-come-from",
                    "a consumer's tokens come from its own issuer, not the tenant's"
                )))
            }
            Self::ApiKey { .. } | Self::ClientCert { .. } | Self::JwtBearer { .. } => Ok(()),
        }
    }

    /// Refuses a token from `token_issuer` unless this is a JWT credential
    /// for that issuer and the issuer is not the tenant's own.
    ///
    /// The tenant's issuer can change after the consumer is set up, for
    /// example when the tenant switches to its own custom issuer. So the
    /// check made at setup is made again on every token, against the
    /// tenant's issuer of that moment.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the credential is not a JWT
    ///   credential.
    /// - [`DomainError::Forbidden`] when the token's issuer is not the one
    ///   the credential names.
    /// - [`DomainError::Forbidden`] when that issuer is now the tenant's
    ///   own, `tenant_issuer`.
    pub fn ensure_accepts_token_from(
        &self,
        token_issuer: &Issuer,
        tenant_issuer: &Issuer,
    ) -> Result<(), DomainError> {
        let Self::JwtBearer { issuer, .. } = self else {
            return Err(DomainError::forbidden(message!(
                "consumers-this-consumer-does-not-sign-in",
                "this consumer does not sign in with tokens"
            )));
        };
        if issuer != token_issuer {
            return Err(DomainError::forbidden(message!(
                "consumers-the-token-comes-from-an-issuer",
                "the token comes from an issuer the consumer does not name"
            )));
        }
        self.ensure_foreign_to(tenant_issuer)
    }

    /// A short name for logs. It never holds the secret.
    #[must_use]
    pub fn display_hint(&self) -> String {
        match self {
            Self::ApiKey { prefix, .. } => prefix.to_string(),
            Self::ClientCert { fingerprint, .. } => fingerprint.to_string(),
            Self::JwtBearer { subject, .. } => subject.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

    /// An API key starting "sk_live_abc" shows only that prefix in logs,
    /// never the hash.
    #[test]
    fn api_key_display_hint_is_prefix() {
        let cred = ConsumerCredentialKind::ApiKey {
            prefix: KeyPrefix::new("sk_live_abc").unwrap(),
            key_hash: TokenHash::from_stored("hash".to_owned()),
        };
        assert_eq!(cred.display_hint(), "sk_live_abc");
    }

    /// A JWT credential for subject "payment-consumer" shows that subject in
    /// logs.
    #[test]
    fn jwt_bearer_display_hint_is_subject() {
        let cred = jwt_from("https://auth.example.com");
        assert_eq!(cred.display_hint(), "payment-consumer");
    }

    fn jwt_from(issuer: &str) -> ConsumerCredentialKind {
        ConsumerCredentialKind::JwtBearer {
            issuer: Issuer::new(issuer).unwrap(),
            subject: FederatedSubject::new("payment-consumer").unwrap(),
            jwks_uri: HttpsUrl::new("https://auth.example.com/.well-known/jwks.json").unwrap(),
        }
    }

    /// A consumer credential trusting the tenant's issuer is rejected,
    /// while a credential trusting an outside issuer passes the check.
    #[test]
    fn a_consumer_cannot_trust_the_tenants_own_issuer() {
        let tenant = Issuer::new("https://acme.ianua.test").unwrap();

        assert!(matches!(
            jwt_from("https://acme.ianua.test").ensure_foreign_to(&tenant),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            jwt_from("https://auth.example.com")
                .ensure_foreign_to(&tenant)
                .is_ok()
        );
    }

    /// A consumer's configured issuer cannot accept tokens when that issuer
    /// is also the tenant's current issuer.
    #[test]
    fn a_token_from_an_issuer_the_tenant_later_took_is_refused() {
        let credential = jwt_from("https://login.acme.com");
        let issuer = Issuer::new("https://login.acme.com").unwrap();

        assert!(matches!(
            credential.ensure_accepts_token_from(&issuer, &issuer),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A token from the consumer's own outside issuer is accepted while the
    /// tenant keeps a different issuer.
    #[test]
    fn a_token_from_the_consumers_issuer_is_accepted() {
        let credential = jwt_from("https://auth.example.com");
        let tenant = Issuer::new("https://acme.ianua.test").unwrap();
        let token = Issuer::new("https://auth.example.com").unwrap();

        assert!(
            credential
                .ensure_accepts_token_from(&token, &tenant)
                .is_ok()
        );
    }

    /// Token issuer validation rejects an outside issuer that differs
    /// from the one configured for the consumer.
    #[test]
    fn a_token_from_another_issuer_is_refused() {
        let credential = jwt_from("https://auth.example.com");
        let tenant = Issuer::new("https://acme.ianua.test").unwrap();
        let token = Issuer::new("https://eve.example.com").unwrap();

        assert!(matches!(
            credential.ensure_accepts_token_from(&token, &tenant),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A consumer that signs in with a client certificate accepts no token
    /// at all.
    #[test]
    fn a_certificate_consumer_accepts_no_token() {
        let credential = ConsumerCredentialKind::ClientCert {
            fingerprint: CertificateFingerprint::parse(FINGERPRINT).unwrap(),
        };
        let tenant = Issuer::new("https://acme.ianua.test").unwrap();
        let token = Issuer::new("https://auth.example.com").unwrap();

        assert!(matches!(
            credential.ensure_accepts_token_from(&token, &tenant),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A client certificate written with colons shows in logs as its
    /// `sha256:` fingerprint in plain hex.
    #[test]
    fn client_cert_display_hint_is_fingerprint() {
        let cred = ConsumerCredentialKind::ClientCert {
            fingerprint: CertificateFingerprint::parse(FINGERPRINT).unwrap(),
        };
        assert_eq!(
            cred.display_hint(),
            "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
    }
}
