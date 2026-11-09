//! The tenant's own JWTs: signing them, telling a JWT access token the
//! tenant signed from an opaque one (RFC 9068), and reading an
//! `id_token_hint` back (OIDC RP-Initiated Logout).
//!
//! A token is always checked against a key of the tenant's set that a
//! verifier may still accept, with the algorithm that key pins, never the
//! one the header names.

use async_trait::async_trait;
use ianua_app::ports::crypto::{JwtSigner, JwtSigningKey};
use ianua_app::ports::oauth::{
    AccessTokenJwtVerifier, HintClaims, IdTokenHintVerifier, PresentedJwt,
};
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::crypto::signing_key::SigningKeySet;
use ianua_domain::domains::crypto::verifying_key::VerifyingKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, Issuer, Lifetime, SessionId, TokenId, UserId};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto::jws::{Compact, PrivateKey, TokenHeader, signed};
use crate::crypto::tokens::claims::{Audiences, checking_key, checking_public_key, refused};

/// The signer of the tenant's JWTs with the key it is handed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pkcs8JwtSigner;

#[async_trait]
impl JwtSigner for Pkcs8JwtSigner {
    async fn sign_typed(
        &self,
        claims_json: &str,
        typ: JwtType,
        key: JwtSigningKey<'_>,
    ) -> Result<String, DomainError> {
        let private = PrivateKey::from_pem(key.algorithm, key.private_key.expose())
            .map_err(DomainError::infra)?;
        signed(
            claims_json,
            TokenHeader::new(typ, key.kid.as_str(), key.algorithm),
            &private,
        )
        .map_err(DomainError::infra)
    }
}

/// The claims an access token is found by.
#[derive(Debug, Deserialize)]
struct AccessClaims {
    iss: String,
    jti: String,
}

/// The check of a presented access token against the tenant's keys.
#[derive(Debug, Clone, Copy)]
pub struct Pkcs8AccessTokenJwtVerifier {
    grace: Lifetime,
}

impl Pkcs8AccessTokenJwtVerifier {
    /// A check accepting a rotated key's tokens for `grace`.
    #[must_use]
    pub fn new(grace: Lifetime) -> Self {
        Self { grace }
    }

    fn signed_id(
        &self,
        token: &Compact,
        keys: &[VerifyingKey],
        issuer: &Issuer,
    ) -> Option<TokenId> {
        let key = checking_public_key(keys, token, self.grace, clock::now()).ok()?;
        let claims: AccessClaims = token.verified(&key, JwtType::Access).ok()?;
        (claims.iss == issuer.as_str())
            .then(|| TokenId::new(claims.jti).ok())
            .flatten()
    }
}

#[async_trait]
impl AccessTokenJwtVerifier for Pkcs8AccessTokenJwtVerifier {
    async fn classify(
        &self,
        token: &Secret,
        keys: &[VerifyingKey],
        issuer: &Issuer,
    ) -> Result<PresentedJwt, DomainError> {
        let Ok(token) = Compact::parse(token.expose()) else {
            return Ok(PresentedJwt::Opaque);
        };
        Ok(self
            .signed_id(&token, keys, issuer)
            .map_or(PresentedJwt::Refused, PresentedJwt::Signed))
    }
}

/// The claims an ID token hint is read for.
#[derive(Debug, Deserialize)]
struct HintFields {
    iss: String,
    aud: Audiences,
    sub: Uuid,
    sid: Uuid,
}

/// The reader of an `id_token_hint` against the tenant's keys. It reads a
/// hint long expired, as an app signing a person out often holds one.
#[derive(Debug, Clone, Copy)]
pub struct Pkcs8IdTokenHintVerifier {
    grace: Lifetime,
}

impl Pkcs8IdTokenHintVerifier {
    /// A reader accepting a rotated key's tokens for `grace`.
    #[must_use]
    pub fn new(grace: Lifetime) -> Self {
        Self { grace }
    }
}

#[async_trait]
impl IdTokenHintVerifier for Pkcs8IdTokenHintVerifier {
    async fn verify(
        &self,
        hint: &Secret,
        keys: &SigningKeySet<ResolvedTenant>,
        issuer: &Issuer,
    ) -> Result<HintClaims, DomainError> {
        let token = Compact::parse(hint.expose()).map_err(|_| refused("the hint is no JWT"))?;
        let key = checking_key(keys, &token, self.grace, clock::now())?;
        let fields: HintFields = token
            .verified(&key, JwtType::IdToken)
            .map_err(|_| refused("the hint was not signed by the tenant"))?;
        if fields.iss != issuer.as_str() {
            return Err(refused("the hint names another issuer"));
        }
        let [audience] = fields
            .aud
            .all()
            .try_into()
            .map_err(|_| refused("the hint names no one client"))?;
        Ok(HintClaims {
            audience: ClientId::new(audience).map_err(|_| refused("the hint names no client"))?,
            subject: UserId::from_uuid(fields.sub),
            session: SessionId::from_uuid(fields.sid),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::types::KeyId;
    use serde_json::json;

    use super::*;
    use crate::crypto::tokens::claims::tests::{grace, key_set};

    struct Tenant {
        keys: SigningKeySet<ResolvedTenant>,
        private: Secret,
        issuer: Issuer,
    }

    fn tenant() -> Tenant {
        let (keys, private) = key_set();
        Tenant {
            keys,
            private,
            issuer: Issuer::new("https://acme.ianua.example").unwrap(),
        }
    }

    async fn sign(tenant: &Tenant, claims: serde_json::Value, typ: JwtType) -> Secret {
        let kid = KeyId::new("k1").unwrap();
        let signed = Pkcs8JwtSigner
            .sign_typed(
                &claims.to_string(),
                typ,
                JwtSigningKey {
                    kid: &kid,
                    algorithm: SigningAlgorithm::Es256,
                    private_key: &tenant.private,
                },
            )
            .await
            .unwrap();
        Secret::new(signed)
    }

    /// An access token the tenant signed is found by its `jti`; an opaque
    /// token is told apart from a JWT.
    #[tokio::test]
    async fn a_signed_access_token_is_found_by_its_jti() {
        let tenant = tenant();
        let token = sign(
            &tenant,
            json!({"iss": tenant.issuer.as_str(), "jti": "t-1"}),
            JwtType::Access,
        )
        .await;
        let verifier = Pkcs8AccessTokenJwtVerifier::new(grace());

        let signed = verifier
            .classify(&token, &tenant.keys.verifying_keys(), &tenant.issuer)
            .await
            .unwrap();
        let opaque = verifier
            .classify(
                &Secret::new("at_opaque"),
                &tenant.keys.verifying_keys(),
                &tenant.issuer,
            )
            .await
            .unwrap();

        assert_eq!(signed, PresentedJwt::Signed(TokenId::new("t-1").unwrap()));
        assert_eq!(opaque, PresentedJwt::Opaque);
    }

    /// An incorrect issuer, token type or tenant signing key produces a refused access token.
    #[tokio::test]
    async fn a_foreign_or_mistyped_jwt_is_refused() {
        let tenant = tenant();
        let other = self::tenant();
        let verifier = Pkcs8AccessTokenJwtVerifier::new(grace());
        let elsewhere = sign(
            &tenant,
            json!({"iss": "https://evil.example", "jti": "t"}),
            JwtType::Access,
        )
        .await;
        let session = sign(
            &tenant,
            json!({"iss": tenant.issuer.as_str(), "jti": "t"}),
            JwtType::AppSession,
        )
        .await;
        let theirs = sign(
            &other,
            json!({"iss": tenant.issuer.as_str(), "jti": "t"}),
            JwtType::Access,
        )
        .await;

        for token in [elsewhere, session, theirs] {
            let read = verifier
                .classify(&token, &tenant.keys.verifying_keys(), &tenant.issuer)
                .await
                .unwrap();
            assert_eq!(read, PresentedJwt::Refused);
        }
    }

    /// An ID token hint names its client, person and session, and is read
    /// even long after it expired.
    #[tokio::test]
    async fn an_id_token_hint_reads_back_past_its_expiry() {
        let tenant = tenant();
        let (sub, sid) = (Uuid::now_v7(), Uuid::now_v7());
        let hint = sign(
            &tenant,
            json!({"iss": tenant.issuer.as_str(), "aud": "client_app", "sub": sub, "sid": sid, "exp": 1}),
            JwtType::IdToken,
        )
        .await;

        let read = Pkcs8IdTokenHintVerifier::new(grace())
            .verify(&hint, &tenant.keys, &tenant.issuer)
            .await
            .unwrap();

        assert_eq!(read.audience.as_str(), "client_app");
        assert_eq!(read.subject, UserId::from_uuid(sub));
        assert_eq!(read.session, SessionId::from_uuid(sid));
    }

    /// An access token is unauthorized when read as an ID-token hint.
    #[tokio::test]
    async fn an_access_token_is_no_hint() {
        let tenant = tenant();
        let token = sign(
            &tenant,
            json!({"iss": tenant.issuer.as_str(), "aud": "c", "sub": Uuid::now_v7(), "sid": Uuid::now_v7()}),
            JwtType::Access,
        )
        .await;

        let read = Pkcs8IdTokenHintVerifier::new(grace())
            .verify(&token, &tenant.keys, &tenant.issuer)
            .await;

        assert!(matches!(read, Err(DomainError::Unauthorized(_))));
    }
}
