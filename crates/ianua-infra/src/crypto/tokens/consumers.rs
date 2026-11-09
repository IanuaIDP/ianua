//! A consumer's own token, checked at the gateway against the keys the
//! consumer publishes, never the tenant's.
//!
//! The key is the one the token's `kid` names in the published set, or the
//! set's only key when it names none, and the algorithm is the one that key
//! signs with. Fetching the set is the [`PublishedKeys`] seam's, which an
//! HTTP adapter fills with a timeout and a bounded cache.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::authentication::{
    ConsumerToken, ConsumerTokenVerifier, ExpectedToken, TokenFault, TokenReading,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{FederatedSubject, HttpsUrl, Issuer};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::crypto::jws::Compact;
use crate::crypto::tokens::claims::{Audiences, Times};
use crate::crypto::tokens::clients::{PublishedKeys, key_for};
use crate::crypto::tokens::presented::{Read, ScopeClaims, expiry_of, reading, times_hold};

/// What a consumer's token says.
#[derive(Debug, Deserialize)]
struct ConsumerClaims {
    iss: String,
    sub: String,
    aud: Audiences,
    #[serde(flatten)]
    scopes: ScopeClaims,
    #[serde(flatten)]
    times: Times,
}

/// The check of a consumer's token against the keys it publishes.
pub struct JwkConsumerTokenVerifier {
    published: Arc<dyn PublishedKeys>,
}

impl JwkConsumerTokenVerifier {
    /// A check reading published key sets through `published`.
    #[must_use]
    pub fn new(published: Arc<dyn PublishedKeys>) -> Self {
        Self { published }
    }
}

/// What a consumer token's `claims`, checked out under its key, says for
/// `expected`, at `now`.
fn consumer_token(
    claims: ConsumerClaims,
    expected: ExpectedToken<'_>,
    now: OffsetDateTime,
) -> Read<ConsumerToken> {
    if claims.iss != expected.issuer.as_str() {
        return Err(TokenFault::WrongIssuer);
    }
    if !claims.aud.names(expected.audience.as_str()) {
        return Err(TokenFault::WrongAudience);
    }
    times_hold(claims.times, now)?;
    Ok(ConsumerToken {
        issuer: Issuer::new(claims.iss).map_err(|_| TokenFault::Invalid)?,
        subject: FederatedSubject::new(claims.sub).map_err(|_| TokenFault::Invalid)?,
        expires_at: expiry_of(claims.times.exp)?,
        scopes: claims.scopes.scopes()?,
    })
}

#[async_trait]
impl ConsumerTokenVerifier for JwkConsumerTokenVerifier {
    async fn verify(
        &self,
        token: &Secret,
        keys_at: &HttpsUrl,
        expected: ExpectedToken<'_>,
    ) -> Result<TokenReading<ConsumerToken>, DomainError> {
        let Ok(token) = Compact::parse(token.expose()) else {
            return Ok(TokenReading::Refused(TokenFault::Invalid));
        };
        let keys = self.published.keys_at(keys_at).await?;
        let Ok(key) = key_for(&token, &keys) else {
            return Ok(TokenReading::Refused(TokenFault::Invalid));
        };
        let Ok(claims) = token.verified_untyped::<ConsumerClaims>(&key) else {
            return Ok(TokenReading::Refused(TokenFault::Invalid));
        };
        Ok(reading(consumer_token(claims, expected, clock::now())))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::jwk::JwkComponents;
    use ianua_domain::domains::crypto::jwt_type::JwtType;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::types::{Audience, Scope};
    use serde_json::{Value, json};

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;
    use crate::crypto::jws::{PrivateKey, PublicKey, TokenHeader, components, signed};

    /// A published key set holding `keys`, or none to be fetched at all.
    struct Fixed(Option<Vec<Value>>);

    #[async_trait]
    impl PublishedKeys for Fixed {
        async fn keys_at(&self, _url: &HttpsUrl) -> Result<Vec<Value>, DomainError> {
            self.0
                .clone()
                .ok_or_else(|| DomainError::infra_msg("the keys did not come in time"))
        }
    }

    /// A consumer's signing key, and the JWK it publishes under `p1`.
    struct Partner {
        signer: PrivateKey,
        jwk: Value,
    }

    fn partner() -> Partner {
        let (private, public) = pair(SigningAlgorithm::EdDsa);
        let public = PublicKey::from_pem(SigningAlgorithm::EdDsa, &public).unwrap();
        let JwkComponents::Okp { crv, x, .. } = components(&public, "p1") else {
            unreachable!("an Ed25519 key");
        };
        Partner {
            signer: PrivateKey::from_pem(SigningAlgorithm::EdDsa, &private).unwrap(),
            jwk: json!({"kty": "OKP", "crv": crv, "x": x, "kid": "p1"}),
        }
    }

    fn sign(partner: &Partner, claims: &Value) -> Secret {
        let algorithm = SigningAlgorithm::EdDsa;
        let token = signed(
            &claims.to_string(),
            TokenHeader::new(JwtType::Access, "p1", algorithm),
            &partner.signer,
        );
        Secret::new(token.unwrap())
    }

    fn claims(aud: &str) -> Value {
        let now = clock::now().unix_timestamp();
        json!({
            "iss": "https://partner.example",
            "sub": "feed",
            "aud": aud,
            "scp": ["ledger:read"],
            "iat": now,
            "exp": now + 300,
        })
    }

    struct Expected {
        issuer: Issuer,
        audience: Audience,
        keys_at: HttpsUrl,
    }

    fn expected() -> Expected {
        Expected {
            issuer: Issuer::new("https://partner.example").unwrap(),
            audience: Audience::new("ledger").unwrap(),
            keys_at: HttpsUrl::new("https://partner.example/jwks").unwrap(),
        }
    }

    async fn verify(
        keys: Fixed,
        token: &Secret,
    ) -> Result<TokenReading<ConsumerToken>, DomainError> {
        let wanted = expected();
        let expected = ExpectedToken {
            issuer: &wanted.issuer,
            audience: &wanted.audience,
        };
        JwkConsumerTokenVerifier::new(Arc::new(keys))
            .verify(token, &wanted.keys_at, expected)
            .await
    }

    /// A token the consumer signed with a key it publishes, for the route's
    /// audience, reads as its issuer and subject with its scopes.
    #[tokio::test]
    async fn a_consumers_token_reads_under_its_published_key() {
        let feed = partner();
        let token = sign(&feed, &claims("ledger"));

        let read = verify(Fixed(Some(vec![feed.jwk.clone()])), &token).await;

        let Ok(TokenReading::Read(read)) = read else {
            panic!("the token did not read");
        };
        assert_eq!(read.issuer.as_str(), "https://partner.example");
        assert_eq!(read.subject.as_str(), "feed");
        let scopes: Vec<&str> = read.scopes.iter().map(Scope::as_str).collect();
        assert_eq!(scopes, ["ledger:read"]);
    }

    /// A mismatched consumer audience receives its own refusal; an unpublished signing key
    /// makes the token invalid.
    #[tokio::test]
    async fn a_misdirected_or_foreign_token_is_refused() {
        let feed = partner();
        let stranger = partner();
        let elsewhere = sign(&feed, &claims("billing"));
        let forged = sign(&stranger, &claims("ledger"));

        let misdirected = verify(Fixed(Some(vec![feed.jwk.clone()])), &elsewhere).await;
        let foreign = verify(Fixed(Some(vec![feed.jwk.clone()])), &forged).await;

        assert!(matches!(
            misdirected,
            Ok(TokenReading::Refused(TokenFault::WrongAudience))
        ));
        assert!(matches!(
            foreign,
            Ok(TokenReading::Refused(TokenFault::Invalid))
        ));
    }

    /// Failure to fetch the consumer's published keys remains an infrastructure error.
    #[tokio::test]
    async fn keys_that_cannot_be_fetched_are_an_error() {
        let feed = partner();
        let token = sign(&feed, &claims("ledger"));

        let read = verify(Fixed(None), &token).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
