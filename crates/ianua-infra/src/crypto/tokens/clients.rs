//! Client assertions (RFC 7523): a JWT a `private_key_jwt` client signs
//! with its own key to prove itself at the token endpoint.
//!
//! The key is found in the client's registered JWK Set, or in the one it
//! publishes at an address, by the assertion's `kid`, or as the set's only
//! key when the assertion names none. The algorithm is the one that key
//! signs with. Fetching a published set is the [`PublishedKeys`] seam's,
//! which an HTTP adapter fills with a timeout.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::oauth::{ClientAssertionVerifier, VerifiedAssertion};
use ianua_domain::domains::oauth::clients::credential::ClientKeys;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, HttpsUrl, Issuer, TokenId};
use serde::Deserialize;
use serde_json::Value;

use crate::crypto::jws::{Compact, Jwk, PublicKey, read_jwk};
use crate::crypto::tokens::claims::{Audiences, Times, refused};

/// Where a client's published JWK Set is read from, inside the adapters.
#[async_trait]
pub trait PublishedKeys: Send + Sync {
    /// The keys of the JWK Set published at `url`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the set cannot be fetched
    /// in time, or is no JWK Set.
    async fn keys_at(&self, url: &HttpsUrl) -> Result<Vec<Value>, DomainError>;
}

/// The path of the tenant's token endpoint under its issuer, which an
/// assertion may name as its audience.
const TOKEN_ENDPOINT_PATH: &str = "/oauth/token";

/// A JWK Set as a client registers or publishes it.
#[derive(Debug, Deserialize)]
struct KeySet {
    keys: Vec<Value>,
}

/// The claims an assertion proves its client with.
#[derive(Debug, Deserialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
    aud: Audiences,
    jti: String,
    #[serde(flatten)]
    times: Times,
}

/// The key of `keys` a token is checked with: the one its `kid` names, or
/// the set's only key when it names none.
pub(super) fn key_for(token: &Compact, keys: &[Value]) -> Result<PublicKey, DomainError> {
    let read: Vec<Jwk> = keys.iter().filter_map(|key| read_jwk(key).ok()).collect();
    let chosen = match token.header().kid.as_deref() {
        Some(kid) => read.into_iter().find(|key| key.kid.as_deref() == Some(kid)),
        None => <[Jwk; 1]>::try_from(read).ok().map(|[only]| only),
    };
    chosen
        .map(|jwk| jwk.key)
        .ok_or_else(|| refused("the assertion names no key of the client"))
}

/// The check of a client's assertion against its registered or published
/// keys.
pub struct JwkClientAssertionVerifier {
    published: Arc<dyn PublishedKeys>,
}

impl JwkClientAssertionVerifier {
    /// A check reading published key sets through `published`.
    #[must_use]
    pub fn new(published: Arc<dyn PublishedKeys>) -> Self {
        Self { published }
    }

    async fn keys_of(&self, keys: &ClientKeys) -> Result<Vec<Value>, DomainError> {
        match keys {
            ClientKeys::Listed(jwks) => serde_json::from_str::<KeySet>(jwks.as_str())
                .map(|set| set.keys)
                .map_err(|_| refused("the client's registered keys are no JWK Set")),
            ClientKeys::Published(url) => self.published.keys_at(url).await,
        }
    }
}

/// Whether `audience` names the tenant: its issuer, or its token endpoint.
fn names_tenant(audience: &Audiences, issuer: &Issuer) -> bool {
    let endpoint = format!(
        "{}{TOKEN_ENDPOINT_PATH}",
        issuer.as_str().trim_end_matches('/')
    );
    audience.names(issuer.as_str()) || audience.names(&endpoint)
}

#[async_trait]
impl ClientAssertionVerifier for JwkClientAssertionVerifier {
    async fn verify(
        &self,
        assertion: &Secret,
        keys: &ClientKeys,
        issuer: &Issuer,
    ) -> Result<VerifiedAssertion, DomainError> {
        let token =
            Compact::parse(assertion.expose()).map_err(|_| refused("the assertion is no JWT"))?;
        let key = key_for(&token, &self.keys_of(keys).await?)?;
        let claims: AssertionClaims = token
            .verified_untyped(&key)
            .map_err(|_| refused("the assertion does not check against the client's key"))?;
        if claims.iss != claims.sub {
            return Err(refused("the assertion's issuer and subject differ"));
        }
        if !names_tenant(&claims.aud, issuer) {
            return Err(refused("the assertion is for another audience"));
        }
        claims.times.hold_at(clock::now())?;
        let expires_at = claims.times.accepted_until()?;
        Ok(VerifiedAssertion {
            client: ClientId::new(claims.sub)
                .map_err(|_| refused("the assertion names no client"))?,
            jti: TokenId::new(claims.jti).map_err(|_| refused("the assertion's jti is not one"))?,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ianua_domain::domains::crypto::jwk::JwkComponents;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::domains::oauth::clients::credential::ClientJwks;
    use serde_json::json;

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;
    use crate::crypto::jws::{PrivateKey, components};

    /// A published key set holding `keys`.
    struct Fixed(Vec<Value>);

    #[async_trait]
    impl PublishedKeys for Fixed {
        async fn keys_at(&self, _url: &HttpsUrl) -> Result<Vec<Value>, DomainError> {
            Ok(self.0.clone())
        }
    }

    struct Client {
        signer: PrivateKey,
        jwk: Value,
    }

    fn client(kid: &str) -> Client {
        let (private, public) = pair(SigningAlgorithm::EdDsa);
        let public = PublicKey::from_pem(SigningAlgorithm::EdDsa, &public).unwrap();
        let JwkComponents::Okp { crv, x, .. } = components(&public, kid) else {
            unreachable!("an Ed25519 key");
        };
        Client {
            signer: PrivateKey::from_pem(SigningAlgorithm::EdDsa, &private).unwrap(),
            jwk: json!({"kty": "OKP", "crv": crv, "x": x, "kid": kid}),
        }
    }

    fn issuer() -> Issuer {
        Issuer::new("https://acme.ianua.example").unwrap()
    }

    fn assertion(client: &Client, claims: &Value) -> Secret {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","kid":"c1"}"#);
        let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let signature = client.signer.sign(input.as_bytes()).unwrap();
        Secret::new(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    fn claims(aud: &str) -> Value {
        let now = clock::now().unix_timestamp();
        json!({"iss": "client_app", "sub": "client_app", "aud": aud, "jti": "a-1", "exp": now + 60, "iat": now})
    }

    fn listed(client: &Client) -> ClientKeys {
        ClientKeys::Listed(ClientJwks::new(json!({"keys": [client.jwk]}).to_string()).unwrap())
    }

    /// An assertion signed with a registered key, for the token endpoint,
    /// proves its client.
    #[tokio::test]
    async fn an_assertion_proves_its_client() {
        let client = client("c1");
        let verifier = JwkClientAssertionVerifier::new(Arc::new(Fixed(Vec::new())));
        let assertion = assertion(&client, &claims("https://acme.ianua.example/oauth/token"));

        let proved = verifier
            .verify(&assertion, &listed(&client), &issuer())
            .await
            .unwrap();

        assert_eq!(proved.client.as_str(), "client_app");
        assert_eq!(proved.jti.as_str(), "a-1");
    }

    /// The verified assertion's expiry includes the allowed clock skew,
    /// giving replay tracking the full acceptance window.
    #[tokio::test]
    async fn an_assertion_lasts_until_its_expiry_and_the_skew() {
        let client = client("c1");
        let verifier = JwkClientAssertionVerifier::new(Arc::new(Fixed(Vec::new())));
        let exp = clock::now().unix_timestamp() + 60;
        let mut claims = claims("https://acme.ianua.example");
        claims["exp"] = json!(exp);

        let proved = verifier
            .verify(&assertion(&client, &claims), &listed(&client), &issuer())
            .await
            .unwrap();

        assert_eq!(
            proved.expires_at.unix_timestamp(),
            exp + crate::crypto::tokens::claims::ALLOWED_SKEW
        );
    }

    /// A client publishing its keys at an address is checked against what
    /// is published there.
    #[tokio::test]
    async fn an_assertion_checks_against_published_keys() {
        let client = client("c1");
        let verifier = JwkClientAssertionVerifier::new(Arc::new(Fixed(vec![client.jwk.clone()])));
        let published = ClientKeys::Published(HttpsUrl::new("https://app.example/jwks").unwrap());

        let proved = verifier
            .verify(
                &assertion(&client, &claims("https://acme.ianua.example")),
                &published,
                &issuer(),
            )
            .await;

        assert!(proved.is_ok());
    }

    /// Another audience or an unregistered signing key makes client authentication unauthorized.
    #[tokio::test]
    async fn an_assertion_for_elsewhere_or_by_another_key_is_refused() {
        let client = client("c1");
        let impostor = self::client("c1");
        let verifier = JwkClientAssertionVerifier::new(Arc::new(Fixed(Vec::new())));
        let elsewhere = assertion(&client, &claims("https://evil.example"));
        let forged = assertion(&impostor, &claims("https://acme.ianua.example"));

        for assertion in [elsewhere, forged] {
            let read = verifier
                .verify(&assertion, &listed(&client), &issuer())
                .await;
            assert!(matches!(read, Err(DomainError::Unauthorized(_))));
        }
    }
}
