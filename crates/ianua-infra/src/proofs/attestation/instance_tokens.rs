//! GCP instance identity tokens: a JWT Google's metadata server gives a VM,
//! for an audience the VM names.
//!
//! The material is the token, requested from inside the instance with
//! `format=full`, so it names the instance, and with the binding of the
//! platform's nonce and the key being enrolled, in hex, as its audience.
//! It is taken when it is signed with RS256 by a key Google publishes,
//! whatever its header says, is from Google, names that binding as its
//! audience, is within its times and was issued just now. The metadata
//! server answers only the instance itself, so a token for this binding
//! proves the request came from that instance now, to enrol that key;
//! someone who sees the token before it is used cannot enrol a key of
//! their own with it. It does not tell two processes on one instance
//! apart.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::agents::{AgentAttestor, AttestationPresentation, EnrolledKey};
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestedIdentity, AttestedSubject, WorkloadIssuer,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::crypto::jws::{Compact, JwsAlgorithm, PublicKey};
use crate::proofs::attestation::published::{IssuerKeys, named_key};
use crate::proofs::attestation::{binding_for, material_for, refused};

/// The issuer Google's instance identity tokens name, as the key source is
/// asked for it.
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// The issuer Google may also write, without the scheme.
const GOOGLE_ISSUER_BARE: &str = "accounts.google.com";

/// How far apart this node's clock and Google's may be, in seconds.
const ALLOWED_SKEW: i64 = 60;

/// How long ago a token may have been issued and still be taken, in
/// seconds.
const LONGEST_AGE: i64 = 300;

/// The claims an instance identity token is read for.
#[derive(Deserialize)]
struct InstanceClaims {
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    google: GoogleClaim,
}

/// The `google` claim of a full-format token.
#[derive(Deserialize)]
struct GoogleClaim {
    compute_engine: ComputeEngine,
}

/// The instance a full-format token names.
#[derive(Deserialize)]
struct ComputeEngine {
    project_id: String,
    zone: String,
    instance_id: String,
}

/// The attestor of GCP instance identity tokens, against the keys Google
/// publishes.
pub struct GcpAgentAttestor {
    keys: Arc<dyn IssuerKeys>,
    issuer: WorkloadIssuer,
}

impl GcpAgentAttestor {
    /// An attestor reading Google's keys through `keys`, such as a
    /// [`FixedIssuerKeys`](crate::proofs::attestation::FixedIssuerKeys) on
    /// `https://www.googleapis.com/oauth2/v3/certs`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if Google's issuer is not one
    /// the domain accepts, which no configuration can cause.
    pub fn new(keys: Arc<dyn IssuerKeys>) -> Result<Self, DomainError> {
        Ok(Self {
            keys,
            issuer: Self::google_issuer()?,
        })
    }

    /// The issuer Google's keys are asked for under, for the
    /// [`FixedIssuerKeys`](crate::proofs::attestation::FixedIssuerKeys)
    /// this attestor reads them through.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if Google's issuer is not one
    /// the domain accepts, which no configuration can cause.
    pub fn google_issuer() -> Result<WorkloadIssuer, DomainError> {
        WorkloadIssuer::new(GOOGLE_ISSUER)
            .map_err(|_| DomainError::infra_msg("Google's issuer is not an issuer"))
    }

    /// The published RS256 key the token's `kid` names, read again once
    /// when Google rotated its keys since they were kept.
    async fn key_for(&self, token: &Compact) -> Result<PublicKey, DomainError> {
        named_key(
            self.keys.as_ref(),
            &self.issuer,
            token,
            &[JwsAlgorithm::Rs256],
        )
        .await
    }
}

#[async_trait]
impl AgentAttestor for GcpAgentAttestor {
    async fn verify(
        &self,
        presentation: &AttestationPresentation,
        key: &EnrolledKey,
    ) -> Result<AttestedIdentity, DomainError> {
        let material = material_for(presentation, AttestationMethod::GcpInstanceIdentity)?;
        let binding = binding_for(presentation, key)?;
        let token = Compact::parse(material).map_err(|_| refused("the token is no JWT"))?;
        let key = self.key_for(&token).await?;
        let claims: InstanceClaims = token
            .verified_untyped(&key)
            .map_err(|_| refused("the token does not check against Google's key"))?;
        if claims.iss != GOOGLE_ISSUER && claims.iss != GOOGLE_ISSUER_BARE {
            return Err(refused("the token is not from Google"));
        }
        if claims.aud != binding.as_hex() {
            return Err(refused("the token was not made for this attestation"));
        }
        ensure_fresh(&claims, clock::now())?;
        Ok(AttestedIdentity::new(
            AttestationMethod::GcpInstanceIdentity,
            subject_of(&claims.google.compute_engine)?,
        ))
    }
}

/// Refused unless the token, at `now`, has not expired and was issued
/// within [`LONGEST_AGE`], allowing [`ALLOWED_SKEW`] either way.
fn ensure_fresh(claims: &InstanceClaims, now: OffsetDateTime) -> Result<(), DomainError> {
    let now = now.unix_timestamp();
    let expired = claims.exp.saturating_add(ALLOWED_SKEW) <= now;
    let ahead = claims.iat > now.saturating_add(ALLOWED_SKEW);
    let old = now.saturating_sub(claims.iat) > LONGEST_AGE;
    if expired || ahead || old {
        return Err(refused("the token was not issued just now"));
    }
    Ok(())
}

/// The subject a token attests, `gcp:<project>:<zone>:<instance>`,
/// refused when a part is empty or holds a colon, so no part can reach
/// into another.
fn subject_of(instance: &ComputeEngine) -> Result<AttestedSubject, DomainError> {
    let parts = [&instance.project_id, &instance.zone, &instance.instance_id];
    if parts
        .iter()
        .any(|part| part.is_empty() || part.contains(':'))
    {
        return Err(refused("the token names no instance; ask for format=full"));
    }
    AttestedSubject::new(format!(
        "gcp:{}:{}:{}",
        instance.project_id, instance.zone, instance.instance_id
    ))
    .map_err(|_| refused("the token names no instance"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ianua_app::ports::agents::AttestationProof;
    use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
    use serde_json::{Value, json};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::crypto::certificates::rsa_keys::RsaSigningKey;
    use crate::proofs::attestation::tests::enrolled_key;
    use crate::proofs::attestation::{AttestationBinding, FixedIssuerKeys, KeyKeeping};

    const NONCE: &str = "gcp-bootstrap-nonce-0123456789abcdef0123";

    /// Google's signing key, published on a stand-in for its key address.
    struct Google {
        key: RsaSigningKey,
        server: MockServer,
    }

    /// Google's keys kept ten minutes, asked again at most once a minute.
    fn keeping() -> KeyKeeping {
        KeyKeeping {
            keep_for: Duration::from_secs(600),
            renew_after: Duration::from_secs(60),
        }
    }

    /// A fresh 2048-bit RSA signing key.
    fn rsa_key() -> RsaSigningKey {
        RsaSigningKey::generated().unwrap().0
    }

    async fn google() -> Google {
        let key = rsa_key();
        let public = key.public_key();
        let set = json!({"keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "google-1",
            "n": URL_SAFE_NO_PAD.encode(public.modulus()),
            "e": URL_SAFE_NO_PAD.encode(public.exponent()),
        }]});
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/v3/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(set))
            .mount(&server)
            .await;
        Google { key, server }
    }

    fn attestor(google: &Google) -> GcpAgentAttestor {
        let address = url::Url::parse(&format!("{}/oauth2/v3/certs", google.server.uri())).unwrap();
        let keys = FixedIssuerKeys::new(
            GcpAgentAttestor::google_issuer().unwrap(),
            address,
            Duration::from_secs(5),
            keeping(),
        )
        .unwrap();
        GcpAgentAttestor::new(Arc::new(keys)).unwrap()
    }

    /// Full-format claims for `audience`, issued `age` seconds ago.
    fn claims(audience: &str, age: i64) -> Value {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        json!({
            "iss": GOOGLE_ISSUER,
            "aud": audience,
            "sub": "1234567890",
            "iat": now - age,
            "exp": now - age + 3600,
            "google": {"compute_engine": {
                "project_id": "acme-prod",
                "zone": "europe-west1-b",
                "instance_id": "4567890123",
            }},
        })
    }

    /// `claims` signed by `key` under a header of `alg`.
    fn token(key: &RsaSigningKey, alg: &str, claims: &Value) -> String {
        let header = json!({"alg": alg, "kid": "google-1", "typ": "JWT"});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = key.sign_sha256(input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn presented(material: String) -> AttestationPresentation {
        AttestationPresentation {
            method: AttestationMethod::GcpInstanceIdentity,
            material,
            proof: AttestationProof {
                nonce: AttestationNonce::new(NONCE).unwrap(),
                signature: String::new(),
            },
        }
    }

    /// The binding of the test nonce and `key`, as the token's audience.
    fn audience(key: &EnrolledKey) -> String {
        AttestationBinding::of(&AttestationNonce::new(NONCE).unwrap(), &key.public_key)
            .unwrap()
            .as_hex()
            .to_owned()
    }

    /// A fresh token Google signed for the binding attests the instance it
    /// names.
    #[tokio::test]
    async fn a_fresh_token_for_the_binding_attests_its_instance() {
        let google = google().await;
        let key = enrolled_key();
        let material = token(&google.key, "RS256", &claims(&audience(&key), 5));

        let attested = attestor(&google)
            .verify(&presented(material), &key)
            .await
            .unwrap();

        assert_eq!(
            attested.subject().as_str(),
            "gcp:acme-prod:europe-west1-b:4567890123"
        );
    }

    /// Instance tokens addressed to an earlier nonce or a bare nonce fail attestation.
    #[tokio::test]
    async fn a_token_for_another_audience_is_refused() {
        let google = google().await;
        let key = enrolled_key();

        for aud in ["an-earlier-nonce", NONCE] {
            let material = token(&google.key, "RS256", &claims(aud, 5));

            let attested = attestor(&google).verify(&presented(material), &key).await;

            assert!(
                matches!(attested, Err(DomainError::Unauthorized(_))),
                "{aud}"
            );
        }
    }

    /// A token's audience binding cannot attest a different enrolled key.
    #[tokio::test]
    async fn a_token_made_for_another_key_is_refused() {
        let google = google().await;
        let workload = enrolled_key();
        let thief = enrolled_key();
        let material = token(&google.key, "RS256", &claims(&audience(&workload), 5));

        let attested = attestor(&google).verify(&presented(material), &thief).await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// Instance-token headers declaring `none`, HS256 or ES256 are unauthorized.
    #[tokio::test]
    async fn a_token_naming_another_algorithm_is_refused() {
        let google = google().await;
        let attestor = attestor(&google);
        let key = enrolled_key();

        for alg in ["none", "HS256", "ES256"] {
            let material = token(&google.key, alg, &claims(&audience(&key), 5));

            let attested = attestor.verify(&presented(material), &key).await;

            assert!(
                matches!(attested, Err(DomainError::Unauthorized(_))),
                "{alg}"
            );
        }
    }

    /// A token signed by an unpublished RSA key fails instance attestation.
    #[tokio::test]
    async fn a_token_signed_by_another_key_is_refused() {
        let google = google().await;
        let forger = rsa_key();
        let key = enrolled_key();
        let material = token(&forger, "RS256", &claims(&audience(&key), 5));

        let attested = attestor(&google).verify(&presented(material), &key).await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// Expired tokens, incomplete instance claims and malformed token text are unauthorized.
    #[tokio::test]
    async fn an_old_token_or_one_naming_no_instance_is_refused() {
        let google = google().await;
        let attestor = attestor(&google);
        let key = enrolled_key();
        let mut unnamed = claims(&audience(&key), 5);
        unnamed["google"]["compute_engine"]["zone"] = json!("");

        let old = attestor
            .verify(
                &presented(token(&google.key, "RS256", &claims(&audience(&key), 7200))),
                &key,
            )
            .await;
        let unnamed = attestor
            .verify(&presented(token(&google.key, "RS256", &unnamed)), &key)
            .await;
        let garbled = attestor
            .verify(&presented("not.a.jwt".to_owned()), &key)
            .await;

        assert!(matches!(old, Err(DomainError::Unauthorized(_))));
        assert!(matches!(unnamed, Err(DomainError::Unauthorized(_))));
        assert!(matches!(garbled, Err(DomainError::Unauthorized(_))));
    }

    /// Failure to fetch Google's keys makes instance attestation fail.
    #[tokio::test]
    async fn keys_that_cannot_be_fetched_refuse_the_token() {
        let google = google().await;
        let key = enrolled_key();
        let material = token(&google.key, "RS256", &claims(&audience(&key), 5));
        let unreachable = GcpAgentAttestor::new(Arc::new(
            FixedIssuerKeys::new(
                WorkloadIssuer::new(GOOGLE_ISSUER).unwrap(),
                url::Url::parse(&format!("{}/missing", google.server.uri())).unwrap(),
                Duration::from_secs(5),
                keeping(),
            )
            .unwrap(),
        ))
        .unwrap();

        let attested = unreachable.verify(&presented(material), &key).await;

        assert!(attested.is_err());
    }
}
