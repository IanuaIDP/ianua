//! The proofs the runner beside an agent's sandbox makes: with the agent's
//! key, the assertion it exchanges for a task token and each request's
//! proof of possession; with its workload's SVID key, the signature over an
//! attestation's binding.
//!
//! Only elliptic-curve keys sign here, P-256 and Ed25519: a proof carries
//! its public key, and the platform's own RSA keys never make one. Every
//! proof and assertion carries an id of its own, so none is taken twice.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::agents::{ProofRequest, RunnerKey, RunnerKeys, RunnerProofs, TaskToken};
use ianua_domain::domains::agents::runner::ASSERTION_LIFETIME;
use ianua_domain::domains::crypto::jwk::JwkComponents;
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentId, Audience, KeyId};
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::DecodePrivateKey as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::jws::{Header, PrivateKey, components, signed_under};

/// A key mounted into the runner, the same for its life: the key of a
/// credential enrolled on the agent by hand.
///
/// Whoever holds the file can act as the agent from anywhere, so a
/// deployment that can attest its workloads lets the runner attest
/// instead, and holds no key on disk.
pub struct MountedRunnerKeys {
    key: RunnerKey,
}

impl MountedRunnerKeys {
    /// The key `pem` holds, PKCS#8, of `algorithm`, enrolled on the agent's
    /// credential as `kid`.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when `algorithm` is RSA, or `pem` holds
    ///   no key of `algorithm`. The error never quotes the key.
    pub fn new(kid: KeyId, algorithm: SigningAlgorithm, pem: Secret) -> Result<Self, DomainError> {
        let key = RunnerKey {
            kid,
            algorithm,
            private_key: pem,
        };
        private_of(&key).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-runner-s-key-is-not",
                "the runner's key is not a P-256 or Ed25519 key"
            ))
        })?;
        Ok(Self { key })
    }
}

#[async_trait]
impl RunnerKeys for MountedRunnerKeys {
    async fn current(&self) -> Result<RunnerKey, DomainError> {
        Ok(self.key.clone())
    }
}

/// Signs proofs of possession (RFC 9449) carrying the runner's public key.
#[derive(Debug, Clone, Copy, Default)]
pub struct JwsRunnerProofs;

impl RunnerProofs for JwsRunnerProofs {
    fn proof(&self, key: &RunnerKey, request: &ProofRequest<'_>) -> Result<Secret, DomainError> {
        let private = private_of(key)?;
        let public = private
            .public_key()
            .ok_or_else(|| DomainError::infra_msg("an RSA key makes no proof of possession"))?;
        let header = Header {
            alg: private.algorithm().name().to_owned(),
            typ: Some(JwtType::DpopProof.header_value().to_owned()),
            kid: None,
            jwk: Some(carried(components(&public, ""))),
        };
        let claims = json!({
            "htm": request.method.as_str(),
            "htu": request.target,
            "iat": request.at.unix_timestamp(),
            "jti": Uuid::now_v7().to_string(),
            "ath": token_hash(request.token),
        });
        signed_under(&claims.to_string(), &header, &private)
            .map(Secret::new)
            .map_err(DomainError::infra)
    }
}

/// The assertion `key` signs that this is `agent`, for the token endpoint
/// `audience` names, made at `now` and good for
/// [`ASSERTION_LIFETIME`]. It names its key and carries no type: it is
/// the agent's own word, checked against its credential, never a token
/// the platform issued.
///
/// # Errors
///
/// - `DomainError::Infrastructure` when the key does not read or cannot
///   sign.
pub(crate) fn assertion(
    key: &RunnerKey,
    agent: &AgentId,
    audience: &Audience,
    now: OffsetDateTime,
) -> Result<Secret, DomainError> {
    let private = private_of(key)?;
    let header = Header {
        alg: private.algorithm().name().to_owned(),
        typ: None,
        kid: Some(key.kid.as_str().to_owned()),
        jwk: None,
    };
    let claims = json!({
        "iss": agent.to_string(),
        "sub": agent.to_string(),
        "aud": audience.as_str(),
        "iat": now.unix_timestamp(),
        "exp": now.saturating_add(ASSERTION_LIFETIME).unix_timestamp(),
        "jti": Uuid::now_v7().to_string(),
    });
    signed_under(&claims.to_string(), &header, &private)
        .map(Secret::new)
        .map_err(DomainError::infra)
}

/// The signature the SVID's PKCS#8 key `svid_key` makes over `bytes`, in
/// the form the SPIFFE attestor checks: DER for ECDSA on P-256, the raw 64
/// bytes for Ed25519.
///
/// # Errors
///
/// - `DomainError::Infrastructure` when the key is neither.
pub(crate) fn svid_signature(svid_key: &Secret, bytes: &[u8]) -> Result<Vec<u8>, DomainError> {
    if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(svid_key.expose()) {
        let signature: p256::ecdsa::DerSignature = key.sign(bytes);
        return Ok(signature.as_bytes().to_vec());
    }
    let key = ed25519_dalek::SigningKey::from_pkcs8_pem(svid_key.expose())
        .map_err(|_| DomainError::infra_msg("the SVID's key is neither P-256 nor Ed25519"))?;
    let signature: ed25519_dalek::Signature = key.sign(bytes);
    Ok(signature.to_bytes().to_vec())
}

/// `key`'s private half, read for its algorithm, when that is one a runner
/// signs with.
fn private_of(key: &RunnerKey) -> Result<PrivateKey, DomainError> {
    if key.algorithm == SigningAlgorithm::Rs256 {
        return Err(DomainError::infra_msg(
            "a runner signs with P-256 or Ed25519",
        ));
    }
    PrivateKey::from_pem(key.algorithm, key.private_key.expose()).map_err(DomainError::infra)
}

/// The JWK a proof carries in its header: the key's public members alone,
/// without a `kid`.
fn carried(key: JwkComponents) -> Value {
    match key {
        JwkComponents::Ec { crv, x, y, .. } => json!({"kty": "EC", "crv": crv, "x": x, "y": y}),
        JwkComponents::Okp { crv, x, .. } => json!({"kty": "OKP", "crv": crv, "x": x}),
        JwkComponents::Rsa { n, e, .. } => json!({"kty": "RSA", "n": n, "e": e}),
    }
}

/// The base64url SHA-256 of `token`, as a proof's `ath` names it.
fn token_hash(token: &TaskToken) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.reveal().as_bytes()))
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::{AgentAssertionVerifier, AssertionCheck, AssertionVerification};
    use ianua_app::ports::oauth::{DpopProofVerifier, DpopUse};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{HttpMethod, PublicKeyPem};
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;
    use crate::crypto::{JwkDpopProofVerifier, Pkcs8AgentAssertionVerifier};

    /// A fresh key of `algorithm` enrolled as `k1`, and its public half.
    fn key(algorithm: SigningAlgorithm) -> (RunnerKey, String) {
        let (private, public) = pair(algorithm);
        let key = RunnerKey {
            kid: KeyId::new("k1").unwrap(),
            algorithm,
            private_key: Secret::new(private),
        };
        (key, public)
    }

    /// A proof for `GET https://api.acme.test/reports` checks against the
    /// key it carries, names the token it is sent with, and says what it
    /// was made for, with either kind of key.
    #[tokio::test]
    async fn a_proof_checks_against_its_key_and_names_its_token() {
        for algorithm in [SigningAlgorithm::EdDsa, SigningAlgorithm::Es256] {
            let (key, _) = key(algorithm);
            let token = TaskToken::new("the.task.token");
            let request = ProofRequest {
                method: HttpMethod::Get,
                target: "https://api.acme.test/reports",
                token: &token,
                at: clock::now(),
            };

            let proof = JwsRunnerProofs.proof(&key, &request).unwrap();
            let presented = Secret::new(token.reveal());
            let read = JwkDpopProofVerifier
                .verify(&proof, DpopUse::AccessToken(&presented))
                .await
                .unwrap();

            assert_eq!(read.method, "GET");
            assert_eq!(read.url, "https://api.acme.test/reports");
        }
    }

    /// A runner proof bound to one token is unauthorized when paired with another token.
    #[tokio::test]
    async fn a_proof_for_one_token_is_refused_with_another() {
        let (key, _) = key(SigningAlgorithm::EdDsa);
        let token = TaskToken::new("the.task.token");
        let request = ProofRequest {
            method: HttpMethod::Post,
            target: "https://api.acme.test/orders",
            token: &token,
            at: clock::now(),
        };

        let proof = JwsRunnerProofs.proof(&key, &request).unwrap();
        let other = Secret::new("another.task.token");
        let read = JwkDpopProofVerifier
            .verify(&proof, DpopUse::AccessToken(&other))
            .await;

        assert!(matches!(read, Err(DomainError::Unauthorized(_))));
    }

    /// The assertion the runner signs for its agent checks against the
    /// agent's credential as the token exchange checks it.
    #[tokio::test]
    async fn an_assertion_proves_the_agent_to_the_exchange() {
        let (key, public) = key(SigningAlgorithm::Es256);
        let agent = AgentId::new();
        let audience = Audience::new("https://ianua.test").unwrap();

        let signed = assertion(&key, &agent, &audience, clock::now()).unwrap();
        let public = PublicKeyPem::new(public).unwrap();
        let proved = Pkcs8AgentAssertionVerifier
            .verify(
                signed.expose(),
                &AssertionVerification {
                    public_key: &public,
                    algorithm: SigningAlgorithm::Es256,
                    expected_issuer: &agent,
                    expected_audience: &audience,
                },
            )
            .await
            .unwrap();

        let AssertionCheck::Verified(proved) = proved else {
            panic!("the runner's assertion is refused");
        };
        assert_eq!(proved.agent_id, agent);
    }

    /// An SVID's P-256 key signs in DER, as the SPIFFE attestor reads it.
    #[test]
    fn an_svid_signature_is_der_for_p256() {
        let (private, public) = pair(SigningAlgorithm::Es256);
        let verifying = p256::ecdsa::VerifyingKey::from_public_key_pem(&public).unwrap();

        let signature = svid_signature(&Secret::new(private), b"the binding").unwrap();

        let der = p256::ecdsa::DerSignature::try_from(signature.as_slice()).unwrap();
        assert!(verifying.verify(b"the binding", &der).is_ok());
    }

    /// Loading an RSA key or malformed key text fails validation before a runner signer is created.
    #[test]
    fn a_mounted_key_the_runner_cannot_sign_with_is_refused() {
        let (rsa, _) = pair(SigningAlgorithm::Rs256);

        let rsa = MountedRunnerKeys::new(
            KeyId::new("k1").unwrap(),
            SigningAlgorithm::Rs256,
            Secret::new(rsa),
        );
        let garbled = MountedRunnerKeys::new(
            KeyId::new("k1").unwrap(),
            SigningAlgorithm::EdDsa,
            Secret::new("not a key"),
        );

        assert!(matches!(rsa, Err(DomainError::Validation(_))));
        assert!(matches!(garbled, Err(DomainError::Validation(_))));
    }
}
