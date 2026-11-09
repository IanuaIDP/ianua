//! `DPoP` proofs (RFC 9449): a JWT the client signs with the key its tokens
//! are bound to, carrying that public key in its own header.
//!
//! The key in the header is the only key the proof is checked against, so
//! the algorithm is the one that key signs with. A key with a private
//! part, or of a kind the platform does not read, is refused. How fresh
//! `iat` is and whether `jti` was seen before are the domain's to judge.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::oauth::{
    DPOP_SIGNING_ALGORITHMS, DpopProofVerifier, DpopUse, SignedDpopProof,
};
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::TokenId;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::crypto::issued::made;
use crate::crypto::jws::{Compact, read_jwk, thumbprint};
use crate::crypto::tokens::claims::refused;

/// The claims a proof must carry.
#[derive(Debug, Deserialize)]
struct ProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default)]
    ath: Option<String>,
}

/// The base64url SHA-256 of an access token, as a proof's `ath` names it.
fn access_token_hash(token: &Secret) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.expose().as_bytes()))
}

/// Refused unless the proof's `ath` names the access token it is sent with,
/// or it carries none when sent for tokens.
fn ensure_names(sent_for: DpopUse<'_>, ath: Option<&str>) -> Result<(), DomainError> {
    match (sent_for, ath) {
        (DpopUse::TokenRequest, _) => Ok(()),
        (DpopUse::AccessToken(token), Some(ath)) if ath == access_token_hash(token) => Ok(()),
        (DpopUse::AccessToken(_), _) => Err(refused("the proof does not name the access token")),
    }
}

/// The check of a `DPoP` proof against the key it carries.
#[derive(Debug, Clone, Copy, Default)]
pub struct JwkDpopProofVerifier;

#[async_trait]
impl DpopProofVerifier for JwkDpopProofVerifier {
    async fn verify(
        &self,
        proof: &Secret,
        sent_for: DpopUse<'_>,
    ) -> Result<SignedDpopProof, DomainError> {
        let token = Compact::parse(proof.expose()).map_err(|_| refused("the proof is no JWT"))?;
        if !DPOP_SIGNING_ALGORITHMS.contains(&token.header().alg.as_str()) {
            return Err(refused(
                "the proof is signed with an algorithm it may not use",
            ));
        }
        let jwk = token
            .header()
            .jwk
            .as_ref()
            .ok_or_else(|| refused("the proof carries no key"))?;
        let key = read_jwk(jwk)
            .map_err(|_| refused("the proof carries no public key it may use"))?
            .key;
        let claims: ProofClaims = token
            .verified(&key, JwtType::DpopProof)
            .map_err(|_| refused("the proof does not check against its key"))?;
        ensure_names(sent_for, claims.ath.as_deref())?;
        Ok(SignedDpopProof {
            thumbprint: made(JwkThumbprint::new(thumbprint(&key)))?,
            jti: TokenId::new(claims.jti).map_err(|_| refused("the proof's jti is not one"))?,
            method: claims.htm,
            url: claims.htu,
            issued_at: OffsetDateTime::from_unix_timestamp(claims.iat)
                .map_err(|_| refused("the proof's iat is no time"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use serde_json::{Value, json};

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;
    use crate::crypto::jws::{PrivateKey, PublicKey, components};

    /// A proof signed by a fresh EC key, carrying that key, with `claims`.
    fn proof(claims: &Value) -> (Secret, String) {
        let (private, public) = pair(SigningAlgorithm::Es256);
        let public = PublicKey::from_pem(SigningAlgorithm::Es256, &public).unwrap();
        let jwk = match components(&public, "") {
            ianua_domain::domains::crypto::jwk::JwkComponents::Ec { crv, x, y, .. } => {
                json!({"kty": "EC", "crv": crv, "x": x, "y": y})
            }
            _ => unreachable!("an EC key"),
        };
        let header = json!({"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signer = PrivateKey::from_pem(SigningAlgorithm::Es256, &private).unwrap();
        let signature = signer.sign(input.as_bytes()).unwrap();
        (
            Secret::new(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))),
            thumbprint(&public),
        )
    }

    fn claims(ath: Option<&str>) -> Value {
        json!({"jti": "p-1", "htm": "POST", "htu": "https://acme.example/token", "iat": 1_800_000_000, "ath": ath})
    }

    /// A proof for a token request reads back with its method, address and
    /// the thumbprint of the key it carries.
    #[tokio::test]
    async fn a_proof_reads_back_bound_to_its_key() {
        let (proof, expected) = proof(&claims(None));

        let read = JwkDpopProofVerifier
            .verify(&proof, DpopUse::TokenRequest)
            .await
            .unwrap();

        assert_eq!(read.thumbprint.as_str(), expected);
        assert_eq!(
            (read.method.as_str(), read.url.as_str()),
            ("POST", "https://acme.example/token")
        );
        assert_eq!(read.jti.as_str(), "p-1");
    }

    /// A proof sent with an access token names that token's hash, and is
    /// refused when it names another.
    #[tokio::test]
    async fn a_proof_with_an_access_token_must_name_it() {
        let token = Secret::new("at_abc");
        let (right, _) = proof(&claims(Some(&access_token_hash(&token))));
        let (wrong, _) = proof(&claims(Some("not-the-hash")));

        let named = JwkDpopProofVerifier
            .verify(&right, DpopUse::AccessToken(&token))
            .await;
        let unnamed = JwkDpopProofVerifier
            .verify(&wrong, DpopUse::AccessToken(&token))
            .await;

        assert!(named.is_ok());
        assert!(matches!(unnamed, Err(DomainError::Unauthorized(_))));
    }

    /// DPoP verification rejects both the `none` algorithm and a missing public key.
    #[tokio::test]
    async fn a_proof_with_no_signature_or_no_key_is_refused() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"dpop+jwt"}"#);
        let body = URL_SAFE_NO_PAD.encode(claims(None).to_string());
        let unsigned = Secret::new(format!("{header}.{body}."));
        let keyless_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"dpop+jwt"}"#);
        let keyless = Secret::new(format!("{keyless_header}.{body}.AAAA"));

        for proof in [unsigned, keyless] {
            let read = JwkDpopProofVerifier
                .verify(&proof, DpopUse::TokenRequest)
                .await;
            assert!(matches!(read, Err(DomainError::Unauthorized(_))));
        }
    }
}
