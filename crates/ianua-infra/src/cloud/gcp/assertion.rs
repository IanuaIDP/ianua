//! The signed assertion a Google service account key is exchanged for an
//! access token with: a JWT signed RS256 with the key, naming the account,
//! the scope asked for and Google's own token endpoint, good for ten
//! minutes.
//!
//! Only the parts of the key the domain holds are used, and the token
//! endpoint is always Google's, whatever the uploaded file said.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_domain::domains::organization::cloud::credential::{
    CloudIdentifier, GcpServiceAccountKey,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use time::OffsetDateTime;

use crate::crypto::certificates::rsa_keys::RsaSigningKey;

/// What the access token may do: read the project and its networks.
pub(crate) const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// How long an assertion is good for, in seconds: the longest Google takes.
const LIFETIME_SECONDS: i64 = 600;

/// The assertion `key` of `client_email` signs at `now`.
///
/// # Errors
///
/// - `DomainError::Forbidden` when the key is no RSA private key, which is
///   the customer's to fix.
/// - `DomainError::Infrastructure` when the assertion cannot be written or
///   signed.
pub(crate) fn assertion(
    key: &GcpServiceAccountKey,
    client_email: &CloudIdentifier,
    now: OffsetDateTime,
) -> Result<Secret, DomainError> {
    let issued = now.unix_timestamp();
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": key.private_key_id().as_str(),
    });
    let claims = serde_json::json!({
        "iss": client_email.as_str(),
        "scope": SCOPE,
        "aud": GcpServiceAccountKey::TOKEN_URI,
        "iat": issued,
        "exp": issued.saturating_add(LIFETIME_SECONDS),
    });
    let signed = format!("{}.{}", encoded(&header)?, encoded(&claims)?);
    let signature = signature_of(key, signed.as_bytes())?;
    Ok(Secret::new(format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    )))
}

/// `value` as JSON, base64url without padding.
fn encoded(value: &serde_json::Value) -> Result<String, DomainError> {
    let json = serde_json::to_vec(value).map_err(DomainError::infra)?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

/// The RS256 signature of `data` with the private key `key` holds.
fn signature_of(key: &GcpServiceAccountKey, data: &[u8]) -> Result<Vec<u8>, DomainError> {
    let private = RsaSigningKey::from_pkcs8_pem(key.private_key().expose()).map_err(|_| {
        DomainError::forbidden(message!(
            "infra-the-service-account-key-could-not",
            "the service account key could not be read as an RSA private key; download a \
             new JSON key for the account"
        ))
    })?;
    private
        .sign_sha256(data)
        .map_err(|_| DomainError::infra_msg("the service account key could not sign"))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::credential::{
        CloudSecret, GcpKeyFacts, GcpKeyParts,
    };

    use super::*;
    use crate::crypto::certificates::rsa_keys::RsaDigest;

    const EMAIL: &str = "ianua@acme-prod.iam.gserviceaccount.com";

    fn email() -> CloudIdentifier {
        CloudIdentifier::new(EMAIL).unwrap()
    }

    fn key_with(pem: &str) -> GcpServiceAccountKey {
        let parts = GcpKeyParts {
            project_id: CloudIdentifier::new("acme-prod").unwrap(),
            client_id: CloudIdentifier::new("1234567890").unwrap(),
            private_key_id: CloudIdentifier::new("key-1").unwrap(),
            private_key: CloudSecret::new(pem).unwrap(),
        };
        let facts = GcpKeyFacts {
            key_type: "service_account",
            client_email: EMAIL,
            token_uri: GcpServiceAccountKey::TOKEN_URI,
            universe_domain: None,
        };
        GcpServiceAccountKey::new(parts, &facts, &email()).unwrap()
    }

    fn decoded(part: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    /// The assertion names the account, the scope and Google's token
    /// endpoint, lasts ten minutes, and verifies with the key's public half.
    #[test]
    fn the_assertion_is_signed_by_the_key_for_googles_endpoint() {
        let (private, pem) = RsaSigningKey::generated().unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        let jwt = assertion(&key_with(&pem), &email(), now).unwrap();

        let parts: Vec<&str> = jwt.expose().split('.').collect();
        let claims = decoded(parts[1]);
        assert_eq!(decoded(parts[0])["alg"], "RS256");
        assert_eq!(claims["iss"], EMAIL);
        assert_eq!(claims["aud"], GcpServiceAccountKey::TOKEN_URI);
        assert_eq!(claims["scope"], SCOPE);
        assert_eq!(claims["exp"], 1_700_000_600);
        let signed = format!("{}.{}", parts[0], parts[1]);
        assert!(private.public_key().verifies(
            RsaDigest::Sha256,
            signed.as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        ));
    }

    /// Malformed RSA key material produces a forbidden error that omits the submitted key.
    #[test]
    fn a_key_that_is_no_rsa_key_is_the_customers_to_fix() {
        let pem = "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n";

        let error = assertion(&key_with(pem), &email(), OffsetDateTime::UNIX_EPOCH).unwrap_err();

        assert!(matches!(error, DomainError::Forbidden(_)));
        assert!(!format!("{error:?}").contains("bm90IGEga2V5"));
    }
}
