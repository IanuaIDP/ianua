//! JWTs in compact serialization: `header.payload.signature`, each part
//! base64url without padding.
//!
//! A token is signed with its key's algorithm, which the header then
//! names. A token is checked with the algorithm of the key it is checked
//! against: a header naming another algorithm, `none` among them, is
//! refused before any signature is checked, so the token can never choose
//! how it is verified.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::jws::keys::{JwsAlgorithm, KeyError, PrivateKey, PublicKey};

/// Why a token could not be made or read. None of it names the token.
#[derive(Debug, thiserror::Error)]
pub(crate) enum JwsError {
    /// The token is not three base64url parts with a JSON header.
    #[error("the token is not a compact JWS")]
    Malformed,
    /// The header names another algorithm than the key's.
    #[error("the token names an algorithm its key does not sign with")]
    WrongAlgorithm,
    /// The header names another type than the one expected.
    #[error("the token is not of the expected type")]
    WrongType,
    /// The signature does not check against the key.
    #[error("the token's signature does not check")]
    BadSignature,
    /// The claims are not the JSON expected.
    #[error("the token's claims are not the ones expected")]
    BadClaims,
    /// The key could not be read or could not sign.
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// The name JWS gives `algorithm` in a header's `alg`.
pub(crate) fn alg_name(algorithm: SigningAlgorithm) -> &'static str {
    JwsAlgorithm::from(algorithm).name()
}

/// A token's protected header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Header {
    pub(crate) alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) jwk: Option<Value>,
}

/// The protected metadata identifying a platform token and its signing key.
#[derive(Clone, Copy)]
pub(crate) struct TokenHeader<'a> {
    typ: JwtType,
    kid: &'a str,
    algorithm: SigningAlgorithm,
}

impl<'a> TokenHeader<'a> {
    /// Keeps the caller's token type, key name and declared algorithm together.
    pub(crate) fn new(typ: JwtType, kid: &'a str, algorithm: SigningAlgorithm) -> Self {
        Self {
            typ,
            kid,
            algorithm,
        }
    }
}

/// Signs claims with the supplied key and protected token metadata.
pub(crate) fn signed(
    claims_json: &str,
    metadata: TokenHeader<'_>,
    key: &PrivateKey,
) -> Result<String, JwsError> {
    let header = Header {
        alg: alg_name(metadata.algorithm).to_owned(),
        typ: Some(metadata.typ.header_value().to_owned()),
        kid: Some(metadata.kid.to_owned()),
        jwk: None,
    };
    let header = serde_json::to_vec(&header).map_err(|_| JwsError::Malformed)?;
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims_json.as_bytes())
    );
    let signature = key.sign(input.as_bytes())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// `claims` signed with `key` under `header`, for a token whose header is
/// not the platform's own: an assertion a runner signs for its agent,
/// which names its key and no type, and a proof of possession, which
/// carries its public key instead of naming one. The header's `alg` must
/// be `key`'s, or the token is refused before anything is signed.
pub(crate) fn signed_under(
    claims_json: &str,
    header: &Header,
    key: &PrivateKey,
) -> Result<String, JwsError> {
    if header.alg != key.algorithm().name() {
        return Err(JwsError::WrongAlgorithm);
    }
    let header = serde_json::to_vec(header).map_err(|_| JwsError::Malformed)?;
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims_json.as_bytes())
    );
    let signature = key.sign(input.as_bytes())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// A token split and its header read, its signature not yet checked.
#[derive(Debug, Clone)]
pub(crate) struct Compact {
    header: Header,
    payload: Vec<u8>,
    input: String,
    signature: Vec<u8>,
}

impl Compact {
    /// The parts of `token`.
    pub(crate) fn parse(token: &str) -> Result<Self, JwsError> {
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwsError::Malformed);
        };
        let decode = |part: &str| {
            URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|_| JwsError::Malformed)
        };
        let header_json = decode(header)?;
        Ok(Self {
            header: serde_json::from_slice(&header_json).map_err(|_| JwsError::Malformed)?,
            payload: decode(payload)?,
            input: format!("{header}.{payload}"),
            signature: decode(signature)?,
        })
    }

    /// The header, read before the key it names is chosen.
    pub(crate) fn header(&self) -> &Header {
        &self.header
    }

    /// The claims as written, before any signature is checked: only to
    /// choose, among keys already trusted, which one the token is then
    /// checked with. Nothing read here may be believed.
    pub(crate) fn unchecked_claims<C: DeserializeOwned>(&self) -> Result<C, JwsError> {
        serde_json::from_slice(&self.payload).map_err(|_| JwsError::BadClaims)
    }

    /// Whether the header's `typ` is exactly `typ`.
    pub(crate) fn is_typed(&self, typ: JwtType) -> bool {
        typ.is_named_by(self.header.typ.as_deref())
    }

    /// The claims, once the signature checks against `key` with the
    /// algorithm `key` signs with and the header is of `typ`.
    pub(crate) fn verified<C: DeserializeOwned>(
        &self,
        key: &PublicKey,
        typ: JwtType,
    ) -> Result<C, JwsError> {
        if !self.is_typed(typ) {
            return Err(JwsError::WrongType);
        }
        self.verified_untyped(key)
    }

    /// The claims, once the signature checks against `key` with the
    /// algorithm `key` signs with, for a token another party types: a
    /// client's assertion or a workload's token.
    pub(crate) fn verified_untyped<C: DeserializeOwned>(
        &self,
        key: &PublicKey,
    ) -> Result<C, JwsError> {
        if self.header.alg != key.algorithm().name() {
            return Err(JwsError::WrongAlgorithm);
        }
        if !key.verifies(self.input.as_bytes(), &self.signature) {
            return Err(JwsError::BadSignature);
        }
        serde_json::from_slice(&self.payload).map_err(|_| JwsError::BadClaims)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::crypto::jws::keys::tests::pair;

    fn keys(algorithm: SigningAlgorithm) -> (PrivateKey, PublicKey) {
        let (private, public) = pair(algorithm);
        (
            PrivateKey::from_pem(algorithm, &private).unwrap(),
            PublicKey::from_pem(algorithm, &public).unwrap(),
        )
    }

    /// A token signed with a key reads back, with its claims, against the
    /// key's public half, and names its algorithm, type and key.
    #[test]
    fn a_signed_token_reads_back_with_its_claims() {
        let (private, public) = keys(SigningAlgorithm::Es256);

        let token = signed(
            r#"{"sub":"ann"}"#,
            TokenHeader::new(JwtType::Access, "k1", SigningAlgorithm::Es256),
            &private,
        )
        .unwrap();
        let read = Compact::parse(&token).unwrap();

        let claims: Value = read.verified(&public, JwtType::Access).unwrap();
        assert_eq!(claims, json!({"sub": "ann"}));
        assert_eq!(read.header().alg, "ES256");
        assert_eq!(read.header().kid.as_deref(), Some("k1"));
    }

    /// An unsigned token declaring `alg: none` fails with the wrong-algorithm error.
    #[test]
    fn a_token_naming_none_is_refused() {
        let (_, public) = keys(SigningAlgorithm::EdDsa);
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"at+jwt"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"mallory"}"#);
        let token = format!("{header}.{payload}.");

        let read = Compact::parse(&token)
            .unwrap()
            .verified::<Value>(&public, JwtType::Access);

        assert!(matches!(read, Err(JwsError::WrongAlgorithm)));
    }

    /// Foreign keys and changed claims fail signature verification;
    /// a mismatched token type receives the separate type error.
    #[test]
    fn a_token_of_another_key_type_or_changed_claims_is_refused() {
        let (private, public) = keys(SigningAlgorithm::EdDsa);
        let (other, _) = keys(SigningAlgorithm::EdDsa);
        let access = TokenHeader::new(JwtType::Access, "k1", SigningAlgorithm::EdDsa);
        let theirs = signed("{}", access, &other).unwrap();
        let session = signed(
            "{}",
            TokenHeader::new(JwtType::AppSession, "k1", SigningAlgorithm::EdDsa),
            &private,
        )
        .unwrap();
        let ours = signed(r#"{"sub":"ann"}"#, access, &private).unwrap();
        let mut parts: Vec<&str> = ours.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(r#"{"sub":"mallory"}"#);
        parts[1] = &forged;
        let changed = parts.join(".");

        let read = |token: &str| {
            Compact::parse(token)
                .unwrap()
                .verified::<Value>(&public, JwtType::Access)
        };

        assert!(matches!(read(&theirs), Err(JwsError::BadSignature)));
        assert!(matches!(read(&session), Err(JwsError::WrongType)));
        assert!(matches!(read(&changed), Err(JwsError::BadSignature)));
    }

    /// Incorrect compact-token part counts and malformed headers fail parsing.
    #[test]
    fn a_malformed_token_is_refused() {
        for token in ["a.b.c.d", "only-one-part", "!!!.e30.sig", "e30"] {
            assert!(Compact::parse(token).is_err(), "{token} was read");
        }
    }
}
