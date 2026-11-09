//! JSON Web Keys (RFC 7517): a public key written as the fields of its
//! type, read back from them, and its SHA-256 thumbprint (RFC 7638).
//!
//! Only the three kinds the platform signs with are read: RSA, EC on
//! P-256, and Ed25519 as an OKP. A key of any other kind or curve, or one
//! with a private part, is refused rather than guessed at.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_domain::domains::crypto::jwk::JwkComponents;
use p256::elliptic_curve::sec1::FromEncodedPoint as _;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::crypto::certificates::rsa_keys::{RsaKeyError, RsaVerifyingKey};
use crate::crypto::jws::keys::{EcPoint, KeyError, PublicKey};

/// Why a JWK could not be read. None of it names the key.
#[derive(Debug, thiserror::Error)]
pub(crate) enum JwkError {
    /// The JWK is not one of the kinds the platform reads.
    #[error("the JWK is not an RSA, P-256 or Ed25519 public key")]
    Unsupported,
    /// The JWK carries a private part.
    #[error("the JWK carries a private key")]
    Private,
    /// The JWK's fields do not make a key.
    #[error("the JWK's fields do not make a key")]
    Malformed,
    /// The key is not one the platform accepts.
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// The members a JWK is read from.
#[derive(Debug, Deserialize)]
struct Members {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    d: Option<String>,
}

/// One public key read from a JWK, with the `kid` it was listed under.
#[derive(Debug, Clone)]
pub(crate) struct Jwk {
    pub(crate) kid: Option<String>,
    pub(crate) key: PublicKey,
}

fn bytes(field: Option<&str>) -> Result<Vec<u8>, JwkError> {
    let field = field.ok_or(JwkError::Malformed)?;
    URL_SAFE_NO_PAD
        .decode(field)
        .map_err(|_| JwkError::Malformed)
}

/// The public key the JWK `value` writes.
pub(crate) fn read_jwk(value: &Value) -> Result<Jwk, JwkError> {
    let members = Members::deserialize(value).map_err(|_| JwkError::Malformed)?;
    if members.d.is_some() {
        return Err(JwkError::Private);
    }
    let key = match (members.kty.as_str(), members.crv.as_deref()) {
        ("RSA", None) => rsa_key(&members)?,
        ("EC", Some("P-256")) => p256_key(&members)?,
        ("EC", Some("P-384")) => PublicKey::P384(ec_point(&members, P384_BYTES)?),
        ("EC", Some("P-521")) => PublicKey::P521(ec_point(&members, P521_BYTES)?),
        ("OKP", Some("Ed25519")) => ed25519_key(&members)?,
        _ => return Err(JwkError::Unsupported),
    };
    Ok(Jwk {
        kid: members.kid,
        key,
    })
}

fn rsa_key(members: &Members) -> Result<PublicKey, JwkError> {
    let n = bytes(members.n.as_deref())?;
    let e = bytes(members.e.as_deref())?;
    RsaVerifyingKey::from_components(&n, &e)
        .map(PublicKey::Rsa)
        .map_err(|refused| match refused {
            RsaKeyError::TooShort => JwkError::Key(KeyError::TooShort),
            RsaKeyError::Unreadable | RsaKeyError::CouldNotUse => JwkError::Malformed,
        })
}

fn p256_key(members: &Members) -> Result<PublicKey, JwkError> {
    let x = bytes(members.x.as_deref())?;
    let y = bytes(members.y.as_deref())?;
    let (Ok(x), Ok(y)) = (<[u8; 32]>::try_from(x), <[u8; 32]>::try_from(y)) else {
        return Err(JwkError::Malformed);
    };
    let point = p256::EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
    Option::<p256::PublicKey>::from(p256::PublicKey::from_encoded_point(&point))
        .map(|key| PublicKey::P256(key.into()))
        .ok_or(JwkError::Malformed)
}

/// How long a P-384 coordinate is, as RFC 7518 section 6.2.1.2 writes it.
const P384_BYTES: usize = 48;

/// How long a P-521 coordinate is, as RFC 7518 section 6.2.1.2 writes it.
const P521_BYTES: usize = 66;

/// The point the `x` and `y` of `members` name, each `size` bytes long.
fn ec_point(members: &Members, size: usize) -> Result<EcPoint, JwkError> {
    let x = bytes(members.x.as_deref())?;
    let y = bytes(members.y.as_deref())?;
    EcPoint::of(&x, &y, size).ok_or(JwkError::Malformed)
}

fn ed25519_key(members: &Members) -> Result<PublicKey, JwkError> {
    let x = <[u8; 32]>::try_from(bytes(members.x.as_deref())?).map_err(|_| JwkError::Malformed)?;
    ed25519_dalek::VerifyingKey::from_bytes(&x)
        .map(PublicKey::Ed25519)
        .map_err(|_| JwkError::Malformed)
}

/// The fields of `key` as a JWK listed under `kid`.
pub(crate) fn components(key: &PublicKey, kid: &str) -> JwkComponents {
    let kid = kid.to_owned();
    match key {
        PublicKey::Rsa(key) => JwkComponents::Rsa {
            kid,
            n: URL_SAFE_NO_PAD.encode(key.modulus()),
            e: URL_SAFE_NO_PAD.encode(key.exponent()),
        },
        PublicKey::P256(key) => {
            let point = key.to_encoded_point(false);
            let coordinate = |part: Option<&p256::FieldBytes>| {
                URL_SAFE_NO_PAD.encode(part.map(p256::FieldBytes::as_slice).unwrap_or_default())
            };
            JwkComponents::Ec {
                kid,
                crv: "P-256".to_owned(),
                x: coordinate(point.x()),
                y: coordinate(point.y()),
            }
        }
        PublicKey::P384(point) => ec_components(kid, "P-384", point),
        PublicKey::P521(point) => ec_components(kid, "P-521", point),
        PublicKey::Ed25519(key) => JwkComponents::Okp {
            kid,
            crv: "Ed25519".to_owned(),
            x: URL_SAFE_NO_PAD.encode(key.as_bytes()),
        },
    }
}

/// The JWK fields of `point` on the curve `crv`, listed under `kid`.
fn ec_components(kid: String, crv: &str, point: &EcPoint) -> JwkComponents {
    let (x, y) = point.coordinates();
    JwkComponents::Ec {
        kid,
        crv: crv.to_owned(),
        x: URL_SAFE_NO_PAD.encode(x),
        y: URL_SAFE_NO_PAD.encode(y),
    }
}

/// The RFC 7638 thumbprint of `key`: the SHA-256 of its required members,
/// in their order, with no spaces, written as base64url.
pub(crate) fn thumbprint(key: &PublicKey) -> String {
    let canonical = match components(key, "") {
        JwkComponents::Rsa { n, e, .. } => format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#),
        JwkComponents::Ec { crv, x, y, .. } => {
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        JwkComponents::Okp { crv, x, .. } => format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#),
    };
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use serde_json::json;

    use super::*;
    use crate::crypto::jws::keys::tests::pair;

    fn public(algorithm: SigningAlgorithm) -> PublicKey {
        PublicKey::from_pem(algorithm, &pair(algorithm).1).unwrap()
    }

    fn as_value(components: &JwkComponents) -> Value {
        match components {
            JwkComponents::Rsa { kid, n, e } => json!({"kty": "RSA", "kid": kid, "n": n, "e": e}),
            JwkComponents::Ec { kid, crv, x, y } => {
                json!({"kty": "EC", "kid": kid, "crv": crv, "x": x, "y": y})
            }
            JwkComponents::Okp { kid, crv, x } => {
                json!({"kty": "OKP", "kid": kid, "crv": crv, "x": x})
            }
        }
    }

    /// Each kind of key written as a JWK reads back as the same key, under
    /// the same `kid`.
    #[test]
    fn a_key_written_as_a_jwk_reads_back() {
        for algorithm in [
            SigningAlgorithm::Rs256,
            SigningAlgorithm::Es256,
            SigningAlgorithm::EdDsa,
        ] {
            let key = public(algorithm);

            let read = read_jwk(&as_value(&components(&key, "k1"))).unwrap();

            assert_eq!(read.kid.as_deref(), Some("k1"));
            assert_eq!(thumbprint(&read.key), thumbprint(&key), "{algorithm:?}");
        }
    }

    /// The thumbprint of RFC 7638's example key is the one the RFC gives.
    #[test]
    fn the_rfc_example_key_has_its_thumbprint() {
        let example = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        });

        let key = read_jwk(&example).unwrap().key;

        assert_eq!(
            thumbprint(&key),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// Private key material, unsupported curves and short coordinates each produce
    /// the corresponding public-JWK parsing error.
    #[test]
    fn a_private_or_foreign_jwk_is_refused() {
        let private = json!({"kty": "OKP", "crv": "Ed25519", "x": "AA", "d": "AA"});
        let foreign = json!({"kty": "EC", "crv": "secp256k1", "x": "AA", "y": "AA"});
        let short = json!({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"});

        assert!(matches!(read_jwk(&private), Err(JwkError::Private)));
        assert!(matches!(read_jwk(&foreign), Err(JwkError::Unsupported)));
        assert!(matches!(read_jwk(&short), Err(JwkError::Malformed)));
    }
}
