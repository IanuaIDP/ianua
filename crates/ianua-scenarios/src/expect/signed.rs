//! The check someone outside the platform makes of a JWT a tenant signed,
//! with nothing but the keys the tenant publishes: the header pins RS256
//! and the expected type, names a published key, and that key verifies the
//! header and claims as sent.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac as _};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::Sha256;

use crate::upstreams::Received;
use crate::wire::oauth::{Key, Keys};

/// The header of a JWT, as far as the check reads it.
#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
    #[serde(default)]
    typ: Option<String>,
}

/// The claims of `token`, once `published` verifies it as RS256 and typed
/// `typ`.
///
/// # Errors
///
/// Why the token does not check out: not three base64url parts, another
/// algorithm or type, a key not published, or a signature that does not
/// verify.
pub fn verified_rs256(published: &Keys, token: &str, typ: &str) -> Result<Value, String> {
    let mut parts = token.split('.');
    let (Some(head), Some(body), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a compact JWT".to_owned());
    };
    let header: Header = decoded(head)?;
    if header.alg != "RS256" {
        return Err(format!("signed with {} instead of RS256", header.alg));
    }
    if header.typ.as_deref() != Some(typ) {
        return Err(format!("typed {:?}, not {typ}", header.typ));
    }
    let key = published
        .keys
        .iter()
        .find(|key| key.kid == header.kid)
        .ok_or("the header names no published key")?;
    let signature = Signature::try_from(bytes(signature)?.as_slice())
        .map_err(|_| "the signature is no RSA signature")?;
    VerifyingKey::<Sha256>::new(public_key(key)?)
        .verify(format!("{head}.{body}").as_bytes(), &signature)
        .map_err(|_| "the signature does not hold".to_owned())?;
    decoded(body)
}

/// The RSA public key `key` publishes.
fn public_key(key: &Key) -> Result<RsaPublicKey, String> {
    if key.kty != "RSA" {
        return Err(format!("the published key is {}, not RSA", key.kty));
    }
    RsaPublicKey::new(
        BigUint::from_bytes_be(&bytes(&key.n)?),
        BigUint::from_bytes_be(&bytes(&key.e)?),
    )
    .map_err(|_| "the published key is no RSA key".to_owned())
}

/// A base64url part read as JSON.
fn decoded<T: DeserializeOwned>(part: &str) -> Result<T, String> {
    serde_json::from_slice(&bytes(part)?)
        .map_err(|_| "a part is not the JSON it should be".to_owned())
}

/// The bytes of a base64url part.
fn bytes(part: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| "a part is not base64url".to_owned())
}

/// Whether `arrival` carries a Standard Webhooks signature made with
/// `secret`, as a receiver rebuilds it: the secret's key decoded from its
/// `whsec_` form, and an HMAC-SHA256 over the id, the timestamp and the
/// body joined by dots, matched against any `v1,` entry of the signature
/// header. Written from the published layout, not from the platform's
/// signing code.
#[must_use]
pub fn standard_webhook_signed_by(arrival: &Received, secret: &str) -> bool {
    let (Some(id), Some(timestamp), Some(signature)) = (
        arrival.header("webhook-id"),
        arrival.header("webhook-timestamp"),
        arrival.header("webhook-signature"),
    ) else {
        return false;
    };
    let Some(key) = secret
        .strip_prefix("whsec_")
        .or_else(|| secret.strip_prefix("psec_"))
        .or_else(|| secret.strip_prefix("dsec_"))
        .and_then(|encoded| STANDARD.decode(encoded).ok())
    else {
        return false;
    };
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(&key) else {
        return false;
    };
    mac.update(format!("{id}.{timestamp}.{}", arrival.body).as_bytes());
    let expected = format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()));
    signature.split(' ').any(|entry| entry == expected)
}
