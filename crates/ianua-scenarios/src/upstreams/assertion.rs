//! The check an app behind the gateway makes of `X-Ianua-Assertion`, as
//! the docs tell a customer to make it: a compact JWT typed
//! `ianua-assertion+jwt`, signed ES256 by a key in the tenant's published
//! assertion key set, its times holding. What it then says is who the
//! gateway vouches the caller is.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::{EncodedPoint, FieldBytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::clock;

/// The type an assertion must carry, so no access token passes for one.
const ASSERTION_TYPE: &str = "ianua-assertion+jwt";

/// The one algorithm assertions are signed with.
const ALGORITHM: &str = "ES256";

/// How far the app's clock may be from the gateway's, in seconds.
const SKEW: i64 = 30;

/// Who the gateway says the caller is, as its assertion names them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertedCaller {
    /// The tenant's issuer.
    pub iss: String,
    /// The service the request was forwarded to.
    pub aud: String,
    /// The person, consumer or agent's principal.
    pub sub: String,
    /// The tenant.
    pub tid: String,
    /// The request's correlation id.
    pub cid: String,
    /// `user`, `agent` or `consumer`.
    pub kind: String,
    /// The agent acting, for an agent.
    #[serde(default)]
    pub act: Option<String>,
    /// Whom the agent acts for, for an agent.
    #[serde(default)]
    pub obo: Option<String>,
    /// The roles the caller holds.
    #[serde(default)]
    pub roles: Vec<String>,
    /// The permissions the caller holds.
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// What an app made of the assertion a request carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum AssertionCheck {
    /// The request carried none.
    Absent,
    /// It checked out, naming this caller. Boxed: the caller carries every
    /// claim, many times the size of a refusal's reason.
    Verified {
        /// Who it names.
        caller: Box<AssertedCaller>,
    },
    /// It did not check out.
    Refused {
        /// Failed verification condition reported without trusting the token's claims.
        why: String,
    },
}

/// The header of a JWT, as far as the check reads it.
#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

/// The times of a JWT.
#[derive(Debug, Deserialize)]
struct Times {
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
}

/// `token` checked against `key_set`, a JWK Set as the tenant publishes
/// it.
pub(crate) fn checked(token: &str, key_set: &Value) -> AssertionCheck {
    match verified(token, key_set) {
        Ok(caller) => AssertionCheck::Verified {
            caller: Box::new(caller),
        },
        Err(why) => AssertionCheck::Refused { why },
    }
}

/// Who `token` names, once its type, key, signature and times hold.
fn verified(token: &str, key_set: &Value) -> Result<AssertedCaller, String> {
    let mut parts = token.split('.');
    let (Some(head), Some(body), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a compact JWT".to_owned());
    };
    let header: Header = decoded(head)?;
    if header.alg != ALGORITHM {
        return Err(format!("signed with {} instead of {ALGORITHM}", header.alg));
    }
    if header.typ.as_deref() != Some(ASSERTION_TYPE) {
        return Err(format!("typed {:?}, not {ASSERTION_TYPE}", header.typ));
    }
    let kid = header.kid.ok_or("names no key")?;
    let key = key_named(key_set, &kid)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "the signature is not base64url".to_owned())?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| "the signature is no P-256 signature")?;
    key.verify(format!("{head}.{body}").as_bytes(), &signature)
        .map_err(|_| "the signature does not hold".to_owned())?;
    let times: Times = decoded(body)?;
    ensure_current(&times)?;
    decoded(body)
}

/// The P-256 key `kid` names in `key_set`.
fn key_named(key_set: &Value, kid: &str) -> Result<VerifyingKey, String> {
    let keys = key_set
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("the key set lists no keys")?;
    let key = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or_else(|| format!("the key set has no key {kid}"))?;
    let coordinate = |name: &str| -> Result<FieldBytes, String> {
        let text = key
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("the key has no {name}"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| format!("the key's {name} is not base64url"))?;
        if bytes.len() != 32 {
            return Err(format!("the key's {name} is not 32 bytes"));
        }
        Ok(*FieldBytes::from_slice(&bytes))
    };
    let point = EncodedPoint::from_affine_coordinates(&coordinate("x")?, &coordinate("y")?, false);
    VerifyingKey::from_encoded_point(&point).map_err(|_| "the key is no P-256 point".to_owned())
}

/// Refuses times that do not hold now, give or take [`SKEW`]. A controlled
/// scenario's app observes the same clock as its gateway, while keeping
/// this independent assertion verifier and its ordinary tolerance.
fn ensure_current(times: &Times) -> Result<(), String> {
    let now = i64::try_from(clock::seconds())
        .map_err(|_| "the clock is outside the timestamp range".to_owned())?;
    if times.exp + SKEW < now {
        return Err("it expired".to_owned());
    }
    if times.nbf.is_some_and(|nbf| nbf - SKEW > now) {
        return Err("it is not valid yet".to_owned());
    }
    Ok(())
}

/// `part`, base64url without padding, read as JSON `T`.
fn decoded<T: serde::de::DeserializeOwned>(part: &str) -> Result<T, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| "a part is not base64url".to_owned())?;
    serde_json::from_slice(&bytes).map_err(|error| format!("a part does not read: {error}"))
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer as _;
    use serde_json::json;

    use super::*;

    /// The instant both the test signer and its independent verifier see.
    fn now() -> i64 {
        i64::try_from(clock::seconds()).expect("a representable timestamp")
    }

    /// The public half of the signer's key, in the published JWK shape.
    fn key_set(key: &SigningKey) -> Value {
        let point = key.verifying_key().to_encoded_point(false);
        json!({ "keys": [{
            "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    /// An assertion carrying the chosen type and expiry, genuinely signed
    /// so refusal tests reach the claim check rather than fail its signature.
    fn signed(key: &SigningKey, typ: &str, exp: i64) -> String {
        let head =
            URL_SAFE_NO_PAD.encode(json!({ "alg": "ES256", "typ": typ, "kid": "k1" }).to_string());
        let body = URL_SAFE_NO_PAD.encode(
            json!({
                "iss": "https://app.s1.test", "aud": "svc", "sub": "pat", "tid": "t",
                "cid": "c", "kind": "user", "roles": ["Member"], "permissions": [],
                "iat": now(), "nbf": now(), "exp": exp,
            })
            .to_string(),
        );
        let signature: Signature = key.sign(format!("{head}.{body}").as_bytes());
        format!(
            "{head}.{body}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    /// A fresh signing key so assertion fixtures never share a private half.
    fn key() -> SigningKey {
        SigningKey::random(&mut rand::thread_rng())
    }

    /// An assertion signed by a published key names its caller.
    #[test]
    fn a_signed_assertion_names_its_caller() {
        let key = key();

        let check = checked(&signed(&key, ASSERTION_TYPE, now() + 60), &key_set(&key));

        let AssertionCheck::Verified { caller } = check else {
            panic!("expected the assertion to check out: {check:?}");
        };
        assert_eq!(caller.sub, "pat");
        assert_eq!(caller.kind, "user");
    }

    /// A correctly signed access token is refused as an assertion because
    /// its token type differs.
    #[test]
    fn a_token_of_another_type_is_refused() {
        let key = key();

        let check = checked(&signed(&key, "at+jwt", now() + 60), &key_set(&key));

        assert!(matches!(check, AssertionCheck::Refused { .. }));
    }

    /// An assertion signed with a key outside the published set is refused.
    #[test]
    fn a_signature_of_another_key_is_refused() {
        let check = checked(
            &signed(&key(), ASSERTION_TYPE, now() + 60),
            &key_set(&key()),
        );

        assert!(matches!(check, AssertionCheck::Refused { .. }));
    }

    /// A valid signature cannot rescue an assertion beyond its expiry and clock skew.
    #[test]
    fn an_expired_assertion_is_refused() {
        let key = key();

        let check = checked(&signed(&key, ASSERTION_TYPE, now() - 120), &key_set(&key));

        assert!(matches!(check, AssertionCheck::Refused { .. }));
    }

    /// Advancing a scenario clock does not bypass the app's expiry check:
    /// its signed assertion works first and fails after its time and skew.
    #[tokio::test]
    async fn an_assertion_expires_on_the_controlled_clock_too() {
        let clock = clock::Clock::controlled();
        let key = key();
        let token = signed(&key, ASSERTION_TYPE, now() + 2);
        let keys = key_set(&key);
        assert!(matches!(
            checked(&token, &keys),
            AssertionCheck::Verified { .. }
        ));
        clock.advance(std::time::Duration::from_secs(33));
        assert_eq!(
            checked(&token, &keys),
            AssertionCheck::Refused {
                why: "it expired".to_owned()
            }
        );
    }
}
