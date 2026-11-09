//! The tenant's published assertion keys, served on its own hosts at
//! [`KEY_SET_PATH`], so a service behind the gateway checks
//! `X-Ianua-Assertion` against the host it already answers on.
//!
//! The document is a JWK Set of the public halves the app's use case
//! lists, in the shape the API serves the same set in. It is public: an
//! upstream fetches it without a credential, and it names nothing secret.

use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{Response, StatusCode};
use http_body_util::Full;
use hyper::body::Bytes;
use ianua_domain::domains::crypto::jwk::JwkComponents;
use serde_json::{Value, json};

/// Where a tenant's hosts serve its published assertion keys.
pub const KEY_SET_PATH: &str = "/.well-known/ianua-assertion-keys.json";

/// How long an upstream may keep the set before it asks again: short, as
/// a rotated key must reach every upstream within the day it overlaps.
const KEPT_FOR: &str = "public, max-age=300";

/// The JWK Set of `keys`.
#[must_use]
pub fn key_set(keys: Vec<JwkComponents>) -> Response<Full<Bytes>> {
    let entries: Vec<Value> = keys.into_iter().map(entry).collect();
    let body = json!({ "keys": entries }).to_string();
    let built = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/jwk-set+json")
        .header(CACHE_CONTROL, KEPT_FOR)
        .body(Full::new(Bytes::from(body)));
    built.unwrap_or_else(|_| {
        let mut bare = Response::new(Full::new(Bytes::new()));
        *bare.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        bare
    })
}

/// One key as a JWK, its type and algorithm named by its components.
fn entry(components: JwkComponents) -> Value {
    match components {
        JwkComponents::Rsa { kid, n, e } => {
            json!({ "kty": "RSA", "use": "sig", "kid": kid, "alg": "RS256", "n": n, "e": e })
        }
        JwkComponents::Ec { kid, crv, x, y } => {
            json!({ "kty": "EC", "use": "sig", "kid": kid, "alg": "ES256", "crv": crv, "x": x, "y": y })
        }
        JwkComponents::Okp { kid, crv, x } => {
            json!({ "kty": "OKP", "use": "sig", "kid": kid, "alg": "EdDSA", "crv": crv, "x": x })
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt as _;

    use super::*;

    /// An EC key is published with its curve and coordinates, and nothing
    /// private.
    #[tokio::test]
    async fn an_ec_key_is_published_as_a_jwk() {
        let keys = vec![JwkComponents::Ec {
            kid: "a1".to_owned(),
            crv: "P-256".to_owned(),
            x: "xx".to_owned(),
            y: "yy".to_owned(),
        }];

        let answer = key_set(keys);

        assert_eq!(answer.headers()[CONTENT_TYPE], "application/jwk-set+json");
        let body = answer.into_body().collect().await.unwrap().to_bytes();
        let set: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(set["keys"][0]["kid"], "a1");
        assert_eq!(set["keys"][0]["alg"], "ES256");
        assert!(set["keys"][0].get("d").is_none());
    }
}
