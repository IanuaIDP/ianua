//! DPoP proofs (RFC 9449): a JWT the agent signs with the key its token is
//! bound to, made for one request and used once.

use serde_json::{Value, json};
use url::Url;

use crate::agent::keys::{ALGORITHM, AgentKey, sha256_url};

/// The type every proof's header names.
const PROOF_TYPE: &str = "dpop+jwt";

/// The request a proof is made for: its method and its address.
#[derive(Debug, Clone, Copy)]
pub struct ProvenRequest<'a> {
    /// The method, such as `GET`.
    pub method: &'a str,
    /// The whole address it is sent to.
    pub url: &'a str,
}

/// A proof by `key` for `request`, at `issued_at` seconds since the epoch,
/// naming `access_token`'s hash in `ath` when the request carries one.
///
/// The header carries the public key as a JWK and names the proof's type
/// and its algorithm; the claims are a fresh `jti`, `htm`, `htu` without
/// its query and fragment, and `iat`.
#[must_use]
pub fn proof(
    key: &AgentKey,
    request: ProvenRequest<'_>,
    access_token: Option<&str>,
    issued_at: i64,
) -> String {
    let header = json!({"typ": PROOF_TYPE, "alg": ALGORITHM, "jwk": key.jwk()});
    let mut claims = json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": request.method,
        "htu": target_uri(request.url),
        "iat": issued_at
    });
    if let Some(token) = access_token {
        claims["ath"] = Value::String(sha256_url(token));
    }
    key.signed_jws(&header, &claims)
}

/// `url` as `htu` names it: without its query and fragment.
fn target_uri(url: &str) -> String {
    let Ok(mut parsed) = Url::parse(url) else {
        return url.to_owned();
    };
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;
    use crate::agent::keys::claims_of;

    fn header_of(jws: &str) -> Value {
        let header = jws.split('.').next().unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap()
    }

    /// A proof names its type, algorithm and key, and the request without
    /// its query, with the token's hash.
    #[test]
    fn a_proof_names_the_request_and_the_tokens_hash() {
        let key = AgentKey::generate();
        let request = ProvenRequest {
            method: "POST",
            url: "https://tools.s1.test/mcp?session=1#part",
        };

        let made = proof(&key, request, Some("the token"), 1_700_000_000);

        let header = header_of(&made);
        let claims = claims_of(&made).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["x"], key.jwk().x);
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://tools.s1.test/mcp");
        assert_eq!(claims["ath"], sha256_url("the token"));
        assert_eq!(claims["iat"], 1_700_000_000);
    }

    /// Two proofs for the same request differ by their `jti`, so neither
    /// passes for the other.
    #[test]
    fn two_proofs_for_one_request_differ() {
        let key = AgentKey::generate();
        let request = ProvenRequest {
            method: "GET",
            url: "https://tools.s1.test/mcp",
        };

        let first = claims_of(&proof(&key, request, None, 1)).unwrap();
        let second = claims_of(&proof(&key, request, None, 1)).unwrap();

        assert_ne!(first["jti"], second["jti"]);
        assert!(first.get("ath").is_none());
    }
}
