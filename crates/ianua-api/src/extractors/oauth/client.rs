//! How a client proved itself, as its request shows it: a secret in the
//! `Authorization: Basic` header or in the body, a signed assertion
//! (RFC 7523), or nothing for a public client.
//!
//! A client uses one way only (RFC 6749 2.3): naming itself in the header
//! and the body, or sending a secret beside an assertion, is refused. A
//! TLS client certificate never reaches the API, so `tls_client_auth` is
//! not read here.

use base64::Engine;
use ianua_app::use_cases::oauth::token::client_auth::ClientProof;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::ClientId;
use serde_json::Value;

use crate::error::oauth::OAuthError;
use crate::extractors::oauth::form::{BasicCredentials, OAuthForm};

/// The only client assertion type offered (RFC 7523 2.2).
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How the client of `form` proved itself, its parameters taken out.
///
/// # Errors
///
/// - `invalid_request` when it proves itself two ways, or names an
///   assertion type not offered.
/// - `invalid_client` when it names no client, or names one malformed.
pub(crate) fn client_proof(form: &mut OAuthForm) -> Result<ClientProof, OAuthError> {
    let named = form.take("client_id");
    let secret = form.take("client_secret");
    let assertion = assertion_sent(form)?;
    if let Some(basic) = form.take_basic() {
        return basic_proof(basic, named, &Sent { secret, assertion });
    }
    match (assertion, secret) {
        (Some(_), Some(_)) => Err(two_ways()),
        (Some(assertion), None) => signed_proof(named, assertion),
        (None, Some(secret)) => Ok(ClientProof::PostedSecret {
            client_id: client_id(named)?,
            secret: Secret::new(secret),
        }),
        (None, None) => Ok(ClientProof::Nothing {
            client_id: client_id(named)?,
        }),
    }
}

/// What a body sent beside the client id to prove the client.
struct Sent {
    secret: Option<String>,
    assertion: Option<Secret>,
}

/// The proof of a client that sent its secret in a Basic header and
/// nothing in the body but, at most, the same client id.
fn basic_proof(
    basic: BasicCredentials,
    named: Option<String>,
    sent: &Sent,
) -> Result<ClientProof, OAuthError> {
    if sent.secret.is_some() || sent.assertion.is_some() {
        return Err(two_ways());
    }
    if named.is_some_and(|named| named != basic.client_id) {
        return Err(OAuthError::invalid_request(
            "the client_id in the body is not the one in the Basic header",
        ));
    }
    Ok(ClientProof::BasicSecret {
        client_id: client_id(Some(basic.client_id))?,
        secret: Secret::new(basic.secret),
    })
}

/// The proof of a client that signed an assertion: the client it names in
/// the body, or the assertion's `sub`, read unchecked only to find its
/// keys. The use case checks the signed `sub` is the same one.
fn signed_proof(named: Option<String>, assertion: Secret) -> Result<ClientProof, OAuthError> {
    let named = named.or_else(|| assertion_subject(assertion.expose()));
    Ok(ClientProof::SignedAssertion {
        client_id: client_id(named)?,
        assertion,
    })
}

/// The assertion the body sent, with its type, or none.
fn assertion_sent(form: &mut OAuthForm) -> Result<Option<Secret>, OAuthError> {
    let kind = form.take("client_assertion_type");
    let assertion = form.take("client_assertion");
    match (kind, assertion) {
        (None, None) => Ok(None),
        (Some(kind), Some(assertion)) if kind == JWT_BEARER => Ok(Some(Secret::new(assertion))),
        (Some(_), Some(_)) => Err(OAuthError::invalid_request(
            "the only client_assertion_type offered is jwt-bearer",
        )),
        (Some(_), None) | (None, Some(_)) => Err(OAuthError::invalid_request(
            "client_assertion and client_assertion_type go together",
        )),
    }
}

/// The `sub` of the JWT `assertion`, read without checking it.
fn assertion_subject(assertion: &str) -> Option<String> {
    let payload = assertion.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("sub")?.as_str().map(str::to_owned)
}

/// The client `raw` names.
fn client_id(raw: Option<String>) -> Result<ClientId, OAuthError> {
    let raw = raw.ok_or_else(|| OAuthError::invalid_client("the request names no client"))?;
    ClientId::new(raw).map_err(|_| OAuthError::invalid_client("the client_id is malformed"))
}

/// A client proving itself more than one way.
fn two_ways() -> OAuthError {
    OAuthError::invalid_request("a client proves itself one way only")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `sub` of an unsigned assertion is read to find the client's
    /// keys.
    #[test]
    fn an_assertions_subject_is_read() {
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"client_7"}"#);

        assert_eq!(
            assertion_subject(&format!("e30.{payload}.sig")).as_deref(),
            Some("client_7")
        );
    }

    /// A token that is not a JWT names no subject.
    #[test]
    fn a_token_that_is_no_jwt_names_no_subject() {
        assert_eq!(assertion_subject("opaque"), None);
    }
}
