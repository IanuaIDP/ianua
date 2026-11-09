//! The credential's header, as each kind of account sends it: a bearer
//! token, a token after a scheme of the service's own, a user and token as
//! `Basic`, or a Trello key and token in one `OAuth` header. Every header
//! is marked sensitive, so it is never logged, and a blank credential is
//! refused before anything is sent.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::security::secret::Secret;
use reqwest::header::HeaderValue;
use serde::Deserialize;

use crate::answer::failed;
use crate::rest::access::Reached;
use crate::{Renewed, ServiceEndpoint};

/// `token` as a `Bearer` header, refused when blank.
pub(super) fn bearer(token: &str) -> Result<Option<HeaderValue>, ActionOutcome> {
    let token = token.trim();
    if token.is_empty() {
        return Err(failed("the account holds no token"));
    }
    sensitive(&format!("Bearer {token}"))
}

/// `token` after `scheme`, refused when blank.
pub(super) fn after_scheme(
    scheme: &str,
    token: &str,
) -> Result<Option<HeaderValue>, ActionOutcome> {
    let token = token.trim();
    if token.is_empty() {
        return Err(failed("the account holds no token"));
    }
    sensitive(&format!("{scheme}{token}"))
}

/// The reach of a Trello account: its key and token in one `OAuth` header,
/// refused unless both are there and plain.
pub(super) fn key_and_token(
    endpoint: &ServiceEndpoint,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    let Ok(held) = serde_json::from_str::<KeyedToken>(credential.expose()) else {
        return Err(failed("the account holds no key and token"));
    };
    let (key, token) = (held.key.trim(), held.token.trim());
    let plain = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric());
    if !plain(key) || !plain(token) {
        return Err(failed(
            "the account's key and token must be letters and digits",
        ));
    }
    Ok(Reached {
        endpoint: endpoint.clone(),
        authorization: sensitive(&format!(
            "OAuth oauth_consumer_key=\"{key}\", oauth_token=\"{token}\""
        ))?,
        place: None,
        acting_for: None,
        renewed: Renewed::Unchanged,
    })
}

/// What a Trello account holds.
#[derive(Deserialize)]
struct KeyedToken {
    key: String,
    token: String,
}

/// `user` and `token` as a `Basic` header, refused when the token is blank.
pub(super) fn basic(user: &str, token: &str) -> Result<Option<HeaderValue>, ActionOutcome> {
    if token.trim().is_empty() {
        return Err(failed("the account holds no token"));
    }
    let encoded = STANDARD.encode(format!("{}:{}", user.trim(), token.trim()));
    sensitive(&format!("Basic {encoded}"))
}

/// `value` as a header marked sensitive, which the call is signed with.
fn sensitive(value: &str) -> Result<Option<HeaderValue>, ActionOutcome> {
    let Ok(mut header) = HeaderValue::from_str(value) else {
        return Err(failed("the account's token cannot be sent"));
    };
    header.set_sensitive(true);
    Ok(Some(header))
}
