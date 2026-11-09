//! The body a client sends an OAuth endpoint, and the issuer it is sent to.
//!
//! The standard body is a form (`application/x-www-form-urlencoded`). JSON
//! is read too, for callers that already send it. A parameter sent twice is
//! refused and one sent empty counts as not sent, as RFC 6749 3.1 asks; the
//! client may also name itself in an `Authorization: Basic` header.

use std::collections::BTreeMap;

use axum::extract::{FromRequest, Request};
use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use base64::Engine;
use ianua_app::error::AppError;
use ianua_domain::types::{Issuer, TenantSlug};
use serde_json::Value;

use crate::error::oauth::OAuthError;
use crate::extractors::callers::PathSlugs;
use crate::state::ApiState;

/// The largest body an OAuth endpoint reads.
const MOST_BODY_BYTES: usize = 64 * 1024;

/// A client's id and secret from an `Authorization: Basic` header.
pub(crate) struct BasicCredentials {
    /// The client id, form-decoded.
    pub client_id: String,
    /// The secret, form-decoded.
    pub secret: String,
}

/// An OAuth request's parameters, the client's Basic credentials if it sent
/// them, and the issuer of the tenant the path names.
pub(crate) struct OAuthForm {
    fields: BTreeMap<String, String>,
    basic: Option<BasicCredentials>,
    issuer: Issuer,
}

impl OAuthForm {
    /// The parameter `name`, taken out so nothing reads it twice.
    pub(crate) fn take(&mut self, name: &str) -> Option<String> {
        self.fields.remove(name)
    }

    /// The parameter `name`, which the request must carry.
    ///
    /// # Errors
    ///
    /// - `invalid_request` when it is missing.
    pub(crate) fn required(&mut self, name: &str) -> Result<String, OAuthError> {
        self.take(name)
            .ok_or_else(|| OAuthError::invalid_request(format!("{name} is required")))
    }

    /// The Basic credentials, taken out so nothing reads them twice.
    pub(crate) fn take_basic(&mut self) -> Option<BasicCredentials> {
        self.basic.take()
    }

    /// The issuer of the tenant the request is addressed to.
    #[must_use]
    pub(crate) fn issuer(&self) -> Issuer {
        self.issuer.clone()
    }
}

impl FromRequest<ApiState> for OAuthForm {
    type Rejection = OAuthError;

    async fn from_request(req: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let issuer = path_issuer(&mut parts, state).await?;
        let basic = basic_credentials(&parts.headers)?;
        let bytes = axum::body::to_bytes(body, MOST_BODY_BYTES)
            .await
            .map_err(|_| OAuthError::invalid_request("the body is unreadable or too large"))?;
        let fields = fields(&parts.headers, &bytes)?;
        Ok(Self {
            fields,
            basic,
            issuer,
        })
    }
}

/// The issuer of the tenant `parts`' path names, under the deployment's
/// address.
///
/// # Errors
///
/// - `AppError::NotFound` when the path names no tenant.
pub(crate) async fn path_issuer(
    parts: &mut axum::http::request::Parts,
    state: &ApiState,
) -> Result<Issuer, AppError> {
    let slugs = PathSlugs::of(parts, state).await.map_err(|e| e.0)?;
    let org: &TenantSlug = slugs.organization().map_err(|e| e.0)?;
    let tenant: &TenantSlug = slugs.tenant().map_err(|e| e.0)?;
    Ok(Issuer::of_tenant(&state.oauth.app_base_url, org, tenant))
}

/// The parameters in `bytes`, read as a form or as JSON by the content
/// type `headers` name.
fn fields(headers: &HeaderMap, bytes: &[u8]) -> Result<BTreeMap<String, String>, OAuthError> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if content_type.starts_with("application/x-www-form-urlencoded") {
        return form_fields(bytes);
    }
    if content_type.starts_with("application/json") {
        return json_fields(bytes);
    }
    Err(OAuthError::invalid_request(
        "send the request as application/x-www-form-urlencoded",
    ))
}

/// The parameters of a form, refusing one sent twice and leaving out one
/// sent empty.
fn form_fields(bytes: &[u8]) -> Result<BTreeMap<String, String>, OAuthError> {
    let mut fields = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(bytes) {
        if fields.contains_key(name.as_ref()) {
            return Err(OAuthError::invalid_request(format!("{name} is sent twice")));
        }
        fields.insert(name.into_owned(), value.into_owned());
    }
    fields.retain(|_, value| !value.is_empty());
    Ok(fields)
}

/// The parameters of a JSON object: strings as they are, numbers and
/// booleans written out, a list of strings joined by spaces as a scope is.
fn json_fields(bytes: &[u8]) -> Result<BTreeMap<String, String>, OAuthError> {
    let object: serde_json::Map<String, Value> = serde_json::from_slice(bytes)
        .map_err(|_| OAuthError::invalid_request("the body is not a JSON object"))?;
    Ok(object
        .into_iter()
        .filter_map(|(name, value)| json_text(value).map(|text| (name, text)))
        .filter(|(_, text)| !text.is_empty())
        .collect())
}

/// `value` as a parameter's text, or `None` for a null or an object.
fn json_text(value: Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Array(items) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        Value::Null | Value::Object(_) => None,
    }
}

/// The client id and secret in an `Authorization: Basic` header, each
/// form-decoded as RFC 6749 2.3.1 asks.
///
/// # Errors
///
/// - `invalid_client` when the header is not well formed.
pub(crate) fn basic_credentials(
    headers: &HeaderMap,
) -> Result<Option<BasicCredentials>, OAuthError> {
    let Some(encoded) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
    else {
        return Ok(None);
    };
    let invalid = || OAuthError::invalid_client("the Basic credentials are not well formed");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| invalid())?;
    let pair = String::from_utf8(decoded).map_err(|_| invalid())?;
    let (id, secret) = pair.split_once(':').ok_or_else(invalid)?;
    Ok(Some(BasicCredentials {
        client_id: form_decoded(id),
        secret: form_decoded(secret),
    }))
}

/// `value` with its form encoding undone, so `%2B` reads as `+`.
fn form_decoded(value: &str) -> String {
    url::form_urlencoded::parse(format!("v={value}").as_bytes())
        .next()
        .map(|(_, decoded)| decoded.into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// The `Authorization: Basic` value for `id` and `secret`.
    fn basic(id: &str, secret: &str) -> HeaderMap {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        headers
    }

    /// A form-encoded secret in a Basic header is read back as the client
    /// meant it.
    #[test]
    fn a_basic_secret_is_form_decoded() {
        let Ok(Some(credentials)) = basic_credentials(&basic("client_1", "s%2Bcret")) else {
            panic!("the credentials are read");
        };

        assert_eq!(credentials.client_id, "client_1");
        assert_eq!(credentials.secret, "s+cret");
    }

    /// Duplicate authorization codes make the form invalid.
    #[test]
    fn a_parameter_sent_twice_is_refused() {
        assert!(form_fields(b"code=a&code=b").is_err());
    }

    /// A parameter sent empty counts as not sent.
    #[test]
    fn an_empty_parameter_counts_as_not_sent() {
        let Ok(fields) = form_fields(b"scope=&code=a") else {
            panic!("the form is read");
        };

        assert!(!fields.contains_key("scope"));
        assert_eq!(fields["code"], "a");
    }

    /// A JSON list of scopes reads as the space-separated scope a form
    /// sends.
    #[test]
    fn a_json_list_reads_as_a_spaced_scope() {
        let Ok(fields) = json_fields(br#"{"scope": ["openid", "email"], "n": 3}"#) else {
            panic!("the object is read");
        };

        assert_eq!(fields["scope"], "openid email");
        assert_eq!(fields["n"], "3");
    }
}
