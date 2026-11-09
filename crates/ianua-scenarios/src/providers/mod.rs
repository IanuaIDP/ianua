//! Identity providers independent of the platform, each with its own key,
//! for the scenarios where people sign in through one:
//!
//! - [`oidc`]: an OIDC provider over real HTTPS, with discovery, a key
//!   set and a single-use code exchange.
//! - [`saml`]: a SAML provider signing assertions with its own key.
//! - [`metadata_host`]: where a SAML provider publishes its metadata.

pub mod metadata_host;
pub mod oidc;
pub mod saml;

/// Reads a required redirect parameter without printing any redirect secrets.
///
/// # Panics
///
/// When the redirect is not a URL or does not carry the named parameter.
/// Redirect parsing asserts the platform produced the URL required by the scenario.
#[allow(clippy::expect_used)]
#[must_use]
pub fn parameter(redirect: &str, name: &str) -> String {
    url::Url::parse(redirect)
        .expect("a provider redirect")
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("the redirect must carry {name}"))
}
