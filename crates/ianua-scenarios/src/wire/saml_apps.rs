//! A tenant as the identity provider of outside SAML apps: registering an
//! app, and the answer to its sign-in request the dashboard hands the
//! browser to post.

use serde::{Deserialize, Serialize};

/// `POST …/saml/apps`: an outside app the tenant signs people in to.
#[derive(Debug, Clone, Serialize)]
pub struct NewSamlApp {
    /// The app's name, as people see it.
    pub name: String,
    /// The app's SAML entity id.
    pub entity_id: String,
    /// Where its answers may be posted, the default first.
    pub acs_urls: Vec<String>,
    /// Where logout requests and answers to it go; single logout with it
    /// is off without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logout_url: Option<String>,
    /// The certificate its sign-in requests must be signed with, PEM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_signing_certificate: Option<String>,
}

/// The app just registered.
#[derive(Debug, Clone, Deserialize)]
pub struct SamlAppMade {
    /// Handle used to manage the tenant's new service-provider registration.
    pub id: String,
}

/// `POST …/saml/sso/answer`: the dashboard answers the app's request the
/// platform holds under `request`, for the person signed in.
#[derive(Debug, Clone, Serialize)]
pub struct AnswerSignIn {
    /// The id the request is held by, from the address the platform sent
    /// the browser on to.
    pub request: String,
}

/// `POST …/saml/slo/answer`: the dashboard hands back an app's logout
/// request as the browser posted it, with the person's session when the
/// browser holds one.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "binding", rename = "post")]
pub struct AnswerLogout {
    /// The `SAMLRequest` field, as posted.
    pub message: String,
    /// The `RelayState` field, if the form carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_state: Option<String>,
}

/// `POST …/saml/slo/start`: the logout requests owed to every app the
/// session signed in to, for the browser to post one by one.
#[derive(Clone, Deserialize)]
pub struct LogoutRequests {
    /// Each request and where it goes.
    pub messages: Vec<FormPost>,
}

/// A signed SAML message and where the browser posts it. Holds a signed
/// assertion, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct FormPost {
    /// The address to post to.
    pub destination: String,
    /// The form field the message goes in: `SAMLRequest` or
    /// `SAMLResponse`.
    pub parameter: String,
    /// The message, base64-encoded.
    pub message: String,
    /// The `RelayState` to post beside it, if the app sent one.
    pub relay_state: Option<String>,
}
