//! SAML message bodies: a message a peer sent through the browser, as the
//! browser brought it and as the dashboard hands it back, and the messages
//! this platform has the browser post to a peer.
//!
//! A peer's sign-in or logout request reaches this platform in a browser
//! that holds its session in the dashboard, not in a cookie here. So the
//! browser is sent on to the dashboard with the message exactly as it
//! arrived, and the dashboard, signed in, hands it back with its session.

use ianua_app::use_cases::federation::idp::SamlResponseOutput;
use ianua_app::use_cases::federation::logout::messages::OutgoingLogoutMessage;
use ianua_domain::types::SamlArrivalId;
use serde::{Deserialize, Serialize};
use url::form_urlencoded::Serializer;
use uuid::Uuid;

/// A SAML message as the browser brought it, by binding.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(tag = "binding", rename_all = "snake_case")]
pub(crate) enum SamlMessageBody {
    /// HTTP-Redirect: the query string exactly as it reached this platform,
    /// which any signature covers.
    Redirect {
        /// The query string, without the `?`.
        query: String,
    },
    /// HTTP-POST: the form's fields.
    Post {
        /// The `SAMLRequest` field, as posted.
        message: String,
        /// The `RelayState` field, if the form carried one.
        #[serde(default)]
        relay_state: Option<String>,
    },
}

impl SamlMessageBody {
    /// The query that carries this message on to a dashboard page, with
    /// `asked_at`, when it reached this platform, in Unix seconds.
    #[must_use]
    pub(crate) fn bounce_query(&self, asked_at: i64) -> String {
        let mut query = self.message_query();
        query.append_pair("asked_at", &asked_at.to_string());
        query.finish()
    }

    /// The query that carries this sign-in request on to the dashboard's
    /// sign-in page, with `request`, the id it is held by on the server.
    /// When it arrived stays on the server.
    #[must_use]
    pub(crate) fn sign_in_bounce_query(&self, request: &SamlArrivalId) -> String {
        let mut query = self.message_query();
        query.append_pair("request", &request.to_string());
        query.finish()
    }

    /// A query naming this message's binding and its fields.
    fn message_query(&self) -> Serializer<'static, String> {
        let mut query = Serializer::new(String::new());
        match self {
            Self::Redirect { query: raw } => {
                query.append_pair("binding", "redirect");
                query.append_pair("query", raw);
            }
            Self::Post {
                message,
                relay_state,
            } => {
                query.append_pair("binding", "post");
                query.append_pair("message", message);
                append_relay_state(&mut query, relay_state.as_deref());
            }
        }
        query
    }
}

/// Adds `relay_state` to `query` when there is one.
fn append_relay_state(query: &mut Serializer<'_, String>, relay_state: Option<&str>) {
    if let Some(relay_state) = relay_state {
        query.append_pair("relay_state", relay_state);
    }
}

/// A SAML message posted by the browser in a form, as the HTTP-POST binding
/// carries it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SamlForm {
    /// A request from the peer.
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    /// An answer from the peer.
    #[serde(rename = "SAMLResponse")]
    pub saml_response: Option<String>,
    /// What the peer wants back with the answer.
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// Query parameters of a sign-in started here, at a link to an app.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct InitiateQuery {
    /// The SAML app to sign in to.
    pub app_id: Uuid,
}

impl InitiateQuery {
    /// The dashboard page that signs the person in to the app.
    #[must_use]
    pub(crate) fn sign_in_page(&self) -> String {
        format!("/saml/apps/{}/sign-in", self.app_id)
    }
}

/// Request body for answering an app's sign-in request: the id the request
/// is held by on the server.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SsoAnswerBody {
    /// The `request` the dashboard page received. The app's message and
    /// when it reached this platform are read from the server: a request
    /// older than ten minutes, or answered already, is refused, and an app
    /// that asked for a fresh sign-in is answered only for a sign-in made
    /// after the request arrived.
    pub request: Uuid,
}

/// The form field a SAML message is posted in.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) enum SamlParameter {
    /// A request to the peer.
    #[serde(rename = "SAMLRequest")]
    Request,
    /// An answer to the peer.
    #[serde(rename = "SAMLResponse")]
    Response,
}

/// A message for the browser to post to a peer, in an auto-submitting
/// form: `<form method="post" action="{destination}">` with a field named
/// `parameter` holding `message`, and `RelayState` when there is one.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SamlFormPost {
    /// The peer's address to post to.
    pub destination: String,
    /// `SAMLRequest` or `SAMLResponse`: the form field the message goes in.
    pub parameter: SamlParameter,
    /// The signed message, base64-encoded.
    pub message: String,
    /// The `RelayState` to post beside it, if the peer sent one.
    pub relay_state: Option<String>,
}

impl SamlFormPost {
    /// The answer to an app's sign-in, carrying back the relay state the
    /// app sent with its request.
    #[must_use]
    pub(crate) fn sign_in(output: SamlResponseOutput) -> Self {
        Self {
            destination: output.acs_url.as_str().to_owned(),
            parameter: SamlParameter::Response,
            message: output.base64_response,
            relay_state: output.relay_state,
        }
    }

    /// The answer to a peer's logout request, carrying back its
    /// `relay_state`.
    #[must_use]
    pub(crate) fn logout_answer(
        message: OutgoingLogoutMessage,
        relay_state: Option<String>,
    ) -> Self {
        Self {
            destination: message.destination.as_str().to_owned(),
            parameter: SamlParameter::Response,
            message: message.base64_message,
            relay_state,
        }
    }

    /// A logout request this platform sends a peer.
    #[must_use]
    pub(crate) fn logout_request(message: OutgoingLogoutMessage) -> Self {
        Self {
            destination: message.destination.as_str().to_owned(),
            parameter: SamlParameter::Request,
            message: message.base64_message,
            relay_state: None,
        }
    }
}

/// The logout requests a person's sign-out sends to the peers their
/// session reached, for the browser to post one by one.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LogoutRequestsResponse {
    /// Each request, to an app the session signed in to, then to the
    /// provider it was opened through.
    pub messages: Vec<SamlFormPost>,
}

impl From<Vec<OutgoingLogoutMessage>> for LogoutRequestsResponse {
    fn from(messages: Vec<OutgoingLogoutMessage>) -> Self {
        Self {
            messages: messages
                .into_iter()
                .map(SamlFormPost::logout_request)
                .collect(),
        }
    }
}
