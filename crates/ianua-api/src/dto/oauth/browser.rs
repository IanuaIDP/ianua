//! What a browser in an OAuth flow is sent on with, and the bodies of the
//! dashboard's steps in it: the authorization request carried to the
//! dashboard's sign-in and consent page, the answer sent back to the
//! client, the consent step's body and answer, a pushed request's
//! `request_uri`, and signing out through an app.

use ianua_app::use_cases::oauth::flows::{
    AuthorizeOutcome, AuthorizeRequest, Consent, ConsentAnswer, EndSessionOutcome,
    EndSessionRequest, LogoutConfirmation, PushedRequestResult, Reply, ScreenedRequest,
};
use ianua_domain::domains::oauth::grants::authorization_request::{AuthorizeRefusal, ResponseMode};
use ianua_domain::domains::oauth::grants::logout::AfterLogout;
use ianua_domain::domains::oauth::grants::pushed_request::StateSent;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{HttpsUrl, Issuer, Scope};
use serde::{Deserialize, Serialize};
use url::form_urlencoded::Serializer;

use crate::error::ApiError;
use crate::extractors::oauth::authorization::AuthorizationParams;
use crate::extractors::oauth::logout::LogoutParams;
use crate::extractors::public_tenant::PublicTenant;
use crate::response::oauth::BrowserReply;

/// The dashboard page at `page` for the tenant `tenant` names, under
/// `base`, carrying `sent` on.
fn dashboard_page<'a>(
    base: &HttpsUrl,
    tenant: &PublicTenant,
    page: &str,
    sent: impl Iterator<Item = (&'static str, &'a str)>,
) -> String {
    let mut query = Serializer::new(String::new());
    for (name, value) in sent {
        query.append_pair(name, value);
    }
    format!(
        "{}/organizations/{}/tenants/{}/oauth/{page}?{}",
        base.as_str().trim_end_matches('/'),
        tenant.org_slug.as_str(),
        tenant.tenant_slug.as_str(),
        query.finish()
    )
}

/// Where the browser goes once its authorization request is screened: on
/// to the dashboard's sign-in and consent page, carrying the request, or
/// back to the client with what is wrong.
///
/// # Errors
///
/// `422` when the client is unknown, or the redirect is not one it
/// registered: with no redirect to trust, only the browser is told.
pub(crate) fn screened_reply(
    answer: ScreenedRequest,
    params: &AuthorizationParams,
    tenant: &PublicTenant,
    base: &HttpsUrl,
) -> Result<BrowserReply, ApiError> {
    match answer {
        ScreenedRequest::Proceed(_) => Ok(BrowserReply::Redirect(dashboard_page(
            base,
            tenant,
            "authorize",
            params.sent(),
        ))),
        ScreenedRequest::TellClient { refusal, reply } => {
            let error = vec![("error", error_code(refusal).to_owned())];
            Ok(client_reply(&reply, error, &tenant.issuer(base)))
        }
        ScreenedRequest::TellBrowser => Err(ApiError::validation(message!(
            "api-unknown-client-or-a-redirect-it",
            "unknown client, or a redirect it did not register"
        ))),
    }
}

/// The dashboard's sign-out page for the tenant `tenant` names, carrying
/// the app's request on.
#[must_use]
pub(crate) fn logout_page(params: &LogoutParams, tenant: &PublicTenant, base: &HttpsUrl) -> String {
    dashboard_page(base, tenant, "logout", params.sent())
}

/// The answer `fields` sent back to the client `reply` names, with its
/// `state` and the `issuer` that answers (RFC 9207), the way the request
/// asked.
fn client_reply(
    reply: &Reply,
    mut fields: Vec<(&'static str, String)>,
    issuer: &Issuer,
) -> BrowserReply {
    if let StateSent::Sent(state) = &reply.state {
        fields.push(("state", state.as_str().to_owned()));
    }
    fields.push(("iss", issuer.as_str().to_owned()));
    let action = reply.redirect_uri.as_str().to_owned();
    match reply.response_mode {
        ResponseMode::FormPost => BrowserReply::FormPost { action, fields },
        ResponseMode::Query | ResponseMode::Unsupported => {
            BrowserReply::Redirect(with_query(&action, &fields))
        }
    }
}

/// `address` with `fields` added to its query.
fn with_query(address: &str, fields: &[(&'static str, String)]) -> String {
    let mut query = Serializer::new(String::new());
    for (name, value) in fields {
        query.append_pair(name, value);
    }
    let joiner = if address.contains('?') { '&' } else { '?' };
    format!("{address}{joiner}{}", query.finish())
}

/// The OAuth error code `refusal` is told to the client as.
fn error_code(refusal: AuthorizeRefusal) -> &'static str {
    match refusal {
        AuthorizeRefusal::InvalidRequest => "invalid_request",
        AuthorizeRefusal::UnauthorizedClient => "unauthorized_client",
        AuthorizeRefusal::UnsupportedResponseType => "unsupported_response_type",
        AuthorizeRefusal::InvalidScope => "invalid_scope",
        AuthorizeRefusal::LoginRequired => "login_required",
        AuthorizeRefusal::ConsentRequired => "consent_required",
    }
}

/// Whether the person answered the consent page.
#[derive(Clone, Copy, Default, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentAnswerBody {
    /// They agreed to what the request asks.
    #[default]
    Given,
    /// They were not asked yet: the page asks what to show first.
    NotAskedYet,
}

/// Request body for the dashboard's consent step: the authorization
/// request as the browser brought it, and the person's answer.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AuthorizeBody {
    /// The request's parameters, as the browser brought them.
    #[serde(flatten)]
    pub request: AuthorizationParams,
    /// The scopes asked for, as a list; read when `scope` is not sent.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Whether the person agreed. Left out, they did.
    #[serde(default)]
    pub consent: ConsentAnswerBody,
}

impl AuthorizeBody {
    /// The consent step this body asks of the tenant `issuer` names. A
    /// body from before the full request was carried, with no
    /// `response_type`, no challenge method and a list of scopes, reads as
    /// the code flow with `S256`, as it meant.
    ///
    /// # Errors
    ///
    /// `422` when the client or the redirect is missing or malformed, or
    /// the `request_uri` was not issued here.
    pub(crate) fn request(self, issuer: Issuer) -> Result<AuthorizeRequest, ApiError> {
        let mut params = self.request;
        params
            .response_type
            .get_or_insert_with(|| "code".to_owned());
        params
            .code_challenge_method
            .get_or_insert_with(|| "S256".to_owned());
        if params.scope.is_none() && !self.scopes.is_empty() {
            params.scope = Some(self.scopes.join(" "));
        }
        let ask = params.ask()?;
        Ok(AuthorizeRequest {
            client_id: ask.client_id,
            parameters: ask.parameters,
            answer: match self.consent {
                ConsentAnswerBody::Given => ConsentAnswer::Given,
                ConsentAnswerBody::NotAskedYet => ConsentAnswer::NotAskedYet,
            },
            id_token_hint: params.hint(),
            issuer,
        })
    }
}

/// What the consent step comes to.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthorizeStep {
    /// A code was issued; send the browser on with it.
    Issued,
    /// The person must sign in, again or as someone else, first.
    SignIn,
    /// The person must be asked to consent to `scopes`.
    Consent,
    /// The request is refused; send the browser on with the error.
    Refused,
}

/// The client's answer, sent as a form the browser posts.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FormPostReply {
    /// The client's redirect URI, the form's action.
    pub action: String,
    /// The form's fields, by name.
    pub fields: std::collections::BTreeMap<String, String>,
}

/// The answer to the consent step.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuthorizeResponse {
    /// What the step came to.
    pub outcome: AuthorizeStep,
    /// The raw code, for the redirect URI, once issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Whether this request gave the client new consent, once issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_granted: Option<bool>,
    /// The scopes to ask the person about, when they must consent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// The error the client is told, when refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    /// Where to send the browser, with the answer in its query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    /// The form the browser posts the answer with, for a client that asked
    /// for `form_post`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_post: Option<FormPostReply>,
}

impl AuthorizeResponse {
    /// The answer to the step that came to `outcome`, the client told by
    /// the tenant `issuer` names.
    #[must_use]
    pub(crate) fn of(outcome: AuthorizeOutcome, issuer: &Issuer) -> Self {
        match outcome {
            AuthorizeOutcome::Issued {
                code,
                consent,
                reply,
            } => {
                let code = code.expose().to_owned();
                Self {
                    code: Some(code.clone()),
                    consent_granted: Some(consent == Consent::NewlyGranted),
                    ..Self::sending(AuthorizeStep::Issued, &reply, vec![("code", code)], issuer)
                }
            }
            AuthorizeOutcome::SignIn => Self::step(AuthorizeStep::SignIn),
            AuthorizeOutcome::AskConsent { scopes } => Self {
                scopes: Some(scopes.iter().map(|s| Scope::as_str(s).to_owned()).collect()),
                ..Self::step(AuthorizeStep::Consent)
            },
            AuthorizeOutcome::Refused { refusal, reply } => {
                let code = error_code(refusal);
                let fields = vec![("error", code.to_owned())];
                Self {
                    error: Some(code),
                    ..Self::sending(AuthorizeStep::Refused, &reply, fields, issuer)
                }
            }
        }
    }

    /// An answer saying only what the step came to.
    fn step(outcome: AuthorizeStep) -> Self {
        Self {
            outcome,
            code: None,
            consent_granted: None,
            scopes: None,
            error: None,
            redirect_to: None,
            form_post: None,
        }
    }

    /// An answer sending `fields` to the client `reply` names.
    fn sending(
        outcome: AuthorizeStep,
        reply: &Reply,
        fields: Vec<(&'static str, String)>,
        issuer: &Issuer,
    ) -> Self {
        match client_reply(reply, fields, issuer) {
            BrowserReply::Redirect(to) => Self {
                redirect_to: Some(to),
                ..Self::step(outcome)
            },
            BrowserReply::FormPost { action, fields } => Self {
                form_post: Some(FormPostReply {
                    action,
                    fields: fields
                        .into_iter()
                        .map(|(name, value)| (name.to_owned(), value))
                        .collect(),
                }),
                ..Self::step(outcome)
            },
        }
    }
}

/// A pushed request, by the `request_uri` the browser is sent on with.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PushedRequestResponse {
    /// The `request_uri` to send the browser to the authorization
    /// endpoint with, beside the `client_id`.
    pub request_uri: String,
    /// How long it may be used, in seconds.
    pub expires_in: i64,
}

impl From<PushedRequestResult> for PushedRequestResponse {
    fn from(result: PushedRequestResult) -> Self {
        Self {
            request_uri: result.request_uri.to_string(),
            expires_in: (result.expires_at - clock::now()).whole_seconds().max(0),
        }
    }
}

/// Request body for the dashboard's sign-out step: the app's request as
/// the browser brought it, and whether the person confirmed.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct EndSessionBody {
    /// The request's parameters, as the browser brought them.
    #[serde(flatten)]
    pub request: LogoutParams,
    /// Whether the person confirmed they want to sign out. Asked when the
    /// app did not name them with an ID token.
    #[serde(default)]
    pub confirmed: bool,
}

impl EndSessionBody {
    /// The sign-out this body asks of the tenant `issuer` names.
    ///
    /// # Errors
    ///
    /// `422` when the `client_id` or the address is malformed.
    pub(crate) fn request_of(&self, issuer: Issuer) -> Result<EndSessionRequest, ApiError> {
        let confirmation = match self.confirmed {
            true => LogoutConfirmation::Confirmed,
            false => LogoutConfirmation::NotAsked,
        };
        self.request.request(issuer, confirmation)
    }
}

/// What the sign-out step comes to.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EndSessionStep {
    /// The session ended.
    SignedOut,
    /// Ask the person to confirm first, then send the request again.
    Confirm,
    /// Nobody was signed in here; nothing ended.
    NotSignedIn,
}

/// The answer to the sign-out step.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EndSessionResponse {
    /// What the step came to.
    pub outcome: EndSessionStep,
    /// Where to send the person afterwards, with the app's `state`; none
    /// means the dashboard's own signed-out page.
    pub redirect_to: Option<String>,
    /// The pages of the apps that load in the browser to hear of the
    /// sign-out, each in a hidden frame.
    pub front_channel_logout_uris: Vec<String>,
}

impl EndSessionResponse {
    /// The answer to the step that came to `outcome`, handing the app back
    /// its `state`.
    #[must_use]
    pub(crate) fn of(outcome: EndSessionOutcome, state: Option<&str>) -> Self {
        let (step, after, pages) = match outcome {
            EndSessionOutcome::SignedOut {
                after,
                front_channel,
            } => (EndSessionStep::SignedOut, after, front_channel),
            EndSessionOutcome::ConfirmFirst { after } => {
                (EndSessionStep::Confirm, after, Vec::new())
            }
            EndSessionOutcome::NotSignedIn { after } => {
                (EndSessionStep::NotSignedIn, after, Vec::new())
            }
        };
        Self {
            outcome: step,
            redirect_to: sent_back(&after, state),
            front_channel_logout_uris: pages.iter().map(|page| page.as_str().to_owned()).collect(),
        }
    }
}

/// The address the person is sent back to, with the app's `state`, or
/// none for the signed-out page.
fn sent_back(after: &AfterLogout, state: Option<&str>) -> Option<String> {
    let AfterLogout::SendBack(uri) = after else {
        return None;
    };
    let Some(state) = state else {
        return Some(uri.as_str().to_owned());
    };
    Some(with_query(uri.as_str(), &[("state", state.to_owned())]))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::grants::pushed_request::ClientState;
    use ianua_domain::types::RedirectUri;

    use super::*;

    /// The reply to the portal's callback, with `state` `xyz`, in `mode`.
    fn reply(mode: ResponseMode) -> Reply {
        Reply {
            redirect_uri: RedirectUri::new("https://app.acme.com/callback?tab=1").unwrap(),
            response_mode: mode,
            state: StateSent::Sent(ClientState::new("xyz").unwrap()),
        }
    }

    /// The issuer of the test tenant.
    fn issuer() -> Issuer {
        Issuer::new("https://app.ianua.test/api/v1/organizations/acme/tenants/prod").unwrap()
    }

    /// The client is told the fault in its query, with its state and who
    /// answers.
    #[test]
    fn a_refusal_goes_back_with_the_clients_state() {
        let BrowserReply::Redirect(back) = client_reply(
            &reply(ResponseMode::Query),
            vec![("error", "invalid_scope".to_owned())],
            &issuer(),
        ) else {
            panic!("a query reply redirects");
        };

        assert!(
            back.starts_with(
                "https://app.acme.com/callback?tab=1&error=invalid_scope&state=xyz&iss="
            )
        );
    }

    /// A client that asked for `form_post` is handed a form, not a link.
    #[test]
    fn a_form_post_client_gets_a_form() {
        let answer = client_reply(
            &reply(ResponseMode::FormPost),
            vec![("code", "abc".to_owned())],
            &issuer(),
        );

        assert!(matches!(answer, BrowserReply::FormPost { ref fields, .. } if fields.len() == 3));
    }

    /// The person goes back to the app's address with its `state`.
    #[test]
    fn signing_out_hands_the_app_its_state() {
        let after = AfterLogout::SendBack(RedirectUri::new("https://app.acme.com/bye").unwrap());

        assert_eq!(
            sent_back(&after, Some("s1")).as_deref(),
            Some("https://app.acme.com/bye?state=s1")
        );
        assert_eq!(sent_back(&AfterLogout::SignedOutPage, Some("s1")), None);
    }
}
