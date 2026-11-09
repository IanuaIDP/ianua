//! An authorization request, as the OAuth and OIDC specifications spell it
//! (RFC 6749 4.1.1, RFC 7636 4.3, OIDC Core 3.1.2.1, RFC 9126 4): carried
//! in a browser's query string, pushed by its client in a form, or brought
//! back by the dashboard's consent page.
//!
//! Every field may be missing or malformed: which faults go to the browser
//! and which to the client is the app's screen, not the parser's. Only the
//! client and its redirect, without which nothing can be sent back, are
//! refused here.

use ianua_app::use_cases::oauth::flows::{AuthorizationAsk, BrowserParameters, HintSent};
use ianua_domain::domains::oauth::grants::authorization_code::{CodeChallenge, NonceSent};
use ianua_domain::domains::oauth::grants::authorization_request::{
    AskedFlow, AskedPrompts, AskedRequest, AskedScopes, MaxAge, Prompt, RequestedAcr, ResponseMode,
};
use ianua_domain::domains::oauth::grants::pushed_request::{
    ClientState, PushedParameters, RequestUri, StateSent,
};
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, Nonce, RedirectUri, Scope};
use serde::Deserialize;

use crate::error::ApiError;
use crate::extractors::oauth::form::OAuthForm;

/// The only PKCE method offered.
const S256: &str = "S256";

/// The challenge a request is kept with when it sent no usable `S256` one.
/// The screen refuses every request whose flow is not a code bound with an
/// `S256` challenge before a code is made, so it never binds one.
const UNBOUND_CHALLENGE: &str = "request-sent-no-usable-challenge-and-is-refused";

/// An authorization request, every parameter as it was sent.
#[derive(Default, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct AuthorizationParams {
    /// What the client asks to be handed back; only `code`.
    pub response_type: Option<String>,
    /// The client asking, by the `client_id` it was issued.
    pub client_id: Option<String>,
    /// Where the answer goes; one the client registered.
    pub redirect_uri: Option<String>,
    /// The scopes asked for, separated by spaces.
    pub scope: Option<String>,
    /// The client's own value, handed back with the answer.
    pub state: Option<String>,
    /// The OIDC nonce, which ties the ID token to this request.
    pub nonce: Option<String>,
    /// The PKCE challenge made from the client's verifier.
    pub code_challenge: Option<String>,
    /// How the challenge was made; only `S256`.
    pub code_challenge_method: Option<String>,
    /// How the person is prompted: `none`, `login`, `consent` or
    /// `select_account`, separated by spaces.
    pub prompt: Option<String>,
    /// The longest a sign-in may be old, in seconds.
    pub max_age: Option<String>,
    /// The assurance asked for: `aal1`, `aal2` or `aal3`, separated by
    /// spaces.
    pub acr_values: Option<String>,
    /// How the answer is sent back: `query` (the default) or `form_post`.
    pub response_mode: Option<String>,
    /// An ID token this tenant issued, naming whom the client expects.
    pub id_token_hint: Option<String>,
    /// Who the client expects to sign in; shown on the sign-in page.
    pub login_hint: Option<String>,
    /// The languages the pages should speak, separated by spaces.
    pub ui_locales: Option<String>,
    /// A request the client pushed first, instead of every parameter
    /// above but `client_id`.
    pub request_uri: Option<String>,
}

impl AuthorizationParams {
    /// The parameters a pushed request's form carries, taken out of it.
    pub(crate) fn from_form(form: &mut OAuthForm) -> Self {
        let mut take = |name: &str| form.take(name);
        Self {
            response_type: take("response_type"),
            client_id: None,
            redirect_uri: take("redirect_uri"),
            scope: take("scope"),
            state: take("state"),
            nonce: take("nonce"),
            code_challenge: take("code_challenge"),
            code_challenge_method: take("code_challenge_method"),
            prompt: take("prompt"),
            max_age: take("max_age"),
            acr_values: take("acr_values"),
            response_mode: take("response_mode"),
            id_token_hint: take("id_token_hint"),
            login_hint: take("login_hint"),
            ui_locales: take("ui_locales"),
            request_uri: take("request_uri"),
        }
    }

    /// What the request asks, for the app to screen or answer.
    ///
    /// # Errors
    ///
    /// `422` when the client, the redirect or the `request_uri` is missing
    /// or malformed, or a value nothing could be sent back with is: with no
    /// redirect to trust, only the browser is told.
    pub(crate) fn ask(&self) -> Result<AuthorizationAsk, ApiError> {
        let client = self.client_id.as_deref().unwrap_or_default();
        let client_id = ClientId::new(client).map_err(ApiError::validation)?;
        let parameters = match self.request_uri.as_deref() {
            Some(uri) => {
                BrowserParameters::Pushed(RequestUri::parse(uri).map_err(|e| ApiError(e.into()))?)
            }
            None => BrowserParameters::Carried(self.carried()?),
        };
        Ok(AuthorizationAsk {
            client_id,
            parameters,
        })
    }

    /// The parameters the request carries itself.
    ///
    /// # Errors
    ///
    /// `422` when the redirect is missing or malformed, or the `state`,
    /// `nonce` or `max_age` is malformed.
    pub(crate) fn carried(&self) -> Result<PushedParameters, ApiError> {
        let redirect = self.redirect_uri.as_deref().unwrap_or_default();
        Ok(PushedParameters {
            redirect_uri: RedirectUri::new(redirect).map_err(ApiError::validation)?,
            asked: AskedRequest {
                flow: self.flow(),
                scopes: self.scopes(),
                prompts: self.prompts(),
                response_mode: self.response_mode(),
            },
            max_age: self.max_age()?,
            acr: RequestedAcr::from_values(
                self.acr_values
                    .as_deref()
                    .unwrap_or_default()
                    .split_whitespace(),
            ),
            code_challenge: self.challenge()?,
            nonce: self.nonce()?,
            state: self.state()?,
        })
    }

    /// The ID token the request names whom the client expects with.
    #[must_use]
    pub(crate) fn hint(&self) -> HintSent {
        self.id_token_hint
            .clone()
            .map_or(HintSent::NotSent, |hint| HintSent::Sent(Secret::new(hint)))
    }

    /// Every parameter that was sent, by its name, to carry the request on.
    pub(crate) fn sent(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("response_type", &self.response_type),
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("scope", &self.scope),
            ("state", &self.state),
            ("nonce", &self.nonce),
            ("code_challenge", &self.code_challenge),
            ("code_challenge_method", &self.code_challenge_method),
            ("prompt", &self.prompt),
            ("max_age", &self.max_age),
            ("acr_values", &self.acr_values),
            ("response_mode", &self.response_mode),
            ("id_token_hint", &self.id_token_hint),
            ("login_hint", &self.login_hint),
            ("ui_locales", &self.ui_locales),
            ("request_uri", &self.request_uri),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.as_deref().map(|value| (name, value)))
    }

    /// What the request asked to be handed back, and how it bound itself.
    fn flow(&self) -> AskedFlow {
        if self.response_type.as_deref() != Some("code") {
            return AskedFlow::NotCode;
        }
        let bound = self.code_challenge_method.as_deref() == Some(S256)
            && self
                .code_challenge
                .as_deref()
                .is_some_and(|challenge| CodeChallenge::new(challenge).is_ok());
        if bound {
            return AskedFlow::CodeWithS256Challenge;
        }
        AskedFlow::NoS256Challenge
    }

    /// The challenge the request sent, or [`UNBOUND_CHALLENGE`] when it
    /// sent none usable.
    fn challenge(&self) -> Result<CodeChallenge, ApiError> {
        let sent = self
            .code_challenge
            .as_deref()
            .and_then(|challenge| CodeChallenge::new(challenge).ok());
        match sent {
            Some(challenge) => Ok(challenge),
            None => CodeChallenge::new(UNBOUND_CHALLENGE).map_err(ApiError::validation),
        }
    }

    /// The scopes asked for.
    fn scopes(&self) -> AskedScopes {
        let named: Result<Vec<Scope>, _> = self
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(Scope::new)
            .collect();
        named.map_or(AskedScopes::Unreadable, AskedScopes::Named)
    }

    /// How the person is to be prompted.
    fn prompts(&self) -> AskedPrompts {
        let named: Option<Vec<Prompt>> = self
            .prompt
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(prompt)
            .collect();
        named.map_or(AskedPrompts::Unreadable, AskedPrompts::Named)
    }

    /// How the answer is to be sent back.
    fn response_mode(&self) -> ResponseMode {
        match self.response_mode.as_deref() {
            None | Some("query") => ResponseMode::Query,
            Some("form_post") => ResponseMode::FormPost,
            Some(_) => ResponseMode::Unsupported,
        }
    }

    /// The longest a sign-in may be old.
    fn max_age(&self) -> Result<MaxAge, ApiError> {
        let Some(raw) = self.max_age.as_deref() else {
            return Ok(MaxAge::Any);
        };
        raw.parse::<u32>().map(MaxAge::Seconds).map_err(|_| {
            ApiError::validation(message!(
                "api-max-age-must-be-a-number",
                "max_age must be a number of seconds"
            ))
        })
    }

    /// The nonce the request carried, if any.
    fn nonce(&self) -> Result<NonceSent, ApiError> {
        let Some(nonce) = self.nonce.as_deref() else {
            return Ok(NonceSent::NotSent);
        };
        Nonce::new(nonce)
            .map(NonceSent::Sent)
            .map_err(ApiError::validation)
    }

    /// The `state` the request carried, if any.
    fn state(&self) -> Result<StateSent, ApiError> {
        let Some(state) = self.state.as_deref() else {
            return Ok(StateSent::NotSent);
        };
        ClientState::new(state)
            .map(StateSent::Sent)
            .map_err(ApiError::validation)
    }
}

/// The prompt `value` names, or `None` for one this server does not know.
fn prompt(value: &str) -> Option<Prompt> {
    match value {
        "none" => Some(Prompt::None),
        "login" => Some(Prompt::Login),
        "consent" => Some(Prompt::Consent),
        "select_account" => Some(Prompt::SelectAccount),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A proper request from the portal, asking for `openid`.
    fn proper() -> AuthorizationParams {
        AuthorizationParams {
            response_type: Some("code".to_owned()),
            client_id: Some("client_portal".to_owned()),
            redirect_uri: Some("https://app.acme.com/callback".to_owned()),
            scope: Some("openid email".to_owned()),
            state: Some("xyz".to_owned()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some(S256.to_owned()),
            ..AuthorizationParams::default()
        }
    }

    /// A proper request reads as a code with PKCE, for the scopes named.
    #[test]
    fn a_proper_request_reads_as_a_code_with_pkce() {
        let Ok(carried) = proper().carried() else {
            panic!("a proper request reads");
        };

        assert_eq!(carried.asked.flow, AskedFlow::CodeWithS256Challenge);
        assert!(matches!(carried.asked.scopes, AskedScopes::Named(ref named) if named.len() == 2));
        assert_eq!(carried.asked.response_mode, ResponseMode::Query);
    }

    /// A request with the `plain` method, or none, reads as unbound, and is
    /// still read so the client can be told.
    #[test]
    fn a_challenge_not_made_with_s256_reads_as_unbound() {
        for method in [None, Some("plain".to_owned())] {
            let params = AuthorizationParams {
                code_challenge_method: method,
                ..proper()
            };

            let Ok(carried) = params.carried() else {
                panic!("the request reads");
            };
            assert_eq!(carried.asked.flow, AskedFlow::NoS256Challenge);
        }
    }

    /// `none` beside another prompt is read, for the app to refuse; an
    /// unknown prompt is unreadable.
    #[test]
    fn prompts_are_read_as_sent() {
        let silent = AuthorizationParams {
            prompt: Some("none login".to_owned()),
            ..proper()
        };
        let unknown = AuthorizationParams {
            prompt: Some("sometimes".to_owned()),
            ..proper()
        };

        assert_eq!(
            silent.prompts(),
            AskedPrompts::Named(vec![Prompt::None, Prompt::Login])
        );
        assert_eq!(unknown.prompts(), AskedPrompts::Unreadable);
    }

    /// A request without a redirect is refused before anything is read.
    #[test]
    fn a_missing_redirect_is_refused() {
        let params = AuthorizationParams {
            redirect_uri: None,
            ..proper()
        };

        assert!(params.ask().is_err());
    }

    /// A pushed request is named by its `request_uri` alone.
    #[test]
    fn a_pushed_request_is_read_by_its_uri() {
        let params = AuthorizationParams {
            client_id: Some("client_portal".to_owned()),
            request_uri: Some(
                "urn:ietf:params:oauth:request_uri:019f0000-0000-7000-8000-000000000001".to_owned(),
            ),
            ..AuthorizationParams::default()
        };

        let Ok(ask) = params.ask() else {
            panic!("the request reads");
        };
        assert!(matches!(ask.parameters, BrowserParameters::Pushed(_)));
    }
}
