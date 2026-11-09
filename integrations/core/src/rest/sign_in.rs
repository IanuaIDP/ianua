//! Signing in at a service with OAuth 2.0's authorization code flow, made
//! from a description: the app the deployment registered, the service's
//! authorize and token addresses, the scopes the integration needs, and how
//! the account keeps what the service issues.
//!
//! The browser carries the `S256` challenge of the platform's PKCE
//! verifier, never the verifier. The code is swapped once, with the app's
//! client secret, at the token address the deployment names; the call
//! follows no redirect, reads a bounded answer, and anything short of a
//! token issued is a refusal or the service being unreachable.

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::Deserialize;
use url::form_urlencoded::Serializer;

use crate::answer::body_within;
use crate::connect::{Exchange, SignIn, SignInLink, Swap};
use crate::{ServiceEndpoint, client};

/// The most of a token answer read.
const LARGEST_TOKEN_ANSWER: usize = 64 * 1024;

/// The app a deployment registered with a service: what identifies it, and
/// the secret it proves itself with. The secret is never logged.
#[derive(Clone)]
pub struct OAuthApp {
    /// The app's client id.
    pub client_id: String,
    /// The app's client secret.
    pub client_secret: Secret,
}

impl std::fmt::Debug for OAuthApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthApp")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .finish()
    }
}

/// How a deployment set up signing in at one service: its app there, and
/// where the service signs people in and swaps codes, which a stand-in may
/// take the place of.
#[derive(Debug, Clone)]
pub struct SignInSettings {
    /// The deployment's app at the service.
    pub app: OAuthApp,
    /// Where the browser is sent to sign in.
    pub authorize: ServiceEndpoint,
    /// Where the code is swapped.
    pub token: ServiceEndpoint,
}

/// How the code is sent to the token address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenBody {
    /// As a form, as most services take it.
    Form,
    /// As JSON, as Atlassian takes it.
    Json,
}

/// How an account keeps what the service issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keeps {
    /// The access token alone, which does not expire, as GitHub's and a
    /// Slack bot's do.
    AccessToken,
    /// The app's client id and secret and the refresh grant, as JSON
    /// `{"client_id", "client_secret", "refresh_token"}`, exchanged for a
    /// token before each call, as Google's accounts are.
    RefreshGrant,
}

/// What a sign-in is made from.
pub struct OAuthSignInParams {
    /// The deployment's app at the service, and the service's addresses.
    pub at: SignInSettings,
    /// The scopes the integration needs.
    pub scopes: &'static [&'static str],
    /// What the service separates scopes with: a space, or a comma for
    /// Slack.
    pub scope_separator: &'static str,
    /// More values the authorize address carries, such as Google's
    /// `access_type=offline`.
    pub extra: &'static [(&'static str, &'static str)],
    /// More values the swap carries, such as the scope Microsoft asks to
    /// be named again.
    pub swap_extra: &'static [(&'static str, &'static str)],
    /// How the code is sent.
    pub token_body: TokenBody,
    /// How the account keeps what is issued.
    pub keeps: Keeps,
    /// The service's word for a place the person names besides the
    /// account, such as Azure DevOps's `organization`, kept under that
    /// name beside the grant; none for a service that reaches one place.
    pub place: Option<&'static str>,
    /// How long the swap may take.
    pub timeout: Duration,
}

/// A sign-in through OAuth 2.0's authorization code flow with PKCE.
pub struct OAuthSignIn {
    app: OAuthApp,
    authorize: ServiceEndpoint,
    token: ServiceEndpoint,
    scopes: String,
    extra: &'static [(&'static str, &'static str)],
    swap_extra: &'static [(&'static str, &'static str)],
    token_body: TokenBody,
    keeps: Keeps,
    place: Option<&'static str>,
    client: reqwest::Client,
}

/// A code swapped: the short-lived token the service issued with it, and
/// the credential an account keeps.
pub struct Swapped {
    /// The token issued, for a sign-in that must ask the service more
    /// before the account is kept, such as which site a Jira grant reaches.
    pub access_token: Secret,
    /// The credential the account keeps.
    pub kept: Secret,
}

impl OAuthSignIn {
    /// Signing in at Google through the deployment's OAuth client `at` for
    /// `scopes`, asking for a grant that lasts (`access_type=offline`) and
    /// is issued again on every consent, since Google issues it only on the
    /// first otherwise.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn google(
        at: SignInSettings,
        scopes: &'static [&'static str],
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        Self::new(OAuthSignInParams {
            at,
            scopes,
            scope_separator: " ",
            extra: &[("access_type", "offline"), ("prompt", "consent")],
            swap_extra: &[],
            token_body: TokenBody::Form,
            keeps: Keeps::RefreshGrant,
            place: None,
            timeout,
        })
    }

    /// The sign-in `params` describe.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(params: OAuthSignInParams) -> Result<Self, DomainError> {
        Ok(Self {
            app: params.at.app,
            authorize: params.at.authorize,
            token: params.at.token,
            scopes: params.scopes.join(params.scope_separator),
            extra: params.extra,
            swap_extra: params.swap_extra,
            token_body: params.token_body,
            keeps: params.keeps,
            place: params.place,
            client: client(params.timeout)?,
        })
    }

    /// The token and the credential to keep that the service issues for
    /// `swap`.
    ///
    /// # Errors
    ///
    /// [`Exchange::Refused`] when the service refused the code or issued
    /// nothing to keep; [`Exchange::Unreachable`] when it could not be
    /// reached, was busy or did not answer whole.
    pub async fn swapped(&self, swap: Swap<'_>) -> Result<Swapped, Exchange> {
        let Ok(response) = self.request(swap).send().await else {
            return Err(Exchange::Unreachable);
        };
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(Exchange::Unreachable);
        }
        if !status.is_success() {
            return Err(Exchange::Refused);
        }
        let Ok(body) = body_within(response, LARGEST_TOKEN_ANSWER).await else {
            return Err(Exchange::Unreachable);
        };
        let issued = serde_json::from_slice::<Issued>(&body)
            .ok()
            .filter(|issued| issued.ok != Some(false))
            .ok_or(Exchange::Refused)?;
        self.kept(issued, swap.place).ok_or(Exchange::Refused)
    }

    /// The token request for `swap`.
    fn request(&self, swap: Swap<'_>) -> reqwest::RequestBuilder {
        let fields = self.swap_fields(swap);
        let request = self
            .client
            .post(self.token.base().clone())
            .header(ACCEPT, "application/json");
        match self.token_body {
            TokenBody::Form => {
                let mut form = Serializer::new(String::new());
                for (name, value) in fields {
                    form.append_pair(name, value);
                }
                request
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(form.finish())
            }
            TokenBody::Json => {
                let body: serde_json::Map<String, serde_json::Value> = fields
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value.into()))
                    .collect();
                request.json(&body)
            }
        }
    }

    /// The authorization-code fields, followed by the service's configured additions.
    fn swap_fields<'a>(&'a self, swap: Swap<'a>) -> Vec<(&'a str, &'a str)> {
        [
            ("grant_type", "authorization_code"),
            ("client_id", self.app.client_id.as_str()),
            ("client_secret", self.app.client_secret.expose()),
            ("code", swap.code.expose()),
            ("redirect_uri", swap.redirect),
            ("code_verifier", swap.verifier.expose()),
        ]
        .into_iter()
        .chain(self.swap_extra.iter().copied())
        .collect()
    }

    /// The token `issued` and the credential an account keeps of it, with
    /// `place` beside a grant when the sign-in asks for one, or none when
    /// the service issued nothing it can keep.
    fn kept(&self, issued: Issued, place: Option<&str>) -> Option<Swapped> {
        let access_token = issued.access_token?;
        let kept = match self.keeps {
            Keeps::AccessToken => access_token.clone(),
            Keeps::RefreshGrant => {
                let mut grant = serde_json::json!({
                    "client_id": self.app.client_id,
                    "client_secret": self.app.client_secret.expose(),
                    "refresh_token": issued.refresh_token?,
                });
                if let (Some(name), Some(place), Some(fields)) =
                    (self.place, place, grant.as_object_mut())
                {
                    fields.insert(name.to_owned(), place.trim().into());
                }
                grant.to_string()
            }
        };
        Some(Swapped {
            access_token: Secret::new(access_token),
            kept: Secret::new(kept),
        })
    }
}

/// What a token address answers.
#[derive(Deserialize)]
struct Issued {
    access_token: Option<String>,
    refresh_token: Option<String>,
    /// Slack's word on whether it issued anything.
    ok: Option<bool>,
}

#[async_trait]
impl SignIn for OAuthSignIn {
    fn authorize_address(&self, link: SignInLink<'_>) -> String {
        let mut address = self.authorize.base().clone();
        {
            let mut query = address.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.app.client_id)
                .append_pair("redirect_uri", link.redirect)
                .append_pair("scope", &self.scopes)
                .append_pair("state", link.state.expose())
                .append_pair("code_challenge", link.challenge)
                .append_pair("code_challenge_method", "S256");
            for (name, value) in self.extra {
                query.append_pair(name, value);
            }
        }
        address.to_string()
    }

    fn asks_for_place(&self) -> Option<&'static str> {
        self.place
    }

    async fn exchange(&self, swap: Swap<'_>) -> Exchange {
        match self.swapped(swap).await {
            Ok(swapped) => Exchange::Issued(swapped.kept),
            Err(failed) => failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn sign_in(server: &MockServer, keeps: Keeps) -> OAuthSignIn {
        OAuthSignIn::new(OAuthSignInParams {
            at: SignInSettings {
                app: OAuthApp {
                    client_id: "the app".to_owned(),
                    client_secret: Secret::new("the app's secret words".to_owned()),
                },
                authorize: ServiceEndpoint::at("https://service.test/authorize").unwrap(),
                token: ServiceEndpoint::at(&format!("{}/token", server.uri())).unwrap(),
            },
            scopes: &["repo", "read:user"],
            scope_separator: " ",
            extra: &[("access_type", "offline")],
            swap_extra: &[],
            token_body: TokenBody::Form,
            keeps,
            place: None,
            timeout: Duration::from_secs(5),
        })
        .unwrap()
    }

    fn swap<'a>(code: &'a Secret, verifier: &'a Secret) -> Swap<'a> {
        Swap {
            code,
            verifier,
            redirect: "https://ianua.test/api/v1/integrations/callback",
            place: None,
        }
    }

    /// Ann is sent to the service with the app, the scopes, the state, the
    /// challenge and the callback, never the verifier.
    #[tokio::test]
    async fn the_browser_carries_the_challenge_and_never_the_verifier() {
        let server = MockServer::start().await;
        let state = Secret::new("the state".to_owned());

        let address = sign_in(&server, Keeps::AccessToken).authorize_address(SignInLink {
            state: &state,
            challenge: "the challenge",
            redirect: "https://ianua.test/api/v1/integrations/callback",
        });

        let parsed = url::Url::parse(&address).unwrap();
        let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("code_challenge".to_owned(), "the challenge".to_owned())));
        assert!(pairs.contains(&("scope".to_owned(), "repo read:user".to_owned())));
        assert!(pairs.contains(&("state".to_owned(), "the state".to_owned())));
        assert!(pairs.contains(&("access_type".to_owned(), "offline".to_owned())));
        assert!(!address.contains("verifier"));
    }

    /// The service takes the code with the verifier and issues a token,
    /// which the account keeps as it is.
    #[tokio::test]
    async fn a_code_swapped_gives_the_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("code_verifier=the+verifier"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "issued token", "token_type": "bearer"
            })))
            .mount(&server)
            .await;
        let (code, verifier) = (
            Secret::new("the code".to_owned()),
            Secret::new("the verifier".to_owned()),
        );

        let issued = sign_in(&server, Keeps::AccessToken)
            .exchange(swap(&code, &verifier))
            .await;

        let Exchange::Issued(credential) = issued else {
            panic!("no credential was issued");
        };
        assert_eq!(credential.expose(), "issued token");
    }

    /// Google issues a refresh grant, kept with the app's id and secret as
    /// the account's grant.
    #[tokio::test]
    async fn a_refresh_grant_is_kept_with_the_app() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "short lived", "refresh_token": "the grant"
            })))
            .mount(&server)
            .await;
        let (code, verifier) = (Secret::new("c".to_owned()), Secret::new("v".to_owned()));

        let issued = sign_in(&server, Keeps::RefreshGrant)
            .exchange(swap(&code, &verifier))
            .await;

        let Exchange::Issued(credential) = issued else {
            panic!("no credential was issued");
        };
        let grant: serde_json::Value = serde_json::from_str(credential.expose()).unwrap();
        assert_eq!(grant["refresh_token"], "the grant");
        assert_eq!(grant["client_id"], "the app");
    }

    /// A rejected code, Slack's `"ok": false` and a tokenless answer refuse
    /// the exchange. A busy service is unreachable; none issues credentials.
    #[tokio::test]
    async fn anything_short_of_a_token_issues_nothing() {
        let (code, verifier) = (Secret::new("c".to_owned()), Secret::new("v".to_owned()));
        let answers = [
            (ResponseTemplate::new(400), false),
            (
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"ok": false, "error": "invalid_code"})),
                false,
            ),
            (
                ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
                false,
            ),
            (ResponseTemplate::new(503), true),
        ];
        for (answer, busy) in answers {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(answer)
                .mount(&server)
                .await;

            let issued = sign_in(&server, Keeps::AccessToken)
                .exchange(swap(&code, &verifier))
                .await;

            match (issued, busy) {
                (Exchange::Unreachable, true) | (Exchange::Refused, false) => {}
                (Exchange::Issued(_), _) => panic!("a credential was issued"),
                _ => panic!("the wrong failure"),
            }
        }
    }
}
