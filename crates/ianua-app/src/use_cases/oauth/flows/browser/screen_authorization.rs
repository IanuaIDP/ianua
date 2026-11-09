//! Screening the authorization request a browser brings, before anyone
//! signs in: whether it goes on to sign-in and consent, which fault the
//! client is told, or whether only the browser may be told.
//!
//! The browser carries the request's parameters itself, or a `request_uri`
//! naming ones its client pushed (RFC 9126). A pushed request is checked
//! here, not used up: the consent step uses it, once.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::grants::authorization_request::{
    AuthorizeRefusal, RequestScreen, screen,
};
use ianua_domain::domains::oauth::grants::pushed_request::{PushedParameters, RequestUri};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::ClientId;

use crate::error::{AppError, OrInternal};
use crate::ports::oauth::{OAuthClientStore, PushedRequestStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::oauth::flows::browser::reply::Reply;

/// The parameters of an authorization request, as a browser brings them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserParameters {
    /// Carried in the browser's own request, as the API read them.
    Carried(PushedParameters),
    /// Pushed by the client before, named by this `request_uri`.
    Pushed(RequestUri),
}

/// What a browser's authorization request asks.
pub struct AuthorizationAsk {
    /// The client asking, by the public id it names itself by.
    pub client_id: ClientId,
    /// What it asks.
    pub parameters: BrowserParameters,
}

/// How a browser's authorization request is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenedRequest {
    /// It holds: the person signs in and is asked to consent; the answer
    /// goes back as `Reply` says.
    Proceed(Reply),
    /// The client and its redirect are good; the client is told this.
    TellClient {
        /// What is wrong.
        refusal: AuthorizeRefusal,
        /// Where and how the client is told.
        reply: Reply,
    },
    /// The client is unknown, the redirect is not one it registered, or
    /// the `request_uri` names nothing it may use; only the browser is
    /// told, and nothing is sent to any redirect.
    TellBrowser,
}

/// The ports [`ScreenAuthorizationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ScreenAuthorizationPorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Where pushed requests are kept.
    pub pushed_store: Arc<dyn PushedRequestStore>,
}

/// Screens a browser's authorization request.
pub struct ScreenAuthorizationUseCase {
    ports: ScreenAuthorizationPorts,
}

impl ScreenAuthorizationUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ScreenAuthorizationPorts) -> Self {
        Self { ports }
    }

    /// The parameters `request_uri` names, while `client` may use them.
    /// Only checked, never spent: the consent step spends the request.
    async fn pushed_parameters(
        &self,
        tenant: &ScopedTenant,
        client: &OAuthClient<ResolvedTenant>,
        request_uri: &RequestUri,
    ) -> Result<Option<PushedParameters>, AppError> {
        let found = self
            .ports
            .pushed_store
            .find_by_id(tenant, request_uri.id())
            .await
            .or_internal()?;
        let usable = found.filter(|pushed| pushed.ensure_usable_by(client, clock::now()).is_ok());
        Ok(usable.map(|pushed| pushed.parameters().clone()))
    }
}

impl Query for ScreenAuthorizationUseCase {
    type Caller = ScopedTenant;
    type Input = AuthorizationAsk;
    type Output = Result<ScreenedRequest, AppError>;

    /// How `ask`, brought to `tenant`, is answered. Nobody is signed in yet:
    /// the tenant is the one the request's address names. Nothing is
    /// issued here; the person signs in and consents afterwards, and the
    /// code is issued then.
    ///
    /// An unknown client, an unregistered redirect and a `request_uri` the
    /// client may not use are answered the same, to the browser only, so
    /// the answer never sends anyone to an address the client did not
    /// register.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        ask: AuthorizationAsk,
    ) -> Result<ScreenedRequest, AppError> {
        let client = self
            .ports
            .client_store
            .find_by_client_id_value(tenant, &ask.client_id)
            .await
            .or_internal()?;
        let Some(client) = client else {
            return Ok(ScreenedRequest::TellBrowser);
        };
        let parameters = match ask.parameters {
            BrowserParameters::Carried(parameters) => Some(parameters),
            BrowserParameters::Pushed(uri) => self.pushed_parameters(tenant, &client, &uri).await?,
        };
        let Some(parameters) = parameters else {
            return Ok(ScreenedRequest::TellBrowser);
        };
        Ok(screened(&client, &parameters))
    }
}

/// How `parameters`, asked of `client`, are answered.
fn screened(
    client: &OAuthClient<ResolvedTenant>,
    parameters: &PushedParameters,
) -> ScreenedRequest {
    match screen(Some(client), &parameters.redirect_uri, &parameters.asked) {
        RequestScreen::Proceed => ScreenedRequest::Proceed(Reply::to(parameters)),
        RequestScreen::TellClient(refusal) => ScreenedRequest::TellClient {
            refusal,
            reply: Reply::to(parameters),
        },
        RequestScreen::TellBrowser => ScreenedRequest::TellBrowser,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::grants::authorization_code::{CodeChallenge, NonceSent};
    use ianua_domain::domains::oauth::grants::authorization_request::{
        AskedFlow, AskedPrompts, AskedRequest, AskedScopes, MaxAge, RequestedAcr, ResponseMode,
    };
    use ianua_domain::domains::oauth::grants::pushed_request::{PushedRequest, StateSent};
    use ianua_domain::types::{PushedRequestId, RedirectUri, Scope};

    use super::*;
    use crate::test_support::oauth::{
        FakeOAuthClientStore, FakePushedRequestStore, TEST_REDIRECT, TEST_VERIFIER, stored_client,
    };
    use crate::test_support::{block_on, test_ctx};

    /// The portal asking properly for `read`, its answer sent to `redirect`.
    fn parameters(redirect: &str) -> PushedParameters {
        PushedParameters {
            redirect_uri: RedirectUri::new(redirect).unwrap(),
            asked: AskedRequest {
                flow: AskedFlow::CodeWithS256Challenge,
                scopes: AskedScopes::Named(vec![Scope::new("read").unwrap()]),
                prompts: AskedPrompts::Named(Vec::new()),
                response_mode: ResponseMode::Query,
            },
            max_age: MaxAge::Any,
            acr: RequestedAcr::Any,
            code_challenge: CodeChallenge::new(TEST_VERIFIER).unwrap(),
            nonce: NonceSent::NotSent,
            state: StateSent::NotSent,
        }
    }

    /// A tenant holding the portal's client, and the requests it pushed.
    struct Fixture {
        portal: OAuthClient<ResolvedTenant>,
        clients: Arc<FakeOAuthClientStore>,
        pushed: Arc<FakePushedRequestStore>,
    }

    impl Fixture {
        /// The tenant holding the portal, which pushed nothing yet.
        fn new() -> Self {
            let portal = stored_client("Portal", &[GrantType::AuthorizationCode]);
            Self {
                clients: Arc::new(FakeOAuthClientStore::holding(
                    &test_ctx().tenant(),
                    portal.clone(),
                )),
                portal,
                pushed: Arc::new(FakePushedRequestStore::empty()),
            }
        }

        /// The `request_uri` of a proper request `client` pushed.
        fn pushed_by(&self, client: &OAuthClient<ResolvedTenant>) -> RequestUri {
            let request =
                PushedRequest::push(PushedRequestId::new(), client, parameters(TEST_REDIRECT))
                    .unwrap();
            block_on(self.pushed.insert(&test_ctx().tenant(), &request)).unwrap();
            request.request_uri()
        }

        /// How a browser naming `client_id` with `parameters` is answered.
        fn screen(&self, client_id: ClientId, parameters: BrowserParameters) -> ScreenedRequest {
            let use_case = ScreenAuthorizationUseCase::new(ScreenAuthorizationPorts {
                client_store: self.clients.clone(),
                pushed_store: self.pushed.clone(),
            });
            let ask = AuthorizationAsk {
                client_id,
                parameters,
            };
            block_on(use_case.execute(&test_ctx().tenant(), ask)).unwrap()
        }

        /// How the portal's proper request, carried by the browser with
        /// `redirect`, is answered.
        fn carried(&self, redirect: &str) -> ScreenedRequest {
            self.screen(
                self.portal.client_id_value().clone(),
                BrowserParameters::Carried(parameters(redirect)),
            )
        }
    }

    /// The portal asks properly. The person goes on to sign in and consent,
    /// and the answer will go to the portal's redirect.
    #[test]
    fn a_proper_request_goes_on_to_consent() {
        let fixture = Fixture::new();

        let answer = fixture.carried(TEST_REDIRECT);

        assert_eq!(
            answer,
            ScreenedRequest::Proceed(Reply::to(&parameters(TEST_REDIRECT)))
        );
    }

    /// An unregistered redirect produces a browser-only refusal without a
    /// client redirect destination.
    #[test]
    fn a_redirect_the_client_did_not_register_is_told_only_to_the_browser() {
        let fixture = Fixture::new();

        assert_eq!(
            fixture.carried("https://evil.test/callback"),
            ScreenedRequest::TellBrowser
        );
    }

    /// A client the tenant does not have is told only to the browser.
    #[test]
    fn an_unknown_client_is_told_only_to_the_browser() {
        let fixture = Fixture::new();

        let answer = fixture.screen(
            ClientId::new("client_unknown").unwrap(),
            BrowserParameters::Carried(parameters(TEST_REDIRECT)),
        );

        assert_eq!(answer, ScreenedRequest::TellBrowser);
    }

    /// A request without PKCE is refused to the client, at its redirect.
    #[test]
    fn a_request_without_pkce_is_told_to_the_client() {
        let fixture = Fixture::new();
        let mut asked = parameters(TEST_REDIRECT);
        asked.asked.flow = AskedFlow::NoS256Challenge;

        let answer = fixture.screen(
            fixture.portal.client_id_value().clone(),
            BrowserParameters::Carried(asked.clone()),
        );

        assert_eq!(
            answer,
            ScreenedRequest::TellClient {
                refusal: AuthorizeRefusal::InvalidRequest,
                reply: Reply::to(&asked),
            }
        );
    }

    /// The portal pushed its request and sends the browser on with the
    /// `request_uri`. It goes on to consent, and the request stays unused
    /// for the consent step.
    #[test]
    fn a_pushed_request_goes_on_to_consent() {
        let fixture = Fixture::new();
        let uri = fixture.pushed_by(&fixture.portal);

        let answer = fixture.screen(
            fixture.portal.client_id_value().clone(),
            BrowserParameters::Pushed(uri),
        );

        assert!(matches!(answer, ScreenedRequest::Proceed(_)));
        assert!(!fixture.pushed.is_used(uri.id()));
    }

    /// Naming another client with the portal's pushed request produces a
    /// browser-only refusal.
    #[test]
    fn another_clients_pushed_request_is_told_only_to_the_browser() {
        let fixture = Fixture::new();
        let uri = fixture.pushed_by(&fixture.portal);
        let mallorys = stored_client("Mallory's", &[GrantType::AuthorizationCode]);
        block_on(fixture.clients.save(&test_ctx().tenant(), &mallorys)).unwrap();

        let answer = fixture.screen(
            mallorys.client_id_value().clone(),
            BrowserParameters::Pushed(uri),
        );

        assert_eq!(answer, ScreenedRequest::TellBrowser);
    }
}
