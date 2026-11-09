//! An authorization request a browser brings: screened before anyone signs
//! in, then, once a person is there, what they must still do before a code
//! is issued.
//!
//! The screen's order is the protocol's. Until the client and its redirect
//! are known good, nothing goes to the redirect: Mallory crafts a request
//! naming her own site as the redirect, and an error sent there would make
//! the platform an open redirector. Once they are, every other fault goes
//! back to the client, which is waiting for an answer.

use time::{Duration, OffsetDateTime};

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::oauth::clients::client::{GrantType, OAuthClient};
use crate::isolation::scope::TenantScope;
use crate::types::{RedirectUri, Scope};

/// How recent a sign-in must be when a request asks the person to sign in
/// again (`prompt=login`): five minutes, long enough to finish signing in.
const FRESH_SIGN_IN: Duration = Duration::minutes(5);

/// What the request asked to be handed back, and how it bound itself to
/// the client that will redeem it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskedFlow {
    /// An authorization code, with a PKCE challenge made with `S256`.
    CodeWithS256Challenge,
    /// Something other than an authorization code.
    NotCode,
    /// A code, without an `S256` challenge.
    NoS256Challenge,
}

/// The scopes the request asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskedScopes {
    /// Each one well formed.
    Named(Vec<Scope>),
    /// At least one is not a scope at all.
    Unreadable,
}

/// One value of the `prompt` parameter (OIDC Core 3.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    /// Show nothing: answer at once, or say what the person would have had
    /// to do.
    None,
    /// Ask the person to sign in again, even when they are signed in.
    Login,
    /// Ask the person to consent again, even when they already did.
    Consent,
    /// Let the person choose which account to go on with.
    SelectAccount,
}

/// The `prompt` parameter, as the request sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskedPrompts {
    /// These values; none may be empty.
    Named(Vec<Prompt>),
    /// A value that is not one of the four.
    Unreadable,
}

impl AskedPrompts {
    /// Whether the request asked for `prompt`.
    #[must_use]
    pub fn asks(&self, prompt: Prompt) -> bool {
        matches!(self, Self::Named(prompts) if prompts.contains(&prompt))
    }

    /// Whether the prompts contradict each other: `none` with any other
    /// value, or an unreadable one.
    fn contradict(&self) -> bool {
        match self {
            Self::Named(prompts) => prompts.contains(&Prompt::None) && prompts.len() > 1,
            Self::Unreadable => true,
        }
    }
}

/// How the answer is to be sent back (OAuth 2.0 Multiple Response Types
/// and Form Post Response Mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    /// In the redirect's query string, the default for a code.
    Query,
    /// In a form the browser posts to the redirect, so the code never sits
    /// in an address bar or a server log.
    FormPost,
    /// A mode this server does not offer.
    Unsupported,
}

/// Everything the browser's request asked, beside its client and redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskedRequest {
    /// What it asked to be handed back.
    pub flow: AskedFlow,
    /// The scopes it asked for.
    pub scopes: AskedScopes,
    /// How it wants the person prompted.
    pub prompts: AskedPrompts,
    /// How it wants the answer sent back.
    pub response_mode: ResponseMode,
}

/// What the client is told is wrong with its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeRefusal {
    /// A code without an `S256` challenge, prompts that contradict each
    /// other, or a response mode not offered.
    InvalidRequest,
    /// The client is revoked, or may not use the code flow.
    UnauthorizedClient,
    /// The request asked for something other than a code.
    UnsupportedResponseType,
    /// A scope is unreadable, or not one the client was given.
    InvalidScope,
    /// `prompt=none`, and the person would have had to sign in.
    LoginRequired,
    /// `prompt=none`, and the person would have had to consent.
    ConsentRequired,
}

/// How an authorization request is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestScreen {
    /// It holds: the person signs in and is asked to consent.
    Proceed,
    /// The client and its redirect are good; the client is told this.
    TellClient(AuthorizeRefusal),
    /// The client is unknown, or did not register the redirect; only the
    /// browser is told, and nothing is sent to the redirect.
    TellBrowser,
}

/// The request for `client`, sending its answers to `redirect_uri`, asking
/// `asked`, screened.
#[must_use]
pub fn screen<T: TenantScope>(
    client: Option<&OAuthClient<T>>,
    redirect_uri: &RedirectUri,
    asked: &AskedRequest,
) -> RequestScreen {
    let Some(client) = client.filter(|client| client.accepts_redirect(redirect_uri)) else {
        return RequestScreen::TellBrowser;
    };
    match refusal(client, asked) {
        Some(refused) => RequestScreen::TellClient(refused),
        None => RequestScreen::Proceed,
    }
}

/// What is wrong with a request whose client and redirect are good, if
/// anything.
fn refusal<T: TenantScope>(
    client: &OAuthClient<T>,
    asked: &AskedRequest,
) -> Option<AuthorizeRefusal> {
    match asked.flow {
        AskedFlow::NotCode => return Some(AuthorizeRefusal::UnsupportedResponseType),
        AskedFlow::NoS256Challenge => return Some(AuthorizeRefusal::InvalidRequest),
        AskedFlow::CodeWithS256Challenge => {}
    }
    if asked.prompts.contradict() || asked.response_mode == ResponseMode::Unsupported {
        return Some(AuthorizeRefusal::InvalidRequest);
    }
    if !client.is_active() || !client.supports_grant_type(GrantType::AuthorizationCode) {
        return Some(AuthorizeRefusal::UnauthorizedClient);
    }
    let AskedScopes::Named(scopes) = &asked.scopes else {
        return Some(AuthorizeRefusal::InvalidScope);
    };
    client
        .first_unallowed_scope(scopes)
        .map(|_| AuthorizeRefusal::InvalidScope)
}

/// The longest a request lets a sign-in be old (`max_age`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxAge {
    /// No limit asked.
    Any,
    /// At most this many seconds.
    Seconds(u32),
}

/// The assurance a request asks for, from its `acr_values`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedAcr {
    /// None asked, or none this server knows.
    Any,
    /// At least this level.
    AtLeast(AssuranceLevel),
}

impl RequestedAcr {
    /// The requirement `values` name: the weakest level among those this
    /// server knows, since any of them satisfies the request.
    #[must_use]
    pub fn from_values<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        values
            .into_iter()
            .filter_map(AssuranceLevel::from_acr)
            .min()
            .map_or(Self::Any, Self::AtLeast)
    }
}

/// The person at the consent step, if anyone is signed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInPresence {
    /// Nobody is signed in.
    SignedOut,
    /// Someone is, since this time, at this level.
    SignedIn {
        /// When they signed in.
        at: OffsetDateTime,
        /// The assurance their sign-in reached.
        assurance: AssuranceLevel,
    },
}

/// Whether the person already consented to what the request asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentStanding {
    /// They agreed to every scope asked before.
    Covers,
    /// They have not agreed to all of it.
    Missing,
}

/// What the consent step works from.
#[derive(Debug, Clone)]
pub struct InteractionFacts<'a> {
    /// The request's prompts.
    pub prompts: &'a AskedPrompts,
    /// The request's `max_age`.
    pub max_age: MaxAge,
    /// The request's `acr_values`.
    pub acr: RequestedAcr,
    /// Who is signed in.
    pub presence: SignInPresence,
    /// Whether they already consented.
    pub consent: ConsentStanding,
    /// The time now.
    pub now: OffsetDateTime,
}

/// What must happen before a code is issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interaction {
    /// Nothing: issue the code now.
    IssueNow,
    /// The person signs in, or signs in again, or chooses an account.
    SignIn,
    /// The person is asked to consent.
    Consent,
    /// `prompt=none` forbids asking; the client is told what was needed.
    Refuse(AuthorizeRefusal),
}

/// What the person must still do before a code is issued, as `facts` say.
///
/// They must sign in when nobody is, when the sign-in is older than
/// `max_age` (or than a few minutes, for `prompt=login`), when it is weaker
/// than `acr_values` ask, or when the request asks to choose an account.
/// Then they must consent when they never did to all of it, or the request
/// asks again. With `prompt=none` nothing may be shown: what would have
/// been asked is refused instead, so the client can send the person
/// through with prompts.
#[must_use]
pub fn interaction(facts: &InteractionFacts<'_>) -> Interaction {
    let silent = facts.prompts.asks(Prompt::None);
    if must_sign_in(facts) {
        return if silent {
            Interaction::Refuse(AuthorizeRefusal::LoginRequired)
        } else {
            Interaction::SignIn
        };
    }
    let ask_consent =
        facts.consent == ConsentStanding::Missing || facts.prompts.asks(Prompt::Consent);
    match (ask_consent, silent) {
        (true, true) => Interaction::Refuse(AuthorizeRefusal::ConsentRequired),
        (true, false) => Interaction::Consent,
        (false, _) => Interaction::IssueNow,
    }
}

/// Whether the person must sign in, again or for the first time.
fn must_sign_in(facts: &InteractionFacts<'_>) -> bool {
    let SignInPresence::SignedIn { at, assurance } = facts.presence else {
        return true;
    };
    let too_old = match facts.max_age {
        MaxAge::Any => false,
        MaxAge::Seconds(seconds) => {
            facts.now > at.saturating_add(Duration::seconds(i64::from(seconds)))
        }
    };
    let too_weak = match facts.acr {
        RequestedAcr::Any => false,
        RequestedAcr::AtLeast(level) => !assurance.satisfies(level),
    };
    let not_fresh =
        facts.prompts.asks(Prompt::Login) && facts.now > at.saturating_add(FRESH_SIGN_IN);
    too_old || too_weak || not_fresh || facts.prompts.asks(Prompt::SelectAccount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::oauth::clients::client::NewOAuthClient;
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{ClientId, OAuthClientId, TokenHash};

    /// Where Ann's app registered its answers to go.
    const REDIRECT: &str = "https://app.acme.com/callback";

    /// Ann's app, which may use the code flow and ask for `openid`.
    fn code_client() -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("web_app").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored(
                    "hashed_secret".to_owned(),
                )),
                name: crate::test_support::builders::label("Web app"),
                redirect_uris: vec![RedirectUri::new(REDIRECT).unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: vec![Scope::new("openid").unwrap()],
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// The scopes `names` name.
    fn scopes(names: &[&str]) -> AskedScopes {
        AskedScopes::Named(
            names
                .iter()
                .map(|name| Scope::new(*name).unwrap())
                .collect(),
        )
    }

    /// The client's own redirect.
    fn redirect() -> RedirectUri {
        RedirectUri::new(REDIRECT).unwrap()
    }

    /// A code request with PKCE for `scopes`, prompting nothing, answered in
    /// the query.
    fn asked(scopes: &AskedScopes) -> AskedRequest {
        AskedRequest {
            flow: AskedFlow::CodeWithS256Challenge,
            scopes: scopes.clone(),
            prompts: AskedPrompts::Named(Vec::new()),
            response_mode: ResponseMode::Query,
        }
    }

    /// The screen of a code request with PKCE for `scopes`, by `client`.
    fn screened(
        client: Option<&OAuthClient<ResolvedTenant>>,
        scopes: &AskedScopes,
    ) -> RequestScreen {
        screen(client, &redirect(), &asked(scopes))
    }

    /// A request asking `flow`, otherwise proper.
    fn with_flow(flow: AskedFlow) -> AskedRequest {
        AskedRequest {
            flow,
            ..asked(&scopes(&["openid"]))
        }
    }

    /// Ann's app asks properly. She goes on to sign in and consent.
    #[test]
    fn a_proper_request_goes_on_to_consent() {
        let client = code_client();

        assert_eq!(
            screened(Some(&client), &scopes(&["openid"])),
            RequestScreen::Proceed
        );
    }

    /// A request naming an unregistered redirect is answered only to the
    /// browser, even when its response type is also unsupported.
    #[test]
    fn a_redirect_the_client_did_not_register_is_told_only_to_the_browser() {
        let client = code_client();
        let theirs = RedirectUri::new("https://evil.test/callback").unwrap();

        let answer = screen(Some(&client), &theirs, &with_flow(AskedFlow::NotCode));

        assert_eq!(answer, RequestScreen::TellBrowser);
    }

    /// An unknown client has no redirect to trust, so only the browser is
    /// told.
    #[test]
    fn an_unknown_client_is_told_only_to_the_browser() {
        assert_eq!(
            screened(None, &scopes(&["openid"])),
            RequestScreen::TellBrowser
        );
    }

    /// A request for something other than a code is told to the client.
    #[test]
    fn a_request_for_no_code_is_told_to_the_client() {
        let client = code_client();

        let answer = screen(Some(&client), &redirect(), &with_flow(AskedFlow::NotCode));

        assert_eq!(
            answer,
            RequestScreen::TellClient(AuthorizeRefusal::UnsupportedResponseType)
        );
    }

    /// With a registered redirect, a code request lacking an S256 challenge
    /// is reported to the client as invalid.
    #[test]
    fn a_request_without_pkce_is_told_to_the_client() {
        let client = code_client();

        let answer = screen(
            Some(&client),
            &redirect(),
            &with_flow(AskedFlow::NoS256Challenge),
        );

        assert_eq!(
            answer,
            RequestScreen::TellClient(AuthorizeRefusal::InvalidRequest)
        );
    }

    /// Screening an authorization request after client revocation tells the
    /// client it is unauthorized.
    #[test]
    fn a_revoked_client_is_told_it_may_not_ask() {
        let mut client = code_client();
        client.revoke(&key_admin()).unwrap();

        assert_eq!(
            screened(Some(&client), &scopes(&["openid"])),
            RequestScreen::TellClient(AuthorizeRefusal::UnauthorizedClient)
        );
    }

    /// A scope the client was not given, or one that is not a scope, is
    /// told to the client.
    #[test]
    fn a_scope_the_client_lacks_is_told_to_the_client() {
        let client = code_client();

        for asked in [scopes(&["admin:everything"]), AskedScopes::Unreadable] {
            assert_eq!(
                screened(Some(&client), &asked),
                RequestScreen::TellClient(AuthorizeRefusal::InvalidScope)
            );
        }
    }

    /// Contradictory none-and-login prompts and an unsupported response mode
    /// each produce an invalid-request response to the known client.
    #[test]
    fn contradicting_prompts_or_an_unknown_mode_are_invalid() {
        let client = code_client();
        let both = AskedRequest {
            prompts: AskedPrompts::Named(vec![Prompt::None, Prompt::Login]),
            ..asked(&scopes(&["openid"]))
        };
        let mode = AskedRequest {
            response_mode: ResponseMode::Unsupported,
            ..asked(&scopes(&["openid"]))
        };

        for request in [both, mode] {
            assert_eq!(
                screen(Some(&client), &redirect(), &request),
                RequestScreen::TellClient(AuthorizeRefusal::InvalidRequest)
            );
        }
    }

    /// The facts of a consent step for `prompts`, with Ann signed in an hour
    /// ago at AAL1, having consented before.
    fn facts(prompts: &AskedPrompts) -> InteractionFacts<'_> {
        let now = crate::shared::clock::now();
        InteractionFacts {
            prompts,
            max_age: MaxAge::Any,
            acr: RequestedAcr::Any,
            presence: SignInPresence::SignedIn {
                at: now - Duration::hours(1),
                assurance: AssuranceLevel::Aal1,
            },
            consent: ConsentStanding::Covers,
            now,
        }
    }

    /// Leaves prompt selection empty so tests exercise the normal consent decision.
    fn no_prompts() -> AskedPrompts {
        AskedPrompts::Named(Vec::new())
    }

    /// Ann is signed in and consented before. Her app's code is issued at
    /// once, with nothing shown.
    #[test]
    fn a_signed_in_person_who_consented_gets_a_code_at_once() {
        let prompts = no_prompts();

        assert_eq!(interaction(&facts(&prompts)), Interaction::IssueNow);
    }

    /// Nobody is signed in: the person signs in first; with `prompt=none`
    /// the client is told a sign-in is needed instead.
    #[test]
    fn nobody_signed_in_must_sign_in() {
        let prompts = no_prompts();
        let silent = AskedPrompts::Named(vec![Prompt::None]);
        let signed_out = |prompts| InteractionFacts {
            presence: SignInPresence::SignedOut,
            ..facts(prompts)
        };

        assert_eq!(interaction(&signed_out(&prompts)), Interaction::SignIn);
        assert_eq!(
            interaction(&signed_out(&silent)),
            Interaction::Refuse(AuthorizeRefusal::LoginRequired)
        );
    }

    /// An hour-old AAL1 sign-in requires another sign-in when the request
    /// demands either a five-minute maximum age or AAL2 assurance.
    #[test]
    fn an_old_or_weak_sign_in_must_sign_in_again() {
        let prompts = no_prompts();
        let old = InteractionFacts {
            max_age: MaxAge::Seconds(300),
            ..facts(&prompts)
        };
        let weak = InteractionFacts {
            acr: RequestedAcr::AtLeast(AssuranceLevel::Aal2),
            ..facts(&prompts)
        };

        assert_eq!(interaction(&old), Interaction::SignIn);
        assert_eq!(interaction(&weak), Interaction::SignIn);
    }

    /// Ann never agreed to all the app asks: she is asked to consent; with
    /// `prompt=none` the client is told consent is needed.
    #[test]
    fn missing_consent_is_asked_for() {
        let prompts = no_prompts();
        let silent = AskedPrompts::Named(vec![Prompt::None]);
        let missing = |prompts| InteractionFacts {
            consent: ConsentStanding::Missing,
            ..facts(prompts)
        };

        assert_eq!(interaction(&missing(&prompts)), Interaction::Consent);
        assert_eq!(
            interaction(&missing(&silent)),
            Interaction::Refuse(AuthorizeRefusal::ConsentRequired)
        );
    }

    /// `acr_values` asks for the weakest level it names that is known; an
    /// unknown value asks for nothing.
    #[test]
    fn acr_values_ask_for_the_weakest_known_level() {
        assert_eq!(
            RequestedAcr::from_values(["aal3", "aal2", "gold"]),
            RequestedAcr::AtLeast(AssuranceLevel::Aal2)
        );
        assert_eq!(RequestedAcr::from_values(["gold"]), RequestedAcr::Any);
    }
}
