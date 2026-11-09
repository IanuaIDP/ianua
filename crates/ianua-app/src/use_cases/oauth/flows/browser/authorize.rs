//! The consent step of the `OAuth2` code flow with PKCE: the person signed
//! in comes with an authorization request, and the request's `prompt`,
//! `max_age`, `acr_values` and `id_token_hint` decide whether a code is
//! issued now, they sign in again, they are asked to consent, or the
//! client is told what would have been needed.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::account_check::SessionCheck;
use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::consent::OAuthConsent;
use ianua_domain::domains::oauth::grants::authorization_code::{
    AuthorizationCode, CodeChallengeMethod, Consenting, CreateAuthCodeParams,
};
use ianua_domain::domains::oauth::grants::authorization_request::{
    AskedPrompts, AskedScopes, AuthorizeRefusal, ConsentStanding, Interaction, InteractionFacts,
    Prompt, RequestScreen, SignInPresence, interaction, screen,
};
use ianua_domain::domains::oauth::grants::id_token_hint::IdTokenHint;
use ianua_domain::domains::oauth::grants::pushed_request::PushedParameters;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, Issuer, Lifetime, Scope, TokenHash};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::SigningKeyStore;
use crate::ports::oauth::{
    AuthCodeStore, CodeHasher, IdTokenHintVerifier, OAuthClientStore, OAuthConsentStore,
    PushedRequestStore,
};
use crate::services::lookup::existing_key_set;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::flows::BrowserParameters;
use crate::use_cases::oauth::flows::browser::pushed::{
    Source, ensure_pushed_used_once, parameters_of,
};
use crate::use_cases::oauth::flows::browser::reply::Reply;
use crate::use_cases::oauth::lookup::existing_client_by_client_id;

/// How long a code can be swapped for tokens: one minute.
const CODE_LIFETIME: Lifetime = Lifetime::from_secs(NonZeroU32::MIN.saturating_add(59));

/// Whether the person was just shown the consent screen and agreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentAnswer {
    /// Not yet: the request comes straight from the browser.
    NotAskedYet,
    /// They agreed to what the request asks, on the consent screen.
    Given,
}

/// The `id_token_hint` a request carried, if any.
pub enum HintSent {
    /// None.
    NotSent,
    /// This raw ID token, naming the person the app means.
    Sent(Secret),
}

/// What the person signed in comes with.
pub struct AuthorizeRequest {
    /// The client asking, by the public id it names itself by.
    pub client_id: ClientId,
    /// The request's parameters, carried or pushed.
    pub parameters: BrowserParameters,
    /// Whether the person just agreed on the consent screen.
    pub answer: ConsentAnswer,
    /// The `id_token_hint`, if any.
    pub id_token_hint: HintSent,
    /// The tenant's issuer, which a hint must carry.
    pub issuer: Issuer,
}

/// Whether an authorization request gave the client new consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    /// The person agreed to something new with this request.
    NewlyGranted,
    /// The person had already agreed, or the client is first-party.
    AlreadyGiven,
}

/// What comes of the consent step.
pub enum AuthorizeOutcome {
    /// A code was issued, to go back to the client.
    Issued {
        /// The raw code, sent once.
        code: Secret,
        /// Whether this request gave new consent.
        consent: Consent,
        /// Where and how it goes.
        reply: Reply,
    },
    /// The person must sign in, again, or as another account, first.
    SignIn,
    /// The person must be asked to consent to these scopes first.
    AskConsent {
        /// The scopes asked for.
        scopes: Vec<Scope>,
    },
    /// The client is told why no code comes: `login_required`,
    /// `consent_required`, or a fault in its request.
    Refused {
        /// Why.
        refusal: AuthorizeRefusal,
        /// Where and how the client is told.
        reply: Reply,
    },
}

/// The ports [`AuthorizeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AuthorizePorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Where issued codes are kept.
    pub auth_code_store: Arc<dyn AuthCodeStore>,
    /// Where the scopes people gave clients are kept.
    pub consent_store: Arc<dyn OAuthConsentStore>,
    /// Makes the raw code and its hash.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// Where pushed requests are kept.
    pub pushed_store: Arc<dyn PushedRequestStore>,
    /// Reads an `id_token_hint`.
    pub hint_verifier: Arc<dyn IdTokenHintVerifier>,
    /// Where the tenant's signing keys are kept, to check a hint against.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Decides the consent step, and issues a code when it may.
pub struct AuthorizeUseCase {
    ports: AuthorizePorts,
}

/// The request being answered, with its client and the person.
struct Asked<'a> {
    person: &'a SignedInAccount,
    client: &'a OAuthClient<ResolvedTenant>,
    parameters: &'a PushedParameters,
    source: &'a Source,
    scopes: &'a [Scope],
}

/// What the person brought besides the request: whether they just
/// consented, a hint, and the issuer the hint must carry.
struct Answers<'a> {
    consent: ConsentAnswer,
    hint: &'a HintSent,
    issuer: &'a Issuer,
}

/// A request screened again at the consent step.
enum Screened {
    /// It holds, asking these scopes.
    Scopes(Vec<Scope>),
    /// The client is told this is wrong.
    Refused(AuthorizeRefusal),
}

impl AuthorizeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AuthorizePorts) -> Self {
        Self { ports }
    }

    /// The client named `client_id`, with the request's `parameters`, read
    /// from storage when they were pushed, and where they came from.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant has no such client or pushed
    ///   request.
    /// - `AppError::Domain` when a pushed request was pushed by another
    ///   client, ran out, or was used already.
    /// - `AppError::Internal` on storage failure.
    async fn request_of(
        &self,
        tenant: &ScopedTenant,
        client_id: &ClientId,
        parameters: BrowserParameters,
    ) -> Result<(OAuthClient<ResolvedTenant>, PushedParameters, Source), AppError> {
        let store = self.ports.client_store.as_ref();
        let client = existing_client_by_client_id(store, tenant, client_id).await?;
        let pushed_store = self.ports.pushed_store.as_ref();
        let (parameters, source) = parameters_of(pushed_store, tenant, &client, parameters).await?;
        Ok((client, parameters, source))
    }

    /// What the person must still do, as the request, their sign-in, their
    /// consent and any hint say.
    async fn next_step(
        &self,
        tenant: &ScopedTenant,
        asked: &Asked<'_>,
        answers: &Answers<'_>,
    ) -> Result<Interaction, AppError> {
        let consent = self
            .consent_standing(tenant, asked, answers.consent)
            .await?;
        let prompts = prompts_after(&asked.parameters.asked.prompts, answers.consent);
        let session = &asked.person.session;
        let facts = InteractionFacts {
            prompts: &prompts,
            max_age: asked.parameters.max_age,
            acr: asked.parameters.acr,
            presence: SignInPresence::SignedIn {
                at: session.signed_in_at(),
                assurance: session.assurance_level(),
            },
            consent,
            now: clock::now(),
        };
        let step = interaction(&facts);
        let hint = self.hint(tenant, answers.hint, answers.issuer).await?;
        Ok(held_to_hint(step, hint.as_ref(), asked, &prompts))
    }

    /// Whether the person's consent covers what is asked: given just now,
    /// recorded before, or not needed for a first-party client.
    async fn consent_standing(
        &self,
        tenant: &ScopedTenant,
        asked: &Asked<'_>,
        answer: ConsentAnswer,
    ) -> Result<ConsentStanding, AppError> {
        if answer == ConsentAnswer::Given {
            return Ok(ConsentStanding::Covers);
        }
        let recorded = self
            .ports
            .consent_store
            .find(tenant, asked.person.account.id(), asked.client.id())
            .await
            .or_internal()?;
        let standing = match recorded {
            Some(consent) if consent.covers_scopes(asked.scopes) => ConsentStanding::Covers,
            Some(_) | None => ConsentStanding::Missing,
        };
        Ok(asked.client.settings().consent.standing(standing))
    }

    /// What a hint the request sent names, once its signature checked out.
    async fn hint(
        &self,
        tenant: &ScopedTenant,
        sent: &HintSent,
        issuer: &Issuer,
    ) -> Result<Option<IdTokenHint>, AppError> {
        let HintSent::Sent(raw) = sent else {
            return Ok(None);
        };
        let keys = existing_key_set(self.ports.key_store.as_ref(), tenant).await?;
        let claims = self
            .ports
            .hint_verifier
            .verify(raw, &keys, issuer)
            .await
            .map_err(AppError::from_domain)?;
        Ok(Some(IdTokenHint::verified(
            claims.audience,
            claims.subject,
            claims.session,
        )))
    }

    /// The code `asked` is worth, issued for the person in the session they
    /// came with, with its raw value.
    async fn issued_code(
        &self,
        asked: &Asked<'_>,
    ) -> Result<(AuthorizationCode<ResolvedTenant>, Secret), AppError> {
        let person = asked.person;
        let check = SessionCheck {
            account: &person.account,
            timeout: &person.timeout,
            now: clock::now(),
        };
        let (raw, code_hash) = self.ports.code_hasher.generate_code().await.or_internal()?;
        let consenting = Consenting {
            session: &person.session,
            check: &check,
        };
        let params = code_params(asked, code_hash);
        let code = AuthorizationCode::create(params, asked.client, &consenting)
            .map_err(AppError::from_domain)?;
        Ok((code, raw))
    }

    /// The consent the person just gave, when it is more than they gave
    /// before.
    async fn widened_consent(
        &self,
        tenant: &ScopedTenant,
        asked: &Asked<'_>,
        answer: ConsentAnswer,
    ) -> Result<Option<OAuthConsent<ResolvedTenant>>, AppError> {
        if answer == ConsentAnswer::NotAskedYet {
            return Ok(None);
        }
        let person = asked.person;
        let user_id = person.account.id();
        let given = self
            .ports
            .consent_store
            .find(tenant, user_id, asked.client.id())
            .await
            .or_internal()?;
        let scopes = asked.scopes;
        let consent = match given {
            Some(consent) if consent.covers_scopes(scopes) => return Ok(None),
            Some(mut consent) => consent
                .extend_scopes(scopes, asked.client, &person.signed_in)
                .map(|()| consent),
            None => OAuthConsent::grant(*user_id, asked.client, scopes.to_vec(), &person.signed_in),
        };
        consent.map(Some).map_err(AppError::from_domain)
    }

    /// Issues the code, records any consent the person just gave, keeps
    /// both and records them.
    async fn issue(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        asked: &Asked<'_>,
        answer: ConsentAnswer,
    ) -> Result<(Secret, Consent), AppError> {
        let tenant = caller.tenant();
        let (mut code, raw) = self.issued_code(asked).await?;
        let mut consent = self.widened_consent(&tenant, asked, answer).await?;
        if let Some(consent) = &consent {
            self.ports
                .consent_store
                .save(&tenant, consent)
                .await
                .or_internal()?;
        }
        self.ports
            .auth_code_store
            .save(&tenant, &code)
            .await
            .or_internal()?;
        let mut events = consent
            .as_mut()
            .map_or_else(Vec::new, |consent| consent.take_events(&tenant));
        events.extend(code.take_events(&tenant));
        auditor
            .dispatch_by(&caller.actor(), events)
            .await
            .or_internal()?;
        let given = consent.map_or(Consent::AlreadyGiven, |_| Consent::NewlyGranted);
        Ok((raw, given))
    }

    /// The code `asked` is worth, issued once its pushed request, if any, is
    /// used up, with where and how it goes back to the client.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the pushed request was used already.
    /// - `AppError::Internal` when the code cannot be made, or the code or
    ///   consent cannot be saved or audited.
    async fn issued(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        asked: &Asked<'_>,
        answer: ConsentAnswer,
    ) -> Result<AuthorizeOutcome, AppError> {
        let pushed_store = self.ports.pushed_store.as_ref();
        ensure_pushed_used_once(pushed_store, &caller.tenant(), asked.source).await?;
        let (code, consent) = self.issue(caller, auditor, asked, answer).await?;
        Ok(AuthorizeOutcome::Issued {
            code,
            consent,
            reply: Reply::to(asked.parameters),
        })
    }
}

impl Command for AuthorizeUseCase {
    type Caller = CallerContext;
    type Input = AuthorizeRequest;
    type Output = Result<AuthorizeOutcome, AppError>;

    /// Answers the consent step for the person signed in to `caller`'s
    /// session. When nothing more is needed, issues a code and records any
    /// consent they just gave: `oauth.consent_granted` when they agreed to
    /// something new, then `oauth.authorization_code_issued`. Otherwise
    /// says whether they sign in again or are asked to consent, or what
    /// the client is told; nothing is recorded then, and a pushed request
    /// stays usable.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller is not a person signed
    ///   in to a session of the tenant, or the session no longer counts.
    /// - `AppError::NotFound` when the tenant has no such client or pushed
    ///   request.
    /// - `AppError::Forbidden` when the redirect is not one the client
    ///   registered, or a hint was not signed by the tenant.
    /// - `AppError::Domain` when a pushed request was pushed by another
    ///   client, ran out, or was used already.
    /// - `AppError::Internal` when the code cannot be made, or the code or
    ///   consent cannot be saved or audited.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: AuthorizeRequest,
    ) -> Result<AuthorizeOutcome, AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let tenant = caller.tenant();
        let (client, parameters, source) = self
            .request_of(&tenant, &req.client_id, req.parameters)
            .await?;
        let reply = Reply::to(&parameters);
        let scopes = match screened(&client, &parameters)? {
            Screened::Scopes(scopes) => scopes,
            Screened::Refused(refusal) => return Ok(AuthorizeOutcome::Refused { refusal, reply }),
        };
        let asked = Asked {
            person: &person,
            client: &client,
            parameters: &parameters,
            source: &source,
            scopes: &scopes,
        };
        let answers = Answers {
            consent: req.answer,
            hint: &req.id_token_hint,
            issuer: &req.issuer,
        };
        let step = self.next_step(&tenant, &asked, &answers).await?;
        let Interaction::IssueNow = step else {
            return Ok(not_issued(step, &scopes, reply));
        };
        self.issued(caller, auditor, &asked, req.answer).await
    }
}

/// `parameters`, asked of `client`, screened again: the client may have
/// changed since the browser was screened.
///
/// # Errors
///
/// - `AppError::Forbidden` when the redirect is not one the client
///   registered: nothing may go to it.
fn screened(
    client: &OAuthClient<ResolvedTenant>,
    parameters: &PushedParameters,
) -> Result<Screened, AppError> {
    match screen(Some(client), &parameters.redirect_uri, &parameters.asked) {
        RequestScreen::Proceed => {}
        RequestScreen::TellClient(refusal) => return Ok(Screened::Refused(refusal)),
        RequestScreen::TellBrowser => {
            return Err(AppError::Forbidden(message!(
                "oauth-the-client-did-not-register-this",
                "the client did not register this redirect"
            )));
        }
    }
    match &parameters.asked.scopes {
        AskedScopes::Named(scopes) => Ok(Screened::Scopes(scopes.clone())),
        AskedScopes::Unreadable => Ok(Screened::Refused(AuthorizeRefusal::InvalidScope)),
    }
}

/// What the consent step answers when `step` issues no code yet. It is
/// never asked for `IssueNow`; that would answer sign-in, which issues
/// nothing.
fn not_issued(step: Interaction, scopes: &[Scope], reply: Reply) -> AuthorizeOutcome {
    match step {
        Interaction::SignIn | Interaction::IssueNow => AuthorizeOutcome::SignIn,
        Interaction::Consent => AuthorizeOutcome::AskConsent {
            scopes: scopes.to_vec(),
        },
        Interaction::Refuse(refusal) => AuthorizeOutcome::Refused { refusal, reply },
    }
}

/// The prompts that still count: after the person agreed on the consent
/// screen, `prompt=consent` was answered.
fn prompts_after(prompts: &AskedPrompts, answer: ConsentAnswer) -> AskedPrompts {
    match (answer, prompts) {
        (ConsentAnswer::Given, AskedPrompts::Named(named)) => AskedPrompts::Named(
            named
                .iter()
                .copied()
                .filter(|prompt| *prompt != Prompt::Consent)
                .collect(),
        ),
        (ConsentAnswer::Given | ConsentAnswer::NotAskedYet, _) => prompts.clone(),
    }
}

/// `step`, held to `hint`: a hint issued to another client is a fault in
/// the request, and one about another person means the person signed in is
/// not the one the app means, so they sign in as that one before anything
/// else, or, with `prompt=none`, the client is told sign-in is needed.
fn held_to_hint(
    step: Interaction,
    hint: Option<&IdTokenHint>,
    asked: &Asked<'_>,
    prompts: &AskedPrompts,
) -> Interaction {
    let Some(hint) = hint else {
        return step;
    };
    if hint.ensure_issued_to(asked.client).is_err() {
        return Interaction::Refuse(AuthorizeRefusal::InvalidRequest);
    }
    if hint.is_about(asked.person.account.id()) {
        return step;
    }
    if prompts.asks(Prompt::None) {
        return Interaction::Refuse(AuthorizeRefusal::LoginRequired);
    }
    Interaction::SignIn
}

/// What a code for `asked` is made from, beside its client and session.
fn code_params(asked: &Asked<'_>, code_hash: TokenHash) -> CreateAuthCodeParams {
    let parameters = asked.parameters;
    CreateAuthCodeParams {
        code_hash,
        redirect_uri: parameters.redirect_uri.clone(),
        scopes: asked.scopes.to_vec(),
        code_challenge: parameters.code_challenge.clone(),
        code_challenge_method: CodeChallengeMethod::S256,
        nonce: parameters.nonce.clone(),
        lifetime: CODE_LIFETIME,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::clients::settings::ConsentPrompt;
    use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
    use ianua_domain::domains::oauth::grants::authorization_code::{CodeChallenge, NonceSent};
    use ianua_domain::domains::oauth::grants::authorization_request::{
        AskedFlow, AskedRequest, MaxAge, RequestedAcr, ResponseMode,
    };
    use ianua_domain::domains::oauth::grants::pushed_request::{PushedRequest, StateSent};
    use ianua_domain::types::{PushedRequestId, RedirectUri, SessionId, UserId};

    use super::*;
    use crate::ports::oauth::HintClaims;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{FakeSigningKeyStore, premigration_keys};
    use crate::test_support::oauth::{
        FakeAuthCodeStore, FakeIdTokenHintVerifier, FakeOAuthClientStore, FakeOAuthConsentStore,
        FakePushedRequestStore, TEST_REDIRECT, TEST_VERIFIER, client_with, hash_of, stored_client,
        test_issuer,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with, test_session_id,
    };

    /// The portal asking properly for `read`, prompting as `prompts` say.
    fn parameters(prompts: &[Prompt]) -> PushedParameters {
        PushedParameters {
            redirect_uri: RedirectUri::new(TEST_REDIRECT).unwrap(),
            asked: AskedRequest {
                flow: AskedFlow::CodeWithS256Challenge,
                scopes: AskedScopes::Named(vec![Scope::new("read").unwrap()]),
                prompts: AskedPrompts::Named(prompts.to_vec()),
                response_mode: ResponseMode::Query,
            },
            max_age: MaxAge::Any,
            acr: RequestedAcr::Any,
            code_challenge: CodeChallenge::new(TEST_VERIFIER).unwrap(),
            nonce: NonceSent::NotSent,
            state: StateSent::NotSent,
        }
    }

    /// Ann, signed in, and the tenant's stores, holding one client.
    struct Fixture {
        ann: UserId,
        caller: CallerContext,
        client: OAuthClient<ResolvedTenant>,
        clients: Arc<FakeOAuthClientStore>,
        codes: Arc<FakeAuthCodeStore>,
        consents: Arc<FakeOAuthConsentStore>,
        pushed: Arc<FakePushedRequestStore>,
        hints: FakeHints,
        audit: Arc<FakeEventDispatcher>,
    }

    /// What the hint verifier reads from every hint, if anything.
    enum FakeHints {
        /// Nothing: every hint is refused, as one the tenant never signed.
        Refusing,
        /// These claims, from every hint.
        Reading(HintClaims),
    }

    impl Fixture {
        /// Ann signed in, the tenant holding `client`.
        fn holding(client: OAuthClient<ResolvedTenant>) -> Self {
            let ann = UserId::new();
            let caller = test_ctx_with(test_ctx().organization_id(), test_ctx().tenant_id(), ann);
            Self {
                clients: Arc::new(FakeOAuthClientStore::holding(
                    &caller.tenant(),
                    client.clone(),
                )),
                client,
                codes: Arc::new(FakeAuthCodeStore::empty()),
                consents: Arc::new(FakeOAuthConsentStore::empty()),
                pushed: Arc::new(FakePushedRequestStore::empty()),
                hints: FakeHints::Refusing,
                audit: Arc::new(FakeEventDispatcher::new()),
                ann,
                caller,
            }
        }

        /// Ann signed in, the tenant holding the portal.
        fn portal() -> Self {
            Self::holding(stored_client("Portal", &[GrantType::AuthorizationCode]))
        }

        /// Ann coming with `parameters`, having answered as `answer` says.
        fn ask(&self, parameters: PushedParameters, answer: ConsentAnswer) -> AuthorizeRequest {
            AuthorizeRequest {
                client_id: self.client.client_id_value().clone(),
                parameters: BrowserParameters::Carried(parameters),
                answer,
                id_token_hint: HintSent::NotSent,
                issuer: test_issuer(),
            }
        }

        /// Ann coming straight from the browser, not asked yet.
        fn first_ask(&self) -> AuthorizeRequest {
            self.ask(parameters(&[]), ConsentAnswer::NotAskedYet)
        }

        /// Ann agreeing on the consent screen.
        fn consented(&self) -> AuthorizeRequest {
            self.ask(parameters(&[]), ConsentAnswer::Given)
        }

        /// What the consent step answers Ann for `req`.
        fn authorize(&self, req: AuthorizeRequest) -> Result<AuthorizeOutcome, AppError> {
            self.authorize_as(FakeTenantAuthorities::holding(&[]), req)
        }

        /// What the consent step answers a caller `authorities` describe
        /// for `req`.
        fn authorize_as(
            &self,
            authorities: FakeTenantAuthorities,
            req: AuthorizeRequest,
        ) -> Result<AuthorizeOutcome, AppError> {
            let hint_verifier = match &self.hints {
                FakeHints::Refusing => FakeIdTokenHintVerifier::refusing(),
                FakeHints::Reading(claims) => FakeIdTokenHintVerifier::reading(claims.clone()),
            };
            let use_case = AuthorizeUseCase::new(AuthorizePorts {
                client_store: self.clients.clone(),
                auth_code_store: self.codes.clone(),
                consent_store: self.consents.clone(),
                pushed_store: self.pushed.clone(),
                hint_verifier: Arc::new(hint_verifier),
                key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
                tenant_authorities: Arc::new(authorities),
                ..AuthorizePorts::fakes()
            });
            block_on(use_case.execute(&self.caller, &test_auditor(self.audit.clone()), req))
        }

        /// The audit records written, by event name.
        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        /// The same, with every hint read as an ID token for `audience`
        /// about `subject`.
        fn hinting_at(mut self, subject: UserId, audience: ClientId) -> Self {
            self.hints = FakeHints::Reading(HintClaims {
                audience,
                subject,
                session: SessionId::new(),
            });
            self
        }
    }

    /// The code and consent `outcome` issued; it must have issued one.
    fn issued(outcome: AuthorizeOutcome) -> (Secret, Consent) {
        let AuthorizeOutcome::Issued { code, consent, .. } = outcome else {
            panic!("no code was issued");
        };
        (code, consent)
    }

    /// What the client is told is wrong, if `outcome` refused it.
    fn refusal_of(outcome: &AuthorizeOutcome) -> Option<AuthorizeRefusal> {
        match outcome {
            AuthorizeOutcome::Refused { refusal, .. } => Some(*refusal),
            AuthorizeOutcome::Issued { .. }
            | AuthorizeOutcome::SignIn
            | AuthorizeOutcome::AskConsent { .. } => None,
        }
    }

    /// Ann comes with the portal's request for the first time. She is asked
    /// to consent to `read` first; no code is issued and nothing recorded.
    #[test]
    fn a_first_request_asks_for_consent() {
        let fixture = Fixture::portal();

        let outcome = fixture.authorize(fixture.first_ask()).unwrap();

        let AuthorizeOutcome::AskConsent { scopes } = outcome else {
            panic!("Ann was not asked to consent");
        };
        assert_eq!(scopes, [Scope::new("read").unwrap()]);
        assert_eq!(fixture.codes.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// Ann agrees on the consent screen. The portal gets a code, and her
    /// consent and the code are recorded.
    #[test]
    fn consent_given_issues_a_code() {
        let fixture = Fixture::portal();

        let (code, consent) = issued(fixture.authorize(fixture.consented()).unwrap());

        assert!(!code.expose().is_empty());
        assert_eq!(consent, Consent::NewlyGranted);
        assert_eq!(fixture.consents.count(), 1);
        assert_eq!(
            fixture.recorded(),
            ["oauth.consent_granted", "oauth.authorization_code_issued"]
        );
    }

    /// Ann's code keeps who she is and how she signed in, read from her
    /// session, so the ID token made from it says what her session proved.
    #[test]
    fn the_code_keeps_how_the_session_signed_in() {
        let fixture = Fixture::portal();

        let (raw, _) = issued(fixture.authorize(fixture.consented()).unwrap());

        let code = block_on(
            fixture
                .codes
                .find_by_hash(&fixture.caller.tenant(), &hash_of(raw.expose())),
        )
        .unwrap()
        .unwrap();
        assert_eq!(code.auth_method(), AuthMethod::Password);
        assert_eq!(code.user_id(), &fixture.ann);
        assert_eq!(code.session_id(), &test_session_id());
    }

    /// Ann already agreed to let the portal read. The next request issues a
    /// code at once, without asking her again or recording new consent.
    #[test]
    fn consent_already_given_issues_at_once() {
        let fixture = Fixture::portal();
        fixture.authorize(fixture.consented()).unwrap();

        let (_, consent) = issued(fixture.authorize(fixture.first_ask()).unwrap());

        assert_eq!(consent, Consent::AlreadyGiven);
        assert_eq!(fixture.recorded().len(), 3);
    }

    /// The tenant's own dashboard is first-party. Ann is never asked; a code
    /// is issued at once.
    #[test]
    fn a_first_party_client_issues_without_asking() {
        let fixture = Fixture::holding(client_with(
            "Dashboard",
            &[GrantType::AuthorizationCode],
            |row| row.settings.consent = ConsentPrompt::FirstParty,
        ));

        let outcome = fixture.authorize(fixture.first_ask()).unwrap();

        assert!(matches!(outcome, AuthorizeOutcome::Issued { .. }));
    }

    /// The portal renews silently with `prompt=none`, but Ann never agreed.
    /// Nothing may be shown, so the portal is told consent is required.
    #[test]
    fn silent_renewal_without_consent_is_told_consent_is_required() {
        let fixture = Fixture::portal();

        let outcome = fixture
            .authorize(fixture.ask(parameters(&[Prompt::None]), ConsentAnswer::NotAskedYet))
            .unwrap();

        assert_eq!(
            refusal_of(&outcome),
            Some(AuthorizeRefusal::ConsentRequired)
        );
        assert_eq!(fixture.codes.count(), 0);
    }

    /// Ann agreed before, but the portal asks again with `prompt=consent`.
    /// She is asked again.
    #[test]
    fn prompt_consent_asks_again() {
        let fixture = Fixture::portal();
        fixture.authorize(fixture.consented()).unwrap();

        let outcome = fixture
            .authorize(fixture.ask(parameters(&[Prompt::Consent]), ConsentAnswer::NotAskedYet))
            .unwrap();

        assert!(matches!(outcome, AuthorizeOutcome::AskConsent { .. }));
    }

    /// An AAL3 request with a password-only session requires another
    /// sign-in and stores no authorization code.
    #[test]
    fn a_weaker_sign_in_than_asked_must_sign_in_again() {
        let fixture = Fixture::portal();
        let mut asked = parameters(&[]);
        asked.acr = RequestedAcr::AtLeast(AssuranceLevel::Aal3);

        let outcome = fixture
            .authorize(fixture.ask(asked, ConsentAnswer::Given))
            .unwrap();

        assert!(matches!(outcome, AuthorizeOutcome::SignIn));
        assert_eq!(fixture.codes.count(), 0);
    }

    /// The same, silently: with `prompt=none` the app is told sign-in is
    /// required.
    #[test]
    fn a_weaker_sign_in_silently_is_told_login_is_required() {
        let fixture = Fixture::portal();
        let mut asked = parameters(&[Prompt::None]);
        asked.acr = RequestedAcr::AtLeast(AssuranceLevel::Aal3);

        let outcome = fixture
            .authorize(fixture.ask(asked, ConsentAnswer::NotAskedYet))
            .unwrap();

        assert_eq!(refusal_of(&outcome), Some(AuthorizeRefusal::LoginRequired));
    }

    /// Silent authorization with another person's ID-token hint returns
    /// login_required even after Ann has consented.
    #[test]
    fn a_hint_about_someone_else_is_told_login_is_required() {
        let portal = Fixture::portal();
        let client_id = portal.client.client_id_value().clone();
        let fixture = portal.hinting_at(UserId::new(), client_id);
        fixture.authorize(fixture.consented()).unwrap();
        let req = AuthorizeRequest {
            id_token_hint: HintSent::Sent(Secret::new("bobs-id-token")),
            ..fixture.ask(parameters(&[Prompt::None]), ConsentAnswer::NotAskedYet)
        };

        let outcome = fixture.authorize(req).unwrap();

        assert_eq!(refusal_of(&outcome), Some(AuthorizeRefusal::LoginRequired));
    }

    /// Authorization carrying an ID-token hint issued to another client
    /// returns invalid_request.
    #[test]
    fn a_hint_for_another_client_is_an_invalid_request() {
        let portal = Fixture::portal();
        let ann = portal.ann;
        let fixture = portal.hinting_at(ann, ClientId::new("client_mallory").unwrap());
        let req = AuthorizeRequest {
            id_token_hint: HintSent::Sent(Secret::new("mallorys-id-token")),
            ..fixture.consented()
        };

        let outcome = fixture.authorize(req).unwrap();

        assert_eq!(refusal_of(&outcome), Some(AuthorizeRefusal::InvalidRequest));
    }

    /// An unregistered authorization redirect is forbidden, with no stored
    /// code or audit event.
    #[test]
    fn a_redirect_the_client_did_not_register_is_refused() {
        let fixture = Fixture::portal();
        let mut asked = parameters(&[]);
        asked.redirect_uri = RedirectUri::new("https://evil.example/callback").unwrap();

        let result = fixture.authorize(fixture.ask(asked, ConsentAnswer::Given));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.codes.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// An ungranted scope returns invalid_scope and stores no consent even
    /// when Ann submitted agreement.
    #[test]
    fn a_scope_the_client_may_not_ask_for_is_refused() {
        let fixture = Fixture::portal();
        let mut asked = parameters(&[]);
        asked.asked.scopes = AskedScopes::Named(vec![Scope::new("admin").unwrap()]);

        let outcome = fixture
            .authorize(fixture.ask(asked, ConsentAnswer::Given))
            .unwrap();

        assert_eq!(refusal_of(&outcome), Some(AuthorizeRefusal::InvalidScope));
        assert_eq!(fixture.consents.count(), 0);
    }

    /// A revoked client receives unauthorized_client at the consent step.
    #[test]
    fn a_revoked_client_is_refused() {
        let fixture = Fixture::holding(client_with(
            "Portal",
            &[GrantType::AuthorizationCode],
            |row| row.status = OAuthClientStatus::Revoked,
        ));

        let outcome = fixture.authorize(fixture.consented()).unwrap();

        assert_eq!(
            refusal_of(&outcome),
            Some(AuthorizeRefusal::UnauthorizedClient)
        );
    }

    /// An unknown authorization client returns not found and records no event.
    #[test]
    fn an_unknown_client_is_not_found() {
        let fixture = Fixture::portal();

        let result = fixture.authorize(AuthorizeRequest {
            client_id: ClientId::new("client_unknown").unwrap(),
            ..fixture.consented()
        });

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// The portal pushed its request. Ann agrees, a code is issued, and the
    /// pushed request is used up.
    #[test]
    fn a_pushed_request_issues_once() {
        let fixture = Fixture::portal();
        let request =
            PushedRequest::push(PushedRequestId::new(), &fixture.client, parameters(&[])).unwrap();
        block_on(fixture.pushed.insert(&fixture.caller.tenant(), &request)).unwrap();
        let req = || AuthorizeRequest {
            parameters: BrowserParameters::Pushed(request.request_uri()),
            ..fixture.consented()
        };

        let first = fixture.authorize(req()).unwrap();
        let replay = fixture.authorize(req());

        assert!(matches!(first, AuthorizeOutcome::Issued { .. }));
        assert!(fixture.pushed.is_used(request.id()));
        assert!(matches!(replay, Err(AppError::Domain(_))));
        assert_eq!(fixture.codes.count(), 1);
    }

    /// A signed-out caller cannot authorize the portal and receives an
    /// unauthenticated error with no stored code.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::portal();

        let result = fixture.authorize_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.consented(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.codes.count(), 0);
    }
}
