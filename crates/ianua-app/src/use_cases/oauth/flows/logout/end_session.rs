//! An app signing a person out through ianua (OpenID Connect RP-Initiated
//! Logout): the person's session ends, what it handed out ends with it,
//! the apps that asked are shown the pages that end their own sessions, and
//! the person goes back to an address the app registered, or stays on the
//! signed-out page.
//!
//! A sign-out link anyone can send would sign people out on a whim, so the
//! session ends at once only when the app proves who it means with an ID
//! token naming the person signed in. Otherwise the person is asked first.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::grants::id_token_hint::IdTokenHint;
use ianua_domain::domains::oauth::grants::logout::{AfterLogout, after_logout};
use ianua_domain::domains::oauth::grants::logout_notice::{
    FrontChannelVisit, SignedOut, front_channel_visit,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{
    ActorRef, ClientId, HttpsUrl, Issuer, OAuthClientId, RedirectUri, SessionId,
};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::SigningKeyStore;
use crate::ports::oauth::{
    AuthCodeStore, IdTokenHintVerifier, OAuthClientStore, RefreshTokenStore,
};
use crate::ports::shared::SessionStore;
use crate::services::authentication::logout_browser::LogoutBrowser;
use crate::services::lookup::existing_key_set;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::flows::HintSent;

/// The client a sign-out request names, if any (`client_id`).
pub enum ClientNamed {
    /// None; the hint's audience names it, if a hint came.
    NotNamed,
    /// The explicit client identifier supplied by the request.
    Named(ClientId),
}

/// The address a sign-out request asks to go back to, if any
/// (`post_logout_redirect_uri`).
pub enum AddressAsked {
    /// None.
    NotAsked,
    /// The requested destination to validate before redirecting.
    Asked(RedirectUri),
}

/// Whether the person confirmed, on the signed-out page, that they sign
/// out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutConfirmation {
    /// Not yet: the request comes from the app.
    NotAsked,
    /// They did.
    Confirmed,
}

/// What an app's sign-out request carries.
pub struct EndSessionRequest {
    /// The tenant's issuer, which a hint must carry.
    pub issuer: Issuer,
    /// The ID token the app holds for the person, if it sent one.
    pub id_token_hint: HintSent,
    /// The client it names.
    pub client_id: ClientNamed,
    /// Where it asks the person be sent back.
    pub post_logout_redirect_uri: AddressAsked,
    /// Whether the person confirmed.
    pub confirmation: LogoutConfirmation,
}

/// What comes of a sign-out request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndSessionOutcome {
    /// The session ended. The browser loads each page in `front_channel`,
    /// then goes where `after` says.
    SignedOut {
        /// Where the person goes.
        after: AfterLogout,
        /// The pages that end the apps' own sessions.
        front_channel: Vec<HttpsUrl>,
    },
    /// The person is asked whether they mean to sign out; nothing ended.
    ConfirmFirst {
        /// Where they go once they confirm.
        after: AfterLogout,
    },
    /// Nobody was signed in; the person goes where `after` says.
    NotSignedIn {
        /// Where the person goes.
        after: AfterLogout,
    },
}

/// The ports [`EndSessionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EndSessionPorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Reads an `id_token_hint`.
    pub hint_verifier: Arc<dyn IdTokenHintVerifier>,
    /// Where the tenant's signing keys are kept, to check a hint against.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// The tenant's sessions.
    pub session_store: Arc<dyn SessionStore>,
    /// Where refresh tokens are kept; the session's end with it.
    pub refresh_token_store: Arc<dyn RefreshTokenStore>,
    /// Where codes are kept, to find the apps the session signed in to.
    pub auth_code_store: Arc<dyn AuthCodeStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Signs a person out at an app's request.
pub struct EndSessionUseCase {
    ports: EndSessionPorts,
}

/// What the request settled before anyone is signed out: the hint, and
/// where the person goes after.
struct Settled {
    hint: Option<IdTokenHint>,
    after: AfterLogout,
}

impl EndSessionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EndSessionPorts) -> Self {
        Self { ports }
    }

    /// What the hint `sent` names, once its signature checked out.
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
            .map_err(|_| {
                AppError::Domain(DomainError::invalid(message!(
                    "oauth-the-id-token-hint-was-not",
                    "the id_token_hint was not signed by this tenant"
                )))
            })?;
        Ok(Some(IdTokenHint::verified(
            claims.audience,
            claims.subject,
            claims.session,
        )))
    }

    /// The client the request names, or the hint's audience, if the tenant
    /// has it; a hint must have been issued to it.
    async fn named_client(
        &self,
        tenant: &ScopedTenant,
        named: &ClientNamed,
        hint: Option<&IdTokenHint>,
    ) -> Result<Option<OAuthClient<ResolvedTenant>>, AppError> {
        let id = match (named, hint) {
            (ClientNamed::Named(id), _) => id,
            (ClientNamed::NotNamed, Some(hint)) => hint.audience(),
            (ClientNamed::NotNamed, None) => return Ok(None),
        };
        let client = self
            .ports
            .client_store
            .find_by_client_id_value(tenant, id)
            .await
            .or_internal()?;
        if let (Some(client), Some(hint)) = (&client, hint) {
            hint.ensure_issued_to(client)
                .map_err(AppError::from_domain)?;
        }
        Ok(client)
    }

    /// Ends `person`'s session and the refresh tokens granted in it, and
    /// records `authentication.session_revoked`, which drops its cached
    /// caller once kept.
    async fn ended(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        person: SignedInAccount,
    ) -> Result<SignedInAccount, AppError> {
        let mut person = person;
        person
            .session
            .revoke(&person.signed_in)
            .map_err(AppError::from_domain)?;
        let sessions = self.ports.session_store.as_ref();
        sessions.save(tenant, &person.session).await.or_internal()?;
        self.ports
            .refresh_token_store
            .revoke_session(tenant, person.session.id(), clock::now())
            .await
            .or_internal()?;
        let holder = ActorRef::User(*person.session.user_id());
        auditor
            .dispatch_by(&holder, person.session.take_events(tenant))
            .await
            .or_internal()?;
        Ok(person)
    }

    /// The pages that end, in the person's browser, the sessions of the
    /// apps they signed in to through the session that ended.
    async fn front_channel(
        &self,
        tenant: &ScopedTenant,
        issuer: &Issuer,
        person: &SignedInAccount,
    ) -> Result<Vec<HttpsUrl>, AppError> {
        let session = person.session.id();
        let signed_into = self
            .ports
            .auth_code_store
            .consented_sessions(
                tenant,
                SignedOut::Session {
                    person: *person.account.id(),
                    session: *session,
                },
            )
            .await
            .or_internal()?;
        let ids: Vec<_> = signed_into
            .iter()
            .filter(|pair| pair.session == *session)
            .map(|pair| pair.client)
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let clients = self
            .ports
            .client_store
            .find_by_ids(tenant, &ids)
            .await
            .or_internal()?;
        front_channel_pages(&clients, &ids, issuer, session)
    }

    /// Signs out the person signed in to `caller`, when the hint names them
    /// or they confirmed, and says what comes of it.
    async fn signed_in_outcome(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: &EndSessionRequest,
        settled: Settled,
    ) -> Result<EndSessionOutcome, AppError> {
        let tenant = caller.tenant();
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let named_them = settled
            .hint
            .as_ref()
            .is_some_and(|hint| hint.is_about(person.account.id()));
        let confirmed = req.confirmation == LogoutConfirmation::Confirmed;
        if !named_them && !confirmed {
            return Ok(EndSessionOutcome::ConfirmFirst {
                after: settled.after,
            });
        }
        let person = self.ended(auditor, &tenant, person).await?;
        let front_channel = self.front_channel(&tenant, &req.issuer, &person).await?;
        Ok(EndSessionOutcome::SignedOut {
            after: settled.after,
            front_channel,
        })
    }
}

impl Command for EndSessionUseCase {
    type Caller = LogoutBrowser;
    type Input = EndSessionRequest;
    type Output = Result<EndSessionOutcome, AppError>;

    /// Answers the sign-out request `req` brings for `who`. When the session
    /// ends, its refresh tokens are revoked and
    /// `authentication.session_revoked` is recorded; the worker that hears
    /// it tells the apps that take back-channel logout.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts.
    /// - `AppError::Domain` when the hint was not signed by the tenant, or
    ///   was issued to another client than the one named.
    /// - `AppError::NotFound` when a hint came and the tenant has no signing
    ///   keys to check it against.
    /// - `AppError::Internal` when a lookup, write or the audit fails.
    async fn execute(
        &self,
        who: &LogoutBrowser,
        auditor: &RequestAuditor,
        req: EndSessionRequest,
    ) -> Result<EndSessionOutcome, AppError> {
        let tenant = who.tenant();
        let hint = self.hint(&tenant, &req.id_token_hint, &req.issuer).await?;
        let client = self
            .named_client(&tenant, &req.client_id, hint.as_ref())
            .await?;
        let asked = match &req.post_logout_redirect_uri {
            AddressAsked::Asked(uri) => Some(uri),
            AddressAsked::NotAsked => None,
        };
        let after = after_logout(client.as_ref(), asked);
        let LogoutBrowser::SignedIn(caller) = who else {
            return Ok(EndSessionOutcome::NotSignedIn { after });
        };
        let settled = Settled { hint, after };
        self.signed_in_outcome(caller, auditor, &req, settled).await
    }
}

/// Builds logout visits in the session's client order, omitting missing clients.
fn front_channel_pages(
    clients: &[OAuthClient<ResolvedTenant>],
    ids: &[OAuthClientId],
    issuer: &Issuer,
    session: &SessionId,
) -> Result<Vec<HttpsUrl>, AppError> {
    let clients: HashMap<_, _> = clients
        .iter()
        .map(|client| (*client.id(), client))
        .collect();
    let mut pages = Vec::new();
    for id in ids {
        let Some(client) = clients.get(id) else {
            continue;
        };
        let visit = front_channel_visit(client, issuer, session).map_err(AppError::from_domain)?;
        if let FrontChannelVisit::Visit(page) = visit {
            pages.push(page);
        }
    }
    Ok(pages)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::clients::settings::{ChannelLogout, SessionRequired};
    use ianua_domain::domains::oauth::grants::authorization_code::AuthorizationCode;
    use ianua_domain::domains::oauth::grants::refresh_token::RefreshState;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::ports::oauth::HintClaims;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authentication::FakeSessionStore;
    use crate::test_support::crypto::{FakeSigningKeyStore, premigration_keys};
    use crate::test_support::oauth::{
        FakeAuthCodeStore, FakeIdTokenHintVerifier, FakeOAuthClientStore, FakeRefreshTokenStore,
        TEST_AFTER_LOGOUT, TEST_REFRESH_TOKEN, client_with, code_row, hash_of, refresh_row,
        signed_in_session, test_issuer,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with, test_session_id,
    };

    /// Ann, signed in, who signed in to the portal through her session.
    struct Fixture {
        ann: UserId,
        caller: CallerContext,
        portal: OAuthClient<ResolvedTenant>,
        clients: Arc<FakeOAuthClientStore>,
        sessions: Arc<FakeSessionStore>,
        refresh: Arc<FakeRefreshTokenStore>,
        codes: Arc<FakeAuthCodeStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// Ann signed in to the portal, which takes front-channel logout.
        fn new() -> Self {
            let ann = UserId::new();
            let caller = test_ctx_with(test_ctx().organization_id(), test_ctx().tenant_id(), ann);
            let tenant = caller.tenant();
            let portal = client_with("Portal", &[GrantType::AuthorizationCode], |row| {
                row.settings.logout.front_channel = ChannelLogout::At {
                    uri: HttpsUrl::new("https://app.example.com/front-logout").unwrap(),
                    session: SessionRequired::NotRequired,
                };
            });
            let codes = Arc::new(FakeAuthCodeStore::empty());
            let code = AuthorizationCode::reconstitute(code_row(&portal, ann)).unwrap();
            block_on(codes.save(&tenant, &code)).unwrap();
            Self {
                clients: Arc::new(FakeOAuthClientStore::holding(&tenant, portal.clone())),
                sessions: Arc::new(FakeSessionStore::with_session(signed_in_session(
                    test_session_id(),
                    ann,
                ))),
                refresh: Arc::new(FakeRefreshTokenStore::holding(
                    &tenant,
                    refresh_row(&portal, ann),
                )),
                portal,
                codes,
                audit: Arc::new(FakeEventDispatcher::new()),
                ann,
                caller,
            }
        }

        /// What the sign-out request `req` comes to for `who`, with hints
        /// read as `hints` says.
        fn end(
            &self,
            who: &LogoutBrowser,
            hints: FakeIdTokenHintVerifier,
            req: EndSessionRequest,
        ) -> Result<EndSessionOutcome, AppError> {
            let use_case = EndSessionUseCase::new(EndSessionPorts {
                client_store: self.clients.clone(),
                hint_verifier: Arc::new(hints),
                key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
                session_store: self.sessions.clone(),
                refresh_token_store: self.refresh.clone(),
                auth_code_store: self.codes.clone(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            });
            block_on(use_case.execute(who, &test_auditor(self.audit.clone()), req))
        }

        /// Ann, signed in.
        fn signed_in(&self) -> LogoutBrowser {
            LogoutBrowser::SignedIn(Box::new(self.caller.clone()))
        }

        /// The portal's ID token for `subject`, read back by the verifier.
        fn hint_about(&self, subject: UserId) -> FakeIdTokenHintVerifier {
            FakeIdTokenHintVerifier::reading(HintClaims {
                audience: self.portal.client_id_value().clone(),
                subject,
                session: test_session_id(),
            })
        }

        /// A request from the portal with its ID token, asking to send Ann
        /// back to `address`.
        fn request(&self, address: &str) -> EndSessionRequest {
            EndSessionRequest {
                issuer: test_issuer(),
                id_token_hint: HintSent::Sent(Secret::new("portal-id-token")),
                client_id: ClientNamed::NotNamed,
                post_logout_redirect_uri: AddressAsked::Asked(RedirectUri::new(address).unwrap()),
                confirmation: LogoutConfirmation::NotAsked,
            }
        }

        /// Whether Ann's session ended.
        fn session_ended(&self) -> bool {
            self.sessions.get_status(&test_session_id()) == Some(SessionStatus::Revoked)
        }
    }

    /// The portal signs Ann out with her ID token. Her session ends, its
    /// refresh token too, her browser is sent through the portal's
    /// front-channel page and back to the address the portal registered.
    #[test]
    fn an_app_signs_the_person_out() {
        let fixture = Fixture::new();

        let outcome = fixture
            .end(
                &fixture.signed_in(),
                fixture.hint_about(fixture.ann),
                fixture.request(TEST_AFTER_LOGOUT),
            )
            .unwrap();

        assert_eq!(
            outcome,
            EndSessionOutcome::SignedOut {
                after: AfterLogout::SendBack(RedirectUri::new(TEST_AFTER_LOGOUT).unwrap()),
                front_channel: vec![HttpsUrl::new("https://app.example.com/front-logout").unwrap()],
            }
        );
        assert!(fixture.session_ended());
        assert!(matches!(
            fixture.refresh.state_of(&hash_of(TEST_REFRESH_TOKEN)),
            Some(RefreshState::Revoked { .. })
        ));
        assert_eq!(
            fixture.audit.records.lock().unwrap().as_slice(),
            ["authentication.session_revoked"]
        );
    }

    /// Signing out a session that reached two apps returns both logout
    /// pages using one read of their client records.
    #[test]
    fn front_channel_clients_are_read_together() {
        let fixture = Fixture::new();
        let second = client_with("Second", &[GrantType::AuthorizationCode], |row| {
            row.settings.logout.front_channel =
                fixture.portal.settings().logout.front_channel.clone();
        });
        let tenant = fixture.caller.tenant();
        block_on(fixture.clients.save(&tenant, &second)).unwrap();
        let mut row = code_row(&second, fixture.ann);
        row.code_hash = hash_of("second front channel code");
        block_on(
            fixture
                .codes
                .save(&tenant, &AuthorizationCode::reconstitute(row).unwrap()),
        )
        .unwrap();

        let outcome = fixture
            .end(
                &fixture.signed_in(),
                fixture.hint_about(fixture.ann),
                fixture.request(TEST_AFTER_LOGOUT),
            )
            .unwrap();

        let EndSessionOutcome::SignedOut { front_channel, .. } = outcome else {
            panic!("the session should end");
        };
        assert_eq!(front_channel.len(), 2);
        assert!(fixture.session_ended());
        assert_eq!(fixture.clients.id_reads().len(), 1);
    }

    /// A valid logout hint with an unregistered return address yields a
    /// signed-out result targeting the local signed-out page.
    #[test]
    fn an_unregistered_address_stays_on_the_signed_out_page() {
        let fixture = Fixture::new();

        let outcome = fixture
            .end(
                &fixture.signed_in(),
                fixture.hint_about(fixture.ann),
                fixture.request("https://evil.example/landing"),
            )
            .unwrap();

        assert!(matches!(
            outcome,
            EndSessionOutcome::SignedOut {
                after: AfterLogout::SignedOutPage,
                ..
            }
        ));
    }

    /// A logout request without an ID-token hint asks Ann to confirm and
    /// leaves her session unrevoked.
    #[test]
    fn a_request_without_a_hint_asks_first() {
        let fixture = Fixture::new();
        let req = EndSessionRequest {
            id_token_hint: HintSent::NotSent,
            client_id: ClientNamed::Named(fixture.portal.client_id_value().clone()),
            ..fixture.request(TEST_AFTER_LOGOUT)
        };

        let outcome = fixture
            .end(
                &fixture.signed_in(),
                FakeIdTokenHintVerifier::refusing(),
                req,
            )
            .unwrap();

        assert!(matches!(outcome, EndSessionOutcome::ConfirmFirst { .. }));
        assert!(!fixture.session_ended());
    }

    /// Ann confirms on the signed-out page. Her session ends.
    #[test]
    fn a_confirmed_sign_out_ends_the_session() {
        let fixture = Fixture::new();
        let req = EndSessionRequest {
            id_token_hint: HintSent::NotSent,
            confirmation: LogoutConfirmation::Confirmed,
            ..fixture.request(TEST_AFTER_LOGOUT)
        };

        let outcome = fixture
            .end(
                &fixture.signed_in(),
                FakeIdTokenHintVerifier::refusing(),
                req,
            )
            .unwrap();

        assert!(matches!(outcome, EndSessionOutcome::SignedOut { .. }));
        assert!(fixture.session_ended());
    }

    /// An ID-token hint about another person asks Ann to confirm logout and
    /// leaves her session unrevoked.
    #[test]
    fn a_hint_about_someone_else_asks_first() {
        let fixture = Fixture::new();

        let outcome = fixture
            .end(
                &fixture.signed_in(),
                fixture.hint_about(UserId::new()),
                fixture.request(TEST_AFTER_LOGOUT),
            )
            .unwrap();

        assert!(matches!(outcome, EndSessionOutcome::ConfirmFirst { .. }));
        assert!(!fixture.session_ended());
    }

    /// A logout hint rejected by verification fails the request and leaves
    /// Ann's session unrevoked.
    #[test]
    fn an_unsigned_hint_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.end(
            &fixture.signed_in(),
            FakeIdTokenHintVerifier::refusing(),
            fixture.request(TEST_AFTER_LOGOUT),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(!fixture.session_ended());
    }

    /// Nobody is signed in when the browser arrives. It is sent back to
    /// the portal's address all the same.
    #[test]
    fn nobody_signed_in_is_sent_back() {
        let fixture = Fixture::new();
        let who = LogoutBrowser::SignedOut(fixture.caller.tenant());

        let outcome = fixture
            .end(
                &who,
                fixture.hint_about(fixture.ann),
                fixture.request(TEST_AFTER_LOGOUT),
            )
            .unwrap();

        assert!(matches!(
            outcome,
            EndSessionOutcome::NotSignedIn {
                after: AfterLogout::SendBack(_)
            }
        ));
    }
}
