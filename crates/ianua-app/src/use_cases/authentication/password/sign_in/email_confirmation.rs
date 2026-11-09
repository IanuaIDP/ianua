//! Finishing a sign-in that waits for its person to confirm from their
//! mailbox.
//!
//! The browser that began the sign-in holds the pending session's token. The
//! person follows the link mailed to their address. Together they answer
//! what the sign-in owes: the link proves the mailbox, and the token shows
//! which sign-in it confirms. Neither alone finishes anything.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInRefused;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, SessionId};

use crate::auditor::RequestAuditor;
use crate::email::refused_link;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::identity::{SignInLinkStore, UserStore};
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::sign_in_gate::{self, ClientOrigin};
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::password::sign_in::confirmation::owes_email_confirmation;

/// The ports [`ConfirmSignInByEmailUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmSignInByEmailPorts {
    /// Tenants, which admit the sign-in and set its baseline.
    pub tenants: Arc<dyn TenantStore>,
    /// The pending sessions.
    pub sessions: Arc<dyn SessionStore>,
    /// The accounts signing in.
    pub users: Arc<dyn UserStore>,
    /// The confirmation links mailed out.
    pub links: Arc<dyn SignInLinkStore<SignInConfirmation>>,
    /// Hashes a presented link or session token the way it was stored.
    pub token_hasher: Arc<dyn RefreshTokenGenerator>,
}

/// A followed confirmation link, with the sign-in it confirms.
pub struct ConfirmSignInRequest {
    /// The link's token, as followed.
    pub link: Secret,
    /// The refresh token of the session waiting for the confirmation.
    pub session_token: Secret,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// A sign-in the mailbox confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedSignIn {
    /// The session confirmed.
    pub session_id: SessionId,
    /// What the sign-in still owes: nothing, or a factor to set up when the
    /// tenant requires one.
    pub second_factor: SecondFactor,
}

/// A sign-in waiting for its email confirmation, found by whatever its
/// browser holds, with the link followed for it.
pub(in crate::use_cases::authentication) struct PendingConfirmation<'a> {
    /// The waiting session, as stored.
    pub(in crate::use_cases::authentication) session: Session<ResolvedTenant>,
    /// The link's token, as followed.
    pub(in crate::use_cases::authentication) link: &'a Secret,
    /// Where the request came from.
    pub(in crate::use_cases::authentication) origin: &'a ClientOrigin,
}

/// Finishes a sign-in by the link mailed to its person.
pub struct ConfirmSignInByEmailUseCase {
    ports: ConfirmSignInByEmailPorts,
}

impl ConfirmSignInByEmailUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConfirmSignInByEmailPorts) -> Self {
        Self { ports }
    }

    /// The session whose refresh token is `token`.
    async fn pending_session(
        &self,
        tenant: &ScopedTenant,
        token: &Secret,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        let hash = self.ports.token_hasher.hash_raw(token.expose());
        self.ports
            .sessions
            .find_by_refresh_token_hash(tenant, &hash)
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-sign-in-not-found",
                "sign-in not found"
            ))
    }

    /// Spends the confirmation link `raw` for `account`, giving back the
    /// mailbox it proves.
    async fn followed(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        raw: &Secret,
    ) -> Result<ProvedFactor, AppError> {
        let hash = self.ports.token_hasher.hash_raw(raw.expose());
        let links = self.ports.links.as_ref();
        let mut link = links
            .find_by_hash(tenant, &hash)
            .await
            .or_internal()?
            .or_not_found(message!("app-invalid-link", "invalid link"))?;
        let proof = ProvedFactor::by_confirmation_link(&mut link, account, clock::now())
            .map_err(refused_link)?;
        if !links.consume(tenant, &hash).await.or_internal()? {
            return Err(AppError::NotFound(message!(
                "app-invalid-link",
                "invalid link"
            )));
        }
        Ok(proof)
    }

    /// Answers what `pending.session` owes with its followed link, and
    /// records `authentication.mfa_verified`. The dashboard finds the
    /// session by its refresh token; an app's host by its challenge cookie.
    ///
    /// # Errors
    ///
    /// The errors [`Command::execute`] lists, past finding the session.
    pub(in crate::use_cases::authentication) async fn confirm(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        pending: PendingConfirmation<'_>,
    ) -> Result<ConfirmedSignIn, AppError> {
        let mut session = pending.session;
        ensure_live(&session)?;
        ensure_owes_confirmation(session.owed())?;
        let client_ip = pending.origin.ip_address.as_ref();
        let tenants = self.ports.tenants.as_ref();
        let (record, _) =
            sign_in_gate::admit(tenants, tenant, session.auth_method(), client_ip).await?;
        let account = existing_user(self.ports.users.as_ref(), tenant, session.user_id()).await?;
        let proof = self.followed(tenant, &account, pending.link).await?;
        session
            .answer(&account, proof, record.auth_config().step_up_policy())
            .map_err(answer_refusal)?;
        session.record_factor_verified();
        self.ports
            .sessions
            .save(tenant, &session)
            .await
            .or_internal()?;
        let holder = ActorRef::User(*session.user_id());
        auditor
            .dispatch_by(&holder, session.take_events(tenant))
            .await
            .or_internal()?;
        Ok(ConfirmedSignIn {
            session_id: *session.id(),
            second_factor: session.owed(),
        })
    }
}

impl Command for ConfirmSignInByEmailUseCase {
    type Caller = ScopedTenant;
    type Input = ConfirmSignInRequest;
    type Output = Result<ConfirmedSignIn, AppError>;

    /// Answers what the session holding `request.session_token` owes with
    /// the link `request.link`, and records `authentication.mfa_verified`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` for an unknown, spent or foreign link or no live session, without revealing which links exist.
    /// - `AppError::Conflict` when nothing is owed; `Forbidden` for a different owed factor or a refused request origin.
    /// - `AppError::LinkExpired` for an expired link or changed mailbox; `TenantUnavailable` for a closed tenant.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: ConfirmSignInRequest,
    ) -> Result<ConfirmedSignIn, AppError> {
        let session = self.pending_session(tenant, &request.session_token).await?;
        let pending = PendingConfirmation {
            session,
            link: &request.link,
            origin: &request.origin,
        };
        self.confirm(tenant, auditor, pending).await
    }
}

/// Refuses a sign-in that was signed out of or ran out, as not found.
///
/// # Errors
///
/// - `AppError::NotFound` when the session is revoked or expired.
fn ensure_live(session: &Session<ResolvedTenant>) -> Result<(), AppError> {
    if session.is_revoked() || session.is_expired(clock::now()) {
        return Err(AppError::NotFound(message!(
            "authentication-sign-in-not-found",
            "sign-in not found"
        )));
    }
    Ok(())
}

/// Refuses a sign-in that does not wait for an email confirmation, before
/// the link is spent on it.
///
/// # Errors
///
/// - `AppError::Conflict` when it owes nothing.
/// - `AppError::Forbidden` when it owes another factor.
pub(crate) fn ensure_owes_confirmation(owed: SecondFactor) -> Result<(), AppError> {
    match owed {
        owed if owes_email_confirmation(owed) => Ok(()),
        SecondFactor::NotOwed => Err(AppError::Conflict(message!(
            "authentication-mfa-already-verified",
            "MFA already verified"
        ))),
        _ => Err(AppError::Forbidden(message!(
            "authentication-this-sign-in-is-not-waiting",
            "this sign-in is not waiting for an email confirmation"
        ))),
    }
}

/// What the person is told when the confirmation does not answer the
/// sign-in.
pub(crate) fn answer_refusal(refused: SignInRefused) -> AppError {
    match refused {
        SignInRefused::AlreadyProved => AppError::Conflict(message!(
            "authentication-mfa-already-verified",
            "MFA already verified"
        )),
        SignInRefused::NotAccepted { .. }
        | SignInRefused::BelowBaseline(_)
        | SignInRefused::ForAnotherAccount
        | SignInRefused::AccountMayNotSignIn
        | SignInRefused::WayInNotAllowed => AppError::Forbidden(message!(
            "authentication-this-confirmation-does-not-finish-the",
            "this confirmation does not finish the sign-in"
        )),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
    use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
    use ianua_domain::domains::authentication::sessions::session::{SessionOrigin, SessionRow};
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::identity::tokens::secure::{
        NewSecureToken, SecureToken, SecureTokenRow,
    };
    use ianua_domain::types::{CredentialChange, Email, Fact, Lifetime, Usage, UserId};

    use super::*;
    use crate::ports::identity::SignInConfirmationToken;
    use crate::test_support::authentication::FakeSessionStore;
    use crate::test_support::identity::{FakeSignInLinks, FakeUserStore, hash_of_link};
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor, test_ctx,
    };

    const ANN: &str = "ann@acme.test";
    const LINK: &str = "fake_refresh_link";
    const SESSION_TOKEN: &str = "fake_refresh_session";

    struct Fixture {
        ann: UserId,
        sessions: Arc<FakeSessionStore>,
        links: Arc<FakeSignInLinks>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn owing(owed: SecondFactor) -> Self {
            Self::with(owed, SessionStatus::Active)
        }

        fn with(owed: SecondFactor, status: SessionStatus) -> Self {
            let ann = UserId::new();
            Self {
                ann,
                sessions: Arc::new(FakeSessionStore::with_session(pending(
                    ann,
                    SESSION_TOKEN,
                    owed,
                    status,
                ))),
                links: Arc::new(FakeSignInLinks::holding(&link_for(ann))),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn confirm(&self, session_token: &str) -> Result<ConfirmedSignIn, AppError> {
            self.confirm_through(self.links.clone(), session_token)
        }

        /// Ann's link followed twice at once: both follows read it before
        /// either spent it in the fixture's links.
        fn racing_links(&self) -> Arc<ReadBeforeWrite<FakeSignInLinks>> {
            let seen = FakeSignInLinks::holding(&link_for(self.ann));
            Arc::new(ReadBeforeWrite::new(seen, self.links.clone()))
        }

        fn confirm_through(
            &self,
            links: Arc<dyn SignInLinkStore<SignInConfirmation>>,
            session_token: &str,
        ) -> Result<ConfirmedSignIn, AppError> {
            let use_case = ConfirmSignInByEmailUseCase::new(ConfirmSignInByEmailPorts {
                tenants: tenant_store_signing_in_with(Default::default()),
                sessions: self.sessions.clone(),
                users: Arc::new(FakeUserStore::with_user(self.ann, ANN)),
                links,
                ..ConfirmSignInByEmailPorts::fakes()
            });
            let request = ConfirmSignInRequest {
                link: Secret::new(LINK),
                session_token: Secret::new(session_token),
                origin: ClientOrigin::default(),
            };
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, request))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn pending(
        user_id: UserId,
        token: &str,
        owed: SecondFactor,
        status: SessionStatus,
    ) -> Session<ResolvedTenant> {
        let now = clock::now();
        Session::reconstitute(SessionRow {
            id: SessionId::new(),
            user_id,
            refresh_token_hash: hash_of_link(token),
            parent_id: SessionOrigin::SignIn,
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            signed_in_from: Fact::Unknown,
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed,
            },
            status,
            channel: SessionChannel::Dashboard,
            signed_in_at: now,
            created_at: now,
            last_active_at: now,
            expires_at: now + time::Duration::hours(8),
            kept_through: CredentialChange::Never,
            last_use: Fact::Unknown,
        })
        .unwrap()
    }

    fn link_for(user_id: UserId) -> SignInConfirmationToken {
        SecureToken::create(NewSecureToken {
            token_hash: hash_of_link(LINK),
            user_id,
            sent_to: Email::new(ANN).unwrap(),
            lifetime: Lifetime::seconds(900).unwrap(),
        })
        .unwrap()
    }

    fn expired_link_for(user_id: UserId) -> SignInConfirmationToken {
        let now = clock::now();
        SecureToken::reconstitute(SecureTokenRow {
            token_hash: hash_of_link(LINK),
            user_id,
            sent_to: Email::new(ANN).unwrap(),
            created_at: now - time::Duration::hours(2),
            expires_at: now - time::Duration::hours(1),
            usage: Usage::from_stored(None),
        })
        .unwrap()
    }

    fn session_of(fixture: &Fixture, confirmed: &ConfirmedSignIn) -> Session<ResolvedTenant> {
        fixture.sessions.get_session(&confirmed.session_id).unwrap()
    }

    /// Ann's sign-in waits for her to confirm by email. She follows the link
    /// in the browser she signed in with, and her sign-in is finished.
    #[test]
    fn following_the_link_finishes_the_sign_in() {
        let fixture = Fixture::owing(SecondFactor::ConfirmByEmail);

        let confirmed = fixture.confirm(SESSION_TOKEN).unwrap();

        assert_eq!(confirmed.second_factor, SecondFactor::NotOwed);
        assert!(session_of(&fixture, &confirmed).progress().is_complete());
        assert_eq!(fixture.links.count(), 0);
        assert_eq!(fixture.recorded(), ["authentication.mfa_verified"]);
    }

    /// Ann's tenant requires a second factor she has not set up. Confirming
    /// by email leaves her sign-in waiting for her to set one up.
    #[test]
    fn a_confirmation_then_asks_for_a_factor_to_set_up() {
        let fixture = Fixture::owing(SecondFactor::ConfirmThenEnrol);

        let confirmed = fixture.confirm(SESSION_TOKEN).unwrap();

        assert_eq!(confirmed.second_factor, SecondFactor::Enrol);
    }

    /// Reusing Ann's consumed link returns not found and leaves a second
    /// session waiting for email confirmation.
    #[test]
    fn a_replayed_link_is_refused() {
        let fixture = Fixture::owing(SecondFactor::ConfirmByEmail);
        let mallorys = pending(
            fixture.ann,
            "fake_refresh_mallory",
            SecondFactor::ConfirmByEmail,
            SessionStatus::Active,
        );
        let mallorys_id = *mallorys.id();
        block_on(fixture.sessions.save(&test_ctx().tenant(), &mallorys)).unwrap();
        fixture.confirm(SESSION_TOKEN).unwrap();

        let result = fixture.confirm("fake_refresh_mallory");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        let still = fixture.sessions.get_session(&mallorys_id).unwrap();
        assert_eq!(still.owed(), SecondFactor::ConfirmByEmail);
    }

    /// Two sign-ins read the same unspent link, but only the first confirms;
    /// the second returns not found and still owes email confirmation.
    #[test]
    fn a_link_followed_twice_at_once_finishes_one_sign_in() {
        let fixture = Fixture::owing(SecondFactor::ConfirmByEmail);
        let mallorys = pending(
            fixture.ann,
            "fake_refresh_mallory",
            SecondFactor::ConfirmByEmail,
            SessionStatus::Active,
        );
        let mallorys_id = *mallorys.id();
        block_on(fixture.sessions.save(&test_ctx().tenant(), &mallorys)).unwrap();
        let racing = fixture.racing_links();
        fixture
            .confirm_through(racing.clone(), SESSION_TOKEN)
            .unwrap();

        let result = fixture.confirm_through(racing, "fake_refresh_mallory");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        let still = fixture.sessions.get_session(&mallorys_id).unwrap();
        assert_eq!(still.owed(), SecondFactor::ConfirmByEmail);
    }

    /// A confirmation link expired for one hour returns the expired-link error.
    #[test]
    fn an_expired_link_is_refused() {
        let fixture = Fixture::owing(SecondFactor::ConfirmByEmail);
        let fixture = Fixture {
            links: Arc::new(FakeSignInLinks::holding(&expired_link_for(fixture.ann))),
            ..fixture
        };

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
    }

    /// A link belonging to another account cannot confirm Ann's waiting sign-in.
    #[test]
    fn a_link_for_another_account_is_refused() {
        let fixture = Fixture::owing(SecondFactor::ConfirmByEmail);
        let fixture = Fixture {
            links: Arc::new(FakeSignInLinks::holding(&link_for(UserId::new()))),
            ..fixture
        };

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A complete sign-in refuses confirmation as a conflict and preserves the link.
    #[test]
    fn a_sign_in_that_owes_nothing_is_refused() {
        let fixture = Fixture::owing(SecondFactor::NotOwed);

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(fixture.links.count(), 1);
    }

    /// A sign-in awaiting an authenticator code refuses the email link without spending it.
    #[test]
    fn a_sign_in_owing_a_code_is_refused() {
        let fixture = Fixture::owing(SecondFactor::Verify);

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.links.count(), 1);
    }

    /// A revoked waiting session returns not found when its email link is followed.
    #[test]
    fn a_signed_out_sign_in_is_not_found() {
        let fixture = Fixture::with(SecondFactor::ConfirmByEmail, SessionStatus::Revoked);

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An unknown session token cannot select a sign-in to confirm.
    #[test]
    fn an_unknown_session_token_is_not_found() {
        let fixture = Fixture::owing(SecondFactor::ConfirmByEmail);

        let result = fixture.confirm("fake_refresh_nobody");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
