//! Signing in by following a mailed sign-in link.
//!
//! The link proves its reader holds the account's mailbox, and works once.
//! It never proves a second factor: an account that has one still owes it,
//! and a workspace that requires one has the person set one up.

use std::sync::Arc;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::account_check::MaySignIn;
use ianua_domain::domains::authentication::sessions::session::{CreateSessionParams, Session};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInRefused;
use ianua_domain::domains::authentication::sessions::way_in::WayIn;
use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::tokens::magic_link::MagicLink;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::Refusal;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Fact, SessionId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::input::validate_token;
use crate::ports::authentication::{MfaEnrollmentStore, PasskeyStore};
use crate::ports::identity::{SignInLinkStore, UserStore};
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::sign_in_gate::{ClientOrigin, admit};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::held_factors::FactorSources;
use crate::use_cases::authentication::signed_in_event::record_login;

/// What signing in by link hands back.
pub struct MagicLinkLoginSuccess {
    /// The new session.
    pub session_id: SessionId,
    /// The raw refresh token, handed to the client once and never stored.
    pub refresh_token: Secret,
    /// What the session still owes before it is fully signed in: a second
    /// factor to answer, one to set up, or nothing.
    pub second_factor: SecondFactor,
}

/// The ports [`ConsumeMagicLinkUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConsumeMagicLinkPorts {
    /// Finds the link and spends it.
    pub magic_link_store: Arc<dyn SignInLinkStore<MagicLink>>,
    /// Loads the account the link was mailed for.
    pub user_store: Arc<dyn UserStore>,
    /// The account's authenticator app, for whether it has a second factor.
    pub mfa_store: Arc<dyn MfaEnrollmentStore>,
    /// The account's passkeys, which count as a second factor too.
    pub passkey_store: Arc<dyn PasskeyStore>,
    /// Keeps the new session.
    pub session_store: Arc<dyn SessionStore>,
    /// The tenant, which must accept sign-in links and sets the session's
    /// rules.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Hashes the link's token and makes the session's refresh token.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// A followed sign-in link.
pub struct ConsumeMagicLinkRequest {
    /// The token from the link.
    pub raw_token: String,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// Signs a person in by the link mailed to them.
pub struct ConsumeMagicLinkUseCase {
    ports: ConsumeMagicLinkPorts,
}

impl ConsumeMagicLinkUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConsumeMagicLinkPorts) -> Self {
        Self { ports }
    }

    /// The way in the link `raw_token` gives, spent, with the account it
    /// was mailed for.
    async fn followed(
        &self,
        tenant: &ScopedTenant,
        raw_token: &str,
        now: OffsetDateTime,
    ) -> Result<(WayIn, User<ResolvedTenant>), AppError> {
        let hash = self.ports.token_generator.hash_raw(raw_token);
        let links = self.ports.magic_link_store.as_ref();
        let mut link = links
            .find_by_hash(tenant, &hash)
            .await
            .or_internal()?
            .or_not_found(invalid_link())?;
        let holder = self
            .ports
            .user_store
            .find_by_id(tenant, link.user_id())
            .await
            .or_internal()?
            .or_not_found(invalid_link())?;
        let way_in = WayIn::by_magic_link(&mut link, &holder, now).map_err(|_| {
            AppError::NotFound(message!(
                "authentication-invalid-or-expired-sign-in-link",
                "invalid or expired sign-in link"
            ))
        })?;
        if !links.consume(tenant, &hash).await.or_internal()? {
            return Err(AppError::NotFound(invalid_link()));
        }
        Ok((way_in, holder))
    }

    /// The sign-in the link begins for `holder`, owing what the tenant asks
    /// of someone with or without a second factor.
    async fn begun(
        &self,
        tenant: &ScopedTenant,
        settings: &Tenant,
        holder: &User<ResolvedTenant>,
        way_in: WayIn,
    ) -> Result<MaySignIn<ResolvedTenant>, AppError> {
        let sources = FactorSources {
            enrollments: self.ports.mfa_store.as_ref(),
            passkeys: self.ports.passkey_store.as_ref(),
        };
        let enrolment = sources.enrolment_of(tenant, holder.id()).await?;
        let config = settings.auth_config();
        let owed = SecondFactor::for_enrolment(config.mfa_policy(), enrolment);
        MaySignIn::proven(holder, way_in, owed, config.step_up_policy()).map_err(refused_sign_in)
    }

    /// Opens and keeps the session for the sign-in, with its raw refresh
    /// token.
    async fn opened(
        &self,
        tenant: &ScopedTenant,
        settings: &Tenant,
        signing_in: MaySignIn<ResolvedTenant>,
        origin: &ClientOrigin,
    ) -> Result<(Session<ResolvedTenant>, Secret), AppError> {
        let timeout = settings
            .auth_config()
            .session_timeout()
            .map_err(AppError::from_domain)?;
        let (raw, refresh_token_hash) = self
            .ports
            .token_generator
            .generate()
            .map(RefreshToken::into_parts)
            .or_internal()?;
        let params = CreateSessionParams {
            id: SessionId::new(),
            refresh_token_hash,
            ip_address: origin.ip_address.clone(),
            user_agent: Fact::from_option(origin.user_agent.clone()),
            timeout,
        };
        let session = Session::create(signing_in, params);
        self.ports
            .session_store
            .save(tenant, &session)
            .await
            .or_internal()?;
        Ok((session, raw))
    }
}

impl Command for ConsumeMagicLinkUseCase {
    type Caller = ScopedTenant;
    type Input = ConsumeMagicLinkRequest;
    type Output = Result<MagicLinkLoginSuccess, AppError>;

    /// Spends the link and opens a session for the account it was mailed
    /// to. The session lasts as long as the tenant's sessions do, and still
    /// owes a second factor when the tenant's policy asks for one. Records
    /// `authentication.login_succeeded`.
    ///
    /// # Errors
    ///
    /// - `AppError::TenantUnavailable` when the workspace is closed.
    /// - `AppError::Forbidden` when the workspace does not accept sign-in
    ///   links, or not from where the request came from, or a link alone
    ///   falls short of the assurance it requires.
    /// - `AppError::Domain` when the token is empty or too long.
    /// - `AppError::NotFound` when the link is unknown, expired, used,
    ///   mailed to an address the account has left, or its account may not
    ///   sign in now.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: ConsumeMagicLinkRequest,
    ) -> Result<MagicLinkLoginSuccess, AppError> {
        let ConsumeMagicLinkRequest { raw_token, origin } = request;
        let ip = origin.ip_address.as_ref();
        let tenant_store = self.ports.tenant_store.as_ref();
        let (settings, _) = admit(tenant_store, tenant, AuthMethod::MagicLink, ip).await?;
        validate_token("token", &raw_token)?;
        let now = clock::now();
        let (way_in, holder) = self.followed(tenant, &raw_token, now).await?;
        let signing_in = self.begun(tenant, &settings, &holder, way_in).await?;
        let (mut session, refresh_token) =
            self.opened(tenant, &settings, signing_in, &origin).await?;
        record_login(self.ports.user_store.as_ref(), tenant, session.user_id()).await?;
        session.record_sign_in(Fact::Unknown);
        let holder = ActorRef::User(*session.user_id());
        auditor
            .dispatch_by(&holder, session.take_events(tenant))
            .await
            .or_internal()?;
        Ok(MagicLinkLoginSuccess {
            session_id: *session.id(),
            refresh_token,
            second_factor: session.owed(),
        })
    }
}

/// The one answer to a link that is unknown, spent, or for an account that
/// is gone, all alike.
fn invalid_link() -> Refusal {
    message!(
        "authentication-invalid-sign-in-link",
        "invalid sign-in link"
    )
}

/// The answer to a sign-in the domain would not begin.
///
/// An account that may not sign in, or a link proved for another, answers
/// as an unusable link. A link that alone falls short of what the workspace
/// requires is refused outright, never answered with a server error.
fn refused_sign_in(refused: SignInRefused) -> AppError {
    match refused {
        SignInRefused::AccountMayNotSignIn | SignInRefused::ForAnotherAccount => {
            AppError::NotFound(invalid_link())
        }
        SignInRefused::BelowBaseline(_)
        | SignInRefused::NotAccepted { .. }
        | SignInRefused::AlreadyProved => AppError::Forbidden(message!(
            "authentication-a-sign-in-link-alone-does",
            "a sign-in link alone does not meet this workspace's sign-in requirements"
        )),
        SignInRefused::WayInNotAllowed => AppError::Forbidden(message!(
            "authentication-this-account-signs-in-another-way",
            "this account signs in another way than a sign-in link"
        )),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::MfaPolicy;
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::tokens::purpose::TenantLinkPurpose;
    use ianua_domain::domains::identity::tokens::secure::{
        NewSecureToken, SecureToken, SecureTokenRow,
    };
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::types::{Email, Lifetime, Seconds, Usage, UserId};

    use super::*;
    use crate::ports::identity::{MagicLinkToken, SignInConfirmationToken};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakePasskeyStore, FakeSessionStore,
    };
    use crate::test_support::identity::{
        FakeSignInLinks, FakeUserStore, hash_of_link, stored_user,
    };
    use crate::test_support::tenant::{tenant_store_in_status, tenant_store_signing_in_with};
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor, test_ctx,
    };

    const ADDRESS: &str = "u@acme.com";
    const LINK: &str = "fake_refresh_0";

    fn accepting_links() -> TenantAuthSettings {
        TenantAuthSettings {
            enabled_methods: vec![
                AuthMethod::Password,
                AuthMethod::MagicLink,
                AuthMethod::Passkey,
            ],
            mfa_policy: MfaPolicy::Optional,
            ..TenantAuthSettings::default()
        }
    }

    fn link_for(user_id: UserId) -> MagicLinkToken {
        link_carrying(user_id, LINK)
    }

    fn link_carrying(user_id: UserId, raw: &str) -> MagicLinkToken {
        SecureToken::create(NewSecureToken {
            token_hash: hash_of_link(raw),
            user_id,
            sent_to: Email::new(ADDRESS).unwrap(),
            lifetime: Lifetime::seconds(900).unwrap(),
        })
        .unwrap()
    }

    fn expired_link_for(user_id: UserId) -> MagicLinkToken {
        let now = clock::now();
        SecureToken::reconstitute(SecureTokenRow {
            token_hash: hash_of_link(LINK),
            user_id,
            sent_to: Email::new(ADDRESS).unwrap(),
            created_at: now - time::Duration::minutes(20),
            expires_at: now - time::Duration::minutes(1),
            usage: Usage::from_stored(None),
        })
        .unwrap()
    }

    /// The ports for Ann, active with `ADDRESS`, in a workspace signing in
    /// under `settings`.
    fn ports_for(ann: UserId, settings: TenantAuthSettings) -> ConsumeMagicLinkPorts {
        ConsumeMagicLinkPorts {
            user_store: Arc::new(FakeUserStore::with_user(ann, ADDRESS)),
            tenant_store: tenant_store_signing_in_with(settings),
            ..ConsumeMagicLinkPorts::fakes()
        }
    }

    struct Fixture {
        links: Arc<FakeSignInLinks>,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: ConsumeMagicLinkUseCase,
    }

    impl Fixture {
        /// Ann, holding a fresh link, in a workspace that accepts links.
        fn new() -> Self {
            Self::with(|ann| ports_for(ann, accepting_links()))
        }

        /// Ann, holding a fresh link, with the ports `ports` gives for her.
        fn with(ports: impl FnOnce(UserId) -> ConsumeMagicLinkPorts) -> Self {
            let ann = UserId::new();
            Self::holding(&link_for(ann), ports(ann))
        }

        fn holding<P: TenantLinkPurpose>(
            link: &SecureToken<ResolvedTenant, P>,
            ports: ConsumeMagicLinkPorts,
        ) -> Self {
            let links = Arc::new(FakeSignInLinks::holding(link));
            Self::reading_through(links.clone(), links, ports)
        }

        /// Ann's link followed twice at once: both follows read it from
        /// `seen` before either spent it in `links`.
        fn racing() -> Self {
            let ann = UserId::new();
            let links = Arc::new(FakeSignInLinks::holding(&link_for(ann)));
            let racing =
                ReadBeforeWrite::new(FakeSignInLinks::holding(&link_for(ann)), links.clone());
            Self::reading_through(links, Arc::new(racing), ports_for(ann, accepting_links()))
        }

        fn reading_through(
            links: Arc<FakeSignInLinks>,
            store: Arc<dyn SignInLinkStore<MagicLink>>,
            ports: ConsumeMagicLinkPorts,
        ) -> Self {
            let sessions = Arc::new(FakeSessionStore::empty());
            let use_case = ConsumeMagicLinkUseCase::new(ConsumeMagicLinkPorts {
                magic_link_store: store,
                session_store: sessions.clone(),
                ..ports
            });
            Self {
                links,
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        fn follow(&self) -> Result<MagicLinkLoginSuccess, AppError> {
            let request = ConsumeMagicLinkRequest {
                raw_token: LINK.to_owned(),
                origin: ClientOrigin::default(),
            };
            let auditor = test_auditor(self.audit.clone());
            block_on(
                self.use_case
                    .execute(&test_ctx().tenant(), &auditor, request),
            )
        }

        fn session_of(&self, success: &MagicLinkLoginSuccess) -> Session<ResolvedTenant> {
            self.sessions.get_session(&success.session_id).unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann follows the link mailed to her. She is signed in, the link is
    /// spent and the sign-in is recorded.
    #[test]
    fn a_followed_link_signs_in_and_is_spent() {
        let fixture = Fixture::new();

        let success = fixture.follow().unwrap();

        assert!(!success.refresh_token.expose().is_empty());
        assert_eq!(
            fixture.session_of(&success).auth_method(),
            AuthMethod::MagicLink
        );
        assert_eq!(fixture.links.count(), 0);
        assert_eq!(fixture.recorded(), ["authentication.login_succeeded"]);
    }

    /// A consumed sign-in link returns not found and leaves only the original session.
    #[test]
    fn a_used_link_cannot_sign_in_again() {
        let fixture = Fixture::new();
        fixture.follow().unwrap();

        let replay = fixture.follow();

        assert!(matches!(replay, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 1);
    }

    /// Two requests reading the same unspent link open one session; the
    /// second request returns not found.
    #[test]
    fn a_link_followed_twice_at_once_opens_one_session() {
        let fixture = Fixture::racing();
        fixture.follow().unwrap();

        let second = fixture.follow();

        assert!(matches!(second, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 1);
    }

    /// An expired sign-in link returns not found and opens no session.
    #[test]
    fn an_expired_link_is_refused() {
        let ann = UserId::new();
        let fixture = Fixture::holding(&expired_link_for(ann), ports_for(ann, accepting_links()));

        let result = fixture.follow();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// An email confirmation token cannot serve as a magic link: sign-in
    /// returns not found, opens no session and leaves the token unspent.
    #[test]
    fn a_confirmation_link_does_not_sign_in() {
        let ann = UserId::new();
        let confirmation: SignInConfirmationToken = SecureToken::create(NewSecureToken {
            token_hash: hash_of_link(LINK),
            user_id: ann,
            sent_to: Email::new(ADDRESS).unwrap(),
            lifetime: Lifetime::seconds(900).unwrap(),
        })
        .unwrap();
        let fixture = Fixture::holding(&confirmation, ports_for(ann, accepting_links()));

        let result = fixture.follow();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
        assert_eq!(fixture.links.count(), 1);
    }

    /// An unknown link returns not found without opening a session.
    #[test]
    fn an_unknown_link_is_not_found() {
        let ann = UserId::new();
        let fixture = Fixture::holding(
            &link_carrying(ann, "fake_refresh_9"),
            ports_for(ann, accepting_links()),
        );

        let result = fixture.follow();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// A locked account's link is refused as not found and remains unspent.
    #[test]
    fn a_link_for_a_locked_account_opens_nothing() {
        let fixture = Fixture::with(|ann| {
            let users = FakeUserStore::empty();
            users.add(stored_user(ann, ADDRESS, UserStatus::Locked));
            ConsumeMagicLinkPorts {
                user_store: Arc::new(users),
                ..ports_for(ann, accepting_links())
            }
        });

        let result = fixture.follow();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.links.count(), 1);
    }

    /// A link mailed to the account's former address cannot be used to sign in.
    #[test]
    fn a_link_to_an_address_the_account_left_opens_nothing() {
        let fixture = Fixture::with(|ann| ConsumeMagicLinkPorts {
            user_store: Arc::new(FakeUserStore::with_user(ann, "ann@new.example")),
            ..ports_for(ann, accepting_links())
        });

        let result = fixture.follow();

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A suspended tenant returns unavailable and leaves the sign-in link unspent.
    #[test]
    fn a_link_cannot_be_used_while_the_tenant_is_suspended() {
        let fixture = Fixture::with(|ann| ConsumeMagicLinkPorts {
            tenant_store: tenant_store_in_status(TenantStatus::Suspended),
            ..ports_for(ann, accepting_links())
        });

        let result = fixture.follow();

        assert!(matches!(result, Err(AppError::TenantUnavailable(_))));
        assert_eq!(fixture.links.count(), 1);
    }

    /// A tenant with magic links disabled refuses an outstanding sign-in link.
    #[test]
    fn a_link_is_refused_where_links_are_off() {
        let fixture = Fixture::with(|ann| ports_for(ann, TenantAuthSettings::default()));

        let result = fixture.follow();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann's workspace keeps sessions for an hour. Her session from a link
    /// lasts that hour.
    #[test]
    fn a_session_from_a_link_lasts_as_long_as_the_tenant_says() {
        let hourly = TenantAuthSettings {
            session_lifetime_secs: Seconds::new(3600),
            idle_timeout_secs: Seconds::new(600),
            ..accepting_links()
        };
        let fixture = Fixture::with(|ann| ports_for(ann, hourly));
        let before = clock::now();

        let success = fixture.follow().unwrap();

        let lasts = fixture.session_of(&success).expires_at() - before;
        assert!((lasts - time::Duration::hours(1)).abs() < time::Duration::minutes(1));
    }

    /// Ann has an authenticator app. A link proves her mailbox, not her
    /// factor, so her session still owes it.
    #[test]
    fn a_link_for_an_enrolled_account_still_owes_the_second_factor() {
        let fixture = Fixture::with(|ann| ConsumeMagicLinkPorts {
            mfa_store: Arc::new(FakeMfaEnrollmentStore::active_for(ann)),
            ..ports_for(ann, accepting_links())
        });

        let success = fixture.follow().unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
        assert!(!fixture.session_of(&success).progress().is_complete());
    }

    /// Ann holds only a passkey. It counts as her second factor, so a link
    /// still asks for it.
    #[test]
    fn a_passkey_counts_as_the_second_factor_a_link_owes() {
        let fixture = Fixture::with(|ann| ConsumeMagicLinkPorts {
            passkey_store: Arc::new(FakePasskeyStore::with_passkey(ann)),
            ..ports_for(ann, accepting_links())
        });

        let success = fixture.follow().unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// Ann has no second factor and her workspace does not require one. The
    /// link signs her straight in.
    #[test]
    fn a_link_for_an_account_with_no_factor_signs_straight_in() {
        let fixture = Fixture::new();

        let success = fixture.follow().unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
        assert!(fixture.session_of(&success).progress().is_complete());
    }

    /// Ann's workspace requires a second factor and she has none. She sets
    /// one up before the link lets her in.
    #[test]
    fn a_link_under_required_second_factors_makes_someone_without_one_set_it_up() {
        let required = TenantAuthSettings {
            mfa_policy: MfaPolicy::Required,
            ..accepting_links()
        };
        let fixture = Fixture::with(|ann| ports_for(ann, required));

        let success = fixture.follow().unwrap();

        assert_eq!(success.second_factor, SecondFactor::Enrol);
    }

    /// A magic link below the tenant's required assurance is forbidden
    /// without opening a session.
    #[test]
    fn a_link_below_the_workspaces_baseline_is_refused() {
        let strict = TenantAuthSettings {
            step_up_policy: StepUpPolicy::strict(),
            ..accepting_links()
        };
        let fixture = Fixture::with(|ann| ports_for(ann, strict));

        let result = fixture.follow();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }
}
