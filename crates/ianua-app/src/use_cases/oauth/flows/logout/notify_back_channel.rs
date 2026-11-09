//! Telling one app's server that a person signed out (OpenID Connect
//! Back-Channel Logout 1.0).
//!
//! A logout job runs this, one per app that hears of the sign-out, so one
//! app's server that does not answer never holds up another's. The app
//! gets a signed logout token, or one per session when it wants each
//! session named. A server that does not take its token is counted, and the
//! job tries it again later: the person is signed out of ianua either way.

use std::sync::Arc;

use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::crypto::signing_key::SigningKey;
use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::grants::logout_delivery::{LogoutDelivery, LogoutTold};
use ianua_domain::domains::oauth::grants::logout_notice::{
    LogoutTokenClaims, LogoutTokenParams, SignedOut,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Issuer, OAuthClientId, TokenId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{JwtSigner, SigningKeyStore};
use crate::ports::oauth::{AuthCodeStore, BackChannelLogoutSender, OAuthClientStore};
use crate::services::issuers::TenantIssuers;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::flows::logout::receivers::{Notice, notices_for};
use crate::use_cases::oauth::token::issuing::{active_key, signed};

/// Which app to tell, and who signed out.
pub struct SignOutNotice {
    /// The app.
    pub client_id: OAuthClientId,
    /// Who signed out, of one session or of every one.
    pub signed_out: SignedOut,
}

/// How the app took the news.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogoutDeliveries {
    /// Logout tokens the app's server took.
    pub told: usize,
    /// Logout tokens its server did not take in time.
    pub unreachable: usize,
}

/// The ports [`NotifyBackChannelLogoutUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct NotifyBackChannelLogoutPorts {
    /// Where codes are kept, to find the sessions the person signed in to
    /// the app through.
    pub auth_code_store: Arc<dyn AuthCodeStore>,
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Where the tenant's signing keys are kept.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Signs the logout tokens.
    pub jwt_signer: Arc<dyn JwtSigner>,
    /// Posts a logout token to an app's server.
    pub sender: Arc<dyn BackChannelLogoutSender>,
    /// The issuer the tenant's tokens carry, written into the logout tokens.
    pub issuers: TenantIssuers,
}

/// Tells one app's server that a person signed out.
pub struct NotifyBackChannelLogoutUseCase {
    ports: NotifyBackChannelLogoutPorts,
}

impl NotifyBackChannelLogoutUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: NotifyBackChannelLogoutPorts) -> Self {
        Self { ports }
    }

    /// The tokens to send `notice`'s app: none when it is gone, switched
    /// off, has no back channel, or was never reached through the ended
    /// session.
    async fn notices(
        &self,
        tenant: &ScopedTenant,
        notice: &SignOutNotice,
    ) -> Result<Vec<Notice>, AppError> {
        let client = self
            .ports
            .client_store
            .find_by_id(tenant, &notice.client_id)
            .await
            .or_internal()?;
        let Some(client) = client.filter(OAuthClient::is_active) else {
            return Ok(Vec::new());
        };
        let signed_into = self
            .ports
            .auth_code_store
            .consented_sessions(tenant, notice.signed_out)
            .await
            .or_internal()?;
        Ok(notices_for(&client, notice.signed_out, &signed_into))
    }

    /// Signs `notice` with `key` and posts it, recording how the app's
    /// server took it.
    async fn told(
        &self,
        key: &SigningKey,
        issuer: &Issuer,
        notice: Notice,
    ) -> Result<LogoutTold<ResolvedTenant>, AppError> {
        let jti = TokenId::new(uuid::Uuid::now_v7().to_string()).map_err(AppError::internal)?;
        let claims = LogoutTokenClaims::build(LogoutTokenParams {
            issuer: issuer.clone(),
            client: &notice.client,
            signed_out: notice.signed_out,
            jti,
        })
        .map_err(AppError::from_domain)?;
        let claims_json = serde_json::to_string(&claims).map_err(AppError::internal)?;
        let signer = self.ports.jwt_signer.as_ref();
        let token = signed(signer, key, &claims_json, JwtType::LogoutToken).await?;
        let sent = self.ports.sender.deliver(&notice.uri, &token).await;
        let Err(failure) = &sent else {
            return Ok(LogoutTold::record(&notice.client, LogoutDelivery::Taken));
        };
        tracing::warn!(client = %notice.client.id(), error = %failure, "back-channel logout not delivered");
        Ok(LogoutTold::record(
            &notice.client,
            LogoutDelivery::Unreachable,
        ))
    }
}

impl Command for NotifyBackChannelLogoutUseCase {
    type Caller = ScopedTenant;
    type Input = SignOutNotice;
    type Output = Result<LogoutDeliveries, AppError>;

    /// Sends, in `tenant`, the logout tokens `notice`'s app asked to hear,
    /// and counts how its server took them. Each posting records
    /// `oauth.back_channel_logout_sent`, by the system, with how the server
    /// took it, so an app that may still hold the session shows in the
    /// audit trail.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant has no signing key, or the
    ///   tenant or its organization is gone.
    /// - `AppError::Internal` when a lookup, the signing or the record
    ///   fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        notice: SignOutNotice,
    ) -> Result<LogoutDeliveries, AppError> {
        let notices = self.notices(tenant, &notice).await?;
        if notices.is_empty() {
            return Ok(LogoutDeliveries::default());
        }
        let key = active_key(self.ports.key_store.as_ref(), tenant).await?;
        let issuer = self.ports.issuers.of(tenant).await?;
        let mut deliveries = LogoutDeliveries::default();
        let mut events = Vec::new();
        for each in notices {
            let mut told = self.told(&key, &issuer, each).await?;
            deliveries = tally(deliveries, told.delivery());
            events.extend(told.take_events(tenant));
        }
        auditor
            .dispatch_by(&ActorRef::System, events)
            .await
            .or_internal()?;
        Ok(deliveries)
    }
}

/// `deliveries`, counting one more taken as `delivery` says.
fn tally(deliveries: LogoutDeliveries, delivery: LogoutDelivery) -> LogoutDeliveries {
    match delivery {
        LogoutDelivery::Taken => LogoutDeliveries {
            told: deliveries.told.saturating_add(1),
            ..deliveries
        },
        LogoutDelivery::Unreachable => LogoutDeliveries {
            unreachable: deliveries.unreachable.saturating_add(1),
            ..deliveries
        },
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::clients::settings::{ChannelLogout, SessionRequired};
    use ianua_domain::domains::oauth::grants::authorization_code::AuthorizationCode;
    use ianua_domain::types::{HttpsUrl, SessionId, UserId};

    use super::*;
    use crate::test_support::crypto::{FakeJwtSigner, FakeSigningKeyStore, premigration_keys};
    use crate::test_support::oauth::{
        FakeAuthCodeStore, FakeBackChannelLogoutSender, FakeOAuthClientStore, client_with,
        code_row, stored_client,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };

    /// Ann, signed in to one app through the test session, and the server
    /// it is told at.
    struct Fixture {
        ann: UserId,
        app: OAuthClientId,
        codes: Arc<FakeAuthCodeStore>,
        clients: Arc<FakeOAuthClientStore>,
        sender: Arc<FakeBackChannelLogoutSender>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// Ann signed in to `app`.
        fn signed_in_to(app: OAuthClient<ResolvedTenant>) -> Self {
            let ann = UserId::new();
            let tenant = test_ctx().tenant();
            let codes = Arc::new(FakeAuthCodeStore::empty());
            let code = AuthorizationCode::reconstitute(code_row(&app, ann)).unwrap();
            block_on(codes.save(&tenant, &code)).unwrap();
            Self {
                ann,
                app: *app.id(),
                codes,
                clients: Arc::new(FakeOAuthClientStore::holding(&tenant, app)),
                sender: Arc::new(FakeBackChannelLogoutSender::new()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// What telling the app of `signed_out` comes to, through
        /// `sender`.
        fn notify_through(
            &self,
            sender: Arc<FakeBackChannelLogoutSender>,
            signed_out: SignedOut,
        ) -> LogoutDeliveries {
            let use_case = NotifyBackChannelLogoutUseCase::new(NotifyBackChannelLogoutPorts {
                auth_code_store: self.codes.clone(),
                client_store: self.clients.clone(),
                key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
                jwt_signer: Arc::new(FakeJwtSigner::default()),
                sender,
                issuers: TenantIssuers::fake(),
            });
            let notice = SignOutNotice {
                client_id: self.app,
                signed_out,
            };
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, notice)).unwrap()
        }

        /// How each posting was recorded, by its `delivery`, in order.
        fn recorded_deliveries(&self) -> Vec<String> {
            self.audit
                .all_payloads()
                .iter()
                .filter_map(|payload| payload.get("delivery").map(str::to_owned))
                .collect()
        }

        /// What telling the app of `signed_out` comes to.
        fn notify(&self, signed_out: SignedOut) -> LogoutDeliveries {
            self.notify_through(self.sender.clone(), signed_out)
        }

        /// Ann signed out of the test session.
        fn session_ended(&self) -> SignedOut {
            SignedOut::Session {
                person: self.ann,
                session: test_session_id(),
            }
        }

        /// The logout tokens posted, in order.
        fn posted(&self) -> Vec<(String, String)> {
            self.sender.delivered.lock().unwrap().clone()
        }
    }

    /// An app taking back-channel logout at its server, wanting the session
    /// named as `session` says.
    fn listening_app(session: SessionRequired) -> OAuthClient<ResolvedTenant> {
        client_with("Portal", &[GrantType::AuthorizationCode], |row| {
            row.settings.logout.back_channel = ChannelLogout::At {
                uri: HttpsUrl::new("https://app.example.com/backchannel").unwrap(),
                session,
            };
        })
    }

    /// Ann signs out of the session she used the portal through. The
    /// portal's server gets a logout token naming her and the session.
    #[test]
    fn the_app_hears_of_the_sign_out() {
        let fixture = Fixture::signed_in_to(listening_app(SessionRequired::Required));

        let deliveries = fixture.notify(fixture.session_ended());

        assert_eq!(deliveries.told, 1);
        let posted = fixture.posted();
        assert_eq!(posted[0].0, "https://app.example.com/backchannel");
        assert!(posted[0].1.contains(&test_session_id().to_string()));
        assert!(posted[0].1.contains("backchannel-logout"));
        assert_eq!(fixture.recorded_deliveries(), ["taken"]);
    }

    /// Ann is shut out everywhere. The portal wants each session named, so
    /// it gets a token for the session she used it through.
    #[test]
    fn signing_out_everywhere_names_each_session_to_an_app_that_wants_it() {
        let fixture = Fixture::signed_in_to(listening_app(SessionRequired::Required));

        let deliveries = fixture.notify(SignedOut::Everywhere {
            person: fixture.ann,
        });

        assert_eq!(deliveries.told, 1);
        assert!(
            fixture.posted()[0]
                .1
                .contains(&test_session_id().to_string())
        );
    }

    /// An app that registered no back-channel address is told nothing.
    #[test]
    fn an_app_without_a_back_channel_is_told_nothing() {
        let fixture =
            Fixture::signed_in_to(stored_client("Portal", &[GrantType::AuthorizationCode]));

        let deliveries = fixture.notify(fixture.session_ended());

        assert_eq!(deliveries, LogoutDeliveries::default());
        assert!(fixture.posted().is_empty());
        assert!(fixture.recorded_deliveries().is_empty());
    }

    /// The portal's server is down. The delivery is counted as unreachable
    /// and the sign-out stands.
    #[test]
    fn an_unreachable_app_is_counted() {
        let fixture = Fixture::signed_in_to(listening_app(SessionRequired::NotRequired));

        let deliveries = fixture.notify_through(
            Arc::new(FakeBackChannelLogoutSender::failing()),
            fixture.session_ended(),
        );

        assert_eq!(deliveries.unreachable, 1);
        assert_eq!(deliveries.told, 0);
        assert_eq!(fixture.recorded_deliveries(), ["unreachable"]);
    }

    /// Signing out a session Ann never used with the portal yields no
    /// successful back-channel deliveries to it.
    #[test]
    fn another_session_is_not_told_to_the_app() {
        let fixture = Fixture::signed_in_to(listening_app(SessionRequired::Required));

        let deliveries = fixture.notify(SignedOut::Session {
            person: fixture.ann,
            session: SessionId::new(),
        });

        assert_eq!(deliveries.told, 0);
    }
}
