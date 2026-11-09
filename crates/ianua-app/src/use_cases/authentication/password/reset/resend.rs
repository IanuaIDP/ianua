//! Asking for another reset link from one that no longer works.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::message;
use ianua_domain::types::UserId;

use crate::auditor::RequestAuditor;
use crate::email::{LinkScope, ResendCooldown, TokenResent};
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::ResetRequestStore;
use crate::ports::identity::UserStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::password::reset::lookup::ResetLinks;
use crate::use_cases::authentication::password::{ResetMailRequest, ResetRequestUseCase};

/// The ports [`ResendResetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResendResetPorts {
    /// Finds the link's request and the account's newest one.
    pub reset_store: Arc<dyn ResetRequestStore>,
    /// Loads the account the link was mailed for.
    pub user_store: Arc<dyn UserStore>,
    /// Hashes the link's token the way it was stored.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// The reset link to replace, by its token, and the pages the new one
/// opens.
pub struct ResendResetRequest {
    /// The token from the link the person still holds, usable or not.
    pub raw_token: String,
    /// The organization or tenant whose reset page the new link opens.
    pub scope: LinkScope,
}

/// Mails a fresh reset link to the holder of a dead one.
pub struct ResendResetUseCase {
    cooldown: ResendCooldown,
    reset: Arc<ResetRequestUseCase>,
    ports: ResendResetPorts,
}

impl ResendResetUseCase {
    /// A use case issuing links through `reset`, no more often than
    /// `cooldown` allows, working through `ports`.
    #[must_use]
    pub fn new(
        cooldown: ResendCooldown,
        reset: Arc<ResetRequestUseCase>,
        ports: ResendResetPorts,
    ) -> Self {
        Self {
            cooldown,
            reset,
            ports,
        }
    }

    /// Refuses a replacement while the account's newest link is younger
    /// than the cooldown.
    async fn ensure_cooled_down(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), AppError> {
        let latest = self
            .ports
            .reset_store
            .find_latest_by_user(tenant, user_id)
            .await
            .or_internal()?;
        self.cooldown
            .enforce(latest.map(|reset| reset.created_at()), "reset link")
    }
}

impl Command for ResendResetUseCase {
    type Caller = ScopedTenant;
    type Input = ResendResetRequest;
    type Output = Result<TokenResent, AppError>;

    /// Mails another reset link to where the held one went.
    ///
    /// Keyed on the token rather than an address, so it tells nobody who
    /// has an account: only someone already sent a link can ask for its
    /// replacement. An expired or spent token is what this expects; it only
    /// names its account. The cooldown is measured against the account's
    /// newest link, not the superseded one in hand, so the button cannot be
    /// pressed as often as one likes.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the token is malformed.
    /// - `AppError::NotFound` when the token, or its account, is unknown.
    /// - `AppError::TooManyRequests` when the newest link is younger than
    ///   the cooldown, with the seconds still to wait.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: ResendResetRequest,
    ) -> Result<TokenResent, AppError> {
        let ResendResetRequest { raw_token, scope } = request;
        let links = ResetLinks {
            resets: self.ports.reset_store.as_ref(),
            users: self.ports.user_store.as_ref(),
            hasher: self.ports.token_generator.as_ref(),
        };
        let held = links
            .followed(tenant, &raw_token)
            .await?
            .or_not_found(message!(
                "authentication-invalid-reset-link",
                "invalid reset link"
            ))?;
        self.ensure_cooled_down(tenant, held.holder.id()).await?;
        let mail = ResetMailRequest {
            email: held.reset.email().clone(),
            scope,
        };
        self.reset.execute(tenant, auditor, mail).await?;
        Ok(self.cooldown.sent())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::test_support::fakes::FakeRefreshTokenGenerator;
    use ianua_domain::types::{Email, HttpsUrl, Lifetime};

    use super::*;
    use crate::services::authentication::reset_mail::{ResetMailPorts, ResetRequestPolicy};
    use crate::test_support::authentication::FakeResetRequestStore;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailer, RESEND_COOLDOWN_SECONDS, block_on, resend_cooldown,
        test_auditor, test_ctx, test_link_scope,
    };
    use crate::use_cases::authentication::password::ResetRequestPorts;

    const ADDRESS: &str = "alice@acme.com";

    struct Fixture {
        resets: Arc<FakeResetRequestStore>,
        mailer: Arc<FakeMailer>,
        reset: Arc<ResetRequestUseCase>,
        resend: ResendResetUseCase,
    }

    impl Fixture {
        fn with_alice() -> Self {
            let users = Arc::new(FakeUserStore::with_user(UserId::new(), ADDRESS));
            let resets = Arc::new(FakeResetRequestStore::empty());
            let mailer = Arc::new(FakeMailer::new());
            let tokens: Arc<dyn RefreshTokenGenerator> = Arc::new(FakeRefreshTokenGenerator::new());
            let reset = Arc::new(reset_request(
                users.clone(),
                ResetMailPorts {
                    reset_store: resets.clone(),
                    mailer: mailer.clone(),
                    token_generator: tokens.clone(),
                    mail: Fake::fake(),
                },
            ));
            let resend = ResendResetUseCase::new(
                resend_cooldown(),
                reset.clone(),
                ResendResetPorts {
                    reset_store: resets.clone(),
                    user_store: users,
                    token_generator: tokens,
                },
            );
            Self {
                resets,
                mailer,
                reset,
                resend,
            }
        }

        /// Asks for a first link, and hands back the raw token that was
        /// mailed, as the reader of the email holds it.
        fn first_link(&self) -> String {
            let request = ResetMailRequest {
                email: Email::new(ADDRESS).unwrap(),
                scope: test_link_scope(),
            };
            block_on(
                self.reset
                    .execute(&test_ctx().tenant(), &auditor(), request),
            )
            .unwrap();
            let url = self.mailer.action_url();
            url.split("token=").nth(1).unwrap().to_owned()
        }

        fn resend(&self, raw_token: &str) -> Result<TokenResent, AppError> {
            let request = ResendResetRequest {
                raw_token: raw_token.to_owned(),
                scope: test_link_scope(),
            };
            block_on(
                self.resend
                    .execute(&test_ctx().tenant(), &auditor(), request),
            )
        }
    }

    /// Alice's reset links share the fixture's mail and token stores and last an hour.
    fn reset_request(users: Arc<FakeUserStore>, mail: ResetMailPorts) -> ResetRequestUseCase {
        ResetRequestUseCase::new(
            ResetRequestPolicy {
                lifetime: Lifetime::seconds(3600).unwrap(),
                base_url: HttpsUrl::new("https://test.example.com").unwrap(),
            },
            ResetRequestPorts {
                user_store: users,
                mail,
                ..ResetRequestPorts::fakes()
            },
        )
    }

    fn auditor() -> RequestAuditor {
        test_auditor(Arc::new(FakeEventDispatcher::new()))
    }

    /// Alice's link ran out. She asks for another from it, and a second one
    /// is kept and mailed.
    #[test]
    fn a_dead_link_is_replaced_by_a_new_one() {
        let fixture = Fixture::with_alice();
        let raw = fixture.first_link();
        fixture.resets.age_by(time::Duration::seconds(600));

        let resent = fixture.resend(&raw).unwrap();

        assert_eq!(resent.retry_after_seconds, RESEND_COOLDOWN_SECONDS);
        assert_eq!(fixture.resets.count(), 2);
        assert_eq!(fixture.mailer.recipients().len(), 2);
    }

    /// The replacement supersedes the link that asked for it, so the old
    /// one cannot still be followed.
    #[test]
    fn resending_supersedes_the_link_it_was_asked_from() {
        let fixture = Fixture::with_alice();
        let raw = fixture.first_link();
        fixture.resets.age_by(time::Duration::seconds(600));

        fixture.resend(&raw).unwrap();

        assert_eq!(fixture.resets.superseded().len(), 2);
    }

    /// Alice's link expired long ago. It still names her, so she may ask
    /// for a replacement from it.
    #[test]
    fn an_expired_link_can_still_ask_for_a_replacement() {
        let fixture = Fixture::with_alice();
        let raw = fixture.first_link();
        fixture.resets.age_by(time::Duration::seconds(7200));

        let resent = fixture.resend(&raw);

        assert!(resent.is_ok());
    }

    /// Reusing the older link immediately after a replacement is rate limited;
    /// only the initial and replacement mails are sent.
    #[test]
    fn asking_again_inside_the_cooldown_is_refused() {
        let fixture = Fixture::with_alice();
        let raw = fixture.first_link();
        fixture.resets.age_by(time::Duration::seconds(600));
        fixture.resend(&raw).unwrap();

        let again = fixture.resend(&raw);

        assert!(matches!(again, Err(AppError::TooManyRequests(_))));
        assert_eq!(fixture.mailer.recipients().len(), 2);
    }

    /// An unknown reset token returns not found without sending mail.
    #[test]
    fn an_unknown_token_has_nothing_to_replace() {
        let fixture = Fixture::with_alice();

        let resent = fixture.resend("fake_refresh_never_issued");

        assert!(matches!(resent, Err(AppError::NotFound(_))));
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// An empty token is refused before anything is looked up.
    #[test]
    fn a_malformed_token_is_rejected_before_any_lookup() {
        let fixture = Fixture::with_alice();

        let resent = fixture.resend("");

        assert!(matches!(resent, Err(AppError::Domain(_))));
    }
}
