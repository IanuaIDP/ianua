//! Resend verification: the holder of a dead verification link asks for
//! another, sent to the address their account has now.

use std::sync::Arc;

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, TokenHash};

use crate::auditor::RequestAuditor;
use crate::email::{LinkScope, VerificationResent, VerificationTokenStatus};
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{UserStore, VerificationTokenStore};
use crate::services::authentication::channels::NO_CONFIRMATION_LINKS;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::email::VerificationLinks;
use crate::use_cases::identity::lookup::existing_verification_token;

/// The ports [`ResendVerificationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResendVerificationPorts {
    /// Loads users.
    pub user_store: Arc<dyn UserStore>,
    /// Loads verification links, and when the last one went out.
    pub token_store: Arc<dyn VerificationTokenStore>,
    /// Mails the new link.
    pub verification_links: Arc<VerificationLinks>,
}

/// The verification link to replace, by its token, and the pages the new one
/// opens.
pub struct ResendVerificationRequest {
    /// The token from the link the person still holds, usable or not.
    pub raw_token: String,
    /// Where the new link lands.
    pub scope: LinkScope,
}

/// Mails another verification link to the holder of one.
pub struct ResendVerificationUseCase {
    ports: ResendVerificationPorts,
}

impl ResendVerificationUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResendVerificationPorts) -> Self {
        Self { ports }
    }

    /// The account the link was mailed for, while its address still needs
    /// confirming and the link may be answered at all.
    async fn unconfirmed_holder(
        &self,
        tenant: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<User<ResolvedTenant>, AppError> {
        let token =
            existing_verification_token(self.ports.token_store.as_ref(), tenant, token_hash)
                .await?;
        let user = existing_user(self.ports.user_store.as_ref(), tenant, token.user_id()).await?;
        ensure_unconfirmed(&user)?;
        VerificationTokenStatus::of(token.state_for(&user, clock::now())).ok_or_else(|| {
            AppError::NotFound(message!(
                "identity-invalid-verification-token",
                "invalid verification token"
            ))
        })?;
        Ok(user)
    }
}

impl Command for ResendVerificationUseCase {
    type Caller = ScopedTenant;
    type Input = ResendVerificationRequest;
    type Output = Result<VerificationResent, AppError>;

    /// Mails another verification link to the account `request.raw_token`
    /// was mailed for, at the address it has now.
    ///
    /// Keyed on the token rather than an address, so it tells nobody who is
    /// registered: only someone who was sent a link can ask for its
    /// replacement. An expired link is as good as a live one for this.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the token is unknown, the address is already
    ///   confirmed, the user is gone, or the link must be answered as if it
    ///   did not exist.
    /// - `AppError::TooManyRequests` if the last link is newer than the
    ///   cooldown, carrying the seconds still to wait.
    /// - `AppError::Forbidden` on a deployment with no mail server, before
    ///   the token is looked up, so the link would never arrive.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: ResendVerificationRequest,
    ) -> Result<VerificationResent, AppError> {
        let ResendVerificationRequest { raw_token, scope } = request;
        crate::input::validate_token("token", &raw_token)?;
        let links = &self.ports.verification_links;
        links.ensure_mailable(NO_CONFIRMATION_LINKS)?;
        let mut user = self
            .unconfirmed_holder(tenant, &links.hash_of(&raw_token))
            .await?;
        ensure_cooled_down(self.ports.token_store.as_ref(), links, tenant, &user).await?;

        links.send(tenant, &user, &scope).await?.note_on(&mut user);
        let actor = ActorRef::User(*user.id());
        auditor
            .dispatch_by(&actor, user.take_events(tenant))
            .await
            .or_internal()?;
        Ok(VerificationResent {
            retry_after_seconds: links.policy().resend_cooldown.sent().retry_after_seconds,
        })
    }
}

/// Refuses an account whose address is already confirmed: there is nothing
/// to send.
fn ensure_unconfirmed(user: &User<ResolvedTenant>) -> Result<(), AppError> {
    if user.email_verified() {
        return Err(AppError::NotFound(message!(
            "identity-this-address-is-already-confirmed",
            "this address is already confirmed"
        )));
    }
    Ok(())
}

/// Refuses a resend that comes too soon after the last link `user` was
/// sent.
async fn ensure_cooled_down(
    tokens: &dyn VerificationTokenStore,
    links: &VerificationLinks,
    tenant: &ScopedTenant,
    user: &User<ResolvedTenant>,
) -> Result<(), AppError> {
    let latest = tokens
        .find_latest_by_user(tenant, user.id())
        .await
        .or_internal()?;
    links
        .policy()
        .resend_cooldown
        .enforce(latest.map(|token| token.created_at()), "verification email")
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::UserId;
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::identity::{
        FakeTokenStore, FakeUserStore, hash_of_link, stored_user, stored_verification_link,
        verification_links_over, verification_links_reaching,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, RESEND_COOLDOWN_SECONDS, block_on,
        test_auditor, test_ctx, test_link_scope,
    };

    const LINK: &str = "ann-link";

    /// Ann, whose address is not confirmed, holding a link mailed to it.
    struct Mailbox {
        ann: UserId,
        users: Arc<FakeUserStore>,
        tokens: Arc<FakeTokenStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Mailbox {
        fn with_link_until(expires_at: OffsetDateTime) -> Self {
            let ann = UserId::new();
            Self {
                ann,
                users: Arc::new(FakeUserStore::with_unverified_user(ann, "ann@acme.com")),
                tokens: Arc::new(FakeTokenStore::holding(stored_verification_link(
                    LINK,
                    ann,
                    "ann@acme.com",
                    expires_at,
                ))),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn expired() -> Self {
            Self::with_link_until(clock::now() - time::Duration::minutes(1))
        }

        fn resend(&self, raw_token: &str) -> Result<VerificationResent, AppError> {
            self.resend_through(
                raw_token,
                verification_links_over(&self.tokens, &self.mailer),
            )
        }

        fn resend_through(
            &self,
            raw_token: &str,
            links: Arc<VerificationLinks>,
        ) -> Result<VerificationResent, AppError> {
            let use_case = ResendVerificationUseCase::new(ResendVerificationPorts {
                user_store: self.users.clone(),
                token_store: self.tokens.clone(),
                verification_links: links,
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                ResendVerificationRequest {
                    raw_token: raw_token.to_owned(),
                    scope: test_link_scope(),
                },
            ))
        }

        fn is_spent(&self, raw: &str) -> bool {
            block_on(
                self.tokens
                    .find_by_hash(&test_ctx().tenant(), &hash_of_link(raw)),
            )
            .unwrap()
            .unwrap()
            .consumed_at()
            .is_some()
        }
    }

    /// Without a mail server, Ann cannot replace her expired verification
    /// link. No new token, mail or audit event is created.
    #[test]
    fn no_link_is_resent_where_nothing_is_mailed() {
        let mailbox = Mailbox::expired();
        let links = verification_links_reaching(
            &mailbox.tokens,
            &mailbox.mailer,
            FakeMailSetup::not_set_up(),
        );

        let resent = mailbox.resend_through(LINK, links);

        assert!(matches!(resent, Err(AppError::Forbidden(_))));
        assert_eq!(mailbox.tokens.count(), 1);
        assert_eq!(mailbox.mailer.count(), 0);
        assert!(mailbox.sink.records.lock().unwrap().is_empty());
    }

    /// Ann's link expired. She asks for another: a new link goes to her
    /// address, she is told how long to wait before asking again, and the
    /// mail is recorded.
    #[test]
    fn an_expired_link_gets_a_replacement() {
        let mailbox = Mailbox::expired();

        let resent = mailbox.resend(LINK).unwrap();

        assert_eq!(resent.retry_after_seconds, RESEND_COOLDOWN_SECONDS);
        assert_eq!(mailbox.mailer.recipients(), ["ann@acme.com"]);
        assert_eq!(mailbox.tokens.count(), 2);
        assert_eq!(
            mailbox.sink.records.lock().unwrap().as_slice(),
            ["identity.verification_email_sent"]
        );
    }

    /// Ann's link still works when she asks for another. The replacement
    /// spends the old one, so only the newest link confirms her.
    #[test]
    fn a_replacement_spends_the_link_it_replaces() {
        let mailbox = Mailbox::with_link_until(clock::now() + time::Duration::hours(1));

        mailbox.resend(LINK).unwrap();

        assert!(mailbox.is_spent(LINK));
    }

    /// Ann asks twice in a row. The second ask comes inside the cooldown and
    /// is refused, and no second mail goes out.
    #[test]
    fn a_second_ask_inside_the_cooldown_is_refused() {
        let mailbox = Mailbox::expired();
        mailbox.resend(LINK).unwrap();

        let again = mailbox.resend(LINK);

        assert!(matches!(again, Err(AppError::TooManyRequests(_))));
        assert_eq!(mailbox.mailer.count(), 1);
    }

    /// Ann already confirmed her address. There is nothing to send.
    #[test]
    fn a_confirmed_address_gets_nothing() {
        let mailbox = Mailbox::expired();
        let confirmed = stored_user(mailbox.ann, "ann@acme.com", UserStatus::Active);
        block_on(mailbox.users.save(&test_ctx().tenant(), &confirmed)).unwrap();

        let result = mailbox.resend(LINK);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(mailbox.mailer.count(), 0);
    }

    /// A link nobody sent gets nothing.
    #[test]
    fn an_unknown_link_is_not_found() {
        let mailbox = Mailbox::expired();

        let result = mailbox.resend("nobody-sent-this");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(mailbox.mailer.count(), 0);
    }
}
