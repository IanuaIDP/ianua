//! Verify email: the person follows the link mailed to their address, and
//! the address is confirmed.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, UserId};

use crate::auditor::RequestAuditor;
use crate::email::refused_link;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{UserStore, VerificationTokenStore};
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::lookup::existing_verification_token;

/// The ports [`VerifyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct VerifyPorts {
    /// Loads and saves users.
    pub user_store: Arc<dyn UserStore>,
    /// Loads and saves verification links.
    pub token_store: Arc<dyn VerificationTokenStore>,
    /// Hashes the link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Confirms an address from the link mailed to it.
pub struct VerifyUseCase {
    ports: VerifyPorts,
}

impl VerifyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: VerifyPorts) -> Self {
        Self { ports }
    }
}

impl Command for VerifyUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<UserId, AppError>;

    /// Spends the link `raw_token` for the account it was mailed for, and
    /// marks that account's address confirmed. An account that waited only
    /// on this becomes active.
    ///
    /// No session is needed: following the link shows the reader holds the
    /// mailbox. It works only while the account still has the address it
    /// went to.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the token is unknown or already used, or its
    ///   user is gone.
    /// - `AppError::LinkExpired` if the link ran out of time, or the account
    ///   has moved to another address since: another can be sent.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<UserId, AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let token_hash = self.ports.token_generator.hash_raw(&raw_token);
        let mut token =
            existing_verification_token(self.ports.token_store.as_ref(), tenant, &token_hash)
                .await?;
        let mut user =
            existing_user(self.ports.user_store.as_ref(), tenant, token.user_id()).await?;
        let now = clock::now();
        let proof = token.redeem(&user, now).map_err(refused_link)?;
        user.verify_email(&proof).or_internal()?;

        self.ports
            .token_store
            .save(tenant, &token)
            .await
            .or_internal()?;
        self.ports
            .user_store
            .save(tenant, &user)
            .await
            .or_internal()?;
        let actor = ActorRef::User(*user.id());
        auditor
            .dispatch_by(&actor, user.take_events(tenant))
            .await
            .or_internal()?;
        Ok(*user.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::Email;
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::identity::{
        FakeTokenStore, FakeUserStore, stored_user, stored_verification_link,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const LINK: &str = "ann-link";

    /// Ann, who registered and has not confirmed her address, and the link
    /// mailed to it.
    struct Mailbox {
        ann: UserId,
        users: Arc<FakeUserStore>,
        tokens: Arc<FakeTokenStore>,
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
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn fresh() -> Self {
            Self::with_link_until(clock::now() + time::Duration::hours(1))
        }

        fn follow(&self, raw_token: &str) -> Result<UserId, AppError> {
            let use_case = VerifyUseCase::new(VerifyPorts {
                user_store: self.users.clone(),
                token_store: self.tokens.clone(),
                ..VerifyPorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                raw_token.to_owned(),
            ))
        }
    }

    /// Ann follows her link. Her address is confirmed, her account becomes
    /// active, and both the activation and the confirmation are recorded.
    #[test]
    fn following_the_link_confirms_the_address() {
        let mailbox = Mailbox::fresh();

        let confirmed = mailbox.follow(LINK).unwrap();

        assert_eq!(confirmed, mailbox.ann);
        assert_eq!(
            mailbox.users.get_status(&mailbox.ann),
            Some(UserStatus::Active)
        );
        assert_eq!(
            mailbox.sink.records.lock().unwrap().as_slice(),
            ["identity.user_status_changed", "identity.email_verified"]
        );
    }

    /// Ann follows a link nobody sent. It is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let mailbox = Mailbox::fresh();

        let result = mailbox.follow("nobody-sent-this");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(mailbox.sink.records.lock().unwrap().is_empty());
    }

    /// Ann follows her link twice. The second time it was already used.
    #[test]
    fn a_used_link_is_not_followed_again() {
        let mailbox = Mailbox::fresh();
        mailbox.follow(LINK).unwrap();

        let again = mailbox.follow(LINK);

        assert!(matches!(again, Err(AppError::NotFound(_))));
        assert_eq!(mailbox.sink.records.lock().unwrap().len(), 2);
    }

    /// Ann follows her link a day late. It has expired, so she can ask for
    /// another, and her address stays unconfirmed.
    #[test]
    fn an_expired_link_is_told_apart_from_a_missing_one() {
        let mailbox = Mailbox::with_link_until(clock::now() - time::Duration::minutes(1));

        let result = mailbox.follow(LINK);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert_eq!(
            mailbox.users.get_status(&mailbox.ann),
            Some(UserStatus::PendingVerification)
        );
    }

    /// A verification link sent before Ann changed addresses is treated as
    /// expired. Her new address stays unchanged and unconfirmed.
    #[test]
    fn a_link_to_an_address_the_account_left_confirms_nothing() {
        let mailbox = Mailbox::fresh();
        let moved = stored_user(mailbox.ann, "new@acme.com", UserStatus::PendingVerification);
        block_on(mailbox.users.save(&test_ctx().tenant(), &moved)).unwrap();

        let result = mailbox.follow(LINK);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        let ann = block_on(mailbox.users.find_by_id(&test_ctx().tenant(), &mailbox.ann))
            .unwrap()
            .unwrap();
        assert_eq!(ann.email(), &Email::new("new@acme.com").unwrap());
        assert!(!ann.email_verified());
    }

    /// Ann's account was deleted after the link went out. Following it finds
    /// no one.
    #[test]
    fn a_link_for_a_user_who_is_gone_is_not_found() {
        let mailbox = Mailbox::fresh();
        block_on(mailbox.users.delete(&test_ctx().tenant(), &mailbox.ann)).unwrap();

        let result = mailbox.follow(LINK);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
