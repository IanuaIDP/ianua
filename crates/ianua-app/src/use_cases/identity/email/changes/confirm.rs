//! Confirm email change: the person follows the link mailed to their new
//! address, and their account moves onto it, confirmed.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::email_change::ChangingAccount;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Email};

use crate::auditor::RequestAuditor;
use crate::email::refused_link;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::ResetRequestStore;
use crate::ports::identity::{UserStore, VerificationTokenStore};
use crate::ports::shared::{Mailer, TenantEmailChangeStore};
use crate::services::identity::address_free::ensure_email_free;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::email::changes::links::{MailedIn, notify_old_address};
use crate::use_cases::identity::email::changes::tenant::{change_by_link, changing_user};

/// The ports [`ConfirmChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmChangePorts {
    /// Loads and saves pending email changes.
    pub change_store: Arc<dyn TenantEmailChangeStore>,
    /// Loads and saves the account that moves.
    pub user_store: Arc<dyn UserStore>,
    /// Ends the verification links mailed to the old address.
    pub token_store: Arc<dyn VerificationTokenStore>,
    /// Ends the password resets mailed to the old address.
    pub reset_requests: Arc<dyn ResetRequestStore>,
    /// Tells the old address where the account went.
    pub mailer: Arc<dyn Mailer>,
    /// Hashes the link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Moves a tenant user onto the address their confirmation link was mailed
/// to.
pub struct ConfirmChangeUseCase {
    ports: ConfirmChangePorts,
}

impl ConfirmChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConfirmChangePorts) -> Self {
        Self { ports }
    }

    /// Ends every link mailed to the address `user` left.
    async fn end_old_links(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.ports
            .token_store
            .consume_outstanding(tenant, user.id())
            .await
            .or_internal()?;
        self.ports
            .reset_requests
            .expire_pending_for_user(tenant, user.id())
            .await
            .or_internal()
    }
}

impl Command for ConfirmChangeUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<Email, AppError>;

    /// Confirms the change `raw_token` belongs to and moves its account
    /// onto the new address, confirmed, returning that address.
    ///
    /// Following the link proves the reader holds the new mailbox. It counts
    /// only for the account that asked, while that account still has the
    /// address it asked from and has not changed how it signs in since.
    /// Every link mailed to the old address stops working, and the old
    /// address is told.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is unknown or already used, or its
    ///   account is gone.
    /// - `AppError::LinkExpired` if the link ran out, or the change was
    ///   overtaken by another change to the account.
    /// - `AppError::Conflict` if another user already has the new address.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<Email, AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let (users, changes) = (
            self.ports.user_store.as_ref(),
            self.ports.change_store.as_ref(),
        );
        let token_hash = self.ports.token_generator.hash_raw(&raw_token);
        let mut change = change_by_link(changes, tenant, &token_hash).await?;
        let mut user = changing_user(users, tenant, &change).await?;
        let confirmed = change.confirm(ChangingAccount::from(&user), clock::now());
        let proof = confirmed.map_err(refused_link)?;
        ensure_email_free(users, tenant, proof.as_email()).await?;
        let old_email = user.email().clone();
        user.change_verified_email(proof).or_internal()?;

        users.save(tenant, &user).await.or_internal()?;
        changes.save(tenant, &change).await.or_internal()?;
        self.end_old_links(tenant, &user).await?;
        let actor = ActorRef::User(*user.id());
        auditor
            .dispatch_by(&actor, user.take_events(tenant))
            .await
            .or_internal()?;
        let mailer = self.ports.mailer.as_ref();
        let mailed_in = MailedIn::Tenant {
            tenant: *tenant,
            locale: user.locale(),
        };
        notify_old_address(mailer, &old_email, mailed_in, user.email()).await;
        Ok(user.email().clone())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::UserId;
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::authentication::FakeResetRequestStore;
    use crate::test_support::identity::{
        FakeEmailChangeStore, FakeUserStore, stored_change, stored_user,
    };
    use crate::test_support::{FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_ctx};

    const LINK: &str = "ann-change";

    /// Ann, at ann@acme.com, who asked to move to new@acme.com, and the link
    /// mailed there.
    struct Change {
        ann: UserId,
        users: Arc<FakeUserStore>,
        changes: Arc<FakeEmailChangeStore>,
        resets: Arc<FakeResetRequestStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Change {
        fn with_link_until(expires_at: OffsetDateTime) -> Self {
            let ann = UserId::new();
            let changes = FakeEmailChangeStore::empty();
            let pending = stored_change(
                ann.into(),
                ("ann@acme.com", "new@acme.com"),
                LINK,
                expires_at,
            );
            block_on(TenantEmailChangeStore::save(
                &changes,
                &test_ctx().tenant(),
                &pending,
            ))
            .unwrap();
            Self {
                ann,
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.com")),
                changes: Arc::new(changes),
                resets: Arc::new(FakeResetRequestStore::empty()),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn live() -> Self {
            Self::with_link_until(clock::now() + time::Duration::hours(1))
        }

        fn confirm(&self, raw_token: &str) -> Result<Email, AppError> {
            let use_case = ConfirmChangeUseCase::new(ConfirmChangePorts {
                change_store: self.changes.clone(),
                user_store: self.users.clone(),
                reset_requests: self.resets.clone(),
                mailer: self.mailer.clone(),
                ..ConfirmChangePorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                raw_token.to_owned(),
            ))
        }

        fn ann(&self) -> User<ResolvedTenant> {
            block_on(self.users.find_by_id(&test_ctx().tenant(), &self.ann))
                .unwrap()
                .unwrap()
        }
    }

    /// Ann follows the link at new@acme.com. Her account moves there,
    /// confirmed, the old address is told, and the change is recorded.
    #[test]
    fn following_the_link_moves_the_account() {
        let change = Change::live();

        let moved_to = change.confirm(LINK).unwrap();

        assert_eq!(moved_to.as_str(), "new@acme.com");
        let ann = change.ann();
        assert_eq!(ann.email().as_str(), "new@acme.com");
        assert!(ann.email_verified());
        assert_eq!(change.mailer.recipients(), ["ann@acme.com"]);
        assert_eq!(
            change.sink.records.lock().unwrap()[0],
            "identity.email_changed"
        );
    }

    /// Ann's move ends the password resets mailed to her old address.
    #[test]
    fn resets_mailed_to_the_old_address_are_ended() {
        let change = Change::live();

        change.confirm(LINK).unwrap();

        assert_eq!(change.resets.superseded(), [change.ann]);
    }

    /// Ann follows the link twice. The second time it was already used.
    #[test]
    fn a_used_link_is_not_followed_again() {
        let change = Change::live();
        change.confirm(LINK).unwrap();

        let again = change.confirm(LINK);

        assert!(matches!(again, Err(AppError::NotFound(_))));
    }

    /// Ann follows the link a day late. It has expired and she stays where
    /// she was.
    #[test]
    fn an_expired_link_moves_nothing() {
        let change = Change::with_link_until(clock::now() - time::Duration::minutes(1));

        let result = change.confirm(LINK);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert_eq!(change.ann().email().as_str(), "ann@acme.com");
    }

    /// A credential change expires Ann's earlier email-change link.
    /// Following it leaves her account at its original address.
    #[test]
    fn a_change_the_account_outlived_moves_nothing() {
        let change = Change::live();
        let mut ann = stored_user(change.ann, "ann@acme.com", UserStatus::Active);
        ann.record_credential_change();
        block_on(change.users.save(&test_ctx().tenant(), &ann)).unwrap();

        let result = change.confirm(LINK);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert_eq!(change.ann().email().as_str(), "ann@acme.com");
    }

    /// Bob took new@acme.com while Ann's change waited. Her confirmation is
    /// a conflict and she stays where she was.
    #[test]
    fn an_address_taken_meanwhile_is_a_conflict() {
        let change = Change::live();
        change.users.add_active_user(UserId::new(), "new@acme.com");

        let result = change.confirm(LINK);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(change.ann().email().as_str(), "ann@acme.com");
    }

    /// A link nobody sent is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let change = Change::live();

        let result = change.confirm("nobody-sent-this");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
