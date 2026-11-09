//! Cancel email change: the person reading the old address follows the
//! cancel link mailed there, and a tenant user's pending change of address
//! stops before it lands.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::email_change::ChangingAccount;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::TenantEmailChangeStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::email::changes::tenant::{change_by_cancel_link, changing_user};

/// The ports [`CancelChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelChangePorts {
    /// Loads and saves pending email changes.
    pub change_store: Arc<dyn TenantEmailChangeStore>,
    /// Loads the account the change was asked for.
    pub user_store: Arc<dyn UserStore>,
    /// Hashes the cancel link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Cancels a tenant user's pending email change from the link mailed to
/// their old address.
pub struct CancelChangeUseCase {
    ports: CancelChangePorts,
}

impl CancelChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CancelChangePorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelChangeUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<(), AppError>;

    /// Cancels the change whose cancel link carries `raw_token`, and records
    /// it.
    ///
    /// Following the link proves the reader holds the old mailbox, so a
    /// person whose session was stolen stops the move from there. It works
    /// until the change lands, even after the confirmation link ran out,
    /// and only while the account still has the old address.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed, or the change was
    ///   already confirmed or cancelled.
    /// - `AppError::NotFound` if the link is unknown or its account is gone.
    /// - `AppError::Forbidden` when the account no longer has the address
    ///   the link went to.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<(), AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let changes = self.ports.change_store.as_ref();
        let cancel_hash = self.ports.token_generator.hash_raw(&raw_token);
        let mut change = change_by_cancel_link(changes, tenant, &cancel_hash).await?;
        let user = changing_user(self.ports.user_store.as_ref(), tenant, &change).await?;
        change
            .cancel_from_old_address(ChangingAccount::from(&user), clock::now())
            .map_err(AppError::from_domain)?;

        changes.save(tenant, &change).await.or_internal()?;
        let actor = ActorRef::User(*user.id());
        auditor
            .dispatch_by(&actor, change.take_events(tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::email_change::ChangeState;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::identity::{
        FakeEmailChangeStore, FakeUserStore, stored_change, stored_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const CANCEL_LINK: &str = "cancel-ann-change";

    /// Ann, at ann@acme.com, with a change to new@acme.com waiting, and the
    /// cancel link mailed to her old address.
    struct Waiting {
        ann: UserId,
        users: Arc<FakeUserStore>,
        changes: Arc<FakeEmailChangeStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Waiting {
        fn new() -> Self {
            let ann = UserId::new();
            let changes = FakeEmailChangeStore::empty();
            let pending = stored_change(
                ann.into(),
                ("ann@acme.com", "new@acme.com"),
                "ann-change",
                clock::now() + time::Duration::hours(1),
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
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn cancel(&self, raw_token: &str) -> Result<(), AppError> {
            let use_case = CancelChangeUseCase::new(CancelChangePorts {
                change_store: self.changes.clone(),
                user_store: self.users.clone(),
                ..CancelChangePorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                raw_token.to_owned(),
            ))
        }

        fn stage(&self) -> ChangeState {
            block_on(self.changes.find_by_user(&test_ctx().tenant(), &self.ann))
                .unwrap()
                .unwrap()
                .stage()
        }
    }

    /// Ann reads at her old address that someone asked to move her account,
    /// and follows the cancel link. The change stops and it is recorded.
    #[test]
    fn the_cancel_link_stops_the_change() {
        let waiting = Waiting::new();

        waiting.cancel(CANCEL_LINK).unwrap();

        assert!(matches!(waiting.stage(), ChangeState::Cancelled { .. }));
        assert_eq!(
            waiting.sink.records.lock().unwrap().as_slice(),
            ["identity.email_change_cancelled"]
        );
    }

    /// Ann follows the cancel link twice. The second time the change is
    /// already cancelled.
    #[test]
    fn a_cancelled_change_is_not_cancelled_again() {
        let waiting = Waiting::new();
        waiting.cancel(CANCEL_LINK).unwrap();

        let again = waiting.cancel(CANCEL_LINK);

        assert!(matches!(again, Err(AppError::Domain(_))));
    }

    /// After Ann moves to another address, the old cancellation link is
    /// refused and the pending email change remains waiting.
    #[test]
    fn an_account_that_left_the_old_address_is_refused() {
        let waiting = Waiting::new();
        let moved = stored_user(waiting.ann, "elsewhere@acme.com", UserStatus::Active);
        block_on(waiting.users.save(&test_ctx().tenant(), &moved)).unwrap();

        let result = waiting.cancel(CANCEL_LINK);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(waiting.stage(), ChangeState::Waiting);
    }

    /// A confirmation token is not found as a cancellation link, leaving
    /// the email change waiting.
    #[test]
    fn the_confirmation_link_does_not_cancel() {
        let waiting = Waiting::new();

        let result = waiting.cancel("ann-change");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(waiting.stage(), ChangeState::Waiting);
    }
}
