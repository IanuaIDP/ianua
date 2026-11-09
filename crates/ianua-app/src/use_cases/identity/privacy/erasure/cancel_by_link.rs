//! Cancel erasure by link: the person who asked to be forgotten follows the
//! cancel link mailed to them during the grace period, and their account
//! opens again.
//!
//! Their account is closed while the erasure waits, so they cannot sign in
//! to cancel. The link is how they change their mind.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::identity::{ErasureRequestStore, UserStore};
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`CancelErasureByLinkUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelErasureByLinkPorts {
    /// Keeps erasure requests.
    pub erasure_store: Arc<dyn ErasureRequestStore>,
    /// Loads and saves the account that opens again.
    pub user_store: Arc<dyn UserStore>,
    /// Hashes the cancel link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Cancels an erasure from the link mailed to the person it is for.
pub struct CancelErasureByLinkUseCase {
    ports: CancelErasureByLinkPorts,
}

impl CancelErasureByLinkUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CancelErasureByLinkPorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelErasureByLinkUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<(), AppError>;

    /// Cancels the erasure whose cancel link carries `raw_token`, pending or
    /// held, opens its account again, and records it.
    ///
    /// Following the link proves the reader holds the mailbox it went to.
    /// It counts only while the account still has that address.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed, or the erasure is
    ///   past cancelling.
    /// - `AppError::NotFound` if the link is unknown or its account is gone.
    /// - `AppError::Forbidden` when the account left the address the link
    ///   went to.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<(), AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let (users, erasures) = (
            self.ports.user_store.as_ref(),
            self.ports.erasure_store.as_ref(),
        );
        let cancel_hash = self.ports.token_generator.hash_raw(&raw_token);
        let found = erasures
            .find_by_cancel_token_hash(tenant, &cancel_hash)
            .await;
        let mut request = found.or_internal()?.or_not_found(message!(
            "identity-invalid-erasure-cancel-link",
            "invalid erasure cancel link"
        ))?;
        let mut account = existing_user(users, tenant, request.user_id()).await?;
        let cancelled = request.cancel_from_link(&mut account);
        cancelled.map_err(AppError::from_domain)?;

        erasures.save(tenant, &request).await.or_internal()?;
        users.save(tenant, &account).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::User(*account.id()), request.take_events(tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::privacy::erasure::ErasureState;
    use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
    use ianua_domain::types::{ErasureRequestId, UserId};

    use super::*;
    use crate::test_support::identity::{
        FakeErasureStore, FakeUserStore, stored_erasure_at, stored_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Lea, whose account closed when she asked to be forgotten a day ago,
    /// her erasure standing at some state, and the cancel link mailed to
    /// lea@acme.com.
    struct Erasure {
        lea: UserId,
        request: ErasureRequestId,
        users: Arc<FakeUserStore>,
        erasures: Arc<FakeErasureStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Erasure {
        fn at(state: ErasureState) -> Self {
            let lea = UserId::new();
            let users = Arc::new(FakeUserStore::empty());
            users.add(stored_user(lea, "lea@acme.com", UserStatus::Closing));
            let erasure = stored_erasure_at(lea, "lea@acme.com", (1, 14), state);
            let request = *erasure.id();
            Self {
                lea,
                request,
                users,
                erasures: Arc::new(FakeErasureStore::holding(erasure)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn link(&self) -> String {
            format!("cancel-{}", self.lea)
        }

        fn cancel(&self, raw_token: &str) -> Result<(), AppError> {
            let use_case = CancelErasureByLinkUseCase::new(CancelErasureByLinkPorts {
                erasure_store: self.erasures.clone(),
                user_store: self.users.clone(),
                ..CancelErasureByLinkPorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                raw_token.to_owned(),
            ))
        }

        fn status(&self) -> Option<ErasureStatus> {
            self.erasures.status_of(&self.request)
        }
    }

    /// Lea changes her mind and follows the cancel link. The erasure is
    /// cancelled, her account opens again, and it is recorded.
    #[test]
    fn the_cancel_link_opens_the_account_again() {
        let erasure = Erasure::at(ErasureState::Pending);

        erasure.cancel(&erasure.link()).unwrap();

        assert_eq!(erasure.status(), Some(ErasureStatus::Cancelled));
        assert_eq!(
            erasure.users.get_status(&erasure.lea),
            Some(UserStatus::Active)
        );
        assert_eq!(
            erasure.sink.records.lock().unwrap().as_slice(),
            ["identity.erasure_cancelled"]
        );
    }

    /// Lea's erasure is under a legal hold. She may still cancel it from
    /// her link.
    #[test]
    fn a_held_erasure_is_cancelled_from_the_link() {
        let erasure = Erasure::at(ErasureState::Held);

        erasure.cancel(&erasure.link()).unwrap();

        assert_eq!(erasure.status(), Some(ErasureStatus::Cancelled));
    }

    /// Lea follows the link once deletion has started. It is past
    /// cancelling.
    #[test]
    fn an_erasure_under_way_is_not_cancelled() {
        let erasure = Erasure::at(ErasureState::Processing);

        let result = erasure.cancel(&erasure.link());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(erasure.status(), Some(ErasureStatus::Processing));
    }

    /// After Lea changes address, the cancellation link mailed to her old
    /// address is refused, and her erasure stays pending.
    #[test]
    fn an_account_that_left_the_address_is_refused() {
        let erasure = Erasure::at(ErasureState::Pending);
        let moved = stored_user(erasure.lea, "lea@elsewhere.com", UserStatus::Closing);
        block_on(erasure.users.save(&test_ctx().tenant(), &moved)).unwrap();

        let result = erasure.cancel(&erasure.link());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(erasure.status(), Some(ErasureStatus::Pending));
    }

    /// A cancel link nobody sent is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let erasure = Erasure::at(ErasureState::Pending);

        let result = erasure.cancel("nobody-sent-this");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
