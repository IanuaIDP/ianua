//! Cancel erasure: someone who may erase a person cancels the erasure asked
//! for them during its grace period, and their account opens again.

use std::sync::Arc;

use ianua_domain::domains::authorization::granter::right_for;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ErasureRequestId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::{ErasureRequestStore, UserStore};
use crate::services::lookup::existing_user;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::lookup::existing_erasure_request;

/// The ports [`CancelErasureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelErasurePorts {
    /// Keeps erasure requests.
    pub erasure_store: Arc<dyn ErasureRequestStore>,
    /// Loads and saves the account that opens again.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Cancels an erasure of the caller's tenant while it can still be stopped.
pub struct CancelErasureUseCase {
    ports: CancelErasurePorts,
}

impl CancelErasureUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CancelErasurePorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelErasureUseCase {
    type Caller = CallerContext;
    type Input = ErasureRequestId;
    type Output = Result<(), AppError>;

    /// Cancels the erasure `request_id`, pending or held, and opens its
    /// account again. It needs what erasing the person needs.
    ///
    /// The person cannot sign in while their erasure waits, so they cancel
    /// from the link mailed to them instead.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without erasure rights, before reading the request.
    /// - `AppError::NotFound` for a missing request/account; `Forbidden` when the person holds more rights.
    /// - `AppError::Domain` for a request past cancellation; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request_id: ErasureRequestId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let (users, erasures) = (
            self.ports.user_store.as_ref(),
            self.ports.erasure_store.as_ref(),
        );
        let records = self.ports.access_records.as_ref();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(right_for(AccountAction::Erase))
            .map_err(AppError::from_domain)?;
        let mut request = existing_erasure_request(erasures, &tenant, &request_id).await?;
        let user_id = *request.user_id();
        let mut account = existing_user(users, &tenant, &user_id).await?;
        let erasing = AccountAction::Erase;
        let control = account_control(records, &tenant, &authority, &user_id, erasing).await?;
        let cancelled = request.cancel_for(&mut account, &control);
        cancelled.map_err(AppError::from_domain)?;

        erasures.save(&tenant, &request).await.or_internal()?;
        users.save(&tenant, &account).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), request.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{
        FakeErasureStore, FakeUserStore, access_where_holds, stored_erasure, stored_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Lea, whose account closed when she asked to be forgotten a day ago,
    /// and her waiting erasure.
    struct Waiting {
        lea: UserId,
        request: ErasureRequestId,
        users: Arc<FakeUserStore>,
        erasures: Arc<FakeErasureStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Waiting {
        fn new() -> Self {
            let lea = UserId::new();
            let users = Arc::new(FakeUserStore::empty());
            users.add(stored_user(lea, "lea@acme.com", UserStatus::Closing));
            let erasure = stored_erasure(lea, "lea@acme.com", (1, 14));
            let request = *erasure.id();
            Self {
                lea,
                request,
                users,
                erasures: Arc::new(FakeErasureStore::holding(erasure)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> CancelErasurePorts {
            CancelErasurePorts {
                erasure_store: self.erasures.clone(),
                user_store: self.users.clone(),
                ..CancelErasurePorts::fakes()
            }
        }

        fn cancel(
            &self,
            ports: CancelErasurePorts,
            request: ErasureRequestId,
        ) -> Result<(), AppError> {
            block_on(CancelErasureUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                request,
            ))
        }
    }

    /// Lea phoned support to stop her erasure. Ann cancels it; Lea's
    /// account opens again and the cancellation is recorded.
    #[test]
    fn cancelling_opens_the_account_again() {
        let waiting = Waiting::new();

        waiting.cancel(waiting.ports(), waiting.request).unwrap();

        assert_eq!(
            waiting.erasures.status_of(&waiting.request),
            Some(ErasureStatus::Cancelled)
        );
        assert_eq!(
            waiting.users.get_status(&waiting.lea),
            Some(UserStatus::Active)
        );
        assert_eq!(
            waiting.sink.records.lock().unwrap().as_slice(),
            ["identity.erasure_cancelled"]
        );
    }

    /// Ann cancels an erasure that does not exist. It is not found.
    #[test]
    fn an_unknown_request_is_not_found() {
        let waiting = Waiting::new();

        let result = waiting.cancel(waiting.ports(), ErasureRequestId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann cancels twice. The second time it is past cancelling.
    #[test]
    fn a_cancelled_request_is_not_cancelled_again() {
        let waiting = Waiting::new();
        waiting.cancel(waiting.ports(), waiting.request).unwrap();

        let again = waiting.cancel(waiting.ports(), waiting.request);

        assert!(matches!(again, Err(AppError::Domain(_))));
    }

    /// User-update rights do not permit cancelling Lea's erasure. The
    /// request stays pending after the refusal.
    #[test]
    fn a_caller_who_may_not_delete_users_is_refused() {
        let waiting = Waiting::new();
        let ports = CancelErasurePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..waiting.ports()
        };

        let result = waiting.cancel(ports, waiting.request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            waiting.erasures.status_of(&waiting.request),
            Some(ErasureStatus::Pending)
        );
    }

    /// User-deletion rights do not permit cancelling Lea's erasure when
    /// she holds broader user-management rights.
    #[test]
    fn a_person_holding_more_than_the_caller_is_refused() {
        let waiting = Waiting::new();
        let ports = CancelErasurePorts {
            access_records: access_where_holds(waiting.lea, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Delete),
            ])),
            ..waiting.ports()
        };

        let result = waiting.cancel(ports, waiting.request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot cancel Lea's erasure.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let waiting = Waiting::new();
        let ports = CancelErasurePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..waiting.ports()
        };

        let result = waiting.cancel(ports, waiting.request);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
