//! Hold erasure: someone who may erase a person pauses the erasure asked for
//! them under a legal hold, so their records stay while a court order or an
//! audit duty says they must.

use std::sync::Arc;

use ianua_domain::types::ErasureRequestId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::ErasureRequestStore;
use crate::use_case::Command;
use crate::use_cases::identity::privacy::erasure::legal_hold::{HoldSources, Ruling, rule_on};

/// The ports [`HoldErasureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct HoldErasurePorts {
    /// Keeps erasure requests.
    pub erasure_store: Arc<dyn ErasureRequestStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Puts a pending erasure of the caller's tenant under a legal hold.
pub struct HoldErasureUseCase {
    ports: HoldErasurePorts,
}

impl HoldErasureUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: HoldErasurePorts) -> Self {
        Self { ports }
    }
}

impl Command for HoldErasureUseCase {
    type Caller = CallerContext;
    type Input = ErasureRequestId;
    type Output = Result<(), AppError>;

    /// Holds the pending erasure `request_id`, and records it. It waits,
    /// past its grace period, until the hold is lifted, and the person may
    /// still cancel it meanwhile. It needs what erasing the person needs.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the request doesn't exist.
    /// - `AppError::Forbidden` when the caller may not erase the person, or
    ///   the person holds more than the caller.
    /// - `AppError::Domain` when the request is not pending.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request_id: ErasureRequestId,
    ) -> Result<(), AppError> {
        let sources = HoldSources {
            erasures: self.ports.erasure_store.as_ref(),
            access_records: self.ports.access_records.as_ref(),
            authorities: self.ports.tenant_authorities.as_ref(),
        };
        let events = rule_on(sources, ctx, request_id, Ruling::Hold).await?;
        auditor
            .dispatch_by(&ctx.actor(), events)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeErasureStore, access_where_holds, stored_erasure};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Lea's erasure, asked a day ago and waiting out its grace period.
    struct Waiting {
        lea: UserId,
        request: ErasureRequestId,
        erasures: Arc<FakeErasureStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Waiting {
        fn new() -> Self {
            let lea = UserId::new();
            let erasure = stored_erasure(lea, "lea@acme.com", (1, 14));
            let request = *erasure.id();
            Self {
                lea,
                request,
                erasures: Arc::new(FakeErasureStore::holding(erasure)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> HoldErasurePorts {
            HoldErasurePorts {
                erasure_store: self.erasures.clone(),
                ..HoldErasurePorts::fakes()
            }
        }

        fn hold(&self, ports: HoldErasurePorts) -> Result<(), AppError> {
            block_on(HoldErasureUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                self.request,
            ))
        }

        fn status(&self) -> Option<ErasureStatus> {
            self.erasures.status_of(&self.request)
        }
    }

    /// Acme is under a court order to keep Lea's records. Ann holds her
    /// erasure; it waits, and the hold is recorded.
    #[test]
    fn a_held_erasure_waits() {
        let waiting = Waiting::new();

        waiting.hold(waiting.ports()).unwrap();

        assert_eq!(waiting.status(), Some(ErasureStatus::Held));
        assert_eq!(
            waiting.sink.records.lock().unwrap().as_slice(),
            ["identity.erasure_held"]
        );
    }

    /// Ann holds Lea's erasure twice. The second time it is no longer
    /// pending.
    #[test]
    fn a_held_erasure_is_not_held_again() {
        let waiting = Waiting::new();
        waiting.hold(waiting.ports()).unwrap();

        let again = waiting.hold(waiting.ports());

        assert!(matches!(again, Err(AppError::Domain(_))));
    }

    /// User-update rights do not permit holding Lea's erasure. The request
    /// stays pending after the refusal.
    #[test]
    fn a_caller_who_may_not_delete_users_is_refused() {
        let waiting = Waiting::new();
        let ports = HoldErasurePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..waiting.ports()
        };

        let result = waiting.hold(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(waiting.status(), Some(ErasureStatus::Pending));
    }

    /// User-deletion rights do not permit holding Lea's erasure when she
    /// holds broader user-management rights.
    #[test]
    fn a_person_holding_more_than_the_caller_is_refused() {
        let waiting = Waiting::new();
        let ports = HoldErasurePorts {
            access_records: access_where_holds(waiting.lea, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Delete),
            ])),
            ..waiting.ports()
        };

        let result = waiting.hold(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot hold Lea's erasure.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let waiting = Waiting::new();
        let ports = HoldErasurePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..waiting.ports()
        };

        let result = waiting.hold(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ann holds an erasure that does not exist. It is not found.
    #[test]
    fn an_unknown_request_is_not_found() {
        let waiting = Waiting::new();

        let result = block_on(HoldErasureUseCase::new(waiting.ports()).execute(
            &test_ctx(),
            &test_auditor(waiting.sink.clone()),
            ErasureRequestId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
