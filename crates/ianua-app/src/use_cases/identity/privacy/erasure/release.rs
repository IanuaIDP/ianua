//! Release erasure: someone who may erase a person lifts the legal hold on
//! the erasure asked for them, and it waits again, due at once if its grace
//! period has passed.

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

/// The ports [`ReleaseErasureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReleaseErasurePorts {
    /// Keeps erasure requests.
    pub erasure_store: Arc<dyn ErasureRequestStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lifts the legal hold on an erasure of the caller's tenant.
pub struct ReleaseErasureUseCase {
    ports: ReleaseErasurePorts,
}

impl ReleaseErasureUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReleaseErasurePorts) -> Self {
        Self { ports }
    }
}

impl Command for ReleaseErasureUseCase {
    type Caller = CallerContext;
    type Input = ErasureRequestId;
    type Output = Result<(), AppError>;

    /// Lifts the hold on the erasure `request_id`, and records it. The
    /// erasure waits again, and the next sweep carries it out if its grace
    /// period has passed. It needs what erasing the person needs.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the request doesn't exist.
    /// - `AppError::Forbidden` when the caller may not erase the person, or
    ///   the person holds more than the caller.
    /// - `AppError::Domain` when the request is not held.
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
        let events = rule_on(sources, ctx, request_id, Ruling::Release).await?;
        auditor
            .dispatch_by(&ctx.actor(), events)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::privacy::erasure::ErasureState;
    use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeErasureStore, stored_erasure_at};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Lea's erasure, asked a day ago and paused under a legal hold since,
    /// or standing at `state`.
    struct Erasure {
        request: ErasureRequestId,
        erasures: Arc<FakeErasureStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Erasure {
        fn at(state: ErasureState) -> Self {
            let erasure = stored_erasure_at(UserId::new(), "lea@acme.com", (1, 14), state);
            let request = *erasure.id();
            Self {
                request,
                erasures: Arc::new(FakeErasureStore::holding(erasure)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn held() -> Self {
            Self::at(ErasureState::Held)
        }

        fn ports(&self) -> ReleaseErasurePorts {
            ReleaseErasurePorts {
                erasure_store: self.erasures.clone(),
                ..ReleaseErasurePorts::fakes()
            }
        }

        fn release(&self, ports: ReleaseErasurePorts) -> Result<(), AppError> {
            block_on(ReleaseErasureUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                self.request,
            ))
        }

        fn status(&self) -> Option<ErasureStatus> {
            self.erasures.status_of(&self.request)
        }
    }

    /// The court order on Lea's records ended. Ann lifts the hold; the
    /// erasure waits again and the release is recorded.
    #[test]
    fn a_released_erasure_waits_again() {
        let held = Erasure::held();

        held.release(held.ports()).unwrap();

        assert_eq!(held.status(), Some(ErasureStatus::Pending));
        assert_eq!(
            held.sink.records.lock().unwrap().as_slice(),
            ["identity.erasure_released"]
        );
    }

    /// Ann releases an erasure no hold was put on. There is nothing to
    /// lift.
    #[test]
    fn an_erasure_that_is_not_held_is_not_released() {
        let pending = Erasure::at(ErasureState::Pending);

        let result = pending.release(pending.ports());

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// User-update rights do not permit releasing an erasure hold. Lea's
    /// request stays held after the refusal.
    #[test]
    fn a_caller_who_may_not_delete_users_is_refused() {
        let held = Erasure::held();
        let ports = ReleaseErasurePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..held.ports()
        };

        let result = held.release(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(held.status(), Some(ErasureStatus::Held));
    }

    /// A signed-out caller cannot release Lea's erasure, which stays held.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let held = Erasure::held();
        let ports = ReleaseErasurePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..held.ports()
        };

        let result = held.release(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(held.status(), Some(ErasureStatus::Held));
    }
}
