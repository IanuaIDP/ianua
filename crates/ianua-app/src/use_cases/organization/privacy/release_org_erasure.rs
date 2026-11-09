//! Lifting the legal hold on a member's erasure, so it waits again and is
//! carried out once its grace period is over.

use std::sync::Arc;

use ianua_domain::types::{ActorRef, ErasureRequestId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgErasureRequestStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::privacy::legal_hold::{HoldSources, Ruling, rule_on};

/// The ports [`ReleaseOrgErasureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReleaseOrgErasurePorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Members' erasure requests.
    pub erasures: Arc<dyn OrgErasureRequestStore>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
}

/// Lifts the legal hold on a member's erasure.
pub struct ReleaseOrgErasureUseCase {
    ports: ReleaseOrgErasurePorts,
}

impl ReleaseOrgErasureUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ReleaseOrgErasurePorts) -> Self {
        Self { ports }
    }
}

impl Command for ReleaseOrgErasureUseCase {
    type Caller = OrgCaller;
    type Input = ErasureRequestId;
    type Output = Result<(), AppError>;

    /// Lifts the hold on the erasure `request_id` and records
    /// `organization.org_user_erasure_released`. It is pending again, and
    /// due at once if its grace period has passed. It needs what removing
    /// the member needs.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the organization has no such request.
    /// - `AppError::Forbidden` when the caller may not remove the member.
    /// - `AppError::Domain` when the request is not held.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request_id: ErasureRequestId,
    ) -> Result<(), AppError> {
        let sources = HoldSources {
            actors: self.ports.org_actors.as_ref(),
            erasures: self.ports.erasures.as_ref(),
            members: self.ports.org_users.as_ref(),
        };
        let events = rule_on(sources, caller, request_id, Ruling::Release).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), events)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::privacy::erasure::ErasureState;
    use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgErasureStore, org_user_store_with, stored_org_erasure, test_org_member_at,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ReleaseOrgErasureUseCase,
        erasures: Arc<FakeOrgErasureStore>,
        audit: Arc<FakeEventDispatcher>,
        request: ErasureRequestId,
    }

    /// Sam's erasure standing at `state`, with the caller acting as
    /// `actors` says.
    fn sams_erasure(actors: FakeOrgActors, state: ErasureState) -> Setup {
        let sam = test_org_member_at(
            test_org_caller().organization_id(),
            "sam@acme.test",
            OrgUserStatus::Closing,
        );
        let erasure = stored_org_erasure(&sam, (1, 14), state);
        let request = *erasure.id();
        let erasures = Arc::new(FakeOrgErasureStore::holding([erasure]));
        Setup {
            uc: ReleaseOrgErasureUseCase::new(ReleaseOrgErasurePorts {
                org_actors: Arc::new(actors),
                erasures: erasures.clone(),
                org_users: Arc::new(org_user_store_with([sam])),
            }),
            erasures,
            audit: Arc::new(FakeEventDispatcher::new()),
            request,
        }
    }

    fn release(setup: &Setup) -> Result<(), AppError> {
        block_on(setup.uc.execute(
            &test_org_caller(),
            &test_auditor(setup.audit.clone()),
            setup.request,
        ))
    }

    /// The audit is over and Olivia lifts the hold on Sam's erasure. It is
    /// pending again and the release is recorded.
    #[test]
    fn an_owner_lifts_a_hold() {
        let setup = sams_erasure(FakeOrgActors::in_role(OrgRole::Owner), ErasureState::Held);

        release(&setup).unwrap();

        assert_eq!(
            setup.erasures.status_of(&setup.request),
            Some(ErasureStatus::Pending)
        );
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_erasure_released"]
        );
    }

    /// An erasure never held has no hold to lift.
    #[test]
    fn an_erasure_not_held_is_not_released() {
        let setup = sams_erasure(
            FakeOrgActors::in_role(OrgRole::Owner),
            ErasureState::Pending,
        );

        let result = release(&setup);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A billing contact cannot release an erasure's legal hold, which
    /// remains in place.
    #[test]
    fn a_billing_contact_is_refused() {
        let setup = sams_erasure(FakeOrgActors::in_role(OrgRole::Billing), ErasureState::Held);

        let result = release(&setup);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            setup.erasures.status_of(&setup.request),
            Some(ErasureStatus::Held)
        );
    }

    /// A signed-out session cannot release a legal hold.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = sams_erasure(
            FakeOrgActors::refusing(Refusal::SignedOut),
            ErasureState::Held,
        );

        let result = release(&setup);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
