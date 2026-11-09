//! Someone who may remove a member pauses the erasure asked for them under
//! a legal hold, so their records stay while a court order or an audit
//! duty says they must.

use std::sync::Arc;

use ianua_domain::types::{ActorRef, ErasureRequestId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgErasureRequestStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::privacy::legal_hold::{HoldSources, Ruling, rule_on};

/// The ports [`HoldOrgErasureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct HoldOrgErasurePorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Members' erasure requests.
    pub erasures: Arc<dyn OrgErasureRequestStore>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
}

/// Puts a pending erasure of a member under a legal hold.
pub struct HoldOrgErasureUseCase {
    ports: HoldOrgErasurePorts,
}

impl HoldOrgErasureUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: HoldOrgErasurePorts) -> Self {
        Self { ports }
    }
}

impl Command for HoldOrgErasureUseCase {
    type Caller = OrgCaller;
    type Input = ErasureRequestId;
    type Output = Result<(), AppError>;

    /// Holds the pending erasure `request_id` and records
    /// `organization.org_user_erasure_held`. It waits, past its grace
    /// period, until the hold is lifted, and the member may still cancel it
    /// meanwhile. It needs what removing the member needs.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the organization has no such request.
    /// - `AppError::Forbidden` when the caller may not remove the member.
    /// - `AppError::Domain` when the request is not pending.
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
        let events = rule_on(sources, caller, request_id, Ruling::Hold).await?;
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
        uc: HoldOrgErasureUseCase,
        erasures: Arc<FakeOrgErasureStore>,
        audit: Arc<FakeEventDispatcher>,
        request: ErasureRequestId,
    }

    /// Sam's erasure waiting at `state`, with the caller acting as `actors`
    /// says.
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
            uc: HoldOrgErasureUseCase::new(HoldOrgErasurePorts {
                org_actors: Arc::new(actors),
                erasures: erasures.clone(),
                org_users: Arc::new(org_user_store_with([sam])),
            }),
            erasures,
            audit: Arc::new(FakeEventDispatcher::new()),
            request,
        }
    }

    fn hold(setup: &Setup, id: ErasureRequestId) -> Result<(), AppError> {
        block_on(
            setup
                .uc
                .execute(&test_org_caller(), &test_auditor(setup.audit.clone()), id),
        )
    }

    /// Olivia, an owner, holds Sam's pending erasure for an audit. It is
    /// held and the hold is recorded.
    #[test]
    fn an_owner_holds_a_pending_erasure() {
        let setup = sams_erasure(
            FakeOrgActors::in_role(OrgRole::Owner),
            ErasureState::Pending,
        );

        hold(&setup, setup.request).unwrap();

        assert_eq!(
            setup.erasures.status_of(&setup.request),
            Some(ErasureStatus::Held)
        );
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_erasure_held"]
        );
    }

    /// An erasure already being carried out cannot be held.
    #[test]
    fn an_erasure_under_way_is_not_held() {
        let setup = sams_erasure(
            FakeOrgActors::in_role(OrgRole::Owner),
            ErasureState::Processing,
        );

        let result = hold(&setup, setup.request);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A viewer cannot place a legal hold on a member's erasure, which
    /// stays pending.
    #[test]
    fn a_viewer_is_refused() {
        let setup = sams_erasure(
            FakeOrgActors::in_role(OrgRole::Viewer),
            ErasureState::Pending,
        );

        let result = hold(&setup, setup.request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            setup.erasures.status_of(&setup.request),
            Some(ErasureStatus::Pending)
        );
    }

    /// Olivia names a request Acme does not have. It is not found.
    #[test]
    fn an_unknown_request_is_not_found() {
        let setup = sams_erasure(
            FakeOrgActors::in_role(OrgRole::Owner),
            ErasureState::Pending,
        );

        let result = hold(&setup, ErasureRequestId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot authorize a legal hold.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = sams_erasure(
            FakeOrgActors::refusing(Refusal::SignedOut),
            ErasureState::Pending,
        );

        let result = hold(&setup, setup.request);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
