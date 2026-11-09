//! Someone who may remove a member cancels the erasure asked for them, and
//! the member's account opens again.

use std::sync::Arc;

use ianua_domain::domains::organization::members::account_control::OrgAccountControl;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, ErasureRequestId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgErasureRequestStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::privacy::lookup::existing_org_erasure;

/// The ports [`CancelOrgErasureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelOrgErasurePorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Members' erasure requests.
    pub erasures: Arc<dyn OrgErasureRequestStore>,
    /// The organization's members, the one opening again among them.
    pub org_users: Arc<dyn OrgUserStore>,
}

/// Cancels a member's erasure for them.
pub struct CancelOrgErasureUseCase {
    ports: CancelOrgErasurePorts,
}

impl CancelOrgErasureUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: CancelOrgErasurePorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelOrgErasureUseCase {
    type Caller = OrgCaller;
    type Input = ErasureRequestId;
    type Output = Result<(), AppError>;

    /// Cancels the erasure `request_id`, pending or held, opens its
    /// member's account again, and records
    /// `organization.org_user_erasure_cancelled`. It needs what removing
    /// the member needs.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the organization has no such request or
    ///   member.
    /// - `AppError::Forbidden` when the caller may not remove the member.
    /// - `AppError::Domain` when the erasure is past cancelling.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request_id: ErasureRequestId,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let (erasures, users) = (self.ports.erasures.as_ref(), self.ports.org_users.as_ref());
        let mut request = existing_org_erasure(erasures, organization.id(), &request_id).await?;
        let member_id = *request.org_user_id();
        let target = existing_member(users, organization.id(), &member_id).await?;
        let mut member = existing_member(users, organization.id(), &member_id).await?;
        request
            .cancel_for(&mut member, &OrgAccountControl::new(control, &target))
            .map_err(AppError::from_domain)?;
        erasures.save(&request).await.or_internal()?;
        users.save(&member).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), request.take_events())
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
    use ianua_domain::types::OrgUserId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgErasureStore, FakeOrgUserStore, org_user_store_with, stored_org_erasure,
        test_org_member_at,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: CancelOrgErasureUseCase,
        users: Arc<FakeOrgUserStore>,
        erasures: Arc<FakeOrgErasureStore>,
        audit: Arc<FakeEventDispatcher>,
        sam: OrgUserId,
        request: ErasureRequestId,
    }

    /// Sam's pending erasure, with the caller acting as `actors` says.
    fn sams_erasure(actors: FakeOrgActors) -> Setup {
        let sam = test_org_member_at(
            test_org_caller().organization_id(),
            "sam@acme.test",
            OrgUserStatus::Closing,
        );
        let erasure = stored_org_erasure(&sam, (1, 14), ErasureState::Pending);
        let (sam_id, request) = (*sam.id(), *erasure.id());
        let users = Arc::new(org_user_store_with([sam]));
        let erasures = Arc::new(FakeOrgErasureStore::holding([erasure]));
        Setup {
            uc: CancelOrgErasureUseCase::new(CancelOrgErasurePorts {
                org_actors: Arc::new(actors),
                erasures: erasures.clone(),
                org_users: users.clone(),
            }),
            users,
            erasures,
            audit: Arc::new(FakeEventDispatcher::new()),
            sam: sam_id,
            request,
        }
    }

    fn cancel(setup: &Setup, id: ErasureRequestId) -> Result<(), AppError> {
        block_on(
            setup
                .uc
                .execute(&test_org_caller(), &test_auditor(setup.audit.clone()), id),
        )
    }

    /// Sam asked by phone to stay. Olivia, an owner, cancels his erasure.
    /// It is cancelled, his account opens again, and it is recorded.
    #[test]
    fn an_owner_cancels_for_a_member() {
        let setup = sams_erasure(FakeOrgActors::in_role(OrgRole::Owner));

        cancel(&setup, setup.request).unwrap();

        assert_eq!(
            setup.erasures.status_of(&setup.request),
            Some(ErasureStatus::Cancelled)
        );
        assert_eq!(
            setup.users.get_status(&setup.sam),
            Some(OrgUserStatus::Active)
        );
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_erasure_cancelled"]
        );
    }

    /// A viewer cannot cancel Sam's erasure; his account stays closing and
    /// no cancellation is recorded.
    #[test]
    fn a_viewer_is_refused() {
        let setup = sams_erasure(FakeOrgActors::in_role(OrgRole::Viewer));

        let result = cancel(&setup, setup.request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            setup.users.get_status(&setup.sam),
            Some(OrgUserStatus::Closing)
        );
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// Olivia names a request Acme does not have. It is not found.
    #[test]
    fn an_unknown_request_is_not_found() {
        let setup = sams_erasure(FakeOrgActors::in_role(OrgRole::Owner));

        let result = cancel(&setup, ErasureRequestId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot authorize an erasure cancellation.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = sams_erasure(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = cancel(&setup, setup.request);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
