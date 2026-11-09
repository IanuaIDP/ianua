//! Resume destination: post an organization's notifications to a paused
//! destination again.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, NotificationDestinationId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::NotificationDestinationStore;
use crate::use_case::Command;
use crate::use_cases::notifications::destinations::lookup::existing_destination;

/// The ports [`ResumeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResumePorts {
    /// Where the organization's destinations are kept.
    pub destinations: Arc<dyn NotificationDestinationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Posts to a paused destination again.
pub struct ResumeUseCase {
    ports: ResumePorts,
}

impl ResumeUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ResumePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResumeUseCase {
    type Caller = OrgCaller;
    type Input = NotificationDestinationId;
    type Output = Result<(), AppError>;

    /// Posts to the destination `destination_id` again and records
    /// `notifications.destination_resumed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage the
    ///   organization's notifications.
    /// - `AppError::NotFound` when the organization has no such destination.
    /// - `AppError::Domain` when it is not paused.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        destination_id: NotificationDestinationId,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let store = self.ports.destinations.as_ref();
        let mut destination =
            existing_destination(store, organization.id(), &destination_id).await?;
        destination
            .resume(&control)
            .map_err(AppError::from_domain)?;
        store.save(&destination).await.or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*actor.member().id()),
                destination.take_events(),
            )
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::destination::DestinationState;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::notification_delivery::{FakeDestinationStore, destination_in_state};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ResumeUseCase,
        destinations: Arc<FakeDestinationStore>,
        audit: Arc<FakeEventDispatcher>,
        id: NotificationDestinationId,
    }

    impl Setup {
        fn over(state: DestinationState, actors: FakeOrgActors) -> Self {
            let hook = destination_in_state(
                test_org_caller().organization_id(),
                NotificationSeverity::Info,
                state,
            );
            let id = *hook.id();
            let destinations = Arc::new(FakeDestinationStore::holding([hook]));
            Self {
                uc: ResumeUseCase::new(ResumePorts {
                    destinations: destinations.clone(),
                    org_actors: Arc::new(actors),
                }),
                destinations,
                audit: Arc::new(FakeEventDispatcher::new()),
                id,
            }
        }

        fn resume(&self, id: NotificationDestinationId) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(&test_org_caller(), &test_auditor(self.audit.clone()), id),
            )
        }

        fn state(&self) -> DestinationState {
            self.destinations.stored(&self.id).unwrap().state()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann resumes Acme's paused webhook. It posts again and the resume is
    /// recorded.
    #[test]
    fn an_owner_resumes_a_destination() {
        let setup = Setup::over(
            DestinationState::Paused,
            FakeOrgActors::in_role(OrgRole::Owner),
        );

        setup.resume(setup.id).unwrap();

        assert_eq!(setup.state(), DestinationState::Active);
        assert_eq!(setup.recorded(), vec!["notifications.destination_resumed"]);
    }

    /// The webhook is posting already. Resuming it is refused.
    #[test]
    fn an_active_destination_cannot_be_resumed() {
        let setup = Setup::over(
            DestinationState::Active,
            FakeOrgActors::in_role(OrgRole::Owner),
        );

        let result = setup.resume(setup.id);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Ann names a destination Acme does not have. It is not found.
    #[test]
    fn an_unknown_destination_is_not_found() {
        let setup = Setup::over(
            DestinationState::Paused,
            FakeOrgActors::in_role(OrgRole::Owner),
        );

        let result = setup.resume(NotificationDestinationId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An ordinary organization member cannot resume a destination; it stays
    /// paused and no event is recorded.
    #[test]
    fn a_member_who_may_not_manage_notifications_is_refused() {
        let setup = Setup::over(
            DestinationState::Paused,
            FakeOrgActors::in_role(OrgRole::Member),
        );

        let result = setup.resume(setup.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.state(), DestinationState::Paused);
        assert!(setup.recorded().is_empty());
    }

    /// Resuming a destination with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::over(
            DestinationState::Paused,
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        let result = setup.resume(setup.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
