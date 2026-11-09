//! Remove destination: stop posting an organization's notifications to a
//! destination for good, and forget its sealed address and secret.

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

/// The ports [`RemoveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemovePorts {
    /// Where the organization's destinations are kept.
    pub destinations: Arc<dyn NotificationDestinationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Removes a notification destination.
pub struct RemoveUseCase {
    ports: RemovePorts,
}

impl RemoveUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RemovePorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveUseCase {
    type Caller = OrgCaller;
    type Input = NotificationDestinationId;
    type Output = Result<(), AppError>;

    /// Deletes the destination `destination_id` and records
    /// `notifications.destination_removed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage the
    ///   organization's notifications.
    /// - `AppError::NotFound` when the organization has no such destination.
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
            .remove(&control)
            .map_err(AppError::from_domain)?;
        store
            .delete(organization.id(), &destination_id)
            .await
            .or_internal()?;
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
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::notification_delivery::{FakeDestinationStore, webhook_destination};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: RemoveUseCase,
        destinations: Arc<FakeDestinationStore>,
        audit: Arc<FakeEventDispatcher>,
        id: NotificationDestinationId,
    }

    impl Setup {
        fn acting_as(actors: FakeOrgActors) -> Self {
            let hook = webhook_destination(
                test_org_caller().organization_id(),
                NotificationSeverity::Info,
            );
            let id = *hook.id();
            let destinations = Arc::new(FakeDestinationStore::holding([hook]));
            Self {
                uc: RemoveUseCase::new(RemovePorts {
                    destinations: destinations.clone(),
                    org_actors: Arc::new(actors),
                }),
                destinations,
                audit: Arc::new(FakeEventDispatcher::new()),
                id,
            }
        }

        fn remove(&self, id: NotificationDestinationId) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(&test_org_caller(), &test_auditor(self.audit.clone()), id),
            )
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann removes the webhook Acme stopped using. It is gone and the
    /// removal recorded.
    #[test]
    fn an_owner_removes_a_destination() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Owner));

        setup.remove(setup.id).unwrap();

        assert_eq!(setup.destinations.count(), 0);
        assert_eq!(setup.recorded(), vec!["notifications.destination_removed"]);
    }

    /// Ann names a destination Acme does not have. It is not found, and the
    /// one it has stays.
    #[test]
    fn an_unknown_destination_is_not_found() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.remove(NotificationDestinationId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.destinations.count(), 1);
    }

    /// An ordinary organization member cannot remove a destination; it stays
    /// stored and no event is recorded.
    #[test]
    fn a_member_who_may_not_manage_notifications_is_refused() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.remove(setup.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.destinations.count(), 1);
        assert!(setup.recorded().is_empty());
    }

    /// Removing a destination with a signed-out session returns an
    /// unauthenticated error and leaves the destination stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::acting_as(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.remove(setup.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.destinations.count(), 1);
    }
}
