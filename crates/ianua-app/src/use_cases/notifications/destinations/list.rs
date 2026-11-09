//! List destinations: where an organization's notifications are posted
//! outside the app.

use std::sync::Arc;

use ianua_domain::domains::notifications::destination::NotificationDestination;
use ianua_domain::domains::organization::members::permission::{
    OrgNotificationAction, OrgPermission,
};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::NotificationDestinationStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Where the organization's destinations are kept.
    pub destinations: Arc<dyn NotificationDestinationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Lists the caller's organization's notification destinations.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<Vec<NotificationDestination>, AppError>;

    /// Every destination of `caller`'s organization, oldest first. Slack and
    /// Teams addresses and webhook secrets stay sealed; the API shows each
    /// one's kind, a webhook's address, its filter and whether it posts.
    ///
    /// They are where the organization's alerts go, so only a member who
    /// manages its notifications reads them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage the
    ///   organization's notifications.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        (): (),
    ) -> Result<Vec<NotificationDestination>, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Notifications(OrgNotificationAction::Manage),
            )
            .map_err(AppError::from_domain)?;
        self.ports
            .destinations
            .list(organization.id())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::notification_delivery::{FakeDestinationStore, webhook_destination};
    use crate::test_support::{block_on, test_org_caller};

    fn list_with(actors: FakeOrgActors) -> Result<Vec<NotificationDestination>, AppError> {
        let acme = test_org_caller().organization_id();
        let destinations = FakeDestinationStore::holding([
            webhook_destination(acme, NotificationSeverity::Info),
            webhook_destination(OrganizationId::new(), NotificationSeverity::Info),
        ]);
        let uc = ListUseCase::new(ListPorts {
            destinations: Arc::new(destinations),
            org_actors: Arc::new(actors),
        });
        block_on(uc.execute(&test_org_caller(), ()))
    }

    /// Ann, an owner of Acme, lists its destinations. She sees Acme's one,
    /// never another organization's.
    #[test]
    fn an_owner_lists_their_organizations_destinations() {
        let listed = list_with(FakeOrgActors::in_role(OrgRole::Owner)).unwrap();

        assert_eq!(listed.len(), 1);
    }

    /// Listing notification destinations as an ordinary organization member
    /// returns forbidden.
    #[test]
    fn a_member_who_may_not_manage_notifications_is_refused() {
        let result = list_with(FakeOrgActors::in_role(OrgRole::Member));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Listing destinations with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list_with(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
