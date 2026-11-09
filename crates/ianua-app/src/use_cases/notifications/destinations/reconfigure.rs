//! Reconfigure destination: rename a destination, point it somewhere else,
//! or change what it receives.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, NotificationDestinationId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::notifications::{
    DestinationSecretGenerator, NotificationDestinationStore, destination_endpoint_place,
};
use crate::use_case::Command;
use crate::use_cases::notifications::destinations::endpoint::{
    DestinationSettings, Sealing, SigningSecret, new_destination,
};
use crate::use_cases::notifications::destinations::lookup::existing_destination;

/// The destination to change, and all it is to be, as a form saves it.
pub struct ReconfigureRequest {
    /// The saved delivery configuration to replace.
    pub destination_id: NotificationDestinationId,
    /// Its new name, address and filter.
    pub settings: DestinationSettings,
}

/// The ports [`ReconfigureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReconfigurePorts {
    /// Where the organization's destinations are kept.
    pub destinations: Arc<dyn NotificationDestinationStore>,
    /// Seals addresses and signing secrets.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Makes a webhook's signing secret.
    pub secrets: Arc<dyn DestinationSecretGenerator>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Replaces a destination's name, address and filter.
pub struct ReconfigureUseCase {
    ports: ReconfigurePorts,
}

impl ReconfigureUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ReconfigurePorts) -> Self {
        Self { ports }
    }
}

impl Command for ReconfigureUseCase {
    type Caller = OrgCaller;
    type Input = ReconfigureRequest;
    type Output = Result<SigningSecret, AppError>;

    /// Replaces everything the destination `request` names is, and records
    /// `notifications.destination_changed`. A webhook gets a new signing
    /// secret, shown this once; the old one stops signing at once.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage the
    ///   organization's notifications.
    /// - `AppError::NotFound` when the organization has no such destination.
    /// - `AppError::Domain` when the filter names no category or one twice,
    ///   or a Slack or Teams address is not on their own hosts.
    /// - `AppError::Internal` on sealing, persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: ReconfigureRequest,
    ) -> Result<SigningSecret, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let store = self.ports.destinations.as_ref();
        let mut destination =
            existing_destination(store, organization.id(), &request.destination_id).await?;
        let place = destination_endpoint_place(organization.id(), destination.id());
        let sealing = Sealing {
            encryptor: self.ports.encryptor.as_ref(),
            secrets: self.ports.secrets.as_ref(),
            place: &place,
        };
        let (new, signing_secret) = new_destination(sealing, request.settings).await?;
        destination
            .reconfigure(new, &control)
            .map_err(AppError::from_domain)?;
        store.save(&destination).await.or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*actor.member().id()),
                destination.take_events(),
            )
            .await
            .or_internal()?;
        Ok(signing_secret)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::destination::DestinationKind;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{Label, PublicHttpsUrl};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::notification_delivery::{FakeDestinationStore, webhook_destination};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};
    use crate::use_cases::notifications::destinations::endpoint::DestinationTarget;

    struct Setup {
        uc: ReconfigureUseCase,
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
                uc: ReconfigureUseCase::new(ReconfigurePorts {
                    destinations: destinations.clone(),
                    org_actors: Arc::new(actors),
                    ..ReconfigurePorts::fakes()
                }),
                destinations,
                audit: Arc::new(FakeEventDispatcher::new()),
                id,
            }
        }

        fn to_slack(&self, id: NotificationDestinationId) -> Result<SigningSecret, AppError> {
            let request = ReconfigureRequest {
                destination_id: id,
                settings: DestinationSettings {
                    name: Label::new("name", "On-call Slack").unwrap(),
                    target: DestinationTarget::Slack(
                        PublicHttpsUrl::new("https://hooks.slack.com/services/T0/B0/x").unwrap(),
                    ),
                    categories: vec![NotificationCategory::Authentication],
                    minimum: NotificationSeverity::Critical,
                },
            };
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn kind(&self) -> DestinationKind {
            self.destinations
                .stored(&self.id)
                .unwrap()
                .endpoint()
                .kind()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann moves Acme's alerts from its webhook to the on-call Slack
    /// channel. The destination posts to Slack now, and the change is
    /// recorded.
    #[test]
    fn an_owner_points_a_destination_elsewhere() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Owner));

        setup.to_slack(setup.id).unwrap();

        assert_eq!(setup.kind(), DestinationKind::Slack);
        assert_eq!(setup.recorded(), vec!["notifications.destination_changed"]);
    }

    /// Ann names a destination Acme does not have. It is not found.
    #[test]
    fn an_unknown_destination_is_not_found() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.to_slack(NotificationDestinationId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An ordinary organization member cannot change a webhook destination
    /// to Slack; it remains a webhook and no event is recorded.
    #[test]
    fn a_member_who_may_not_manage_notifications_is_refused() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.to_slack(setup.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.kind(), DestinationKind::Webhook);
        assert!(setup.recorded().is_empty());
    }

    /// Reconfiguring with a signed-out session returns an unauthenticated
    /// error and leaves the destination as a webhook.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::acting_as(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.to_slack(setup.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.kind(), DestinationKind::Webhook);
    }
}
