//! Add destination: post an organization's notifications to a Slack or
//! Teams channel, or a webhook of its own.
//!
//! Where alerts go decides who learns of an attack first, so only a member
//! who may manage the organization's notifications adds one.

use std::sync::Arc;

use ianua_domain::domains::notifications::destination::{NewDestination, NotificationDestination};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, NotificationDestinationId, OrganizationId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::notifications::{
    DestinationSecretGenerator, NotificationDestinationStore, destination_endpoint_place,
};
use crate::use_case::Command;
use crate::use_cases::notifications::destinations::endpoint::{
    DestinationSettings, Sealing, SigningSecret, new_destination,
};

/// A destination just added, with its signing secret shown this once.
pub struct AddedDestination {
    /// The destination.
    pub id: NotificationDestinationId,
    /// A webhook's signing secret, or that a Slack or Teams address needs
    /// none.
    pub signing_secret: SigningSecret,
}

/// The ports [`AddUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddPorts {
    /// Where the organization's destinations are kept.
    pub destinations: Arc<dyn NotificationDestinationStore>,
    /// Seals addresses and signing secrets.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Makes a webhook's signing secret.
    pub secrets: Arc<dyn DestinationSecretGenerator>,
    /// The organization's plan limits.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Adds a notification destination to the caller's organization.
pub struct AddUseCase {
    ports: AddPorts,
}

impl AddUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: AddPorts) -> Self {
        Self { ports }
    }

    /// What `settings` ask the destination `id` of `organization` to be,
    /// its endpoint sealed for it, with the signing secret to show once.
    ///
    /// # Errors
    ///
    /// As [`new_destination`] lists.
    async fn sealed_settings(
        &self,
        organization: &OrganizationId,
        id: &NotificationDestinationId,
        settings: DestinationSettings,
    ) -> Result<(NewDestination, SigningSecret), AppError> {
        let place = destination_endpoint_place(organization, id);
        let sealing = Sealing {
            encryptor: self.ports.encryptor.as_ref(),
            secrets: self.ports.secrets.as_ref(),
            place: &place,
        };
        new_destination(sealing, settings).await
    }
}

impl Command for AddUseCase {
    type Caller = OrgCaller;
    type Input = DestinationSettings;
    type Output = Result<AddedDestination, AppError>;

    /// Adds the destination `settings` describe to `caller`'s organization,
    /// active at once, and records `notifications.destination_added`,
    /// naming its kind and never its address or secret. A webhook's signing
    /// secret comes back this once.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage the
    ///   organization's notifications, or the plan's destination limit is
    ///   reached.
    /// - `AppError::Domain` when the filter names no category or one twice,
    ///   or a Slack or Teams address is not on their own hosts.
    /// - `AppError::Internal` on sealing, persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        settings: DestinationSettings,
    ) -> Result<AddedDestination, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_within_plan(self.ports.limit_enforcer.as_ref(), &organization).await?;
        let id = NotificationDestinationId::new();
        let (new, signing_secret) = self
            .sealed_settings(organization.id(), &id, settings)
            .await?;
        let mut destination = NotificationDestination::add(id, *organization.id(), new, &control)
            .map_err(AppError::from_domain)?;
        self.ports
            .destinations
            .save(&destination)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*actor.member().id()),
                destination.take_events(),
            )
            .await
            .or_internal()?;
        Ok(AddedDestination {
            id: *destination.id(),
            signing_secret,
        })
    }
}

/// Refuses a new destination once the plan `organization` is on has as
/// many as it allows. The plan is the one on record.
///
/// # Errors
///
/// `AppError::Forbidden` when the limit is reached.
async fn ensure_within_plan(
    limits: &dyn LimitEnforcer,
    organization: &Organization,
) -> Result<(), AppError> {
    limits
        .check_org_limit(
            &organization.limits(),
            organization.id(),
            ResourceKind::NotificationDestinations,
        )
        .await
        .map_err(AppError::from_domain)
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
    use crate::test_support::notification_delivery::{
        FakeDestinationStore, TEST_DESTINATION_SECRET,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_auditor,
        test_org_caller,
    };
    use crate::use_cases::notifications::destinations::endpoint::DestinationTarget;

    struct Setup {
        uc: AddUseCase,
        destinations: Arc<FakeDestinationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn acting_as(actors: FakeOrgActors) -> Self {
            Self::limited_by(actors, Arc::new(FakeLimitEnforcer))
        }

        fn limited_by(actors: FakeOrgActors, limits: Arc<dyn LimitEnforcer>) -> Self {
            let destinations = Arc::new(FakeDestinationStore::empty());
            Self {
                uc: AddUseCase::new(AddPorts {
                    destinations: destinations.clone(),
                    limit_enforcer: limits,
                    org_actors: Arc::new(actors),
                    ..AddPorts::fakes()
                }),
                destinations,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn add(&self, target: DestinationTarget) -> Result<AddedDestination, AppError> {
            let settings = DestinationSettings {
                name: Label::new("name", "On-call").unwrap(),
                target,
                categories: vec![NotificationCategory::Authentication],
                minimum: NotificationSeverity::Critical,
            };
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                settings,
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn url(value: &str) -> PublicHttpsUrl {
        PublicHttpsUrl::new(value).unwrap()
    }

    /// Ann, an owner of Acme, posts critical sign-in alerts to the on-call
    /// Slack channel. It is kept, needs no signing secret, and is recorded.
    #[test]
    fn an_owner_adds_a_slack_channel() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Owner));

        let added = setup
            .add(DestinationTarget::Slack(url(
                "https://hooks.slack.com/services/T0/B0/x",
            )))
            .unwrap();

        let stored = setup.destinations.stored(&added.id).unwrap();
        assert_eq!(stored.endpoint().kind(), DestinationKind::Slack);
        assert!(matches!(added.signing_secret, SigningSecret::NotSigned));
        assert_eq!(setup.recorded(), vec!["notifications.destination_added"]);
    }

    /// Ann adds Acme's own webhook. She is shown its signing secret once.
    #[test]
    fn a_webhook_gets_a_signing_secret_shown_once() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Owner));

        let added = setup
            .add(DestinationTarget::Webhook(url(
                "https://alerts.acme.com/in",
            )))
            .unwrap();

        let SigningSecret::Shown(secret) = added.signing_secret else {
            panic!("a webhook is signed");
        };
        assert_eq!(secret.expose(), TEST_DESTINATION_SECRET);
    }

    /// A Slack destination on a lookalike host returns a domain error and
    /// saves no destination.
    #[test]
    fn an_address_that_only_claims_to_be_slack_is_refused() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Owner));

        let lookalike = url("https://hooks.slack.com.attacker.net/x");

        let result = setup.add(DestinationTarget::Slack(lookalike));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.destinations.count(), 0);
    }

    /// An ordinary organization member cannot add a notification destination;
    /// the request is forbidden without saving or recording a destination.
    #[test]
    fn a_member_who_may_not_manage_notifications_is_refused() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.add(DestinationTarget::Webhook(url(
            "https://sam.example.com/in",
        )));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.destinations.count(), 0);
        assert!(setup.recorded().is_empty());
    }

    /// Adding a destination with a signed-out session returns an
    /// unauthenticated error and saves no destination.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::acting_as(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.add(DestinationTarget::Webhook(url(
            "https://alerts.acme.com/in",
        )));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.destinations.count(), 0);
    }

    /// Acme already posts to as many destinations as its plan allows. Ann's
    /// next one is refused, and nothing is kept or recorded.
    #[test]
    fn a_destination_past_the_plan_limit_is_refused() {
        let setup = Setup::limited_by(
            FakeOrgActors::in_role(OrgRole::Owner),
            Arc::new(RejectingLimitEnforcer),
        );

        let result = setup.add(DestinationTarget::Webhook(url(
            "https://alerts.acme.com/in",
        )));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.destinations.count(), 0);
        assert!(setup.recorded().is_empty());
    }
}
