//! A workflow's registration at an integration's service, which the service
//! sends the events the workflow starts on to.
//!
//! A version in service whose trigger is a service event gets one, made
//! through the account its trigger names: a webhook at GitHub, a watch
//! channel on a Google calendar. It holds the secret the service signs its
//! events with, sealed, and the service's own name for the registration.
//!
//! It is the only way a service's event starts a run. An event is admitted
//! only while the registration is live, only once the service's signature
//! checked out, and only for the very version it was made for, as a
//! [`ServiceDelivery`] that one start spends. Anyone who learns the
//! registration's address, without the secret, starts nothing.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::workflows::design::workflow::{Workflow, WorkflowStatus};
use crate::domains::workflows::events::{
    ServiceSubscriptionLapsed, ServiceSubscriptionRegistered, ServiceSubscriptionRemoved,
    SubscriptionRef,
};
use crate::domains::workflows::integration::IntegrationKey;
use crate::domains::workflows::integration::events::ServiceEventKey;
use crate::domains::workflows::triggers::{EventFilter, ServiceTrigger, Trigger};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{
    EventLabel, IntegrationAccountId, SealedSecret, ServiceSubscriptionId, WorkflowId,
};

text_value! {
    /// The service's own name for a registration, such as the id of a
    /// GitHub webhook or a Google watch channel, which removing or renewing
    /// it names.
    pub struct RemoteRegistration;
}

impl TextValue for RemoteRegistration {
    const FIELD: &'static str = "registration";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=256).no_control_chars()
    }
}

text_value! {
    /// Why a registration lapsed, in the platform's own words, such as "the
    /// watch channel expired".
    pub struct LapseReason;
}

impl TextValue for LapseReason {
    const FIELD: &'static str = "reason";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=512).no_control_chars()
    }
}

/// Where a registration is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionStatus {
    /// It is being made at the service.
    Registering,
    /// The service took it.
    Live,
    /// It lapsed or could not be made; the service's events start nothing.
    Lapsed,
    /// It was removed as its version left service.
    Removed,
}

impl SubscriptionStatus {
    /// Moves to `to`. A registration being made goes live, and a live one
    /// stays live as it is renewed; either may lapse or be removed, and a
    /// lapsed one may still be removed. Nothing comes back from removed.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!(
                (from, to),
                (
                    Self::Registering | Self::Live,
                    Self::Live | Self::Lapsed | Self::Removed
                ) | (Self::Lapsed, Self::Removed)
            )
        })
    }
}

/// The service's side of a registration: nothing until it takes it, then
/// its name for it and whether it lapses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// The service has not taken it.
    NotTaken,
    /// The service took it under this name.
    Taken {
        /// The service's name for it.
        remote: RemoteRegistration,
        /// When it lapses unless renewed, for a service whose registrations
        /// do.
        lapses: Lapse,
    },
}

/// Whether a live registration lapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lapse {
    /// It lasts until removed, as a GitHub webhook does.
    Never,
    /// It lapses at this time unless renewed, as a Google watch channel
    /// does.
    At(OffsetDateTime),
}

/// What the service's signature on one delivery said, as the integration
/// checked it with the registration's secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryCheck {
    /// The service signed it with the registration's secret.
    Authentic,
    /// It was not signed, or signed with something else.
    Forged,
}

/// One delivery a live registration admitted for one version. Starting a
/// run spends it.
#[derive(Debug)]
pub struct ServiceDelivery {
    workflow_id: WorkflowId,
    version: u32,
}

impl ServiceDelivery {
    /// Whether it was admitted for `workflow`, this very version.
    pub(crate) fn admits<T: TenantScope>(self, workflow: &Workflow<T>) -> bool {
        self.workflow_id == *workflow.id() && self.version == workflow.version()
    }
}

/// A registration as stored.
pub struct ServiceSubscriptionRow {
    /// Its id, which the address the service sends events to names.
    pub id: ServiceSubscriptionId,
    /// The workflow it starts.
    pub workflow_id: WorkflowId,
    /// The version it was made for.
    pub version: u32,
    /// What it registers for: integration, event, account and filters.
    pub trigger: ServiceTrigger,
    /// The secret the service signs with, sealed.
    pub secret: SealedSecret,
    /// Where it is.
    pub status: SubscriptionStatus,
    /// The service's side of it.
    pub registration: Registration,
    /// The workflow's name, for the records it raises.
    pub label: EventLabel,
    /// When it was opened.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A workflow's registration at an integration's service.
#[derive(Debug)]
pub struct ServiceSubscription<T: TenantScope> {
    id: ServiceSubscriptionId,
    workflow_id: WorkflowId,
    version: u32,
    trigger: ServiceTrigger,
    secret: SealedSecret,
    status: SubscriptionStatus,
    registration: Registration,
    label: EventLabel,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> ServiceSubscription<T> {
    /// Opens, under `id`, the registration `workflow`'s version in service
    /// needs, with `secret`, sealed for it, for the service to sign with.
    /// It is made at the service next.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when `workflow` is not a version in
    ///   service starting on a service's event.
    pub fn open(
        workflow: &Workflow<T>,
        id: ServiceSubscriptionId,
        secret: SealedSecret,
    ) -> Result<Self, DomainError> {
        let trigger = service_trigger_in_service(workflow)?.clone();
        let now = crate::shared::clock::now();
        Ok(Self {
            id,
            workflow_id: *workflow.id(),
            version: workflow.version(),
            trigger,
            secret,
            status: SubscriptionStatus::Registering,
            registration: Registration::NotTaken,
            label: EventLabel::of(workflow.name().as_str()),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Rebuilds a registration from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it changed
    ///   before it was opened, or is live with no name from the service.
    pub fn reconstitute(row: ServiceSubscriptionRow) -> Result<Self, DomainError> {
        RowCheck::of("service subscription")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was opened",
            )
            .finish()?;
        if row.status == SubscriptionStatus::Live && row.registration == Registration::NotTaken {
            return Err(DomainError::corrupt_row(
                "service subscription",
                "live with no name from the service",
            ));
        }
        Ok(Self {
            id: row.id,
            workflow_id: row.workflow_id,
            version: row.version,
            trigger: row.trigger,
            secret: row.secret,
            status: row.status,
            registration: row.registration,
            label: row.label,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The service took it, or renewed it, naming it `remote`, lapsing as
    /// `lapses` says. Raises `workflows.subscription_registered` the first
    /// time.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it lapsed or was removed;
    ///   a new one is opened instead.
    pub fn register(
        &mut self,
        remote: RemoteRegistration,
        lapses: Lapse,
    ) -> Result<(), DomainError> {
        let first = self.status == SubscriptionStatus::Registering;
        self.status = self.status.try_transition(SubscriptionStatus::Live)?;
        self.registration = Registration::Taken { remote, lapses };
        self.touch();
        if first {
            self.raised.raise(ServiceSubscriptionRegistered {
                subscription: self.subscription_ref(),
                occurred_at: self.updated_at,
            });
        }
        Ok(())
    }

    /// It lapsed, or could not be made or renewed, for `reason`. Raises
    /// `workflows.subscription_lapsed`, which colleagues hear of.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it already lapsed or was
    ///   removed.
    pub fn lapse(&mut self, reason: LapseReason) -> Result<(), DomainError> {
        self.status = self.status.try_transition(SubscriptionStatus::Lapsed)?;
        self.touch();
        self.raised.raise(ServiceSubscriptionLapsed {
            subscription: self.subscription_ref(),
            reason,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// It was removed, as its version left service. Raises
    /// `workflows.subscription_removed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it was already removed.
    pub fn remove(&mut self) -> Result<(), DomainError> {
        self.status = self.status.try_transition(SubscriptionStatus::Removed)?;
        self.touch();
        self.raised.raise(ServiceSubscriptionRemoved {
            subscription: self.subscription_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// The delivery `check` vouches for, admitted for `workflow`, the
    /// version in service it starts.
    ///
    /// The signature is asked about first, so a forged delivery learns
    /// nothing of the registration or its workflow.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when the signature did not check out.
    /// - [`DomainError::Conflict`] when the registration is not live.
    /// - [`DomainError::Forbidden`] when `workflow` is not the version it was
    ///   made for, or no longer starts on this event.
    pub fn admit(
        &self,
        check: DeliveryCheck,
        workflow: &Workflow<T>,
    ) -> Result<ServiceDelivery, DomainError> {
        if check == DeliveryCheck::Forged {
            return Err(DomainError::unauthorized(message!(
                "workflows-the-service-event-is-not-signed",
                "the event is not signed with the registration's secret"
            )));
        }
        if self.status != SubscriptionStatus::Live {
            return Err(DomainError::conflict(message!(
                "workflows-the-subscription-is-not-live",
                "the registration is not live"
            )));
        }
        let in_service = service_trigger_in_service(workflow)?;
        let same_version = *workflow.id() == self.workflow_id && workflow.version() == self.version;
        if !same_version || *in_service != self.trigger {
            return Err(DomainError::forbidden(message!(
                "workflows-the-subscription-starts-another-version",
                "the registration was made for another version"
            )));
        }
        Ok(ServiceDelivery {
            workflow_id: self.workflow_id,
            version: self.version,
        })
    }

    /// Whether a check that the platform holds its address is answered:
    /// while the registration is being made, and while it is live, as a
    /// service may check again when it renews one.
    #[must_use]
    pub fn answers_checks(&self) -> bool {
        matches!(
            self.status,
            SubscriptionStatus::Registering | SubscriptionStatus::Live
        )
    }

    /// Whether a secret the service hands over is taken: only while the
    /// registration is being made, so nobody who learns the address of a
    /// live one can replace what it is proven with.
    #[must_use]
    pub fn takes_service_secret(&self) -> bool {
        self.status == SubscriptionStatus::Registering
    }

    /// Records a change without moving the stored timestamp backwards.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now().max(self.updated_at);
    }

    fn subscription_ref(&self) -> SubscriptionRef {
        SubscriptionRef {
            subscription_id: self.id,
            version: crate::domains::workflows::events::VersionRef {
                workflow_id: self.workflow_id,
                version: self.version,
                label: self.label.clone(),
            },
            integration: self.trigger.integration().clone(),
            event: self.trigger.event().clone(),
        }
    }

    /// The workflow it starts.
    #[must_use]
    pub fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// The version it was made for.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// What it registers for.
    #[must_use]
    pub fn trigger(&self) -> &ServiceTrigger {
        &self.trigger
    }

    /// The integration whose service it is made at.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        self.trigger.integration()
    }

    /// The event it registers for.
    #[must_use]
    pub fn event(&self) -> &ServiceEventKey {
        self.trigger.event()
    }

    /// The account it is made through.
    #[must_use]
    pub fn account(&self) -> IntegrationAccountId {
        self.trigger.account()
    }

    /// The event's filters.
    #[must_use]
    pub fn filters(&self) -> &[EventFilter] {
        self.trigger.filters()
    }

    /// The secret the service signs with, sealed.
    #[must_use]
    pub fn secret(&self) -> &SealedSecret {
        &self.secret
    }

    /// Where it is.
    #[must_use]
    pub fn status(&self) -> SubscriptionStatus {
        self.status
    }

    /// The service's side of it.
    #[must_use]
    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    /// The workflow's name, as its records name it.
    #[must_use]
    pub fn label(&self) -> &EventLabel {
        &self.label
    }
}

/// The service trigger of `workflow`, a version in service.
fn service_trigger_in_service<T: TenantScope>(
    workflow: &Workflow<T>,
) -> Result<&ServiceTrigger, DomainError> {
    let Trigger::Service(trigger) = workflow.trigger() else {
        return Err(DomainError::conflict(message!(
            "workflows-the-workflow-does-not-start-on-a-service-event",
            "the workflow does not start on a service's event"
        )));
    };
    if workflow.status() != WorkflowStatus::Published {
        return Err(DomainError::conflict(message!(
            "workflows-no-version-in-service-starts-on-the-event",
            "no version in service starts on the service's event"
        )));
    }
    Ok(trigger)
}

impl<T: TenantScope> Raises for ServiceSubscription<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for ServiceSubscription<T> {
    type Id = ServiceSubscriptionId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::data::FieldName;
    use crate::domains::workflows::design::node::Join;
    use crate::domains::workflows::execution::ServiceStartParams;
    use crate::domains::workflows::execution::tests::fixtures::{
        Check, Execution, SeesAll, acting, ann, bob, draft_with, publish_as, transform,
        trigger_data,
    };
    use crate::domains::workflows::triggers::FilterValue;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::raised;
    use crate::types::event_type::{EventType, WorkflowsEvent};

    /// "An issue is opened in `acme/web`", through `account`.
    fn issue_opened(account: IntegrationAccountId) -> ServiceTrigger {
        ServiceTrigger::from_stored(
            IntegrationKey::new("github").unwrap(),
            ServiceEventKey::new("issue-opened").unwrap(),
            account,
            vec![EventFilter::new(
                FieldName::new("repository").unwrap(),
                FilterValue::new("acme/web").unwrap(),
            )],
        )
        .unwrap()
    }

    /// Ann's workflow starting on issues opened in `acme/web`, published by
    /// her.
    fn watching() -> Workflow<ResolvedTenant> {
        let mut workflow = draft_with(
            vec![transform("tidy", Join::All)],
            Vec::new(),
            Trigger::Service(issue_opened(IntegrationAccountId::new())),
        );
        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();
        workflow
    }

    fn secret() -> SealedSecret {
        SealedSecret::new("v1.AAECAwQF").unwrap()
    }

    fn live(workflow: &Workflow<ResolvedTenant>) -> ServiceSubscription<ResolvedTenant> {
        let mut subscription =
            ServiceSubscription::open(workflow, ServiceSubscriptionId::new(), secret()).unwrap();
        subscription
            .register(RemoteRegistration::new("hook-42").unwrap(), Lapse::Never)
            .unwrap();
        subscription
    }

    fn kinds(subscription: &mut ServiceSubscription<ResolvedTenant>) -> Vec<EventType> {
        raised(subscription)
            .iter()
            .map(DomainEvent::event_type)
            .collect()
    }

    fn started_for(person: &crate::types::Human) -> ServiceStartParams {
        ServiceStartParams {
            acting_for: acting(person),
            input: trigger_data(Check::Passes),
            exposure: DataClassLevel::Public,
        }
    }

    /// GitHub takes the registration and an issue is opened: the signed
    /// delivery starts Ann's workflow, acting for her, as a service start.
    /// The registration is recorded once.
    #[test]
    fn a_signed_delivery_starts_the_version_for_its_publisher() {
        let workflow = watching();
        let mut subscription = live(&workflow);

        let delivery = subscription
            .admit(DeliveryCheck::Authentic, &workflow)
            .unwrap();
        let (execution, _) =
            Execution::start_on_service_event(&workflow, delivery, started_for(&ann())).unwrap();

        assert_eq!(
            execution.cause(),
            crate::domains::workflows::execution::Cause::Service
        );
        assert_eq!(execution.acting_for(), &ann());
        assert_eq!(
            kinds(&mut subscription),
            [EventType::Workflows(WorkflowsEvent::SubscriptionRegistered)]
        );
    }

    /// A live subscription rejects a delivery marked as forged with an
    /// unauthorized error.
    #[test]
    fn a_forged_delivery_starts_nothing() {
        let workflow = watching();

        let admitted = live(&workflow).admit(DeliveryCheck::Forged, &workflow);

        assert!(matches!(admitted, Err(DomainError::Unauthorized(_))));
    }

    /// Authentic deliveries are refused while a subscription is registering
    /// or lapsed, and when a live subscription is given another workflow.
    #[test]
    fn a_delivery_to_a_registration_not_live_or_for_another_version_is_refused() {
        let workflow = watching();
        let other = watching();
        let registering =
            ServiceSubscription::open(&workflow, ServiceSubscriptionId::new(), secret()).unwrap();
        let mut lapsed = live(&workflow);
        lapsed
            .lapse(LapseReason::new("GitHub refused the webhook").unwrap())
            .unwrap();

        assert!(matches!(
            registering.admit(DeliveryCheck::Authentic, &workflow),
            Err(DomainError::Conflict(_))
        ));
        assert!(matches!(
            lapsed.admit(DeliveryCheck::Authentic, &workflow),
            Err(DomainError::Conflict(_))
        ));
        assert!(matches!(
            live(&workflow).admit(DeliveryCheck::Authentic, &other),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A service delivery admitted for a workflow cannot start an execution
    /// acting for someone other than its publisher.
    #[test]
    fn a_service_run_acts_only_for_the_publisher() {
        let workflow = watching();
        let delivery = live(&workflow)
            .admit(DeliveryCheck::Authentic, &workflow)
            .unwrap();

        let started = Execution::start_on_service_event(&workflow, delivery, started_for(&bob()));

        assert!(matches!(started, Err(DomainError::Forbidden(_))));
    }

    /// The ordinary trigger entry point rejects a service event because it
    /// lacks an admitted delivery.
    #[test]
    fn a_service_event_never_starts_without_its_registration() {
        let workflow = watching();

        let started = Execution::start_on_trigger(
            &workflow,
            crate::domains::workflows::execution::StartExecutionParams {
                acting_for: acting(&ann()),
                cause: crate::domains::workflows::execution::Cause::Service,
                input: trigger_data(Check::Passes),
                exposure: DataClassLevel::Public,
            },
        );

        assert!(matches!(started, Err(DomainError::Forbidden(_))));
    }

    /// A registration that lapses tells colleagues; removing it as its
    /// version leaves service is recorded too, and a removed one is not
    /// made again.
    #[test]
    fn a_lapse_and_a_removal_are_recorded_and_a_removed_registration_stays_removed() {
        let workflow = watching();
        let mut lapsing = live(&workflow);
        let mut removed = live(&workflow);
        kinds(&mut lapsing);
        kinds(&mut removed);

        lapsing
            .lapse(LapseReason::new("the watch channel expired").unwrap())
            .unwrap();
        removed.remove().unwrap();

        assert_eq!(
            kinds(&mut lapsing),
            [EventType::Workflows(WorkflowsEvent::SubscriptionLapsed)]
        );
        assert_eq!(
            kinds(&mut removed),
            [EventType::Workflows(WorkflowsEvent::SubscriptionRemoved)]
        );
        assert!(
            removed
                .register(RemoteRegistration::new("hook-43").unwrap(), Lapse::Never)
                .is_err()
        );
    }

    /// A published workflow with a manual trigger cannot open a service
    /// subscription.
    #[test]
    fn a_workflow_not_starting_on_a_service_event_gets_no_registration() {
        let mut manual = draft_with(
            vec![transform("tidy", Join::All)],
            Vec::new(),
            Trigger::Manual,
        );
        publish_as(&mut manual, &ann(), &[], &SeesAll).unwrap();

        assert!(matches!(
            ServiceSubscription::open(&manual, ServiceSubscriptionId::new(), secret()),
            Err(DomainError::Conflict(_))
        ));
    }
}
