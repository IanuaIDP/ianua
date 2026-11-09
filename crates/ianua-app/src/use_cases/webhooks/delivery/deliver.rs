//! Deliver webhook: send one event to one subscription, if its creator may
//! still see it, record the attempt and count it towards the endpoint's
//! failure streak, and say whether to try again.

use std::sync::Arc;

use ianua_domain::domains::webhooks::delivery::DeliveryAttempt;
use ianua_domain::domains::webhooks::retry_policy::WebhookRetryPolicy;
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{FailureOutcome, Seconds};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::ports::organization::{OrgTenantGrantStore, OrgUserStore, OrganizationStore};
use crate::ports::webhooks::{StreakChange, WebhookMessage};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::webhooks::delivery::creator::{Audience, CreatorStores};
use crate::use_cases::webhooks::delivery::sending::{SendingPorts, SentBy, Try};
use crate::use_cases::webhooks::lookup::existing_subscription;

/// The ports [`DeliverWebhookUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeliverWebhookPorts {
    /// Signs and sends each try, keeps it, counts it on the streak and
    /// records it, all together.
    pub sending: SendingPorts,
    /// Who holds what in the tenant, for what the creator may see now.
    pub access: Arc<dyn AccessRecordStore>,
    /// The tenant's users, for a creator who is one.
    pub users: Arc<dyn UserStore>,
    /// Organization members, for a creator who is one.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organizations, for a member creator's organization.
    pub organizations: Arc<dyn OrganizationStore>,
    /// A member creator's tenant grants.
    pub org_grants: Arc<dyn OrgTenantGrantStore>,
}

/// One try of one event to send to one subscription.
pub struct DeliverWebhookRequest {
    /// The message: the subscription, the event and its body, under an id
    /// made once for the first try and passed unchanged with every retry,
    /// so the receiver handles the event once.
    pub message: WebhookMessage,
    /// Which try this is. The first is 0; a retry passes the number
    /// [`NextTry::Retry`] gave.
    pub attempt_number: u8,
}

/// What came of one try, and whether to make another.
#[derive(Debug)]
pub struct DeliveryReport {
    /// The record of the try.
    pub attempt: DeliveryAttempt,
    /// Whether the event is sent again.
    pub next: NextTry,
}

/// Whether an event is sent to a subscription again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextTry {
    /// No further try: it was delivered, the retries are used up, or the
    /// failure switched the endpoint off.
    Done,
    /// Send the same message again as try `attempt_number` once `after` has
    /// passed.
    Retry {
        /// The number the next try carries.
        attempt_number: u8,
        /// How long to wait before it.
        after: Seconds,
    },
}

/// Delivers an event to a single webhook subscription.
pub struct DeliverWebhookUseCase {
    ports: DeliverWebhookPorts,
}

impl DeliverWebhookUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeliverWebhookPorts) -> Self {
        Self { ports }
    }

    /// Whether `subscription` is sent `message`'s event now: it is active,
    /// and the domain says it lists the event and its creator may still see
    /// it.
    async fn receives_now(
        &self,
        tenant: &ScopedTenant,
        subscription: &WebhookSubscription<ResolvedTenant>,
        message: &WebhookMessage,
    ) -> Result<bool, AppError> {
        if !subscription.is_active() {
            return Ok(false);
        }
        let audience = Audience {
            creators: CreatorStores {
                users: self.ports.users.as_ref(),
                org_users: self.ports.org_users.as_ref(),
                organizations: self.ports.organizations.as_ref(),
                org_grants: self.ports.org_grants.as_ref(),
            },
            access: self.ports.access.as_ref(),
        };
        audience
            .receives_now(tenant, subscription, &message.event_type)
            .await
    }
}

impl Command for DeliverWebhookUseCase {
    type Caller = ScopedTenant;
    type Input = DeliverWebhookRequest;
    type Output = Result<Option<DeliveryReport>, AppError>;

    /// Sends the event, signed with every secret the subscription signs
    /// with now and bounded by its retry policy's timeout, keeps the
    /// message for a later resend, records the attempt, and records
    /// `webhooks.delivery_attempted` whatever the outcome.
    ///
    /// A success starts the subscription's failure streak again. A failure
    /// adds to it, and once the streak reaches the policy's limit the domain
    /// switches the subscription off and `webhooks.subscription_disabled` is
    /// recorded too. A failure that leaves it on is tried again after the
    /// policy's delay until the retries are used up. The policy is the one
    /// the subscription chose.
    ///
    /// Nothing is sent or recorded, and `None` comes back, when the
    /// subscription is not active, does not list the event, or its creator
    /// may not see the event now, holds nothing, or is gone.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant has no such subscription, or
    ///   it was deleted while the event was on its way.
    /// - `AppError::Domain` when the URL resolves to an address deliveries
    ///   may not reach.
    /// - `AppError::Internal` when a store fails, a record names a role or
    ///   group that is not there, a secret cannot be opened, or the audit
    ///   record cannot be written.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: DeliverWebhookRequest,
    ) -> Result<Option<DeliveryReport>, AppError> {
        let store = self.ports.sending.webhook_store.as_ref();
        let subscription =
            existing_subscription(store, tenant, &request.message.subscription_id).await?;
        if !self
            .receives_now(tenant, &subscription, &request.message)
            .await?
        {
            return Ok(None);
        }
        let attempt = Try {
            message: &request.message,
            attempt_number: request.attempt_number,
        };
        let sent = self
            .ports
            .sending
            .sender(tenant, auditor, SentBy::Platform)
            .send(&subscription, attempt)
            .await?;
        let policy = subscription.retry().policy();
        let next = next_try(&policy, sent.attempt.attempt_number, sent.change);
        Ok(Some(DeliveryReport {
            attempt: sent.attempt,
            next,
        }))
    }
}

/// The next try after try `attempt_number`: only a failure that left the
/// subscription on is retried, and only while the policy has retries left.
fn next_try(policy: &WebhookRetryPolicy, attempt_number: u8, change: StreakChange) -> NextTry {
    let StreakChange::Failed(FailureOutcome::Counted) = change else {
        return NextTry::Done;
    };
    let next = attempt_number.saturating_add(1);
    if next > policy.max_retries() {
        return NextTry::Done;
    }
    NextTry::Retry {
        attempt_number: next,
        after: Seconds::new(policy.delay_for_attempt(next)),
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
    use ianua_domain::domains::webhooks::control::WebhookControl;
    use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
    use ianua_domain::domains::webhooks::subscription::WebhookUpdate;
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::event_type::{IdentityEvent, WebhooksEvent};
    use ianua_domain::types::{
        DeliveryOutcome, EventType, Label, Lifetime, PrincipalRef, RoleId, RotationOverlap, UserId,
        WebhookDeliveryId, WebhookMessageId, WebhookSubscriptionId,
    };

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::ports::runtime::Settlement;
    use crate::ports::webhooks::{
        OutboundDelivery, WebhookDeliverer, WebhookDeliveryOutcome, WebhookStore,
    };
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::authorization::FakeAccessRecordStore;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::webhooks::{
        FakeWebhookDeliverer, FakeWebhookStore, TEST_SIGNING_SECRET, failing_test_subscription,
        signing_secret_place, test_message, test_subscription, test_subscription_creator,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
        test_ctx,
    };

    const ENDPOINT: &str = "https://hooks.acme.com/events";

    /// Ann, who made every test webhook.
    fn ann() -> UserId {
        match test_subscription_creator() {
            PrincipalRef::User(user_id) => Some(user_id),
            _ => None,
        }
        .unwrap()
    }

    /// The tenant's records, where Ann holds one role granting `system`.
    fn records_where_ann_holds(system: &[SystemPermission]) -> AccessRecords {
        let role = Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", "user viewer").unwrap(),
            system_permissions: system.to_vec(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        });
        let assignment = RoleAssignment::create(
            PrincipalRef::User(ann()),
            &role,
            anyone_holding(SystemPermission::all()),
        )
        .unwrap();
        AccessRecords {
            roles: vec![role],
            assignments: vec![assignment],
            ..AccessRecords::default()
        }
    }

    /// A use case delivering to one stored subscription, with its store and
    /// unit of work.
    struct Delivery {
        store: Arc<FakeWebhookStore>,
        id: WebhookSubscriptionId,
        unit: Arc<RecordingUnitOfWork>,
        access: Arc<FakeAccessRecordStore>,
        use_case: DeliverWebhookUseCase,
    }

    /// A delivery to Ann's webhook in `status`, where she holds `ann_holds`.
    fn delivery(
        status: WebhookSubscriptionStatus,
        ann_holds: &[SystemPermission],
        deliverer: Arc<dyn WebhookDeliverer>,
    ) -> Delivery {
        let subscription = test_subscription(ENDPOINT, status);
        delivery_to(&subscription, ann_holds, deliverer)
    }

    /// A delivery to Ann's active webhook, which has failed `failures`
    /// times in a row, at an endpoint that answers `code`.
    fn failing_delivery(failures: u32, code: u16) -> Delivery {
        let subscription =
            failing_test_subscription(ENDPOINT, WebhookSubscriptionStatus::Active, failures);
        let deliverer = Arc::new(FakeWebhookDeliverer::answering(code));
        delivery_to(&subscription, &user_viewer(), deliverer)
    }

    /// A delivery to `subscription`, stored for the test tenant.
    fn delivery_to(
        subscription: &WebhookSubscription<ResolvedTenant>,
        ann_holds: &[SystemPermission],
        deliverer: Arc<dyn WebhookDeliverer>,
    ) -> Delivery {
        let tenant_id = test_ctx().tenant_id();
        let store = Arc::new(FakeWebhookStore::holding(tenant_id, subscription));
        let unit = Arc::new(RecordingUnitOfWork::default());
        let access = Arc::new(FakeAccessRecordStore::holding(
            tenant_id,
            records_where_ann_holds(ann_holds),
        ));
        let use_case = DeliverWebhookUseCase::new(DeliverWebhookPorts {
            sending: SendingPorts {
                webhook_store: store.clone(),
                deliverer,
                unit_of_work: unit.clone(),
                ..SendingPorts::fakes()
            },
            access: access.clone(),
            users: Arc::new(FakeUserStore::with_user(ann(), "ann@acme.com")),
            ..DeliverWebhookPorts::fakes()
        });
        Delivery {
            store,
            id: *subscription.id(),
            unit,
            access,
            use_case,
        }
    }

    /// The right to see user events.
    fn user_viewer() -> [SystemPermission; 1] {
        [SystemPermission::Users(UserAction::View)]
    }

    /// The message of `event_type` to the delivery's subscription.
    fn message_of(delivery: &Delivery, event_type: EventType) -> WebhookMessage {
        WebhookMessage {
            event_type,
            ..test_message(delivery.id)
        }
    }

    /// Sends `event_type` to the webhook as its first try.
    fn deliver(
        delivery: &Delivery,
        audit: &Arc<FakeEventDispatcher>,
        event_type: EventType,
    ) -> Option<DeliveryReport> {
        send_try(delivery, audit, message_of(delivery, event_type), 0)
    }

    /// Sends a registration to the webhook as try `attempt_number`.
    fn registration_try(
        delivery: &Delivery,
        audit: &Arc<FakeEventDispatcher>,
        attempt_number: u8,
    ) -> DeliveryReport {
        let message = message_of(delivery, IdentityEvent::UserRegistered.into());
        send_try(delivery, audit, message, attempt_number).unwrap()
    }

    /// Sends `message` as try `attempt_number`.
    fn send_try(
        delivery: &Delivery,
        audit: &Arc<FakeEventDispatcher>,
        message: WebhookMessage,
        attempt_number: u8,
    ) -> Option<DeliveryReport> {
        let request = DeliverWebhookRequest {
            message,
            attempt_number,
        };
        block_on(delivery.use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(audit.clone()),
            request,
        ))
        .unwrap()
    }

    /// The subscription as the store holds it now.
    fn stored(delivery: &Delivery) -> WebhookSubscription<ResolvedTenant> {
        delivery
            .store
            .stored(test_ctx().tenant_id(), &delivery.id)
            .unwrap()
    }

    /// A user registers, and Ann's webhook for registrations is sent it,
    /// since she may still see user events. The attempt and the message are
    /// kept and the attempt recorded.
    #[test]
    fn a_listed_event_the_creator_may_see_is_delivered() {
        let deliverer = Arc::new(FakeWebhookDeliverer::new());
        let delivery = delivery(
            WebhookSubscriptionStatus::Active,
            &user_viewer(),
            deliverer.clone(),
        );
        let audit = Arc::new(FakeEventDispatcher::new());

        let attempt = deliver(&delivery, &audit, IdentityEvent::UserRegistered.into());

        assert!(attempt.is_some());
        assert_eq!(*deliverer.calls.lock().unwrap(), 1);
        assert_eq!(delivery.store.attempts.lock().unwrap().len(), 1);
        assert_eq!(delivery.store.messages.lock().unwrap().len(), 1);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["webhooks.delivery_attempted"]
        );
    }

    /// Ann's server checks each delivery's signature with the secret she was
    /// shown. The delivery is signed with that secret, opened from its
    /// sealed form, over the message's id.
    #[test]
    fn a_delivery_is_signed_with_the_unsealed_secret_over_its_message_id() {
        let deliverer = Arc::new(FakeWebhookDeliverer::new());
        let delivery = delivery(
            WebhookSubscriptionStatus::Active,
            &user_viewer(),
            deliverer.clone(),
        );
        let message = message_of(&delivery, IdentityEvent::UserRegistered.into());

        send_try(
            &delivery,
            &Arc::new(FakeEventDispatcher::new()),
            message.clone(),
            0,
        );

        let sent = deliverer.deliveries();
        assert_eq!(sent[0].secrets, [TEST_SIGNING_SECRET]);
        assert_eq!(sent[0].signed.message_id(), &message.id);
        assert_eq!(sent[0].payload, message.payload);
    }

    /// Ann rotated her secret and kept the old one signing for a day while
    /// her servers move over. A delivery carries a signature for each, the
    /// new one first, so a server still on the old one accepts it.
    #[test]
    fn a_delivery_during_an_overlap_is_signed_with_both_secrets() {
        let mut subscription = test_subscription(ENDPOINT, WebhookSubscriptionStatus::Active);
        let control = WebhookControl::new(anyone_holding(SystemPermission::all()));
        let a_day = Lifetime::new(time::Duration::days(1)).unwrap();
        subscription
            .rotate_secret(
                FakeEncryptor::sealed_for(
                    "new-signing-secret",
                    &signing_secret_place(subscription.id()),
                ),
                RotationOverlap::For(a_day),
                &control,
            )
            .unwrap();
        let deliverer = Arc::new(FakeWebhookDeliverer::new());
        let delivery = delivery_to(&subscription, &user_viewer(), deliverer.clone());

        registration_try(&delivery, &Arc::new(FakeEventDispatcher::new()), 0);

        assert_eq!(
            deliverer.deliveries()[0].secrets,
            ["new-signing-secret", TEST_SIGNING_SECRET]
        );
    }

    /// Ann's server failed the first try. The retry carries the same
    /// message id, so her server handles the event once.
    #[test]
    fn a_retry_keeps_the_message_id() {
        let deliverer = Arc::new(FakeWebhookDeliverer::answering(503));
        let delivery = delivery(
            WebhookSubscriptionStatus::Active,
            &user_viewer(),
            deliverer.clone(),
        );
        let message = message_of(&delivery, IdentityEvent::UserRegistered.into());
        let audit = Arc::new(FakeEventDispatcher::new());

        send_try(&delivery, &audit, message.clone(), 0);
        send_try(&delivery, &audit, message.clone(), 1);

        let sent = deliverer.deliveries();
        assert_eq!(sent[0].signed.message_id(), sent[1].signed.message_id());
        assert_eq!(delivery.store.messages.lock().unwrap().len(), 1);
        let attempts = delivery.store.attempts_in(test_ctx().tenant_id());
        assert!(
            attempts
                .iter()
                .all(|attempt| attempt.message_id == message.id)
        );
    }

    /// A user is deleted. Ann's webhook lists only registrations, so nothing
    /// is sent or recorded.
    #[test]
    fn an_event_the_subscription_does_not_list_is_skipped() {
        let deliverer = Arc::new(FakeWebhookDeliverer::new());
        let delivery = delivery(
            WebhookSubscriptionStatus::Active,
            &user_viewer(),
            deliverer.clone(),
        );
        let audit = Arc::new(FakeEventDispatcher::new());

        let attempt = deliver(&delivery, &audit, IdentityEvent::UserDeleted.into());

        assert!(attempt.is_none());
        assert_eq!(*deliverer.calls.lock().unwrap(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A user registers and Ann's webhook is checked against what she holds
    /// now. Only her own share of the tenant's records is read for it, never
    /// every record of the tenant, so a busy tenant's events stay cheap.
    #[test]
    fn a_delivery_reads_only_the_creators_records() {
        let delivery = delivery(
            WebhookSubscriptionStatus::Active,
            &user_viewer(),
            Arc::new(FakeWebhookDeliverer::new()),
        );

        let attempt = deliver(
            &delivery,
            &Arc::new(FakeEventDispatcher::new()),
            IdentityEvent::UserRegistered.into(),
        );

        assert!(attempt.is_some());
        assert_eq!(delivery.access.whole_reads(), 0);
    }

    /// A registration is skipped without calling the deliverer when the
    /// subscription's creator lacks the right to view user events.
    #[test]
    fn an_event_the_creator_may_no_longer_see_is_not_delivered() {
        let deliverer = Arc::new(FakeWebhookDeliverer::new());
        let delivery = delivery(WebhookSubscriptionStatus::Active, &[], deliverer.clone());

        let attempt = deliver(
            &delivery,
            &Arc::new(FakeEventDispatcher::new()),
            IdentityEvent::UserRegistered.into(),
        );

        assert!(attempt.is_none());
        assert_eq!(*deliverer.calls.lock().unwrap(), 0);
    }

    /// A registration is skipped without calling the deliverer when the
    /// subscription's creator has no stored account.
    #[test]
    fn a_creator_who_is_gone_receives_nothing() {
        let deliverer = Arc::new(FakeWebhookDeliverer::new());
        let mut delivery = delivery(
            WebhookSubscriptionStatus::Active,
            &user_viewer(),
            deliverer.clone(),
        );
        delivery.use_case.ports.users = Arc::new(FakeUserStore::empty());

        let attempt = deliver(
            &delivery,
            &Arc::new(FakeEventDispatcher::new()),
            IdentityEvent::UserRegistered.into(),
        );

        assert!(attempt.is_none());
        assert_eq!(*deliverer.calls.lock().unwrap(), 0);
    }

    /// Ann paused her webhook. A registration raised meanwhile is not sent.
    #[test]
    fn a_paused_subscription_is_sent_nothing() {
        let deliverer = Arc::new(FakeWebhookDeliverer::new());
        let delivery = delivery(
            WebhookSubscriptionStatus::Paused,
            &user_viewer(),
            deliverer.clone(),
        );

        let attempt = deliver(
            &delivery,
            &Arc::new(FakeEventDispatcher::new()),
            IdentityEvent::UserRegistered.into(),
        );

        assert!(attempt.is_none());
        assert_eq!(*deliverer.calls.lock().unwrap(), 0);
    }

    /// The record of a delivery is never itself delivered, or each delivery
    /// would raise another without end.
    #[test]
    fn a_delivery_record_is_never_itself_delivered() {
        let deliverer = Arc::new(FakeWebhookDeliverer::new());
        let delivery = delivery(
            WebhookSubscriptionStatus::Active,
            SystemPermission::all(),
            deliverer.clone(),
        );

        let attempt = deliver(
            &delivery,
            &Arc::new(FakeEventDispatcher::new()),
            WebhooksEvent::DeliveryAttempted.into(),
        );

        assert!(attempt.is_none());
        assert_eq!(*deliverer.calls.lock().unwrap(), 0);
    }

    /// Ann's server was down for three deliveries and is back. The next
    /// registration gets through: the failure streak starts again, the
    /// delivery time is kept, and nothing is retried.
    #[test]
    fn a_success_clears_the_failure_streak() {
        let delivery = failing_delivery(3, 200);

        let report = registration_try(&delivery, &Arc::new(FakeEventDispatcher::new()), 0);

        assert_eq!(report.next, NextTry::Done);
        assert_eq!(stored(&delivery).consecutive_failures(), 0);
        assert!(stored(&delivery).last_delivered_at().is_some());
    }

    /// Ann's server answers 503. The failure is counted, and the event is
    /// sent again as try 1 after the standard policy's first wait of ten
    /// seconds.
    #[test]
    fn a_failure_is_counted_and_retried_after_the_first_delay() {
        let delivery = failing_delivery(0, 503);

        let report = registration_try(&delivery, &Arc::new(FakeEventDispatcher::new()), 0);

        assert_eq!(
            report.next,
            NextTry::Retry {
                attempt_number: 1,
                after: Seconds::new(10),
            }
        );
        assert_eq!(stored(&delivery).consecutive_failures(), 1);
    }

    /// Ann's integration needs events fast, so she picked the aggressive
    /// policy. A failure is retried after its first wait of one second, not
    /// the standard ten.
    #[test]
    fn the_subscriptions_own_retry_policy_spaces_its_retries() {
        let mut subscription = test_subscription(ENDPOINT, WebhookSubscriptionStatus::Active);
        let control = WebhookControl::new(anyone_holding(SystemPermission::all()));
        subscription
            .update(
                WebhookUpdate {
                    url: None,
                    event_types: None,
                    description: None,
                    retry: Some(RetryPreset::Aggressive),
                },
                &control,
            )
            .unwrap();
        let deliverer = Arc::new(FakeWebhookDeliverer::answering(503));
        let delivery = delivery_to(&subscription, &user_viewer(), deliverer.clone());

        let report = registration_try(&delivery, &Arc::new(FakeEventDispatcher::new()), 0);

        assert_eq!(
            report.next,
            NextTry::Retry {
                attempt_number: 1,
                after: Seconds::new(1),
            }
        );
        assert_eq!(
            deliverer.timeouts.lock().unwrap().as_slice(),
            [Seconds::new(10)]
        );
    }

    /// Ann's server still answers 503 on try 5, the standard policy's last
    /// retry. The attempt keeps its number and nothing more is tried.
    #[test]
    fn a_failure_on_the_last_retry_is_not_retried() {
        let delivery = failing_delivery(0, 503);

        let report = registration_try(&delivery, &Arc::new(FakeEventDispatcher::new()), 5);

        assert_eq!(report.attempt.attempt_number, 5);
        assert_eq!(report.next, NextTry::Done);
    }

    /// The fiftieth consecutive failed delivery disables the subscription,
    /// records the attempt and disablement, and schedules no retry.
    #[test]
    fn the_failure_that_reaches_the_limit_disables_the_subscription() {
        let delivery = failing_delivery(49, 500);
        let audit = Arc::new(FakeEventDispatcher::new());

        let report = registration_try(&delivery, &audit, 0);

        assert_eq!(report.next, NextTry::Done);
        assert_eq!(
            stored(&delivery).status(),
            WebhookSubscriptionStatus::Disabled
        );
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            [
                "webhooks.delivery_attempted",
                "webhooks.subscription_disabled"
            ]
        );
    }

    /// Ann's endpoint fails for the 50th time, and the switch-off cannot be
    /// recorded. The count, the switch-off and the record are one unit, so
    /// all of it is rolled back and the delivery fails as an error.
    #[test]
    fn a_switch_off_that_cannot_be_recorded_is_rolled_back() {
        let delivery = failing_delivery(49, 500);
        let request = DeliverWebhookRequest {
            message: message_of(&delivery, IdentityEvent::UserRegistered.into()),
            attempt_number: 0,
        };

        let result = block_on(delivery.use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            request,
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(delivery.unit.settlements(), [Settlement::Rollback]);
    }

    /// Fails one delivery of its own while it sends, the way a second worker
    /// delivering to the same endpoint at once would, then answers 503.
    struct RacingDeliverer {
        store: Arc<FakeWebhookStore>,
        subscription_id: WebhookSubscriptionId,
    }

    #[async_trait]
    impl WebhookDeliverer for RacingDeliverer {
        async fn deliver(
            &self,
            _: OutboundDelivery<'_>,
        ) -> Result<WebhookDeliveryOutcome, DomainError> {
            let other = DeliveryAttempt {
                id: WebhookDeliveryId::new(),
                message_id: WebhookMessageId::new(),
                subscription_id: self.subscription_id,
                event_type: IdentityEvent::UserRegistered.into(),
                outcome: DeliveryOutcome::Answered { code: 503 },
                duration_ms: 0,
                attempt_number: 0,
                attempted_at: clock::now(),
            };
            let limit = WebhookRetryPolicy::standard().disable_after_failures();
            self.store
                .record_delivery(&test_ctx().tenant(), &other, limit)
                .await?;
            Ok(WebhookDeliveryOutcome {
                outcome: DeliveryOutcome::Answered { code: 503 },
                duration_ms: 0,
            })
        }
    }

    /// Two workers deliver to Ann's server at once and both deliveries
    /// fail. Each failure is counted, rather than one overwriting the
    /// other's count.
    #[test]
    fn failures_delivered_at_once_are_each_counted() {
        let mut delivery = failing_delivery(0, 503);
        delivery.use_case.ports.sending.deliverer = Arc::new(RacingDeliverer {
            store: delivery.store.clone(),
            subscription_id: delivery.id,
        });

        registration_try(&delivery, &Arc::new(FakeEventDispatcher::new()), 0);

        assert_eq!(stored(&delivery).consecutive_failures(), 2);
    }

    /// A delivery waits no longer than the standard policy's thirty
    /// seconds, so a hung server holds no worker past it.
    #[test]
    fn a_delivery_is_bounded_by_the_policy_timeout() {
        let deliverer = Arc::new(FakeWebhookDeliverer::new());
        let delivery = delivery(
            WebhookSubscriptionStatus::Active,
            &user_viewer(),
            deliverer.clone(),
        );

        registration_try(&delivery, &Arc::new(FakeEventDispatcher::new()), 0);

        assert_eq!(
            deliverer.timeouts.lock().unwrap().as_slice(),
            [Seconds::new(30)]
        );
    }
}
