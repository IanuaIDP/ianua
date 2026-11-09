//! One try at sending a message to a webhook: signed as Standard Webhooks
//! lays it out with every secret that still signs, bounded by the
//! subscription's retry policy, then kept, counted on the endpoint's failure
//! streak and recorded as one unit.
//!
//! Delivering an event, resending one and sending a test event all go
//! through here, so each try is signed and recorded the same way. A test
//! send is kept and recorded but never counted: testing an endpoint that is
//! down must not switch it off.

use std::sync::Arc;

use ianua_domain::domains::webhooks::delivery::DeliveryAttempt;
use ianua_domain::domains::webhooks::retry_policy::WebhookRetryPolicy;
use ianua_domain::domains::webhooks::signing::SignedDelivery;
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, FailureOutcome, WebhookDeliveryId, WebhookSubscriptionId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::runtime::UnitOfWork;
use crate::ports::webhooks::{
    OutboundDelivery, RecordedDelivery, StreakChange, WebhookDeliverer, WebhookDeliveryOutcome,
    WebhookMessage, WebhookSendThrottle, WebhookStore,
};
use crate::services::kept_together::kept_together;
use crate::services::sealing::opened_secrets;
use crate::tenancy::ScopedTenant;
use crate::use_cases::webhooks::signing_secret::secret_place;

/// The ports sending a try to a webhook needs, which every use case that
/// sends one holds together.
#[derive(ianua_macros::Fakes)]
pub struct SendingPorts {
    /// Where subscriptions, messages and delivery attempts are kept.
    pub webhook_store: Arc<dyn WebhookStore>,
    /// Sends the signed payload, refusing internal addresses.
    pub deliverer: Arc<dyn WebhookDeliverer>,
    /// Opens the subscription's sealed signing secrets.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Keeps each try, its count on the streak and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

impl SendingPorts {
    /// What sends tries to `tenant`'s webhooks through these ports, recorded
    /// through `auditor` as sent `by`.
    pub(super) fn sender<'a>(
        &'a self,
        tenant: &'a ScopedTenant,
        auditor: &'a RequestAuditor,
        by: SentBy<'a>,
    ) -> Sender<'a> {
        Sender {
            store: self.webhook_store.as_ref(),
            deliverer: self.deliverer.as_ref(),
            encryptor: self.encryptor.as_ref(),
            unit_of_work: self.unit_of_work.as_ref(),
            auditor,
            tenant,
            by,
        }
    }
}

/// Who the record of a try names as having sent it.
#[derive(Debug, Clone, Copy)]
pub(super) enum SentBy<'a> {
    /// The platform, delivering an event as it happened.
    Platform,
    /// A person who asked for the send, such as a resend or a test.
    Person(&'a ActorRef),
}

/// One try of `message`, numbered `attempt_number`.
pub(super) struct Try<'a> {
    /// The message sent.
    pub(super) message: &'a WebhookMessage,
    /// Which try this is. The first is 0.
    pub(super) attempt_number: u8,
}

/// What came of one try.
pub(super) struct Sent {
    /// The record of the try.
    pub(super) attempt: DeliveryAttempt,
    /// What it did to the endpoint's failure streak.
    pub(super) change: StreakChange,
}

/// Sends tries to one tenant's webhooks and records them.
pub(super) struct Sender<'a> {
    /// Where subscriptions, messages and attempts are kept.
    store: &'a dyn WebhookStore,
    /// Sends the signed payload, refusing internal addresses.
    deliverer: &'a dyn WebhookDeliverer,
    /// Opens the subscription's sealed signing secrets.
    encryptor: &'a dyn SecretEncryptor,
    /// Keeps each try, its count and its record together.
    unit_of_work: &'a dyn UnitOfWork,
    /// Where the record of each try goes.
    auditor: &'a RequestAuditor,
    /// The tenant the webhooks belong to.
    tenant: &'a ScopedTenant,
    /// Who the records name.
    by: SentBy<'a>,
}

impl Sender<'_> {
    /// Sends `attempt` to `subscription`, then keeps the message, counts the
    /// try and records `webhooks.delivery_attempted`, and
    /// `webhooks.subscription_disabled` when this failure switched the
    /// endpoint off.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the subscription was deleted while the
    ///   try was on its way.
    /// - `AppError::Domain` when the URL resolves to an address deliveries
    ///   may not reach.
    /// - `AppError::Internal` when a secret cannot be opened, or a store or
    ///   the audit record fails; then nothing of the try is kept.
    pub(super) async fn send(
        &self,
        subscription: &WebhookSubscription<ResolvedTenant>,
        attempt: Try<'_>,
    ) -> Result<Sent, AppError> {
        let policy = subscription.retry().policy();
        let signed = SignedDelivery::now(attempt.message.id);
        let outcome = self
            .delivered(subscription, &attempt, signed, &policy)
            .await?;
        let record = attempt_of(&attempt, signed, outcome);
        let change = kept_together(
            self.unit_of_work,
            self.recorded(attempt.message, &record, &policy),
        )
        .await?;
        Ok(Sent {
            attempt: record,
            change,
        })
    }

    /// Sends `attempt` to `subscription` as a test the owner asked for,
    /// then keeps the message and the try and records
    /// `webhooks.delivery_attempted`. The try is never counted on the
    /// endpoint's failure streak, so testing an endpoint that is down never
    /// switches it off.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the URL resolves to an address deliveries
    ///   may not reach.
    /// - `AppError::Internal` when a secret cannot be opened, or a store or
    ///   the audit record fails; then nothing of the try is kept.
    pub(super) async fn send_test(
        &self,
        subscription: &mut WebhookSubscription<ResolvedTenant>,
        attempt: Try<'_>,
    ) -> Result<DeliveryAttempt, AppError> {
        let policy = subscription.retry().policy();
        let signed = SignedDelivery::now(attempt.message.id);
        let outcome = self
            .delivered(subscription, &attempt, signed, &policy)
            .await?;
        let record = attempt_of(&attempt, signed, outcome);
        kept_together(
            self.unit_of_work,
            self.keep_uncounted(subscription, attempt.message, &record),
        )
        .await?;
        Ok(record)
    }

    /// Keeps `message` and `attempt` in `subscription`'s history, without
    /// counting the attempt, and records it. Run as one unit, so no try is
    /// kept without its record.
    async fn keep_uncounted(
        &self,
        subscription: &mut WebhookSubscription<ResolvedTenant>,
        message: &WebhookMessage,
        attempt: &DeliveryAttempt,
    ) -> Result<(), AppError> {
        self.store
            .keep_message(self.tenant, message)
            .await
            .or_internal()?;
        self.store
            .keep_uncounted_attempt(self.tenant, attempt)
            .await
            .or_internal()?;
        subscription.report_attempt(attempt);
        self.dispatch(subscription.take_events(self.tenant)).await
    }

    /// Sends the try's payload, signed over `signed` with every secret that
    /// still signs, giving up after the policy's timeout.
    async fn delivered(
        &self,
        subscription: &WebhookSubscription<ResolvedTenant>,
        attempt: &Try<'_>,
        signed: SignedDelivery,
        policy: &WebhookRetryPolicy,
    ) -> Result<WebhookDeliveryOutcome, AppError> {
        let place = secret_place(self.tenant, subscription.id());
        let secrets =
            opened_secrets(self.encryptor, subscription.signing_secrets(), &place).await?;
        self.deliverer
            .deliver(OutboundDelivery {
                url: subscription.url(),
                signed,
                payload: &attempt.message.payload,
                secrets: &secrets,
                timeout: policy.timeout_seconds(),
            })
            .await
            .map_err(AppError::from_domain)
    }

    /// Keeps `message`, counts `attempt` on its subscription's streak and
    /// records both. Run as one unit: a subscription switched off with no
    /// record of it, or a record of a try that was never counted, would
    /// tell its owner something that is not so.
    async fn recorded(
        &self,
        message: &WebhookMessage,
        attempt: &DeliveryAttempt,
        policy: &WebhookRetryPolicy,
    ) -> Result<StreakChange, AppError> {
        self.store
            .keep_message(self.tenant, message)
            .await
            .or_internal()?;
        let mut recorded = self
            .store
            .record_delivery(self.tenant, attempt, policy.disable_after_failures())
            .await
            .or_internal()?
            .or_not_found(message!(
                "webhooks-webhook-subscription-not-found",
                "webhook subscription not found"
            ))?;
        report(&mut recorded, attempt);
        self.dispatch(recorded.subscription.take_events(self.tenant))
            .await?;
        Ok(recorded.change)
    }

    /// Records `events` as done by whoever the sender names.
    async fn dispatch(&self, events: Vec<DomainEvent>) -> Result<(), AppError> {
        let dispatched = match self.by {
            SentBy::Platform => self.auditor.dispatch(&events).await,
            SentBy::Person(actor) => self.auditor.dispatch_by(actor, events).await,
        };
        dispatched.or_internal()
    }
}

/// Refuses a resend or a test of the subscription `subscription_id` when
/// one was sent to it a moment ago.
///
/// # Errors
///
/// - `AppError::TooManyRequests` when the webhook was sent to a moment ago.
/// - `AppError::Internal` when the allowance cannot be read.
pub(super) async fn ensure_send_admitted(
    throttle: &dyn WebhookSendThrottle,
    tenant: &ScopedTenant,
    subscription_id: &WebhookSubscriptionId,
) -> Result<(), AppError> {
    if throttle
        .admit(tenant, subscription_id)
        .await
        .or_internal()?
    {
        return Ok(());
    }
    Err(AppError::TooManyRequests(message!(
        "webhooks-this-webhook-was-sent-to-a",
        "this webhook was sent to a moment ago; wait before sending again"
    )))
}

/// Refuses a send a person asks for to a subscription switched off for
/// failing. It is replaced, not sent to.
///
/// # Errors
///
/// `AppError::Conflict` when the subscription is disabled.
pub(super) fn ensure_not_disabled(
    subscription: &WebhookSubscription<ResolvedTenant>,
) -> Result<(), AppError> {
    if !subscription.status().is_disabled() {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "webhooks-a-disabled-webhook-is-replaced-not",
        "a disabled webhook is replaced, not sent to"
    )))
}

/// The record of `attempt`, sent at the time `signed` names, which ended in
/// `outcome`.
fn attempt_of(
    attempt: &Try<'_>,
    signed: SignedDelivery,
    outcome: WebhookDeliveryOutcome,
) -> DeliveryAttempt {
    DeliveryAttempt {
        id: WebhookDeliveryId::new(),
        message_id: attempt.message.id,
        subscription_id: attempt.message.subscription_id,
        event_type: attempt.message.event_type,
        outcome: outcome.outcome,
        duration_ms: outcome.duration_ms,
        attempt_number: attempt.attempt_number,
        attempted_at: signed.sent_at(),
    }
}

/// Has the counted subscription raise what one try did: always the
/// attempt, and the switch-off when this failure did it.
fn report(recorded: &mut RecordedDelivery, attempt: &DeliveryAttempt) {
    recorded.subscription.report_attempt(attempt);
    let StreakChange::Failed(FailureOutcome::Disabled) = recorded.change else {
        return;
    };
    recorded.subscription.report_switched_off();
}
