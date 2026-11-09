//! Send test event: send a webhook a sample of one of its events, so its
//! owner can check the endpoint receives and verifies deliveries.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WebhooksAction;
use ianua_domain::domains::webhooks::control::WebhookControl;
use ianua_domain::domains::webhooks::delivery::DeliveryAttempt;
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EventType, WebhookMessageId, WebhookSubscriptionId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::webhooks::{WebhookMessage, WebhookSendThrottle};
use crate::use_case::Command;
use crate::use_cases::webhooks::delivery::sending::{
    SendingPorts, SentBy, Try, ensure_not_disabled, ensure_send_admitted,
};
use crate::use_cases::webhooks::lookup::existing_subscription;

/// Which webhook to test, with which of its events.
pub struct SendTestEventRequest {
    /// The subscription to send to.
    pub subscription_id: WebhookSubscriptionId,
    /// The event the sample stands for. The subscription must list it.
    pub event_type: EventType,
}

/// The ports [`SendTestEventUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SendTestEventPorts {
    /// Signs and sends the try, keeps it and records it.
    pub sending: SendingPorts,
    /// Lets each webhook be sent a test only now and then.
    pub throttle: Arc<dyn WebhookSendThrottle>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sends a webhook a test event.
pub struct SendTestEventUseCase {
    ports: SendTestEventPorts,
}

impl SendTestEventUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SendTestEventPorts) -> Self {
        Self { ports }
    }
}

impl Command for SendTestEventUseCase {
    type Caller = CallerContext;
    type Input = SendTestEventRequest;
    type Output = Result<DeliveryAttempt, AppError>;

    /// Sends the subscription a sample of the event, marked as a test and
    /// holding none of the tenant's data, signed and bounded like any
    /// delivery. The attempt is kept and recorded as
    /// `webhooks.delivery_attempted` by the caller, so the owner sees in the
    /// history what their endpoint answered. It is never counted on the
    /// endpoint's failure streak, so testing an endpoint that is down never
    /// switches it off, and it is not retried.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without webhook-update rights.
    /// - `AppError::NotFound` for a missing tenant subscription; `Domain` for an unlisted event or forbidden destination address.
    /// - `AppError::Conflict` for a disabled subscription; `TooManyRequests` for a recent send.
    /// - `AppError::Internal` on storage, secret or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: SendTestEventRequest,
    ) -> Result<DeliveryAttempt, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        WebhookControl::new(&authority)
            .ensure_may(WebhooksAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.sending.webhook_store.as_ref();
        let mut subscription =
            existing_subscription(store, &tenant, &request.subscription_id).await?;
        ensure_not_disabled(&subscription)?;
        ensure_listed(&subscription, request.event_type)?;
        ensure_send_admitted(
            self.ports.throttle.as_ref(),
            &tenant,
            &request.subscription_id,
        )
        .await?;
        let message = test_message(&subscription, request.event_type)?;
        let attempt = Try {
            message: &message,
            attempt_number: 0,
        };
        let actor = caller.actor();
        self.ports
            .sending
            .sender(&tenant, auditor, SentBy::Person(&actor))
            .send_test(&mut subscription, attempt)
            .await
    }
}

/// Refuses a test of an event the subscription does not list: its endpoint
/// never receives one, so a sample would test nothing it handles.
///
/// # Errors
///
/// `AppError::Domain` when the subscription does not list `event_type`.
fn ensure_listed(
    subscription: &WebhookSubscription<ResolvedTenant>,
    event_type: EventType,
) -> Result<(), AppError> {
    if subscription.event_types().contains(&event_type) {
        return Ok(());
    }
    Err(AppError::from_domain(DomainError::invalid(message!(
        "webhooks-the-webhook-does-not-receive-this",
        "the webhook does not receive this event"
    ))))
}

/// A fresh message to `subscription` holding a sample of `event_type`:
/// its name, its meaning and a mark that it is a test.
///
/// # Errors
///
/// `AppError::Internal` when the sample cannot be written out.
fn test_message(
    subscription: &WebhookSubscription<ResolvedTenant>,
    event_type: EventType,
) -> Result<WebhookMessage, AppError> {
    let body = serde_json::json!({
        "type": event_type.as_str(),
        "test": true,
        "data": { "description": event_type.description() },
    });
    let payload = serde_json::to_vec(&body).map_err(AppError::internal)?;
    Ok(WebhookMessage {
        id: WebhookMessageId::new(),
        subscription_id: *subscription.id(),
        event_type,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
    use ianua_domain::types::event_type::IdentityEvent;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::webhooks::{
        FakeWebhookDeliverer, FakeWebhookStore, ShutWebhookSendThrottle, TEST_SIGNING_SECRET,
        failing_test_subscription,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann's stored webhook, with the deliverer its endpoint answers
    /// through.
    struct Testing {
        store: Arc<FakeWebhookStore>,
        deliverer: Arc<FakeWebhookDeliverer>,
        id: WebhookSubscriptionId,
    }

    /// Ann's webhook for registrations in `status`, failed `failures` times
    /// in a row, at an endpoint that answers `code`.
    fn testing_failed(status: WebhookSubscriptionStatus, failures: u32, code: u16) -> Testing {
        let subscription =
            failing_test_subscription("https://hooks.acme.com/events", status, failures);
        Testing {
            store: Arc::new(FakeWebhookStore::holding(
                test_ctx().tenant_id(),
                &subscription,
            )),
            deliverer: Arc::new(FakeWebhookDeliverer::answering(code)),
            id: *subscription.id(),
        }
    }

    /// Ann's webhook for registrations in `status`, at an endpoint that
    /// answers `code`.
    fn testing(status: WebhookSubscriptionStatus, code: u16) -> Testing {
        testing_failed(status, 0, code)
    }

    /// A use case sending through `testing`, for a caller holding what
    /// `authorities` says.
    fn use_case(testing: &Testing, authorities: FakeTenantAuthorities) -> SendTestEventUseCase {
        SendTestEventUseCase::new(SendTestEventPorts {
            sending: SendingPorts {
                webhook_store: testing.store.clone(),
                deliverer: testing.deliverer.clone(),
                ..SendingPorts::fakes()
            },
            tenant_authorities: Arc::new(authorities),
            ..SendTestEventPorts::fakes()
        })
    }

    /// The right to update webhooks.
    fn updater() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::Update)])
    }

    /// Sends a test of `event_type` to subscription `id`.
    fn send(
        use_case: &SendTestEventUseCase,
        audit: &Arc<FakeEventDispatcher>,
        id: WebhookSubscriptionId,
        event_type: EventType,
    ) -> Result<DeliveryAttempt, AppError> {
        let request = SendTestEventRequest {
            subscription_id: id,
            event_type,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    /// Ann set up her server and sends it a test registration. It is
    /// signed with her secret, marked as a test, and its outcome is kept in
    /// the history and recorded.
    #[test]
    fn a_test_event_is_signed_sent_and_recorded() {
        let testing = testing(WebhookSubscriptionStatus::Active, 200);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&testing, updater());

        let attempt = send(
            &use_case,
            &audit,
            testing.id,
            IdentityEvent::UserRegistered.into(),
        )
        .unwrap();

        let sent = testing.deliverer.deliveries();
        let body: serde_json::Value = serde_json::from_slice(&sent[0].payload).unwrap();
        assert_eq!(sent[0].secrets, [TEST_SIGNING_SECRET]);
        assert_eq!(body["test"], true);
        assert_eq!(attempt.message_id, *sent[0].signed.message_id());
        assert_eq!(testing.store.attempts_in(test_ctx().tenant_id()).len(), 1);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["webhooks.delivery_attempted"]
        );
    }

    /// Ann's server is still misconfigured and answers 500. The test shows
    /// her what it answered.
    #[test]
    fn a_failing_endpoint_shows_its_answer() {
        let testing = testing(WebhookSubscriptionStatus::Active, 500);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&testing, updater());

        let attempt = send(
            &use_case,
            &audit,
            testing.id,
            IdentityEvent::UserRegistered.into(),
        )
        .unwrap();

        assert_eq!(attempt.outcome.response_code(), Some(500));
    }

    /// A failed test delivery leaves an active subscription's four-failure
    /// streak unchanged and records only the delivery attempt.
    #[test]
    fn a_failed_test_is_not_counted_on_the_failure_streak() {
        let testing = testing_failed(WebhookSubscriptionStatus::Active, 4, 500);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&testing, updater());

        send(
            &use_case,
            &audit,
            testing.id,
            IdentityEvent::UserRegistered.into(),
        )
        .unwrap();

        let stored = testing
            .store
            .stored(test_ctx().tenant_id(), &testing.id)
            .unwrap();
        assert_eq!(stored.consecutive_failures(), 4);
        assert!(stored.is_active());
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["webhooks.delivery_attempted"]
        );
    }

    /// A test delivery rejected by the webhook throttle returns too many
    /// requests without calling the deliverer or recording an event.
    #[test]
    fn a_webhook_tested_a_moment_ago_is_refused() {
        let testing = testing(WebhookSubscriptionStatus::Active, 200);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = SendTestEventUseCase::new(SendTestEventPorts {
            sending: SendingPorts {
                webhook_store: testing.store.clone(),
                deliverer: testing.deliverer.clone(),
                ..SendingPorts::fakes()
            },
            throttle: Arc::new(ShutWebhookSendThrottle),
            tenant_authorities: Arc::new(updater()),
        });

        let result = send(
            &use_case,
            &audit,
            testing.id,
            IdentityEvent::UserRegistered.into(),
        );

        assert!(matches!(result, Err(AppError::TooManyRequests(_))));
        assert_eq!(*testing.deliverer.calls.lock().unwrap(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann tests user deletions on a webhook that only receives
    /// registrations. It is refused and nothing is sent.
    #[test]
    fn an_event_the_webhook_does_not_list_is_refused() {
        let testing = testing(WebhookSubscriptionStatus::Active, 200);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&testing, updater());

        let result = send(
            &use_case,
            &audit,
            testing.id,
            IdentityEvent::UserDeleted.into(),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(*testing.deliverer.calls.lock().unwrap(), 0);
    }

    /// Ann tests a webhook switched off for failing. It is refused: a
    /// disabled webhook is replaced.
    #[test]
    fn a_disabled_subscription_is_not_tested() {
        let testing = testing(WebhookSubscriptionStatus::Disabled, 200);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&testing, updater());

        let result = send(
            &use_case,
            &audit,
            testing.id,
            IdentityEvent::UserRegistered.into(),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(*testing.deliverer.calls.lock().unwrap(), 0);
    }

    /// Ann names a subscription the tenant does not have. It is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let testing = testing(WebhookSubscriptionStatus::Active, 200);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&testing, updater());

        let result = send(
            &use_case,
            &audit,
            WebhookSubscriptionId::new(),
            IdentityEvent::UserRegistered.into(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Webhook viewing rights do not permit sending test events; the request
    /// is forbidden without calling the deliverer or recording an event.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let testing = testing(WebhookSubscriptionStatus::Active, 200);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            &testing,
            FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::View)]),
        );

        let result = send(
            &use_case,
            &audit,
            testing.id,
            IdentityEvent::UserRegistered.into(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(*testing.deliverer.calls.lock().unwrap(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Sending a test event with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let testing = testing(WebhookSubscriptionStatus::Active, 200);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            &testing,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = send(
            &use_case,
            &audit,
            testing.id,
            IdentityEvent::UserRegistered.into(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
