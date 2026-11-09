//! Fakes for the webhooks use cases.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::webhooks::delivery::{DeliveryAttempt, WebhookDeliveryStatus};
use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
use ianua_domain::domains::webhooks::signing::SignedDelivery;
use ianua_domain::domains::webhooks::subscription::{WebhookSubscription, WebhookSubscriptionRow};
use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::event_type::IdentityEvent;
use ianua_domain::types::{
    DeliveryOutcome, EventType, FailureLimit, PreviousSigningSecret, PrincipalRef, PublicHttpsUrl,
    Seconds, TenantId, WebhookDeliveryId, WebhookMessageId, WebhookSubscriptionId,
};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor};
use crate::ports::shared::PublishedEvent;
use crate::ports::webhooks::{
    DeliveryAttemptSortField, OutboundDelivery, RecordedDelivery, StreakChange, WebhookBodies,
    WebhookDeliverer, WebhookDeliveryOutcome, WebhookMessage, WebhookSecretGenerator,
    WebhookSendThrottle, WebhookStore, WebhookSubscriptionSortField,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::FakeEncryptor;
use crate::test_support::listing::page;
use crate::test_support::scheduling::FakeJobQueue;
use crate::test_support::{Fake, test_ctx};
use crate::use_cases::webhooks::delivery::WebhookJobs;

/// The secret every [`test_subscription`] signs with, before it is sealed.
pub const TEST_SIGNING_SECRET: &str = "old-signing-secret";

/// A subscription to user registrations at `url`, in `status`, made by the
/// caller [`test_ctx`] names and signed with [`TEST_SIGNING_SECRET`], sealed
/// as [`FakeEncryptor`] seals it.
///
/// # Panics
///
/// Panics if `url` is not a public HTTPS URL.
#[must_use]
pub fn test_subscription(
    url: &str,
    status: WebhookSubscriptionStatus,
) -> WebhookSubscription<ResolvedTenant> {
    failing_test_subscription(url, status, 0)
}

/// A [`test_subscription`] whose last `failures` deliveries in a row failed.
///
/// # Panics
///
/// Panics if `url` is not a public HTTPS URL.
#[must_use]
pub fn failing_test_subscription(
    url: &str,
    status: WebhookSubscriptionStatus,
    failures: u32,
) -> WebhookSubscription<ResolvedTenant> {
    let now = clock::now();
    let id = WebhookSubscriptionId::new();
    WebhookSubscription::reconstitute(WebhookSubscriptionRow {
        id,
        url: PublicHttpsUrl::new(url).expect("a test passes a public HTTPS URL"),
        signing_secret: FakeEncryptor::sealed_for(TEST_SIGNING_SECRET, &signing_secret_place(&id)),
        previous_secret: PreviousSigningSecret::Retired,
        event_types: vec![IdentityEvent::UserRegistered.into()],
        status,
        description: None,
        retry: RetryPreset::Standard,
        created_by: test_subscription_creator(),
        consecutive_failures: failures,
        last_delivered_at: None,
        created_at: now,
        updated_at: now,
    })
    .expect("a fresh subscription to one event is a consistent row")
}

/// Where the test tenant's subscription `id` keeps its signing secrets.
#[must_use]
pub fn signing_secret_place(id: &WebhookSubscriptionId) -> SealedFor {
    SealedFor::new(
        SealOwner::Tenant(test_ctx().tenant_id()),
        SealedField::WebhookSigningSecret,
        id,
    )
}

/// The principal every [`test_subscription`] names as its creator.
#[must_use]
pub fn test_subscription_creator() -> PrincipalRef {
    test_ctx().principal().expect("the test caller is a user")
}

/// A user registration sent to `subscription_id`, with a fresh message id.
#[must_use]
pub fn test_message(subscription_id: WebhookSubscriptionId) -> WebhookMessage {
    WebhookMessage {
        id: WebhookMessageId::new(),
        subscription_id,
        event_type: IdentityEvent::UserRegistered.into(),
        payload: br#"{"type":"identity.user_registered"}"#.to_vec(),
    }
}

/// The first try of `message`, which its endpoint answered with `code`.
#[must_use]
pub fn test_attempt(message: &WebhookMessage, code: u16) -> DeliveryAttempt {
    DeliveryAttempt {
        id: WebhookDeliveryId::new(),
        message_id: message.id,
        subscription_id: message.subscription_id,
        event_type: message.event_type,
        outcome: DeliveryOutcome::Answered { code },
        duration_ms: 1,
        attempt_number: 0,
        attempted_at: clock::now(),
    }
}

fn copy_of(
    subscription: &WebhookSubscription<ResolvedTenant>,
) -> WebhookSubscription<ResolvedTenant> {
    WebhookSubscription::reconstitute(WebhookSubscriptionRow {
        id: *subscription.id(),
        url: subscription.url().clone(),
        signing_secret: subscription.signing_secret().clone(),
        previous_secret: subscription.previous_secret().clone(),
        event_types: subscription.event_types().to_vec(),
        status: subscription.status(),
        description: subscription.description().cloned(),
        retry: subscription.retry(),
        created_by: *subscription.created_by(),
        consecutive_failures: subscription.consecutive_failures(),
        last_delivered_at: subscription.last_delivered_at(),
        created_at: subscription.created_at(),
        updated_at: subscription.updated_at(),
    })
    .expect("a webhook subscription reads back as itself")
}

type Entry = (TenantId, WebhookSubscription<ResolvedTenant>);

/// In-memory webhook store for tests, keeping each subscription and each
/// delivery attempt under the tenant it was saved for.
#[derive(Default)]
pub struct FakeWebhookStore {
    subscriptions: Mutex<Vec<Entry>>,
    /// Recorded delivery attempts, with the tenant each was recorded for.
    pub attempts: Mutex<Vec<(TenantId, DeliveryAttempt)>>,
    /// Kept messages, with the tenant each was kept for.
    pub messages: Mutex<Vec<(TenantId, WebhookMessage)>>,
}

impl TenantScoped for FakeWebhookStore {}

impl FakeWebhookStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `subscription` in `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, subscription: &WebhookSubscription<ResolvedTenant>) -> Self {
        Self {
            subscriptions: Mutex::new(vec![(tenant, copy_of(subscription))]),
            ..Self::default()
        }
    }

    /// Keeps `message` and one try of it, `attempt`, as though they had been
    /// sent to their subscription in `tenant`.
    pub fn sent(&self, tenant: TenantId, message: WebhookMessage, attempt: DeliveryAttempt) {
        self.messages.lock().unwrap().push((tenant, message));
        self.attempts.lock().unwrap().push((tenant, attempt));
    }

    /// Every attempt recorded for `tenant`, in the order they were made.
    #[must_use]
    pub fn attempts_in(&self, tenant: TenantId) -> Vec<DeliveryAttempt> {
        self.attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| *owner == tenant)
            .map(|(_, attempt)| attempt.clone())
            .collect()
    }

    /// The subscription `id` as `tenant` holds it now.
    #[must_use]
    pub fn stored(
        &self,
        tenant: TenantId,
        id: &WebhookSubscriptionId,
    ) -> Option<WebhookSubscription<ResolvedTenant>> {
        self.subscriptions
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, subscription)| *owner == tenant && subscription.id() == id)
            .map(|(_, subscription)| copy_of(subscription))
    }

    /// Returns the number of stored subscriptions, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.subscriptions.lock().unwrap().len()
    }
}

fn is(entry: &Entry, tenant: &ScopedTenant, id: &WebhookSubscriptionId) -> bool {
    entry.0 == **tenant && entry.1.id() == id
}

#[async_trait]
impl WebhookStore for FakeWebhookStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &WebhookSubscriptionId,
    ) -> Result<Option<WebhookSubscription<ResolvedTenant>>, DomainError> {
        Ok(self
            .subscriptions
            .lock()
            .unwrap()
            .iter()
            .find(|entry| is(entry, tenant_id, id))
            .map(|(_, subscription)| copy_of(subscription)))
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<WebhookSubscriptionStatus>,
        sort: &SortOrder<WebhookSubscriptionSortField>,
        request: &PageRequest,
    ) -> Result<Page<WebhookSubscription<ResolvedTenant>>, DomainError> {
        let all: Vec<_> = self
            .subscriptions
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .filter(|(_, subscription)| status.is_none_or(|wanted| subscription.status() == wanted))
            .map(|(_, subscription)| copy_of(subscription))
            .collect();
        page(all, sort, request)
    }

    async fn list_receiving(
        &self,
        tenant_id: &ScopedTenant,
        event_type: EventType,
    ) -> Result<Vec<WebhookSubscription<ResolvedTenant>>, DomainError> {
        Ok(self
            .subscriptions
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .filter(|(_, subscription)| subscription.is_active())
            .filter(|(_, subscription)| subscription.event_types().contains(&event_type))
            .map(|(_, subscription)| copy_of(subscription))
            .collect())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &WebhookSubscription<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut subscriptions = self.subscriptions.lock().unwrap();
        subscriptions.retain(|entry| !is(entry, tenant_id, subscription.id()));
        subscriptions.push((**tenant_id, copy_of(subscription)));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &WebhookSubscriptionId,
    ) -> Result<(), DomainError> {
        self.subscriptions
            .lock()
            .unwrap()
            .retain(|entry| !is(entry, tenant_id, id));
        self.attempts
            .lock()
            .unwrap()
            .retain(|(owner, attempt)| !(owner == &**tenant_id && attempt.subscription_id == *id));
        self.messages
            .lock()
            .unwrap()
            .retain(|(owner, message)| !(owner == &**tenant_id && message.subscription_id == *id));
        Ok(())
    }

    async fn find_delivery_attempt(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
        id: &WebhookDeliveryId,
    ) -> Result<Option<DeliveryAttempt>, DomainError> {
        Ok(self
            .attempts
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, attempt)| {
                owner == &**tenant_id
                    && attempt.subscription_id == *subscription_id
                    && attempt.id == *id
            })
            .map(|(_, attempt)| attempt.clone()))
    }

    async fn keep_message(
        &self,
        tenant_id: &ScopedTenant,
        message: &WebhookMessage,
    ) -> Result<(), DomainError> {
        let mut messages = self.messages.lock().unwrap();
        if messages
            .iter()
            .any(|(owner, kept)| owner == &**tenant_id && kept.id == message.id)
        {
            return Ok(());
        }
        messages.push((**tenant_id, message.clone()));
        Ok(())
    }

    async fn find_message(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
        id: &WebhookMessageId,
    ) -> Result<Option<WebhookMessage>, DomainError> {
        Ok(self
            .messages
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, message)| {
                owner == &**tenant_id
                    && message.subscription_id == *subscription_id
                    && message.id == *id
            })
            .map(|(_, message)| message.clone()))
    }

    async fn list_delivery_attempts(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
        sort: &SortOrder<DeliveryAttemptSortField>,
        request: &PageRequest,
    ) -> Result<Page<DeliveryAttempt>, DomainError> {
        let all: Vec<_> = self
            .attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, attempt)| {
                owner == &**tenant_id && attempt.subscription_id == *subscription_id
            })
            .map(|(_, attempt)| attempt.clone())
            .collect();
        page(all, sort, request)
    }

    async fn record_delivery(
        &self,
        tenant_id: &ScopedTenant,
        attempt: &DeliveryAttempt,
        disable_after: FailureLimit,
    ) -> Result<Option<RecordedDelivery>, DomainError> {
        let mut subscriptions = self.subscriptions.lock().unwrap();
        let Some((_, subscription)) = subscriptions
            .iter_mut()
            .find(|entry| is(entry, tenant_id, &attempt.subscription_id))
        else {
            return Ok(None);
        };
        let change = counted_on(subscription, attempt, disable_after);
        self.attempts
            .lock()
            .unwrap()
            .push((**tenant_id, attempt.clone()));
        Ok(Some(RecordedDelivery {
            subscription: copy_of(subscription),
            change,
        }))
    }

    async fn keep_uncounted_attempt(
        &self,
        tenant_id: &ScopedTenant,
        attempt: &DeliveryAttempt,
    ) -> Result<(), DomainError> {
        self.attempts
            .lock()
            .unwrap()
            .push((**tenant_id, attempt.clone()));
        Ok(())
    }
}

/// Counts `attempt` on `subscription` the way the domain does.
fn counted_on(
    subscription: &mut WebhookSubscription<ResolvedTenant>,
    attempt: &DeliveryAttempt,
    disable_after: FailureLimit,
) -> StreakChange {
    if attempt.status() == WebhookDeliveryStatus::Success {
        subscription.record_success();
        return StreakChange::Delivered;
    }
    StreakChange::Failed(subscription.record_failure(disable_after))
}

/// Webhook secret generator for tests that hands out `raw-secret-1`,
/// `raw-secret-2` and so on.
#[derive(Default)]
pub struct FakeWebhookSecretGenerator {
    /// How many secrets were generated.
    pub counter: Mutex<u32>,
}

impl FakeWebhookSecretGenerator {
    /// Creates a new generator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WebhookSecretGenerator for FakeWebhookSecretGenerator {
    async fn generate(&self) -> Result<Secret, DomainError> {
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;
        Ok(Secret::new(format!("raw-secret-{counter}")))
    }
}

/// What a [`FakeWebhookDeliverer`] was asked to send, with the secrets
/// opened to plain text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentDelivery {
    /// The message id and send time the signatures cover.
    pub signed: SignedDelivery,
    /// The body.
    pub payload: Vec<u8>,
    /// Every secret it was signed with, in order.
    pub secrets: Vec<String>,
}

/// Webhook deliverer for tests that answers every delivery with one HTTP
/// code and remembers what each delivery carried and the timeout it was
/// given.
pub struct FakeWebhookDeliverer {
    /// How many deliveries were attempted.
    pub calls: Mutex<u32>,
    /// The timeout each delivery was given, in order.
    pub timeouts: Mutex<Vec<Seconds>>,
    /// What each delivery carried, in order.
    pub sent: Mutex<Vec<SentDelivery>>,
    code: u16,
}

impl FakeWebhookDeliverer {
    /// A deliverer whose endpoint answers `200`.
    #[must_use]
    pub fn new() -> Self {
        Self::answering(200)
    }

    /// A deliverer whose endpoint answers `code`.
    #[must_use]
    pub fn answering(code: u16) -> Self {
        Self {
            calls: Mutex::new(0),
            timeouts: Mutex::new(Vec::new()),
            sent: Mutex::new(Vec::new()),
            code,
        }
    }

    /// What each delivery carried, in order.
    #[must_use]
    pub fn deliveries(&self) -> Vec<SentDelivery> {
        self.sent.lock().unwrap().clone()
    }
}

impl Default for FakeWebhookDeliverer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WebhookDeliverer for FakeWebhookDeliverer {
    async fn deliver(
        &self,
        delivery: OutboundDelivery<'_>,
    ) -> Result<WebhookDeliveryOutcome, DomainError> {
        *self.calls.lock().unwrap() += 1;
        self.timeouts.lock().unwrap().push(delivery.timeout);
        self.sent.lock().unwrap().push(SentDelivery {
            signed: delivery.signed,
            payload: delivery.payload.to_vec(),
            secrets: delivery
                .secrets
                .iter()
                .map(|secret| secret.expose().to_owned())
                .collect(),
        });
        Ok(WebhookDeliveryOutcome {
            outcome: DeliveryOutcome::Answered { code: self.code },
            duration_ms: 0,
        })
    }
}

impl Fake for Arc<dyn WebhookDeliverer> {
    fn fake() -> Self {
        Arc::new(FakeWebhookDeliverer::new())
    }
}

impl Fake for Arc<dyn WebhookSecretGenerator> {
    fn fake() -> Self {
        Arc::new(FakeWebhookSecretGenerator::new())
    }
}

impl Fake for Arc<dyn WebhookStore> {
    fn fake() -> Self {
        Arc::new(FakeWebhookStore::empty())
    }
}

/// Send throttle that lets every resend and test through.
pub struct OpenWebhookSendThrottle;

impl TenantScoped for OpenWebhookSendThrottle {}

#[async_trait]
impl WebhookSendThrottle for OpenWebhookSendThrottle {
    async fn admit(
        &self,
        _: &ScopedTenant,
        _: &WebhookSubscriptionId,
    ) -> Result<bool, DomainError> {
        Ok(true)
    }
}

/// Send throttle that holds every resend and test back, as for a webhook
/// sent to a moment ago.
pub struct ShutWebhookSendThrottle;

impl TenantScoped for ShutWebhookSendThrottle {}

#[async_trait]
impl WebhookSendThrottle for ShutWebhookSendThrottle {
    async fn admit(
        &self,
        _: &ScopedTenant,
        _: &WebhookSubscriptionId,
    ) -> Result<bool, DomainError> {
        Ok(false)
    }
}

impl Fake for Arc<dyn WebhookSendThrottle> {
    fn fake() -> Self {
        Arc::new(OpenWebhookSendThrottle)
    }
}

/// Webhook bodies naming only the event's type and id.
pub struct FakeWebhookBodies;

impl WebhookBodies for FakeWebhookBodies {
    fn body(&self, event: &PublishedEvent) -> Result<Vec<u8>, DomainError> {
        Ok(format!(
            r#"{{"id":"{}","type":"{}"}}"#,
            event.id,
            event.event.event_type()
        )
        .into_bytes())
    }
}

impl Fake for Arc<dyn WebhookBodies> {
    fn fake() -> Self {
        Arc::new(FakeWebhookBodies)
    }
}

impl Fake for WebhookJobs {
    fn fake() -> Self {
        WebhookJobs {
            queue: Arc::new(FakeJobQueue::new()),
        }
    }
}
