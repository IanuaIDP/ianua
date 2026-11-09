//! Webhooks-specific ports.

use async_trait::async_trait;
use ianua_domain::domains::webhooks::delivery::{DeliveryAttempt, WebhookDeliveryStatus};
use ianua_domain::domains::webhooks::signing::SignedDelivery;
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    DeliveryOutcome, EventType, FailureLimit, FailureOutcome, PublicHttpsUrl, Seconds,
    WebhookDeliveryId, WebhookMessageId, WebhookSubscriptionId,
};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::shared::PublishedEvent;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a webhook subscription listing can be ordered by.
    pub enum WebhookSubscriptionSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by delivery status.
        Status => "status",
        /// Order by delivery URL.
        Url => "url",
    }
    default = CreatedAt;
    default direction = Desc;
}

define_sort_field! {
    /// Field a delivery-attempt listing can be ordered by.
    pub enum DeliveryAttemptSortField {
        /// Order by when the attempt was made.
        AttemptedAt => "attempted_at",
        /// Order by delivery outcome.
        Status => "status",
        /// Order by retry attempt number.
        AttemptNumber => "attempt_number",
    }
    default = AttemptedAt;
    default direction = Desc;
}

impl SortKeys<WebhookSubscriptionSortField> for WebhookSubscription<ResolvedTenant> {
    fn sort_key(&self, field: WebhookSubscriptionSortField) -> SortKey {
        match field {
            WebhookSubscriptionSortField::CreatedAt => self.created_at().into(),
            WebhookSubscriptionSortField::UpdatedAt => self.updated_at().into(),
            WebhookSubscriptionSortField::Status => subscription_status_word(self.status()).into(),
            WebhookSubscriptionSortField::Url => self.url().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word a subscription's status sorts by, as it is stored.
fn subscription_status_word(status: WebhookSubscriptionStatus) -> &'static str {
    match status {
        WebhookSubscriptionStatus::Active => "active",
        WebhookSubscriptionStatus::Paused => "paused",
        WebhookSubscriptionStatus::Disabled => "disabled",
    }
}

impl SortKeys<DeliveryAttemptSortField> for DeliveryAttempt {
    fn sort_key(&self, field: DeliveryAttemptSortField) -> SortKey {
        match field {
            DeliveryAttemptSortField::AttemptedAt => self.attempted_at.into(),
            DeliveryAttemptSortField::Status => delivery_status_word(self.status()).into(),
            DeliveryAttemptSortField::AttemptNumber => u32::from(self.attempt_number).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id.as_uuid().into()
    }
}

/// The word a delivery's outcome sorts by, as it is stored.
fn delivery_status_word(status: WebhookDeliveryStatus) -> &'static str {
    match status {
        WebhookDeliveryStatus::Success => "success",
        WebhookDeliveryStatus::Failed => "failed",
        WebhookDeliveryStatus::Timeout => "timeout",
        WebhookDeliveryStatus::Unreachable => "unreachable",
    }
}

/// Dyn-safe port for persisting and retrieving webhook subscriptions
/// and delivery attempts.
#[async_trait]
pub trait WebhookStore: Send + Sync + TenantScoped {
    /// Finds a subscription by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &WebhookSubscriptionId,
    ) -> Result<Option<WebhookSubscription<ResolvedTenant>>, DomainError>;

    /// Lists subscriptions for the tenant with optional status filter,
    /// ordering, and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<WebhookSubscriptionStatus>,
        sort: &SortOrder<WebhookSubscriptionSortField>,
        page: &PageRequest,
    ) -> Result<Page<WebhookSubscription<ResolvedTenant>>, DomainError>;

    /// The tenant's active subscriptions that list `event_type`, each an
    /// endpoint the event is sent to. A tenant holds no more webhooks than
    /// its plan allows, so the list is short.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_receiving(
        &self,
        tenant_id: &ScopedTenant,
        event_type: EventType,
    ) -> Result<Vec<WebhookSubscription<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated subscription.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &WebhookSubscription<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a subscription and its delivery history.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &WebhookSubscriptionId,
    ) -> Result<(), DomainError>;

    /// Lists delivery attempts for a subscription with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_delivery_attempts(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
        sort: &SortOrder<DeliveryAttemptSortField>,
        page: &PageRequest,
    ) -> Result<Page<DeliveryAttempt>, DomainError>;

    /// Keeps `attempt` and counts it on its subscription's failure streak,
    /// in one atomic statement. `None` when the subscription is gone.
    ///
    /// Two deliveries to one endpoint at once each count, since neither
    /// writes a streak it read earlier. Only the streak and what goes with
    /// it change, so a pause or an edit made meanwhile is kept. The rule is
    /// the domain's, from `WebhookSubscription::record_success` and
    /// `record_failure`:
    ///
    /// - A success sets the streak to zero and the last delivery time to
    ///   now: [`StreakChange::Delivered`].
    /// - A failure adds one to the streak. When the streak then reaches
    ///   `disable_after` and the subscription was active, it is disabled:
    ///   [`FailureOutcome::Disabled`]. Otherwise only the count changes:
    ///   [`FailureOutcome::Counted`].
    ///
    /// Either way the subscription's update time is now. Exactly one
    /// failure can disable a subscription, so the switch-off is reported
    /// once.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, or when
    /// the stored subscription breaks a rule it keeps.
    async fn record_delivery(
        &self,
        tenant_id: &ScopedTenant,
        attempt: &DeliveryAttempt,
        disable_after: FailureLimit,
    ) -> Result<Option<RecordedDelivery>, DomainError>;

    /// Keeps `attempt` in its subscription's delivery history without
    /// counting it on the failure streak: a test send the owner asked for.
    /// The streak, the last delivery time and the status stay as they are.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn keep_uncounted_attempt(
        &self,
        tenant_id: &ScopedTenant,
        attempt: &DeliveryAttempt,
    ) -> Result<(), DomainError>;

    /// Finds the delivery attempt `id` of subscription `subscription_id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, or when
    /// the stored attempt breaks a rule it keeps.
    async fn find_delivery_attempt(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
        id: &WebhookDeliveryId,
    ) -> Result<Option<DeliveryAttempt>, DomainError>;

    /// Keeps `message`, the body sent to one subscription, so it can be
    /// sent again later. Keeping a message already kept under its id
    /// changes nothing, so every try of one message may call it.
    ///
    /// Messages are part of the subscription's delivery history:
    /// [`delete`](Self::delete) removes them with it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn keep_message(
        &self,
        tenant_id: &ScopedTenant,
        message: &WebhookMessage,
    ) -> Result<(), DomainError>;

    /// Finds the message `id` kept for subscription `subscription_id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_message(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
        id: &WebhookMessageId,
    ) -> Result<Option<WebhookMessage>, DomainError>;
}

/// One event as sent to one subscription: the body every try of it carries,
/// under an id the receiver drops a repeat of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookMessage {
    /// The id every try of the message carries.
    pub id: WebhookMessageId,
    /// The subscription it is sent to.
    pub subscription_id: WebhookSubscriptionId,
    /// The event it carries.
    pub event_type: EventType,
    /// The serialized body.
    pub payload: Vec<u8>,
}

/// What one delivery did to its subscription's failure streak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreakChange {
    /// It was delivered, and the streak starts again.
    Delivered,
    /// It failed, and was counted or switched the endpoint off.
    Failed(FailureOutcome),
}

/// A delivery as the store counted it.
#[derive(Debug)]
pub struct RecordedDelivery {
    /// The subscription as it stands once the delivery was counted.
    pub subscription: WebhookSubscription<ResolvedTenant>,
    /// What the delivery did to its failure streak.
    pub change: StreakChange,
}

/// Outcome of an outbound webhook HTTP delivery.
#[derive(Debug, Clone, Copy)]
pub struct WebhookDeliveryOutcome {
    /// How the attempt ended, with the code the upstream answered with.
    pub outcome: DeliveryOutcome,
    /// Round-trip duration in milliseconds.
    pub duration_ms: u32,
}

/// One try at sending a message, with everything the deliverer signs it
/// with.
///
/// No `Debug`: it carries the unsealed signing secrets.
pub struct OutboundDelivery<'a> {
    /// Where to send it.
    pub url: &'a PublicHttpsUrl,
    /// The message id and send time the signatures cover.
    pub signed: SignedDelivery,
    /// The body.
    pub payload: &'a [u8],
    /// Every secret the try is signed with, unsealed: the current one
    /// first, then the one before a rotation while its overlap lasts.
    pub secrets: &'a [Secret],
    /// The retry policy's limit for one try.
    pub timeout: Seconds,
}

/// Dyn-safe port for delivering a signed payload to a webhook endpoint.
///
/// The implementation re-resolves the host and rejects private/loopback/
/// link-local addresses before connecting (defeating DNS rebinding past
/// the registration-time check), signs the body as Standard Webhooks lays
/// out, and must give up once the timeout it is given has passed, so a
/// hung endpoint holds no worker.
#[async_trait]
pub trait WebhookDeliverer: Send + Sync {
    /// Sends `delivery`'s payload to its URL with the three headers
    /// [`SignedDelivery`] names: the message id, the send time in seconds,
    /// and one `v1,<base64 HMAC-SHA256>` entry per secret, separated by
    /// spaces, each computed over [`SignedDelivery::signed_content`].
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the URL resolves to a blocked
    /// address. Transport failures, a timeout among them, are reported in
    /// the returned [`WebhookDeliveryOutcome`], not as `Err`.
    async fn deliver(
        &self,
        delivery: OutboundDelivery<'_>,
    ) -> Result<WebhookDeliveryOutcome, DomainError>;
}

/// Dyn-safe port letting a person resend a delivery to, or test, one
/// webhook only now and then.
///
/// Each resend and each test makes the platform sign a message and call the
/// subscription's endpoint, so without a bound one admin could turn the
/// platform into a source of requests at the endpoint, at their own pace.
/// The adapter counts per subscription in a short window, held in the
/// process like the API rate limit.
#[async_trait]
pub trait WebhookSendThrottle: Send + Sync + TenantScoped {
    /// Whether the subscription `subscription_id` may be sent a resend or a
    /// test now. Admitting counts as the window's send.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the allowance cannot be read.
    async fn admit(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for generating webhook signing secrets.
#[async_trait]
pub trait WebhookSecretGenerator: Send + Sync {
    /// Generates a new random signing secret.
    ///
    /// The raw secret is shown to the user once at creation or rotation.
    /// The caller seals it before it is stored on the subscription, because
    /// signing a delivery needs the secret itself, not a hash of it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate(&self) -> Result<Secret, DomainError>;
}

/// Dyn-safe port writing the body an event is sent to webhooks as.
///
/// The body is the event's wire form, the same for every subscription:
/// its type, when it happened, its tenant and its details, never a secret
/// the details hold.
pub trait WebhookBodies: Send + Sync {
    /// The body `event` is sent as.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the event cannot be
    /// written out.
    fn body(&self, event: &PublishedEvent) -> Result<Vec<u8>, DomainError>;
}
