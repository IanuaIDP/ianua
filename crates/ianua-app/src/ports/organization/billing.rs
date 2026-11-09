//! What an organization pays for: its subscription, the usage its plan is
//! checked against, and the payment provider that charges it.

use async_trait::async_trait;
use ianua_domain::domains::organization::billing::payment::{PaymentEventId, PaymentReference};
use ianua_domain::domains::organization::billing::subscription::OrgSubscription;
use ianua_domain::domains::organization::billing::usage::PlanUsage;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, HttpsUrl, OrganizationId};
use time::OffsetDateTime;

/// Dyn-safe port for persisting and retrieving organizations'
/// subscriptions, one per organization.
#[async_trait]
pub trait OrgSubscriptionStore: Send + Sync {
    /// The subscription of `organization_id`, if it has one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored row is refused as corrupt.
    async fn find_by_organization(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OrgSubscription>, DomainError>;

    /// Every subscription still trialing whose trial ended at or before
    /// `by`, across every organization, for the sweep that ends them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_trials_ended(
        &self,
        by: OffsetDateTime,
    ) -> Result<Vec<OrgSubscription>, DomainError>;

    /// Every subscription a payment is owed on, across every organization,
    /// for the sweep that suspends the ones overdue too long.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_past_due(&self) -> Result<Vec<OrgSubscription>, DomainError>;

    /// Saves a new or changed subscription.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, subscription: &OrgSubscription) -> Result<(), DomainError>;
}

/// Dyn-safe port counting what an organization uses now, for checking a
/// plan against it.
///
/// The adapter counts fresh, never from a cache: the registered users
/// across every tenant and the tenants themselves for the whole
/// organization; for every other count the most any one tenant of the
/// organization holds (routes, DNS record sets, domains, API keys, OAuth
/// clients, roles, groups, webhooks, federation connections, consumers,
/// services, stream routes, egress policies, resource types, user
/// attributes, agents, agent tools, model providers, workflows); the
/// longest audit retention any tenant keeps; and every isolation level a
/// tenant is placed on.
#[async_trait]
pub trait PlanUsageCounter: Send + Sync {
    /// What `organization_id` uses now.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a count cannot be read.
    async fn usage(&self, organization_id: &OrganizationId) -> Result<PlanUsage, DomainError>;
}

/// What a checkout at the payment provider is opened for: an organization
/// adding or replacing the payment method it is charged through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutRequest {
    /// The organization the payment method will belong to. The provider
    /// carries it back in the notice that reports the method.
    pub organization_id: OrganizationId,
    /// Where the provider sends receipts: the address of the member who
    /// opened the checkout.
    pub billing_email: Email,
}

/// The signature header a payment provider sent with a notice, checked by
/// the adapter against the notice's body before anything in it is read.
#[derive(Clone, PartialEq, Eq)]
pub struct PaymentSignature(String);

impl PaymentSignature {
    /// The signature header as the provider sent it.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The header as sent, for the adapter to verify.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PaymentSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PaymentSignature(<redacted>)")
    }
}

/// A notice a payment provider posted, exactly as it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentWebhook {
    /// The body, byte for byte: the signature covers these bytes.
    pub payload: Vec<u8>,
    /// The signature the provider sent with it.
    pub signature: PaymentSignature,
}

/// What a verified notice from the payment provider reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentNotice {
    /// A checkout finished, and the provider holds this payment method for
    /// the organization from now on.
    MethodRecorded {
        /// The organization the checkout was opened for.
        organization_id: OrganizationId,
        /// The provider's reference to the method.
        reference: PaymentReference,
    },
    /// A charge to the organization failed.
    PaymentFailed {
        /// The organization charged.
        organization_id: OrganizationId,
    },
    /// What the organization owed is paid.
    PaymentSettled {
        /// The organization that paid.
        organization_id: OrganizationId,
    },
    /// A notice the platform does not act on, acknowledged so the provider
    /// stops sending it.
    Ignored,
}

/// One event of the payment provider, as its notice names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentEvent {
    /// The provider's id for the event, the same on every delivery of it.
    pub id: PaymentEventId,
    /// When the provider created the event. The provider delivers events
    /// in no set order, so this is what orders them.
    pub created_at: OffsetDateTime,
}

/// A verified notice: the event it is, and what it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedNotice {
    /// The event the notice delivers.
    pub event: PaymentEvent,
    /// What the event reports.
    pub report: PaymentNotice,
}

/// What a payment event changes. Each is kept in order apart, so a late
/// report of one kind is weighed only against reports of the same kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStream {
    /// The payment method on file.
    Method,
    /// Whether a payment is owed: a failed charge, or a settlement.
    Payment,
}

/// Whether an event is taken for the first time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventReceipt {
    /// It was never taken before, and is acted on now.
    First,
    /// It was taken before: a repeated delivery, acknowledged and not acted
    /// on again.
    Repeated,
}

/// Whether an event is newer than every event of its kind applied before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOrder {
    /// No newer event of its kind was applied, so it is applied.
    Newest,
    /// A newer event of its kind was applied already, so it changes
    /// nothing.
    Stale,
}

/// Dyn-safe port keeping which payment provider events were acted on, so a
/// notice delivered twice is acted on once, and a late one cannot undo a
/// newer one: a failed charge reported after the payment that settled it
/// leaves the organization paid up.
///
/// Both calls write within the unit the notice is handled in, so a notice
/// whose change is rolled back is taken as new on its next delivery. Two
/// deliveries of one event at once are taken one after the other.
#[async_trait]
pub trait PaymentEventLedger: Send + Sync {
    /// Takes `event`, about `organization_id`, answering
    /// [`EventReceipt::Repeated`] when it was taken before. Events taken
    /// long ago, past the days a provider retries, are let go.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be written.
    async fn receive(
        &self,
        organization_id: &OrganizationId,
        event: &PaymentEvent,
    ) -> Result<EventReceipt, DomainError>;

    /// Moves the newest event of `stream` applied to `organization_id` on
    /// to `event`, answering [`EventOrder::Stale`] and moving nothing when
    /// one created later was applied. An event created in the same second
    /// as the newest is applied: the provider counts time in seconds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be written.
    async fn advance(
        &self,
        organization_id: &OrganizationId,
        stream: PaymentStream,
        event: &PaymentEvent,
    ) -> Result<EventOrder, DomainError>;
}

/// Dyn-safe port to the payment provider that holds organizations' payment
/// methods and charges them.
///
/// Every call goes out over the network, so the adapter times each one out
/// and reports the timeout as `DomainError::Infrastructure`. The domain
/// never sees a card number: the provider keeps it and hands back a
/// reference.
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// Opens a checkout where a member adds the payment method
    /// `request.organization_id` is charged through, and returns the page
    /// to send them to.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when the deployment has no payment provider.
    /// - `DomainError::Infrastructure` when the provider cannot be reached,
    ///   answers with an error, or does not answer in time.
    async fn start_checkout(&self, request: &CheckoutRequest) -> Result<HttpsUrl, DomainError>;

    /// Verifies `webhook`'s signature with the provider's signing secret,
    /// refuses one too old to be fresh, and reads what it reports. Nothing
    /// is read from a notice whose signature does not verify.
    ///
    /// # Errors
    ///
    /// - `DomainError::Unauthorized` when the signature does not verify or
    ///   the notice is too old.
    /// - `DomainError::Validation` when a verified notice cannot be read,
    ///   names no event id or creation time, or names no organization the
    ///   platform made.
    fn read_notice(&self, webhook: &PaymentWebhook) -> Result<ReceivedNotice, DomainError>;
}
