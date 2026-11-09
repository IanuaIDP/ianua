//! Workflows started by an integration's service: registering at the
//! service, reading and checking what it sends, finding the registration
//! a delivery is for, and remembering deliveries already started.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::triggers::channel::{
    AccountChannel, ChannelCursor, ChannelSetup, HistoryPlace,
};
use ianua_domain::domains::workflows::triggers::subscription::{
    DeliveryCheck, Lapse, RemoteRegistration, ServiceSubscription,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    AccountChannelId, IntegrationAccountId, SealedSecret, ServiceSubscriptionId, TenantId,
    WorkflowId,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::authentication::SealedAt;
use crate::ports::workflows::Renewal;
use crate::tenancy::ScopedTenant;

/// How a registration's events reach the platform: at an address of its
/// own, or, for a service that sends every event of the platform's app to
/// one address, under a key the event names, such as Slack's workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routing {
    /// At the registration's own address.
    OwnAddress,
    /// At the integration's one address, under this key.
    Keyed(RouteKey),
}

/// The key a service's events name a registration by when they all reach
/// one address, such as a Slack workspace's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteKey(String);

impl RouteKey {
    /// The key `written`, as the integration reads it from its events.
    #[must_use]
    pub fn new(written: String) -> Self {
        Self(written)
    }

    /// The key the workflows waiting on channel `id` are found by.
    #[must_use]
    pub fn of_channel(id: &AccountChannelId) -> Self {
        Self(id.as_uuid().to_string())
    }

    /// The key as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a service answered a registration with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// Its name for the registration.
    pub remote: RemoteRegistration,
    /// When it lapses unless renewed.
    pub lapses: Lapse,
    /// How its events reach the platform.
    pub routing: Routing,
    /// The secret the service chose and showed once in its answer, sealed
    /// where the registration's secret is kept; `None` when it signs with
    /// the one the platform made.
    pub given_secret: Option<SealedSecret>,
}

/// What a service answered about an account's channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRegistered {
    /// Its name for the registration.
    pub remote: RemoteRegistration,
    /// When it lapses unless renewed.
    pub lapses: Lapse,
    /// Where its history can be read from, for a service that has one.
    pub history: HistoryPlace,
}

/// What the platform answers a check that it holds an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReply {
    /// The body answered with.
    pub body: CheckBody,
    /// A header answered with, as Asana asks its secret echoed.
    pub header: Option<(&'static str, String)>,
}

/// The body of an answer to a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckBody {
    /// None.
    Empty,
    /// These bytes, as plain text, as Microsoft Graph asks.
    PlainText(Vec<u8>),
}

/// Whether a request to an address is a service checking it.
#[derive(Debug)]
pub enum Greeting {
    /// It is an ordinary delivery.
    NotOne,
    /// It asks the platform to prove it holds the address.
    Prove(CheckReply),
    /// It hands over the secret its deliveries will be proven with.
    HandsSecret {
        /// The secret, kept only while the address is waiting for one.
        secret: Secret,
        /// The answer once it is kept.
        reply: CheckReply,
    },
}

/// What a service's history held past a delivery that only announced it.
#[derive(Debug)]
pub enum PulledEvents {
    /// The delivery did not prove it came from the service.
    Forged,
    /// These events, read from the service, each to read as a delivery.
    Fetched {
        /// Each event's body.
        deliveries: Vec<Vec<u8>>,
        /// Where the history was read up to.
        cursor: ChannelCursor,
    },
}

/// Why a registration could not be made, renewed or removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationFailure {
    /// The service refused it, for this reason in the integration's words,
    /// such as the account lacking the right to add webhooks.
    Refused(String),
    /// The service could not be reached or was busy; trying again later
    /// may work.
    Unreachable,
}

/// What a registration is made with, each sealed beside where it is kept:
/// the account's credential the service is reached through, and the
/// registration's secret the service signs what it sends with.
pub struct RegistrationKeys {
    /// The trigger's account's credential.
    pub credential: SealedAt,
    /// The registration's secret.
    pub secret: SealedAt,
}

/// What a service answered a call about a registration, and whether the
/// account's credential changed on the way. A service whose grants rotate
/// may replace it even on a call that then fails, so the renewal comes
/// with either answer and is kept whatever the call came to.
#[derive(Debug)]
pub struct RegistrarAnswer<T> {
    /// How the call went.
    pub result: Result<T, RegistrationFailure>,
    /// The account's credential to keep from now on, when it changed.
    pub renewal: Renewal,
}

/// Dyn-safe port saying how each installed service's channels work, read
/// from what is installed and the platform's own addresses, the same for
/// every tenant.
pub trait ServiceChannelSetup: Send + Sync {
    /// How `integration`'s account channel gets ready; `None` for a service
    /// that takes one registration per workflow.
    fn account_setup(&self, integration: &IntegrationKey) -> Option<ChannelSetup>;

    /// The address channel `id` is given.
    fn channel_address(&self, id: &AccountChannelId) -> String;

    /// Whether `integration`'s deliveries only announce a change, so what
    /// changed is read from its history.
    fn pulls_history(&self, integration: &IntegrationKey) -> bool;
}

/// Dyn-safe port registering workflows at integrations' services, through
/// the account each trigger names.
///
/// The adapter opens the keys itself, sends the service the platform's
/// address for the registration, and bounds every call with a timeout.
#[async_trait]
pub trait ServiceRegistrar: Send + Sync + TenantScoped {
    /// Registers `subscription` at its service with `keys`, asking the
    /// service to sign what it sends with the registration's secret.
    async fn register(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<Registered>;

    /// Renews `subscription`, live under the service's name for it, before
    /// it lapses.
    async fn renew(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<Registered>;

    /// Removes `subscription` from its service.
    async fn unregister(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<()>;

    /// Registers `channel` at its service with `keys`.
    async fn open_channel(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<ChannelRegistered>;

    /// Renews `channel` before it lapses.
    async fn renew_channel(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<ChannelRegistered>;

    /// Takes `channel` off its service.
    async fn close_channel(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<()>;

    /// What `received` announces, proven and read from the service past
    /// `channel`'s cursor, for a service whose deliveries only announce a
    /// change.
    async fn pull(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
        keys: &RegistrationKeys,
        received: &ReceivedEvent<'_>,
    ) -> RegistrarAnswer<PulledEvents>;
}

/// One request a service sent the platform: its headers and its body, as
/// they arrived. Nothing in it is trusted until the integration checked
/// its signature.
pub struct ReceivedEvent<'a> {
    /// The address it was sent to, as the service signed it.
    pub address: &'a str,
    /// Its headers, names in lowercase.
    pub headers: &'a [(String, String)],
    /// Its body, as sent.
    pub body: &'a [u8],
}

/// The service's own id for one delivery, which a retried delivery keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryId(String);

impl DeliveryId {
    /// The id `written`, as the integration read it from the delivery.
    #[must_use]
    pub fn new(written: String) -> Self {
        Self(written)
    }

    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a delivery asks of a registration, once its signature is checked.
#[derive(Debug, Clone, PartialEq)]
pub enum Reading {
    /// It is the event the registration starts on: the version in service
    /// starts with these values.
    Start {
        /// The service's id for the delivery.
        delivery: DeliveryId,
        /// The event's values, as the workflow receives them.
        input: FlowData,
        /// The most sensitive data in them.
        exposure: DataClassLevel,
    },
    /// It asks the platform to prove it holds the address, as Slack's
    /// challenge does; the answer is this body.
    Answer(Vec<u8>),
    /// It is something else the service sends, such as a ping, or an event
    /// the trigger's filters leave out; nothing starts.
    Skip,
}

/// A delivery as the integration read it.
#[derive(Debug, PartialEq)]
pub struct EventReading {
    /// Whether the service's signature checked out.
    pub check: DeliveryCheck,
    /// What it asks, read only when it checked out.
    pub reading: Reading,
}

/// Dyn-safe port reading what integrations' services send, checking each
/// delivery's signature before anything else is read from it.
pub trait ServiceEventReader: Send + Sync {
    /// What `received`, sent for `subscription`, signed with `secret`, says.
    /// A delivery whose signature does not check out is
    /// [`DeliveryCheck::Forged`] with [`Reading::Skip`], and nothing else of
    /// it is read.
    fn read(
        &self,
        subscription: &ServiceSubscription<ResolvedTenant>,
        secret: &Secret,
        received: &ReceivedEvent<'_>,
    ) -> EventReading;

    /// Where a delivery to `integration`'s one address goes, its signature
    /// checked first with the platform's app secret for that service.
    fn route(&self, integration: &IntegrationKey, received: &ReceivedEvent<'_>) -> Route;

    /// Whether `received` is `integration`'s service checking the address.
    /// An integration that offers no check makes nothing of it.
    fn greet(&self, integration: &IntegrationKey, received: &ReceivedEvent<'_>) -> Greeting;
}

/// Where a delivery to an integration's one address goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// To the registrations its events name by this key.
    Keyed(RouteKey),
    /// To the platform's app itself, which answers with this body, as Slack
    /// asks it to prove it holds the address.
    App(Vec<u8>),
    /// Nowhere: unsigned, signed with something else, or not something the
    /// platform reads.
    Refused,
}

/// Where a registration is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionAt {
    /// The tenant whose workflow it starts.
    pub tenant_id: TenantId,
    /// The registration.
    pub subscription_id: ServiceSubscriptionId,
}

/// Dyn-safe port keeping workflows' registrations at services.
#[async_trait]
pub trait ServiceSubscriptionStore: Send + Sync + TenantScoped {
    /// The tenant's registration `id`, if it is kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceSubscriptionId,
    ) -> Result<Option<ServiceSubscription<ResolvedTenant>>, DomainError>;

    /// The registrations of `workflow_id` not yet removed, of any version.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read.
    async fn list_for_workflow(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<Vec<ServiceSubscription<ResolvedTenant>>, DomainError>;

    /// Keeps a new `subscription`, and how its events reach the platform.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be written.
    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        routing: &Routing,
    ) -> Result<(), DomainError>;

    /// Keeps a change to `subscription`, already kept. How its events reach
    /// the platform stays as it was kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Moves `subscription`, kept waiting while the service was asked, to
    /// what the service answered, and how its events reach the platform.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be written, or
    /// it is no longer waiting, as a sweep gave up on it.
    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        routing: &Routing,
    ) -> Result<(), DomainError>;

    /// Replaces the secret of the waiting registration `id` with `secret`,
    /// the one its service chose. `true` the first time; the first secret
    /// wins, so one sent later replaces nothing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be written.
    async fn take_service_secret(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceSubscriptionId,
        secret: &SealedSecret,
    ) -> Result<bool, DomainError>;

    /// Forgets the registration `id` if it is still waiting: the service
    /// refused it, or the publish it was for ended.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be removed.
    async fn forget_waiting(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceSubscriptionId,
    ) -> Result<(), DomainError>;
}

/// Where an account's channel is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelAt {
    /// The tenant whose account it is.
    pub tenant_id: TenantId,
    /// Which of the tenant's channels, as the address a service sends to names it.
    pub channel_id: AccountChannelId,
}

/// Dyn-safe port keeping accounts' channels.
#[async_trait]
pub trait AccountChannelStore: Send + Sync + TenantScoped {
    /// The tenant's channel `id`, if it is kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccountChannelId,
    ) -> Result<Option<AccountChannel<ResolvedTenant>>, DomainError>;

    /// The channel of `account`, if it has one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read.
    async fn of_account(
        &self,
        tenant_id: &ScopedTenant,
        account: &IntegrationAccountId,
    ) -> Result<Option<AccountChannel<ResolvedTenant>>, DomainError>;

    /// Keeps a new `channel`, unless its account already has one. `true`
    /// when it was kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be written.
    async fn insert_if_absent(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
    ) -> Result<bool, DomainError>;

    /// Keeps a change to `channel`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Forgets channel `id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be removed.
    async fn remove(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccountChannelId,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port reading accounts' channels across every tenant: the one a
/// delivery's address names, and the ones a sweep looks at.
#[async_trait]
pub trait ChannelDirectory: Send + Sync {
    /// Where channel `id` is kept, if it is.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read.
    async fn find(&self, id: &AccountChannelId) -> Result<Option<ChannelAt>, DomainError>;

    /// Up to `limit` live channels that lapse before `before`, the soonest
    /// first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read.
    async fn due(&self, before: OffsetDateTime, limit: u32) -> Result<Vec<ChannelAt>, DomainError>;

    /// Up to `limit` channels the platform registered, unchanged since
    /// `before`, that no workflow waits on.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read.
    async fn idle(&self, before: OffsetDateTime, limit: u32)
    -> Result<Vec<ChannelAt>, DomainError>;
}

/// Dyn-safe port reading registrations across every tenant: the one a
/// delivery's address names, the ones a keyed delivery is for, and the
/// ones about to lapse.
#[async_trait]
pub trait SubscriptionDirectory: Send + Sync {
    /// Where registration `id` is kept, if it is.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read.
    async fn find(&self, id: &ServiceSubscriptionId)
    -> Result<Option<SubscriptionAt>, DomainError>;

    /// The live registrations of `integration` its events name by `key`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read.
    async fn routed(
        &self,
        integration: &IntegrationKey,
        key: &RouteKey,
    ) -> Result<Vec<SubscriptionAt>, DomainError>;

    /// Up to `limit` of the live registrations that lapse before `before`,
    /// the soonest to lapse first. A sweep handles what it is given and
    /// asks again next round; a renewed or lapsed one leaves the set.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read.
    async fn due(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<SubscriptionAt>, DomainError>;

    /// Up to `limit` of the registrations still waiting on a service since
    /// before `before`: a publish that never came back for them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read.
    async fn stale_waiting(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<SubscriptionAt>, DomainError>;
}

/// Dyn-safe port forgetting, across every tenant, the deliveries noted
/// long enough ago that no service would send them again.
#[async_trait]
pub trait DeliveryRetention: Send + Sync {
    /// Forgets up to `limit` deliveries noted before `before`, and how
    /// many it forgot.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be removed.
    async fn forget_before(&self, before: OffsetDateTime, limit: u32) -> Result<u64, DomainError>;
}

/// Dyn-safe port remembering which deliveries started a run, so a delivery
/// the service sends again starts nothing twice.
#[async_trait]
pub trait DeliveryLedger: Send + Sync + TenantScoped {
    /// Notes `delivery` for `subscription`. `true` the first time it is
    /// noted, `false` after.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be noted.
    async fn first_time(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscriptionId,
        delivery: &DeliveryId,
    ) -> Result<bool, DomainError>;
}
