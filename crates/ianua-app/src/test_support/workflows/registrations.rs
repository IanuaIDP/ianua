//! Fakes for workflows' registrations at services: the registrations kept,
//! the service registering them, the reader checking what services send,
//! the directory across tenants, and the deliveries already started.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::triggers::channel::{
    AccountChannel, AccountChannelRow, ChannelSetup, ChannelStatus, HistoryPlace,
};
use ianua_domain::domains::workflows::triggers::subscription::{
    DeliveryCheck, Lapse, Registration, RemoteRegistration, ServiceSubscription,
    ServiceSubscriptionRow, SubscriptionStatus,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    AccountChannelId, IntegrationAccountId, SealedSecret, ServiceSubscriptionId, TenantId,
    WorkflowId,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::workflows::{
    AccountChannelStore, ChannelAt, ChannelDirectory, ChannelRegistered, DeliveryId,
    DeliveryLedger, DeliveryRetention, EventReading, Greeting, PulledEvents, Reading,
    ReceivedEvent, Registered, RegistrarAnswer, RegistrationFailure, RegistrationKeys, Renewal,
    Route, RouteKey, Routing, ServiceChannelSetup, ServiceEventReader, ServiceRegistrar,
    ServiceSubscriptionStore, SubscriptionAt, SubscriptionDirectory,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// `subscription` as it reads back from storage.
fn subscription_copy(
    subscription: &ServiceSubscription<ResolvedTenant>,
) -> ServiceSubscription<ResolvedTenant> {
    subscription_holding(subscription, subscription.secret())
}

/// `subscription` as it reads back from storage, holding `secret`.
fn subscription_holding(
    subscription: &ServiceSubscription<ResolvedTenant>,
    secret: &SealedSecret,
) -> ServiceSubscription<ResolvedTenant> {
    ServiceSubscription::reconstitute(ServiceSubscriptionRow {
        id: *subscription.id(),
        workflow_id: *subscription.workflow_id(),
        version: subscription.version(),
        trigger: subscription.trigger().clone(),
        secret: secret.clone(),
        status: subscription.status(),
        registration: subscription.registration().clone(),
        label: subscription.label().clone(),
        created_at: Aggregate::created_at(subscription),
        updated_at: Aggregate::updated_at(subscription),
    })
    .expect("a kept registration reads back as itself")
}

/// Whether the renewal sweep looks at `subscription` for `before`: live
/// and lapsing before then.
fn is_due(subscription: &ServiceSubscription<ResolvedTenant>, before: OffsetDateTime) -> bool {
    match (subscription.status(), subscription.registration()) {
        (
            SubscriptionStatus::Live,
            Registration::Taken {
                lapses: Lapse::At(at),
                ..
            },
        ) => *at < before,
        _ => false,
    }
}

/// One kept registration, its tenant and how its events arrive.
struct Kept {
    tenant: TenantId,
    subscription: ServiceSubscription<ResolvedTenant>,
    routing: Routing,
    secret_given: bool,
}

/// In-memory registrations, which also answers as the directory across
/// tenants.
#[derive(Default)]
pub struct FakeServiceSubscriptionStore {
    kept: Mutex<Vec<Kept>>,
}

impl TenantScoped for FakeServiceSubscriptionStore {}

impl FakeServiceSubscriptionStore {
    /// A store holding no registration.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Every registration kept for `tenant`, as stored.
    #[must_use]
    pub fn all(&self, tenant: TenantId) -> Vec<ServiceSubscription<ResolvedTenant>> {
        self.kept
            .lock()
            .unwrap()
            .iter()
            .filter(|kept| kept.tenant == tenant)
            .map(|kept| subscription_copy(&kept.subscription))
            .collect()
    }
}

#[async_trait]
impl ServiceSubscriptionStore for FakeServiceSubscriptionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceSubscriptionId,
    ) -> Result<Option<ServiceSubscription<ResolvedTenant>>, DomainError> {
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .find(|kept| kept.tenant == **tenant_id && kept.subscription.id() == id)
            .map(|kept| subscription_copy(&kept.subscription)))
    }

    async fn list_for_workflow(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<Vec<ServiceSubscription<ResolvedTenant>>, DomainError> {
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .filter(|kept| {
                kept.tenant == **tenant_id && kept.subscription.workflow_id() == workflow_id
            })
            .map(|kept| subscription_copy(&kept.subscription))
            .collect())
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        routing: &Routing,
    ) -> Result<(), DomainError> {
        self.kept.lock().unwrap().push(Kept {
            tenant: **tenant_id,
            subscription: subscription_copy(subscription),
            routing: routing.clone(),
            secret_given: false,
        });
        Ok(())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let Some(held) = kept
            .iter_mut()
            .find(|kept| kept.tenant == **tenant_id && kept.subscription.id() == subscription.id())
        else {
            return Err(DomainError::infra_msg("no such registration is kept"));
        };
        held.subscription = subscription_copy(subscription);
        Ok(())
    }

    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        routing: &Routing,
    ) -> Result<(), DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let Some(held) = kept.iter_mut().find(|kept| {
            kept.tenant == **tenant_id
                && kept.subscription.id() == subscription.id()
                && kept.subscription.status() == SubscriptionStatus::Registering
        }) else {
            return Err(DomainError::infra_msg("no such registration is waiting"));
        };
        held.subscription = subscription_holding(subscription, held.subscription.secret());
        held.routing = routing.clone();
        Ok(())
    }

    async fn take_service_secret(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceSubscriptionId,
        secret: &SealedSecret,
    ) -> Result<bool, DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let held = kept.iter_mut().find(|kept| {
            kept.tenant == **tenant_id
                && kept.subscription.id() == id
                && kept.subscription.status() == SubscriptionStatus::Registering
                && !kept.secret_given
        });
        let Some(held) = held else {
            return Ok(false);
        };
        held.subscription = subscription_holding(&held.subscription, secret);
        held.secret_given = true;
        Ok(true)
    }

    async fn forget_waiting(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceSubscriptionId,
    ) -> Result<(), DomainError> {
        self.kept.lock().unwrap().retain(|kept| {
            kept.tenant != **tenant_id
                || kept.subscription.id() != id
                || kept.subscription.status() != SubscriptionStatus::Registering
        });
        Ok(())
    }
}

#[async_trait]
impl SubscriptionDirectory for FakeServiceSubscriptionStore {
    async fn find(
        &self,
        id: &ServiceSubscriptionId,
    ) -> Result<Option<SubscriptionAt>, DomainError> {
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .find(|kept| kept.subscription.id() == id)
            .map(|kept| SubscriptionAt {
                tenant_id: kept.tenant,
                subscription_id: *id,
            }))
    }

    async fn routed(
        &self,
        integration: &IntegrationKey,
        key: &RouteKey,
    ) -> Result<Vec<SubscriptionAt>, DomainError> {
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .filter(|kept| {
                kept.subscription.integration() == integration
                    && kept.routing == Routing::Keyed(key.clone())
            })
            .map(|kept| SubscriptionAt {
                tenant_id: kept.tenant,
                subscription_id: *kept.subscription.id(),
            })
            .collect())
    }

    async fn due(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<SubscriptionAt>, DomainError> {
        let most = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .filter(|kept| is_due(&kept.subscription, before))
            .take(most)
            .map(|kept| SubscriptionAt {
                tenant_id: kept.tenant,
                subscription_id: *kept.subscription.id(),
            })
            .collect())
    }

    async fn stale_waiting(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<SubscriptionAt>, DomainError> {
        let most = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .filter(|kept| {
                kept.subscription.status() == SubscriptionStatus::Registering
                    && Aggregate::created_at(&kept.subscription) < before
            })
            .take(most)
            .map(|kept| SubscriptionAt {
                tenant_id: kept.tenant,
                subscription_id: *kept.subscription.id(),
            })
            .collect())
    }
}

/// `channel` as it reads back from storage.
fn channel_copy(channel: &AccountChannel<ResolvedTenant>) -> AccountChannel<ResolvedTenant> {
    AccountChannel::reconstitute(AccountChannelRow {
        id: *channel.id(),
        account: channel.account(),
        integration: channel.integration().clone(),
        secret: channel.secret().clone(),
        setup: channel.setup(),
        status: channel.status(),
        registration: channel.registration().clone(),
        history: channel.history().clone(),
        created_at: Aggregate::created_at(channel),
        updated_at: Aggregate::updated_at(channel),
    })
    .expect("a kept channel reads back as itself")
}

/// In-memory channels, which also answers as the directory across tenants.
/// No workflow waits on any of them, as the idle sweep sees it.
#[derive(Default)]
pub struct FakeAccountChannelStore {
    kept: Mutex<Vec<(TenantId, AccountChannel<ResolvedTenant>)>>,
}

impl TenantScoped for FakeAccountChannelStore {}

impl FakeAccountChannelStore {
    /// A store holding no channel.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many channels it holds.
    #[must_use]
    pub fn count(&self) -> usize {
        self.kept.lock().unwrap().len()
    }
}

#[async_trait]
impl AccountChannelStore for FakeAccountChannelStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccountChannelId,
    ) -> Result<Option<AccountChannel<ResolvedTenant>>, DomainError> {
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, channel)| *tenant == **tenant_id && channel.id() == id)
            .map(|(_, channel)| channel_copy(channel)))
    }

    async fn of_account(
        &self,
        tenant_id: &ScopedTenant,
        account: &IntegrationAccountId,
    ) -> Result<Option<AccountChannel<ResolvedTenant>>, DomainError> {
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, channel)| *tenant == **tenant_id && channel.account() == *account)
            .map(|(_, channel)| channel_copy(channel)))
    }

    async fn insert_if_absent(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let held = kept
            .iter()
            .any(|(tenant, other)| *tenant == **tenant_id && other.account() == channel.account());
        if held {
            return Ok(false);
        }
        kept.push((**tenant_id, channel_copy(channel)));
        Ok(true)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let Some(held) = kept
            .iter_mut()
            .find(|(tenant, other)| *tenant == **tenant_id && other.id() == channel.id())
        else {
            return Err(DomainError::infra_msg("no such channel is kept"));
        };
        held.1 = channel_copy(channel);
        Ok(())
    }

    async fn remove(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccountChannelId,
    ) -> Result<(), DomainError> {
        self.kept
            .lock()
            .unwrap()
            .retain(|(tenant, channel)| *tenant != **tenant_id || channel.id() != id);
        Ok(())
    }
}

#[async_trait]
impl ChannelDirectory for FakeAccountChannelStore {
    async fn find(&self, id: &AccountChannelId) -> Result<Option<ChannelAt>, DomainError> {
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .find(|(_, channel)| channel.id() == id)
            .map(|(tenant, _)| ChannelAt {
                tenant_id: *tenant,
                channel_id: *id,
            }))
    }

    async fn due(&self, before: OffsetDateTime, limit: u32) -> Result<Vec<ChannelAt>, DomainError> {
        let most = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, channel)| {
                channel.status() == ChannelStatus::Live
                    && matches!(
                        channel.registration(),
                        Registration::Taken { lapses: Lapse::At(at), .. } if *at < before
                    )
            })
            .take(most)
            .map(|(tenant, channel)| ChannelAt {
                tenant_id: *tenant,
                channel_id: *channel.id(),
            })
            .collect())
    }

    async fn idle(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<ChannelAt>, DomainError> {
        let most = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(self
            .kept
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, channel)| {
                channel.setup() == ChannelSetup::Registered
                    && Aggregate::updated_at(channel) < before
            })
            .take(most)
            .map(|(tenant, channel)| ChannelAt {
                tenant_id: *tenant,
                channel_id: *channel.id(),
            })
            .collect())
    }
}

impl Fake for Arc<dyn AccountChannelStore> {
    fn fake() -> Self {
        Arc::new(FakeAccountChannelStore::empty())
    }
}

impl Fake for Arc<dyn ChannelDirectory> {
    fn fake() -> Self {
        Arc::new(FakeAccountChannelStore::empty())
    }
}

impl Fake for Arc<dyn ServiceSubscriptionStore> {
    fn fake() -> Self {
        Arc::new(FakeServiceSubscriptionStore::empty())
    }
}

impl Fake for Arc<dyn SubscriptionDirectory> {
    fn fake() -> Self {
        Arc::new(FakeServiceSubscriptionStore::empty())
    }
}

/// A service answering every registration, renewal and removal one way,
/// counting what it was asked.
pub struct FakeServiceRegistrar {
    answer: Result<Registered, RegistrationFailure>,
    renewed: Option<SealedSecret>,
    asked: Mutex<Vec<&'static str>>,
    setup: Option<ChannelSetup>,
    pulled: Mutex<Option<PulledEvents>>,
}

impl TenantScoped for FakeServiceRegistrar {}

impl FakeServiceRegistrar {
    /// A service taking every registration, naming it `remote`, lapsing as
    /// `lapses` says.
    #[must_use]
    pub fn taking(remote: &str, lapses: Lapse) -> Self {
        Self {
            answer: Ok(Registered {
                remote: RemoteRegistration::new(remote).expect("a valid name"),
                lapses,
                routing: Routing::OwnAddress,
                given_secret: None,
            }),
            renewed: None,
            asked: Mutex::new(Vec::new()),
            setup: None,
            pulled: Mutex::new(None),
        }
    }

    /// A service failing every request as `failure` says.
    #[must_use]
    pub fn failing(failure: RegistrationFailure) -> Self {
        Self {
            answer: Err(failure),
            renewed: None,
            asked: Mutex::new(Vec::new()),
            setup: None,
            pulled: Mutex::new(None),
        }
    }

    /// The same service, giving one channel per account, set up as `setup`.
    #[must_use]
    pub fn by_channel(self, setup: ChannelSetup) -> Self {
        Self {
            setup: Some(setup),
            ..self
        }
    }

    /// The same service, answering the next read of its history `pulled`.
    #[must_use]
    pub fn pulling(self, pulled: PulledEvents) -> Self {
        Self {
            pulled: Mutex::new(Some(pulled)),
            ..self
        }
    }

    /// The same service, showing `secret` once in its answer.
    #[must_use]
    pub fn giving_secret(mut self, secret: SealedSecret) -> Self {
        if let Ok(answer) = self.answer.as_mut() {
            answer.given_secret = Some(secret);
        }
        self
    }

    /// Its answer about a channel, from its answer about a registration.
    fn channel_answer(&self) -> Result<ChannelRegistered, RegistrationFailure> {
        self.answer.clone().map(|taken| ChannelRegistered {
            remote: taken.remote,
            lapses: taken.lapses,
            history: HistoryPlace::Unknown,
        })
    }

    /// The same service, replacing the account's credential with `renewed`
    /// on every request, as a rotating grant does.
    #[must_use]
    pub fn renewing(self, renewed: SealedSecret) -> Self {
        Self {
            renewed: Some(renewed),
            ..self
        }
    }

    /// Its answer `result`, with the credential it replaced.
    fn answered<T>(&self, result: Result<T, RegistrationFailure>) -> RegistrarAnswer<T> {
        RegistrarAnswer {
            result,
            renewal: self
                .renewed
                .clone()
                .map_or(Renewal::Unchanged, Renewal::Renewed),
        }
    }

    /// What it was asked, in order: `register`, `renew` or `unregister`.
    #[must_use]
    pub fn asked(&self) -> Vec<&'static str> {
        self.asked.lock().unwrap().clone()
    }
}

#[async_trait]
impl ServiceRegistrar for FakeServiceRegistrar {
    async fn register(
        &self,
        _tenant_id: &ScopedTenant,
        _subscription: &ServiceSubscription<ResolvedTenant>,
        _keys: &RegistrationKeys,
    ) -> RegistrarAnswer<Registered> {
        self.asked.lock().unwrap().push("register");
        self.answered(self.answer.clone())
    }

    async fn renew(
        &self,
        _tenant_id: &ScopedTenant,
        _subscription: &ServiceSubscription<ResolvedTenant>,
        _keys: &RegistrationKeys,
    ) -> RegistrarAnswer<Registered> {
        self.asked.lock().unwrap().push("renew");
        self.answered(self.answer.clone())
    }

    async fn unregister(
        &self,
        _tenant_id: &ScopedTenant,
        _subscription: &ServiceSubscription<ResolvedTenant>,
        _keys: &RegistrationKeys,
    ) -> RegistrarAnswer<()> {
        self.asked.lock().unwrap().push("unregister");
        self.answered(self.answer.clone().map(|_| ()))
    }

    async fn open_channel(
        &self,
        _tenant_id: &ScopedTenant,
        _channel: &AccountChannel<ResolvedTenant>,
        _keys: &RegistrationKeys,
    ) -> RegistrarAnswer<ChannelRegistered> {
        self.asked.lock().unwrap().push("open_channel");
        self.answered(self.channel_answer())
    }

    async fn renew_channel(
        &self,
        _tenant_id: &ScopedTenant,
        _channel: &AccountChannel<ResolvedTenant>,
        _keys: &RegistrationKeys,
    ) -> RegistrarAnswer<ChannelRegistered> {
        self.asked.lock().unwrap().push("renew_channel");
        self.answered(self.channel_answer())
    }

    async fn close_channel(
        &self,
        _tenant_id: &ScopedTenant,
        _channel: &AccountChannel<ResolvedTenant>,
        _keys: &RegistrationKeys,
    ) -> RegistrarAnswer<()> {
        self.asked.lock().unwrap().push("close_channel");
        self.answered(self.answer.clone().map(|_| ()))
    }

    async fn pull(
        &self,
        _tenant_id: &ScopedTenant,
        _channel: &AccountChannel<ResolvedTenant>,
        _keys: &RegistrationKeys,
        _received: &ReceivedEvent<'_>,
    ) -> RegistrarAnswer<PulledEvents> {
        self.asked.lock().unwrap().push("pull");
        let pulled = self.pulled.lock().unwrap().take();
        let result = self
            .answer
            .clone()
            .map(|_| pulled.unwrap_or(PulledEvents::Forged));
        self.answered(result)
    }
}

impl ServiceChannelSetup for FakeServiceRegistrar {
    fn account_setup(&self, _integration: &IntegrationKey) -> Option<ChannelSetup> {
        self.setup
    }

    fn channel_address(&self, id: &AccountChannelId) -> String {
        format!(
            "https://ianua.test/api/v1/integrations/events/channels/{}",
            id.as_uuid()
        )
    }

    fn pulls_history(&self, _integration: &IntegrationKey) -> bool {
        self.pulled.lock().unwrap().is_some()
    }
}

impl Fake for Arc<dyn ServiceChannelSetup> {
    fn fake() -> Self {
        Arc::new(FakeServiceRegistrar::failing(
            RegistrationFailure::Unreachable,
        ))
    }
}

impl Fake for Arc<dyn ServiceRegistrar> {
    fn fake() -> Self {
        Arc::new(FakeServiceRegistrar::failing(
            RegistrationFailure::Unreachable,
        ))
    }
}

/// A reader taking a delivery signed with `expected` as the event, and
/// anything else as forged; the one address routes by a fixed key.
pub struct FakeServiceEventReader {
    expected: String,
    reading: Mutex<Option<Reading>>,
    route: Route,
    greeting: Mutex<Option<Greeting>>,
}

impl FakeServiceEventReader {
    /// A reader for deliveries whose `x-signature` header is `expected`,
    /// each read as `reading`.
    #[must_use]
    pub fn signed_with(expected: &str, reading: Reading) -> Self {
        Self {
            expected: expected.to_owned(),
            reading: Mutex::new(Some(reading)),
            route: Route::Refused,
            greeting: Mutex::new(None),
        }
    }

    /// The same reader, routing deliveries to the one address as `route`.
    #[must_use]
    pub fn routing(self, route: Route) -> Self {
        Self { route, ..self }
    }

    /// The same reader, taking the next request as `greeting`.
    #[must_use]
    pub fn greeted(self, greeting: Greeting) -> Self {
        Self {
            greeting: Mutex::new(Some(greeting)),
            ..self
        }
    }
}

impl ServiceEventReader for FakeServiceEventReader {
    fn read(
        &self,
        _subscription: &ServiceSubscription<ResolvedTenant>,
        secret: &Secret,
        received: &ReceivedEvent<'_>,
    ) -> EventReading {
        let signed = received
            .headers
            .iter()
            .any(|(name, value)| name == "x-signature" && *value == self.expected)
            && secret.expose() == self.expected;
        if !signed {
            return EventReading {
                check: DeliveryCheck::Forged,
                reading: Reading::Skip,
            };
        }
        let reading = self
            .reading
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(Reading::Skip);
        EventReading {
            check: DeliveryCheck::Authentic,
            reading,
        }
    }

    fn route(&self, _integration: &IntegrationKey, _received: &ReceivedEvent<'_>) -> Route {
        self.route.clone()
    }

    fn greet(&self, _integration: &IntegrationKey, _received: &ReceivedEvent<'_>) -> Greeting {
        self.greeting
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Greeting::NotOne)
    }
}

impl Fake for Arc<dyn ServiceEventReader> {
    fn fake() -> Self {
        Arc::new(FakeServiceEventReader::signed_with(
            "no secret is ever presented",
            Reading::Skip,
        ))
    }
}

/// In-memory ledger of the deliveries already started, each with when it
/// was noted.
#[derive(Default)]
pub struct FakeDeliveryLedger {
    noted: Mutex<HashMap<(ServiceSubscriptionId, String), OffsetDateTime>>,
}

impl TenantScoped for FakeDeliveryLedger {}

impl FakeDeliveryLedger {
    /// How many deliveries it remembers.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.noted.lock().unwrap().len()
    }
}

#[async_trait]
impl DeliveryLedger for FakeDeliveryLedger {
    async fn first_time(
        &self,
        _tenant_id: &ScopedTenant,
        subscription: &ServiceSubscriptionId,
        delivery: &DeliveryId,
    ) -> Result<bool, DomainError> {
        let mut noted = self.noted.lock().unwrap();
        let key = (*subscription, delivery.as_str().to_owned());
        if noted.contains_key(&key) {
            return Ok(false);
        }
        noted.insert(key, clock::now());
        Ok(true)
    }
}

#[async_trait]
impl DeliveryRetention for FakeDeliveryLedger {
    async fn forget_before(&self, before: OffsetDateTime, limit: u32) -> Result<u64, DomainError> {
        let mut noted = self.noted.lock().unwrap();
        let most = usize::try_from(limit).unwrap_or(usize::MAX);
        let old: Vec<_> = noted
            .iter()
            .filter(|(_, at)| **at < before)
            .map(|(key, _)| key.clone())
            .take(most)
            .collect();
        for key in &old {
            noted.remove(key);
        }
        Ok(u64::try_from(old.len()).unwrap_or(u64::MAX))
    }
}

impl Fake for Arc<dyn DeliveryRetention> {
    fn fake() -> Self {
        Arc::new(FakeDeliveryLedger::default())
    }
}

impl Fake for Arc<dyn DeliveryLedger> {
    fn fake() -> Self {
        Arc::new(FakeDeliveryLedger::default())
    }
}
