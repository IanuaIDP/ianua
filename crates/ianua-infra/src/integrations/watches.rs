//! Workflows registered for their services' events, through the installed
//! integrations: registering, renewing and removing a registration at its
//! service, and reading what a service sends once its signature checks
//! out.
//!
//! Each registration has an address of its own under the deployment's
//! public base URL, which the service is given and signs its deliveries
//! for. The keys a registration is made with arrive sealed and are opened
//! here for the one call; every call to a service is held to a time limit,
//! so a hung service is asked again later rather than holding a publish.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::{SealedAt, SecretEncryptor};
use ianua_app::ports::workflows::{
    ChannelRegistered, CheckBody, CheckReply, DeliveryId, EventReading, Greeting, PulledEvents,
    Reading, ReceivedEvent, Registered, RegistrarAnswer, RegistrationFailure, RegistrationKeys,
    Renewal, Route, RouteKey, Routing, ServiceChannelSetup, ServiceEventReader, ServiceRegistrar,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::triggers::channel::{
    AccountChannel, ChannelCursor, ChannelSetup, HistoryPlace,
};
use ianua_domain::domains::workflows::triggers::subscription::{
    DeliveryCheck, Lapse, Registration, RemoteRegistration, ServiceSubscription,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AccountChannelId, HttpsUrl, SealedSecret, ServiceSubscriptionId};
use ianua_integration::Renewed;
use ianua_integration::events::{
    AccountSetup, AppRoute, ChannelWatch, ChannelWatching, CheckBody as ServiceCheckBody,
    CheckReply as ServiceCheckReply, Delivery, Events, Greeting as ServiceGreeting, HeldCredential,
    MOST_PULLED, Pulled, Read, Watch, WatchFailure, Watching,
};

use crate::http::client::LONGEST_CALL;
use crate::integrations::installed::Installed;

/// The path every registration's own address sits under, beneath the
/// deployment's public base URL.
const EVENTS_PATH: &str = "api/v1/integrations/events";

/// The address each registration is given.
#[derive(Debug, Clone)]
pub struct EventAddresses {
    base: String,
}

impl EventAddresses {
    /// Addresses under `app_base_url`.
    #[must_use]
    pub fn new(app_base_url: &HttpsUrl) -> Self {
        Self {
            base: format!(
                "{}/{EVENTS_PATH}",
                app_base_url.as_str().trim_end_matches('/')
            ),
        }
    }

    /// The address of registration `id`.
    #[must_use]
    pub fn of(&self, id: &ServiceSubscriptionId) -> String {
        format!("{}/{}", self.base, id.as_uuid())
    }

    /// The address of an account's channel `id`.
    #[must_use]
    pub fn of_channel(&self, id: &AccountChannelId) -> String {
        format!("{}/channels/{}", self.base, id.as_uuid())
    }
}

/// Registers workflows at the installed integrations' services.
pub struct InstalledServiceRegistrar {
    installed: Arc<Installed>,
    encryptor: Arc<dyn SecretEncryptor>,
    addresses: EventAddresses,
    limit: Duration,
}

impl TenantScoped for InstalledServiceRegistrar {}

/// What one call to a service is made with, opened.
struct Opened<'a> {
    watcher: &'a dyn Events,
    credential: HeldCredential,
    secret: Secret,
    address: String,
}

impl InstalledServiceRegistrar {
    /// A registrar calling through `installed`, opening keys with
    /// `encryptor`, giving each registration an address of `addresses`,
    /// and giving up on a call after `limit`, at most [`LONGEST_CALL`].
    #[must_use]
    pub fn new(
        installed: Arc<Installed>,
        encryptor: Arc<dyn SecretEncryptor>,
        addresses: EventAddresses,
        limit: Duration,
    ) -> Self {
        Self {
            installed,
            encryptor,
            addresses,
            limit: limit.min(LONGEST_CALL),
        }
    }

    /// `integration`'s watcher, if it offers events.
    fn watcher(&self, integration: &IntegrationKey) -> Option<&dyn Events> {
        self.installed.find(integration)?.watcher()
    }

    /// The integration's watcher and the keys opened for `subscription`.
    async fn opened(
        &self,
        subscription: &ServiceSubscription<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> Result<Opened<'_>, RegistrationFailure> {
        self.opened_at(
            subscription.integration(),
            keys,
            self.addresses.of(subscription.id()),
        )
        .await
    }

    /// The integration's watcher and the keys opened for `channel`.
    async fn opened_for_channel(
        &self,
        channel: &AccountChannel<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> Result<Opened<'_>, RegistrationFailure> {
        self.opened_at(
            channel.integration(),
            keys,
            self.addresses.of_channel(channel.id()),
        )
        .await
    }

    /// `integration`'s watcher and `keys` opened, for what is at `address`.
    async fn opened_at(
        &self,
        integration: &IntegrationKey,
        keys: &RegistrationKeys,
        address: String,
    ) -> Result<Opened<'_>, RegistrationFailure> {
        let watcher = self
            .watcher(integration)
            .ok_or_else(|| refused("the integration no longer offers events"))?;
        Ok(Opened {
            watcher,
            credential: HeldCredential::new(self.open(&keys.credential).await?),
            secret: self.open(&keys.secret).await?,
            address,
        })
    }

    /// `result` with the secret the service showed once sealed into it. A
    /// secret that cannot be sealed fails the registration: without it,
    /// nothing the service sends could ever be proven.
    async fn with_given_secret(
        &self,
        result: Result<Registered, RegistrationFailure>,
        opened: &Opened<'_>,
        keys: &RegistrationKeys,
    ) -> Result<Registered, RegistrationFailure> {
        let taken = result?;
        let Some(given) = opened.credential.given_secret() else {
            return Ok(taken);
        };
        let sealed = self.sealed_given(&given, keys).await?;
        Ok(Registered {
            given_secret: Some(sealed),
            ..taken
        })
    }

    /// `given`, sealed where the registration's secret is kept.
    async fn sealed_given(
        &self,
        given: &Secret,
        keys: &RegistrationKeys,
    ) -> Result<SealedSecret, RegistrationFailure> {
        self.encryptor
            .encrypt(given.expose().as_bytes(), &keys.secret.place)
            .await
            .map_err(|_| refused("the service's secret could not be kept"))
    }

    /// The credential the service issued in place of the account's, sealed
    /// at `sealed`'s place. One that does not seal is dropped with a
    /// warning; the call itself stands.
    async fn renewal(&self, held: HeldCredential, sealed: &SealedAt) -> Renewal {
        let Renewed::To(credential) = held.into_renewed() else {
            return Renewal::Unchanged;
        };
        match self
            .encryptor
            .encrypt(credential.expose().as_bytes(), &sealed.place)
            .await
        {
            Ok(renewed) => Renewal::Renewed(renewed),
            Err(error) => {
                tracing::warn!(%error, "a renewed credential could not be sealed");
                Renewal::Unchanged
            }
        }
    }

    /// `result`, with what the call did to the credential `opened` held.
    async fn answered<T>(
        &self,
        result: Result<T, RegistrationFailure>,
        opened: Opened<'_>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<T> {
        RegistrarAnswer {
            result,
            renewal: self.renewal(opened.credential, &keys.credential).await,
        }
    }

    /// The text `sealed` holds. The sealer's error is dropped, so nothing
    /// of the key reaches a record.
    async fn open(&self, sealed: &SealedAt) -> Result<Secret, RegistrationFailure> {
        let Ok(bytes) = self.encryptor.decrypt(&sealed.secret, &sealed.place).await else {
            return Err(refused("a key of the registration could not be opened"));
        };
        String::from_utf8(bytes)
            .map(Secret::new)
            .map_err(|_| refused("a key of the registration is not text"))
    }

    /// `call` held to the time limit; one past it may yet be answered, so
    /// it is asked again later.
    async fn bounded<T>(
        &self,
        call: impl Future<Output = Result<T, WatchFailure>>,
    ) -> Result<T, RegistrationFailure> {
        tokio::time::timeout(self.limit, call)
            .await
            .map_err(|_| RegistrationFailure::Unreachable)?
            .map_err(failure_of)
    }
}

/// What the installed integrations say about their one-per-account addresses.
pub struct InstalledServiceChannelSetup {
    registrar: Arc<InstalledServiceRegistrar>,
}

impl InstalledServiceChannelSetup {
    /// Answers from what `registrar` has installed.
    #[must_use]
    pub fn new(registrar: Arc<InstalledServiceRegistrar>) -> Self {
        Self { registrar }
    }
}

impl ServiceChannelSetup for InstalledServiceChannelSetup {
    fn account_setup(&self, integration: &IntegrationKey) -> Option<ChannelSetup> {
        self.registrar
            .watcher(integration)?
            .account_setup()
            .map(channel_setup_of)
    }

    fn channel_address(&self, id: &AccountChannelId) -> String {
        self.registrar.addresses.of_channel(id)
    }

    fn pulls_history(&self, integration: &IntegrationKey) -> bool {
        self.registrar
            .watcher(integration)
            .is_some_and(Events::pulls_history)
    }
}

#[async_trait]
impl ServiceRegistrar for InstalledServiceRegistrar {
    async fn register(
        &self,
        _tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<Registered> {
        let opened = match self.opened(subscription, keys).await {
            Ok(opened) => opened,
            Err(failure) => return unrenewed(failure),
        };
        let watch = watch_of(subscription, &opened);
        let result = self
            .bounded(opened.watcher.register(&opened.credential, watch))
            .await
            .and_then(registered);
        let result = self.with_given_secret(result, &opened, keys).await;
        self.answered(result, opened, keys).await
    }

    async fn renew(
        &self,
        _tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<Registered> {
        let opened = match self.opened(subscription, keys).await {
            Ok(opened) => opened,
            Err(failure) => return unrenewed(failure),
        };
        let watch = watch_of(subscription, &opened);
        let result = self
            .bounded(opened.watcher.renew(&opened.credential, watch))
            .await
            .and_then(registered);
        self.answered(result, opened, keys).await
    }

    async fn unregister(
        &self,
        _tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<()> {
        let opened = match self.opened(subscription, keys).await {
            Ok(opened) => opened,
            Err(failure) => return unrenewed(failure),
        };
        let watch = watch_of(subscription, &opened);
        let result = self
            .bounded(opened.watcher.unregister(&opened.credential, watch))
            .await;
        self.answered(result, opened, keys).await
    }

    async fn open_channel(
        &self,
        _tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<ChannelRegistered> {
        let opened = match self.opened_for_channel(channel, keys).await {
            Ok(opened) => opened,
            Err(failure) => return unrenewed(failure),
        };
        let watch = channel_watch_of(channel, &opened);
        let result = self
            .bounded(opened.watcher.open_channel(&opened.credential, watch))
            .await
            .and_then(channel_registered);
        self.answered(result, opened, keys).await
    }

    async fn renew_channel(
        &self,
        _tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<ChannelRegistered> {
        let opened = match self.opened_for_channel(channel, keys).await {
            Ok(opened) => opened,
            Err(failure) => return unrenewed(failure),
        };
        let watch = channel_watch_of(channel, &opened);
        let result = self
            .bounded(opened.watcher.renew_channel(&opened.credential, watch))
            .await
            .and_then(channel_registered);
        self.answered(result, opened, keys).await
    }

    async fn close_channel(
        &self,
        _tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
        keys: &RegistrationKeys,
    ) -> RegistrarAnswer<()> {
        let opened = match self.opened_for_channel(channel, keys).await {
            Ok(opened) => opened,
            Err(failure) => return unrenewed(failure),
        };
        let watch = channel_watch_of(channel, &opened);
        let result = self
            .bounded(opened.watcher.close_channel(&opened.credential, watch))
            .await;
        self.answered(result, opened, keys).await
    }

    async fn pull(
        &self,
        _tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
        keys: &RegistrationKeys,
        received: &ReceivedEvent<'_>,
    ) -> RegistrarAnswer<PulledEvents> {
        let opened = match self.opened_for_channel(channel, keys).await {
            Ok(opened) => opened,
            Err(failure) => return unrenewed(failure),
        };
        let watch = channel_watch_of(channel, &opened);
        let delivery = delivery_of(received);
        let result = self
            .bounded(opened.watcher.pull(&opened.credential, watch, delivery))
            .await
            .and_then(pulled_events);
        self.answered(result, opened, keys).await
    }
}

/// Reads what the installed integrations' services send.
pub struct InstalledServiceEventReader {
    installed: Arc<Installed>,
    addresses: EventAddresses,
}

impl InstalledServiceEventReader {
    /// A reader through `installed`, each registration at its address of
    /// `addresses`.
    #[must_use]
    pub fn new(installed: Arc<Installed>, addresses: EventAddresses) -> Self {
        Self {
            installed,
            addresses,
        }
    }

    /// The watcher of `integration`, if it offers events.
    fn watcher(&self, integration: &IntegrationKey) -> Option<&dyn Events> {
        self.installed.find(integration)?.watcher()
    }
}

impl ServiceEventReader for InstalledServiceEventReader {
    fn read(
        &self,
        subscription: &ServiceSubscription<ResolvedTenant>,
        secret: &Secret,
        received: &ReceivedEvent<'_>,
    ) -> EventReading {
        let Some(watcher) = self.watcher(subscription.integration()) else {
            return forged();
        };
        let address = self.addresses.of(subscription.id());
        let watch = Watch {
            event: subscription.event(),
            filters: subscription.filters(),
            address: &address,
            secret,
            remote: remote_of(subscription),
        };
        reading_of(watcher.read(watch, delivery_of(received)))
    }

    fn route(&self, integration: &IntegrationKey, received: &ReceivedEvent<'_>) -> Route {
        let Some(watcher) = self.watcher(integration) else {
            return Route::Refused;
        };
        match watcher.route(delivery_of(received)) {
            AppRoute::Keyed(key) => Route::Keyed(RouteKey::new(key)),
            AppRoute::Answer(body) => Route::App(body),
            AppRoute::Refused => Route::Refused,
        }
    }

    fn greet(&self, integration: &IntegrationKey, received: &ReceivedEvent<'_>) -> Greeting {
        let Some(watcher) = self.watcher(integration) else {
            return Greeting::NotOne;
        };
        match watcher.greet(delivery_of(received)) {
            ServiceGreeting::NotOne => Greeting::NotOne,
            ServiceGreeting::Prove(reply) => Greeting::Prove(reply_of(reply)),
            ServiceGreeting::HandsSecret { secret, reply } => Greeting::HandsSecret {
                secret,
                reply: reply_of(reply),
            },
        }
    }
}

/// How the platform keeps `setup`.
fn channel_setup_of(setup: AccountSetup) -> ChannelSetup {
    match setup {
        AccountSetup::Registered => ChannelSetup::Registered,
        AccountSetup::PastedKey => ChannelSetup::PastedKey,
        AccountSetup::TokenFromService => ChannelSetup::TokenFromService,
    }
}

/// `channel` as its service is asked about it, with `opened`.
fn channel_watch_of<'a>(
    channel: &'a AccountChannel<ResolvedTenant>,
    opened: &'a Opened<'_>,
) -> ChannelWatch<'a> {
    ChannelWatch {
        address: &opened.address,
        secret: &opened.secret,
        remote: match channel.registration() {
            Registration::NotTaken => None,
            Registration::Taken { remote, .. } => Some(remote.as_str()),
        },
        cursor: channel.history().cursor().map(ChannelCursor::as_str),
    }
}

/// What the platform keeps of `watching`.
fn channel_registered(watching: ChannelWatching) -> Result<ChannelRegistered, RegistrationFailure> {
    let remote = RemoteRegistration::new(watching.remote)
        .map_err(|_| refused("the service named the channel in a way it cannot be kept"))?;
    let cursor = watching.cursor.map(cursor_of).transpose()?;
    Ok(ChannelRegistered {
        remote,
        lapses: watching.lapses.map_or(Lapse::Never, Lapse::At),
        history: cursor.map_or(HistoryPlace::Unknown, HistoryPlace::At),
    })
}

/// `written`, a service's place in its history, as the platform keeps it.
fn cursor_of(written: String) -> Result<ChannelCursor, RegistrationFailure> {
    ChannelCursor::new(written)
        .map_err(|_| refused("the service gave a place in its history that cannot be kept"))
}

/// What the platform makes of what a service's history held. A service
/// handing back more than it may is refused rather than cut short, since
/// the cursor it gave would skip what was cut.
fn pulled_events(pulled: Pulled) -> Result<PulledEvents, RegistrationFailure> {
    match pulled {
        Pulled::Forged => Ok(PulledEvents::Forged),
        Pulled::Fetched { deliveries, .. } if deliveries.len() > MOST_PULLED => {
            Err(refused("the service's history handed back too many events"))
        }
        Pulled::Fetched { deliveries, cursor } => Ok(PulledEvents::Fetched {
            deliveries,
            cursor: cursor_of(cursor)?,
        }),
    }
}

/// What the platform answers, from what the integration said to.
fn reply_of(reply: ServiceCheckReply) -> CheckReply {
    CheckReply {
        body: match reply.body {
            ServiceCheckBody::Empty => CheckBody::Empty,
            ServiceCheckBody::PlainText(bytes) => CheckBody::PlainText(bytes),
        },
        header: reply.header,
    }
}

/// `subscription` as its service is asked to send it, with `opened`.
fn watch_of<'a>(
    subscription: &'a ServiceSubscription<ResolvedTenant>,
    opened: &'a Opened<'_>,
) -> Watch<'a> {
    Watch {
        event: subscription.event(),
        filters: subscription.filters(),
        address: &opened.address,
        secret: &opened.secret,
        remote: remote_of(subscription),
    }
}

/// The service's name for `subscription`, once it took it.
fn remote_of(subscription: &ServiceSubscription<ResolvedTenant>) -> Option<&str> {
    match subscription.registration() {
        Registration::NotTaken => None,
        Registration::Taken { remote, .. } => Some(remote.as_str()),
    }
}

/// What the platform keeps of `watching`.
fn registered(watching: Watching) -> Result<Registered, RegistrationFailure> {
    let remote = RemoteRegistration::new(watching.remote)
        .map_err(|_| refused("the service named the registration in a way it cannot be kept"))?;
    Ok(Registered {
        remote,
        lapses: watching.lapses.map_or(Lapse::Never, Lapse::At),
        routing: watching.routed_by.map_or(Routing::OwnAddress, |key| {
            Routing::Keyed(RouteKey::new(key))
        }),
        given_secret: None,
    })
}

/// `received` as an integration reads it.
fn delivery_of<'a>(received: &'a ReceivedEvent<'_>) -> Delivery<'a> {
    Delivery {
        address: received.address,
        headers: received.headers,
        body: received.body,
    }
}

/// What the platform makes of an integration's reading.
fn reading_of(read: Read) -> EventReading {
    let reading = match read {
        Read::Forged => return forged(),
        Read::Start {
            delivery,
            input,
            exposure,
        } => Reading::Start {
            delivery: DeliveryId::new(delivery),
            input,
            exposure,
        },
        Read::Answer(body) => Reading::Answer(body),
        Read::Skip => Reading::Skip,
    };
    EventReading {
        check: DeliveryCheck::Authentic,
        reading,
    }
}

/// A delivery nothing admits.
fn forged() -> EventReading {
    EventReading {
        check: DeliveryCheck::Forged,
        reading: Reading::Skip,
    }
}

/// A registration refused for `why`.
fn refused(why: &str) -> RegistrationFailure {
    RegistrationFailure::Refused(why.to_owned())
}

/// `failure`, met before any call reached the service, so nothing renewed.
fn unrenewed<T>(failure: RegistrationFailure) -> RegistrarAnswer<T> {
    RegistrarAnswer {
        result: Err(failure),
        renewal: Renewal::Unchanged,
    }
}

/// The platform's failure for the service's.
fn failure_of(failure: WatchFailure) -> RegistrationFailure {
    match failure {
        WatchFailure::Refused(why) => RegistrationFailure::Refused(why),
        WatchFailure::Unreachable => RegistrationFailure::Unreachable,
    }
}
