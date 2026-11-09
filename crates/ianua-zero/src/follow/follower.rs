//! The follower: hears the events, asks for reloads, and runs them.

use std::collections::HashSet;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt as _;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use ianua_infra::bus::{Bus, EventEnvelope, EventFeed, Heard, HeardEvent};
use ianua_infra::crypto::EventCheck;

use super::changes::{Effect, effect_of};
use super::gate::{Gate, TenantRead, Ticket};
use super::locked;
use super::queue::{Cause, ReloadQueue, Target};
use super::snapshot::Tables;
use super::source::SnapshotSource;
use crate::runtime::TablesLoaded;

/// How long the follower waits before following again once the feed is
/// lost or cannot be opened.
const FOLLOW_AGAIN: Duration = Duration::from_secs(1);

/// How long after a full reload that did not finish whole it runs again.
const RELOAD_AGAIN: Duration = Duration::from_secs(5);

/// The most reloads waiting before they are folded into one full reload.
const QUEUE_ROOM: usize = 4096;

/// How long one read of a tenant, the tenants served or the certificates
/// may take, unless the settings say otherwise.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How many reloads run at once, unless the settings say otherwise.
const CONCURRENCY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(7);

/// The follower's settings were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FollowSettingsError {
    /// The full reload would run without pause.
    #[error("the full reload of the gateway's tables needs a period above zero")]
    NoReloadPeriod,
    /// Every read would time out at once.
    #[error("a read of the gateway's tables needs a timeout above zero")]
    NoReadTimeout,
}

/// How the follower reloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FollowSettings {
    reload_every: Duration,
    read_timeout: Duration,
    concurrency: NonZeroUsize,
}

impl FollowSettings {
    /// Reloading everything every `reload_every` (`GATEWAY_RELOAD_SECONDS`),
    /// each read given ten seconds to answer, and eight reloads at once.
    ///
    /// # Errors
    ///
    /// Returns [`FollowSettingsError::NoReloadPeriod`] when `reload_every`
    /// is zero.
    pub(crate) fn every(reload_every: Duration) -> Result<Self, FollowSettingsError> {
        Self::new(reload_every, READ_TIMEOUT, CONCURRENCY)
    }

    /// Reloading everything every `reload_every`, each read given
    /// `read_timeout` to answer, and at most `concurrency` reloads, and as
    /// many tenant reads within a full reload, at once.
    ///
    /// # Errors
    ///
    /// Returns [`FollowSettingsError`] when either period is zero.
    pub(crate) fn new(
        reload_every: Duration,
        read_timeout: Duration,
        concurrency: NonZeroUsize,
    ) -> Result<Self, FollowSettingsError> {
        if reload_every.is_zero() {
            return Err(FollowSettingsError::NoReloadPeriod);
        }
        if read_timeout.is_zero() {
            return Err(FollowSettingsError::NoReadTimeout);
        }
        Ok(Self {
            reload_every,
            read_timeout,
            concurrency,
        })
    }
}

/// Why one read gave nothing to apply. Names no data it read.
#[derive(Debug, thiserror::Error)]
enum ReadFailure {
    #[error("the store did not answer in time")]
    TimedOut,
    #[error("the store could not be read")]
    Refused(#[source] DomainError),
}

/// Whether every part of a reload reached the tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Whole,
    Partial,
}

impl Outcome {
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Whole, Self::Whole) => Self::Whole,
            (Self::Partial, _) | (_, Self::Partial) => Self::Partial,
        }
    }
}

/// What a tenant whose read failed is left as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unread {
    /// Withdrawn: a change to it was heard, so what is held may be revoked.
    Withdrawn,
    /// Served as it was held.
    Kept,
}

impl Unread {
    /// A tenant read on its own for `cause` was named by a heard change
    /// unless the timer asked for it.
    fn for_tenant_read(cause: Cause) -> Self {
        match cause {
            Cause::Routine => Self::Kept,
            Cause::Heard | Cause::Unheard => Self::Withdrawn,
        }
    }
}

/// Whether the follower hears the events now, and which feed it is on.
#[derive(Debug, Default)]
struct Feed {
    opened: u64,
    following: bool,
}

/// The feed a full reload started under, to tell whether it still holds
/// when the reload ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeedMark(u64);

/// How far the follower can tell who published an event it heard.
#[derive(Debug, Clone, Default)]
pub(crate) struct Seals {
    /// Without a verifier, an event only asks for store reads and cannot
    /// withdraw a tenant before the read. A failed change read still does.
    verifier: Option<EventCheck>,
}

impl Seals {
    /// Supplies a publisher verifier to tests whose fixtures hold both roots.
    #[cfg(test)]
    fn checked(verifier: EventCheck) -> Self {
        Self {
            verifier: Some(verifier),
        }
    }
}

/// How far one heard event may act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vouched {
    /// Its seal holds: it acts as it says.
    Fully,
    /// Nobody vouches for it: it only asks for reads.
    AsAHint,
}

impl Vouched {
    /// `effect`, held to what this event may do: a hint never withdraws a
    /// tenant before its read.
    fn limit(self, effect: Effect) -> Effect {
        match (self, effect) {
            (Self::AsAHint, Effect::AtOnce(tenant)) => Effect::TenantAndCertificates(tenant),
            (_, effect) => effect,
        }
    }
}

/// The follower of the events stream for the gateway's tables.
pub(crate) struct ConfigFollower {
    bus: Arc<dyn Bus>,
    seals: Seals,
    source: Arc<dyn SnapshotSource>,
    tables: Arc<dyn Tables>,
    settings: FollowSettings,
    queue: ReloadQueue,
    gate: Gate,
    feed: Mutex<Feed>,
    owed: Mutex<Option<Cause>>,
    loaded: TablesLoaded,
}

/// Event input, publisher trust and the store-to-table path used by a follower.
pub(crate) struct FollowPorts {
    /// The feed notifying this gateway of changes.
    pub bus: Arc<dyn Bus>,
    /// How far the publisher's seal can be checked.
    pub seals: Seals,
    /// Authoritative configuration read after events or timer ticks.
    pub source: Arc<dyn SnapshotSource>,
    /// The routing and certificate tables receiving complete snapshots.
    pub tables: Arc<dyn Tables>,
}

impl std::fmt::Debug for ConfigFollower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigFollower")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl ConfigFollower {
    /// Follows the supplied event feed and reloads its tables within `settings`.
    #[must_use]
    pub(crate) fn new(ports: FollowPorts, settings: FollowSettings) -> Self {
        Self {
            bus: ports.bus,
            seals: ports.seals,
            source: ports.source,
            tables: ports.tables,
            settings,
            queue: ReloadQueue::new(QUEUE_ROOM),
            gate: Gate::default(),
            feed: Mutex::new(Feed::default()),
            owed: Mutex::new(None),
            loaded: TablesLoaded::not_yet(),
        }
    }

    /// Whether the first full reload finished, for the readiness check.
    #[must_use]
    pub(crate) fn loaded(&self) -> TablesLoaded {
        self.loaded.clone()
    }

    /// Follows the events, reloads on the timer and runs the reloads, for
    /// as long as the gateway runs. Spawn it once, until the stop.
    pub(crate) async fn run(self) {
        tokio::join!(
            self.follow(),
            self.reload_on_timer(),
            self.reload_what_is_owed(),
            self.work(),
        );
    }

    async fn follow(&self) {
        loop {
            self.follow_once().await;
            tokio::time::sleep(FOLLOW_AGAIN).await;
        }
    }

    /// Opens a feed, reads everything again, since events may have gone by
    /// before it opened, and acts on what it hears until it ends.
    async fn follow_once(&self) {
        let feed = match self.bus.follow().await {
            Ok(feed) => feed,
            Err(error) => {
                tracing::warn!(%error, "the gateway's tables cannot follow the events; retrying");
                return;
            }
        };
        self.feed_opened();
        self.queue.ask(Target::Everything, Cause::Unheard);
        self.drain(feed).await;
        locked(&self.feed).following = false;
        self.queue.ask(Target::Everything, Cause::Unheard);
        tracing::warn!("the gateway's tables lost the events feed; following again");
    }

    async fn drain(&self, mut feed: Box<dyn EventFeed>) {
        while let Some(heard) = feed.next().await {
            match heard {
                Heard::Event(event) => self.heard(&event),
                Heard::Missed => self.queue.ask(Target::Everything, Cause::Unheard),
            }
        }
    }

    /// Acts on `event` as far as its seal vouches for it.
    fn heard(&self, event: &HeardEvent) {
        let Some(vouched) = self.vouched(event) else {
            tracing::warn!("an event whose seal does not hold was left unapplied");
            return;
        };
        let Ok(envelope) = serde_json::from_slice::<EventEnvelope>(&event.payload) else {
            self.queue.ask(Target::Everything, Cause::Unheard);
            return;
        };
        self.act_on(vouched.limit(effect_of(&envelope)));
    }

    /// How far `event` may act, or `None` when its seal does not hold.
    fn vouched(&self, event: &HeardEvent) -> Option<Vouched> {
        let Some(check) = &self.seals.verifier else {
            return Some(Vouched::AsAHint);
        };
        let seal = event.seal.as_deref()?;
        check
            .holds(&event.subject, &event.payload, seal)
            .then_some(Vouched::Fully)
    }

    /// Asks for what `effect` changed. Every tenant a change names is read
    /// on its own, so a failed read withdraws it and no other.
    fn act_on(&self, effect: Effect) {
        match effect {
            Effect::Nothing => {}
            Effect::Tenant(tenant) => self.queue.ask(Target::Tenant(tenant), Cause::Heard),
            Effect::TenantAndCertificates(tenant) => {
                self.queue.ask(Target::Tenant(tenant), Cause::Heard);
                self.queue.ask(Target::Certificates, Cause::Heard);
            }
            Effect::AtOnce(tenant) => {
                self.withdraw(tenant, self.gate.ticket());
                self.queue.ask(Target::Tenant(tenant), Cause::Heard);
                self.queue.ask(Target::Certificates, Cause::Heard);
            }
            Effect::TenantAndEverything(tenant) => {
                self.queue.ask(Target::Tenant(tenant), Cause::Heard);
                self.queue.ask(Target::Everything, Cause::Heard);
            }
            Effect::Organization(organization) => {
                for tenant in self.gate.held_of(organization) {
                    self.queue.ask(Target::Tenant(tenant), Cause::Heard);
                }
                self.queue.ask(Target::Everything, Cause::Heard);
            }
            Effect::Everything => self.queue.ask(Target::Everything, Cause::Unheard),
        }
    }

    async fn reload_on_timer(&self) {
        loop {
            tokio::time::sleep(self.settings.reload_every).await;
            self.queue.ask(Target::Everything, Cause::Routine);
        }
    }

    async fn reload_what_is_owed(&self) {
        loop {
            tokio::time::sleep(RELOAD_AGAIN).await;
            let Some(cause) = locked(&self.owed).take() else {
                continue;
            };
            self.queue.ask(Target::Everything, cause);
        }
    }

    /// Runs the queued reloads, as many at once as the settings allow.
    async fn work(&self) {
        let workers = (0..self.settings.concurrency.get()).map(|_| self.worker());
        futures_util::future::join_all(workers).await;
    }

    async fn worker(&self) {
        loop {
            let (target, cause) = self.queue.next().await;
            self.reload(target, cause).await;
            self.queue.finish(target);
        }
    }

    async fn reload(&self, target: Target, cause: Cause) {
        match target {
            Target::Tenant(tenant) => {
                self.reload_tenant(tenant, Unread::for_tenant_read(cause))
                    .await;
            }
            Target::Certificates => {
                self.reload_certificates().await;
            }
            Target::Everything => self.reload_everything(cause).await,
        }
    }

    /// Reads `tenant` again and serves what was read, or withdraws it when
    /// it is no longer served. A failed read leaves it as `unread` says.
    async fn reload_tenant(&self, tenant: TenantId, unread: Unread) -> Outcome {
        let ticket = self.gate.ticket();
        let read = TenantRead { tenant, ticket };
        match self.timed(self.source.snapshot(tenant)).await {
            Ok(Some(snapshot)) => {
                let organization = snapshot.organization;
                self.gate.install_tenant(read, organization, || {
                    self.tables.install(snapshot);
                });
                Outcome::Whole
            }
            Ok(None) => {
                self.withdraw(tenant, ticket);
                Outcome::Whole
            }
            Err(failure) => {
                self.tenant_unread(read, unread, &failure);
                Outcome::Partial
            }
        }
    }

    /// Applies the failure policy to this read without affecting other tenants.
    fn tenant_unread(&self, read: TenantRead, unread: Unread, why: &ReadFailure) {
        let TenantRead { tenant, ticket } = read;
        match unread {
            Unread::Withdrawn => {
                tracing::error!(
                    tenant_id = %tenant,
                    error = %why,
                    "a changed tenant could not be read again; it is not served until it can be"
                );
                self.withdraw(tenant, ticket);
            }
            Unread::Kept => tracing::warn!(
                tenant_id = %tenant,
                error = %why,
                "a tenant could not be read again; it is served as it was"
            ),
        }
    }

    fn withdraw(&self, tenant: TenantId, ticket: Ticket) {
        self.gate.withdraw_tenant(tenant, ticket, || {
            self.tables.withdraw(&tenant);
        });
    }

    /// Reads the served certificates again. When the read fails, the
    /// certificates are served as they were: a certificate only proves a
    /// name, and whether the name reaches a tenant is the tenant's reload's
    /// to say.
    async fn reload_certificates(&self) -> Outcome {
        let ticket = self.gate.ticket();
        match self.timed(self.source.certificates()).await {
            Ok(certificates) => {
                self.gate.install_certificates(ticket, || {
                    self.tables.install_certificates(certificates);
                });
                Outcome::Whole
            }
            Err(failure) => {
                tracing::warn!(error = %failure, "the served certificates could not be read");
                Outcome::Partial
            }
        }
    }

    /// Reads every tenant and the certificates again, and withdraws every
    /// tenant no longer served.
    ///
    /// What cannot be read is served as it was held: a tenant a heard
    /// change names is read on its own, and withdrawn there when that read
    /// fails, so a full reload never withdraws a tenant for want of a read.
    /// A reload that did not finish whole runs again shortly; after events
    /// went by unheard, the tables count as stale until one does.
    async fn reload_everything(&self, cause: Cause) {
        let mark = FeedMark(locked(&self.feed).opened);
        let listed = self.gate.ticket();
        let served = match self.timed(self.source.served()).await {
            Ok(served) => served,
            Err(failure) => {
                tracing::warn!(
                    error = %failure,
                    "the tenants served could not be read; they are served as they were"
                );
                self.full_reload_failed(cause);
                return;
            }
        };
        self.withdraw_unserved(&served, listed);
        let tenants = self.reload_each(&served).await;
        let certificates = self.reload_certificates().await;
        match tenants.and(certificates) {
            Outcome::Whole => self.full_reload_done(mark),
            Outcome::Partial => self.full_reload_failed(cause),
        }
    }

    async fn reload_each(&self, served: &[TenantId]) -> Outcome {
        futures_util::stream::iter(served.iter().copied())
            .map(|tenant| self.reload_tenant(tenant, Unread::Kept))
            .buffer_unordered(self.settings.concurrency.get())
            .fold(Outcome::Whole, |all, one| async move { all.and(one) })
            .await
    }

    fn withdraw_unserved(&self, served: &[TenantId], listed: Ticket) {
        let served: HashSet<TenantId> = served.iter().copied().collect();
        for tenant in self.gate.held_tenants() {
            if served.contains(&tenant) {
                continue;
            }
            self.withdraw(tenant, listed);
        }
    }

    /// Runs the full reload again shortly. After events went by unheard,
    /// what is held may miss any change, so the node leaves rotation until
    /// a full reload succeeds; it goes on serving what it holds meanwhile.
    fn full_reload_failed(&self, cause: Cause) {
        match cause {
            Cause::Unheard => self.loaded.mark_stale(),
            Cause::Routine | Cause::Heard => {}
        }
        let mut owed = locked(&self.owed);
        *owed = Some(owed.map_or(cause, |held| held.max(cause)));
    }

    async fn timed<T>(
        &self,
        read: impl Future<Output = Result<T, DomainError>>,
    ) -> Result<T, ReadFailure> {
        match tokio::time::timeout(self.settings.read_timeout, read).await {
            Ok(Ok(read)) => Ok(read),
            Ok(Err(error)) => Err(ReadFailure::Refused(error)),
            Err(_) => Err(ReadFailure::TimedOut),
        }
    }

    fn feed_opened(&self) {
        let mut feed = locked(&self.feed);
        feed.opened += 1;
        feed.following = true;
    }

    /// Counts the tables as loaded when the feed a full reload started
    /// under is still followed: every change since was heard.
    fn full_reload_done(&self, mark: FeedMark) {
        let feed = locked(&self.feed);
        if !feed.following || FeedMark(feed.opened) != mark {
            return;
        }
        self.loaded.mark_loaded();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use ianua_app::ports::pages::ErrorBranding;
    use ianua_app::ports::proxy::{HostedTenant, ServedCertificate};
    use ianua_domain::domains::tenant::access::network_security::MtlsConfig;
    use ianua_domain::domains::tenant::hosts::{PlatformLabel, ReadableAddress};
    use ianua_domain::types::{DisplayName, Issuer, OrganizationId, TenantSlug};
    use ianua_infra::bus::{EventScope, MemoryBus};
    use ianua_infra::crypto::{EventSeal, RootSecret};
    use serde_json::Value;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;
    use crate::follow::TenantSnapshot;

    const SOON: Duration = Duration::from_secs(2);

    /// How the fake store answers for one tenant.
    #[derive(Debug, Clone, Copy)]
    enum Answer {
        Serves,
        Hangs,
        Fails,
    }

    /// Whether the fake store lists the tenants served.
    #[derive(Debug, Clone, Copy)]
    enum Listing {
        Lists,
        Fails,
    }

    /// Every tenant of the fake store belongs to one organization.
    #[derive(Debug)]
    struct FakeSource {
        organization: OrganizationId,
        listing: Mutex<Listing>,
        answers: Mutex<HashMap<TenantId, Answer>>,
    }

    impl FakeSource {
        fn with(answers: &[(TenantId, Answer)]) -> Arc<Self> {
            Arc::new(Self {
                organization: OrganizationId::new(),
                listing: Mutex::new(Listing::Lists),
                answers: Mutex::new(answers.iter().copied().collect()),
            })
        }

        fn answer(&self, tenant: TenantId, answer: Answer) {
            locked(&self.answers).insert(tenant, answer);
        }

        fn list(&self, listing: Listing) {
            *locked(&self.listing) = listing;
        }
    }

    #[async_trait]
    impl SnapshotSource for FakeSource {
        async fn served(&self) -> Result<Vec<TenantId>, DomainError> {
            let listing = *locked(&self.listing);
            match listing {
                Listing::Lists => Ok(locked(&self.answers).keys().copied().collect()),
                Listing::Fails => Err(DomainError::infra_msg("the store is down")),
            }
        }

        async fn snapshot(&self, tenant: TenantId) -> Result<Option<TenantSnapshot>, DomainError> {
            let answer = locked(&self.answers).get(&tenant).copied();
            match answer {
                Some(Answer::Serves) => Ok(Some(snapshot_of(tenant, self.organization))),
                Some(Answer::Hangs) => std::future::pending().await,
                Some(Answer::Fails) => Err(DomainError::infra_msg("the store is down")),
                None => Ok(None),
            }
        }

        async fn certificates(&self) -> Result<Vec<ServedCertificate>, DomainError> {
            Ok(Vec::new())
        }
    }

    fn snapshot_of(tenant: TenantId, organization: OrganizationId) -> TenantSnapshot {
        TenantSnapshot {
            hosted: HostedTenant {
                platform_label: PlatformLabel::new(
                    tenant.as_uuid().simple().to_string()[16..].to_owned(),
                )
                .unwrap(),
                readable_address: ReadableAddress::Off,
                tenant_id: tenant,
                organization_slug: TenantSlug::try_from("acme-org".to_owned()).unwrap(),
                slug: TenantSlug::try_from("acme".to_owned()).unwrap(),
                domains: Vec::new(),
            },
            organization,
            issuer: Issuer::new("https://app.example.com/t/acme-org/acme").unwrap(),
            branding: ErrorBranding {
                name: DisplayName::try_from("Acme".to_owned()).unwrap(),
                logo_url: None,
                primary_color: None,
                background_color: None,
            },
            mtls: MtlsConfig::disabled(),
            routes: Vec::new(),
            services: Vec::new(),
            pipelines: Vec::new(),
            client_keys: Vec::new(),
            connectors: Vec::new(),
        }
    }

    #[derive(Debug, Default)]
    struct FakeTables {
        served: Mutex<HashSet<TenantId>>,
    }

    impl FakeTables {
        fn serves(&self, tenant: TenantId) -> bool {
            locked(&self.served).contains(&tenant)
        }
    }

    impl Tables for FakeTables {
        fn install(&self, snapshot: TenantSnapshot) {
            locked(&self.served).insert(snapshot.hosted.tenant_id);
        }

        fn withdraw(&self, tenant: &TenantId) {
            locked(&self.served).remove(tenant);
        }

        fn install_certificates(&self, _: Vec<ServedCertificate>) {}
    }

    fn root() -> RootSecret {
        RootSecret::parse(&"ab".repeat(32)).unwrap()
    }

    struct Gateway {
        bus: Arc<MemoryBus>,
        source: Arc<FakeSource>,
        tables: Arc<FakeTables>,
        follower: ConfigFollower,
    }

    impl Gateway {
        /// Serves `tenant` as a reload would have installed it.
        fn holding(&self, tenant: TenantId) {
            let organization = self.source.organization;
            let ticket = self.follower.gate.ticket();
            self.follower
                .gate
                .install_tenant(TenantRead { tenant, ticket }, organization, || {
                    self.tables.install(snapshot_of(tenant, organization));
                });
        }

        fn owed(&self) -> Option<Cause> {
            *locked(&self.follower.owed)
        }
    }

    fn gateway(source: Arc<FakeSource>, settings: FollowSettings) -> Gateway {
        let bus = Arc::new(MemoryBus::new(100));
        let tables = Arc::new(FakeTables::default());
        let check = EventCheck::new(
            EventSeal::control_plane(&root()),
            EventSeal::data_plane(&root()),
        );
        Gateway {
            follower: ConfigFollower::new(
                FollowPorts {
                    bus: bus.clone(),
                    seals: Seals::checked(check),
                    source: source.clone(),
                    tables: tables.clone(),
                },
                settings,
            ),
            bus,
            source,
            tables,
        }
    }

    fn sealed(tenant: TenantId, event_type: &str) -> HeardEvent {
        let (subject, payload) = event(tenant, event_type);
        let seal = EventSeal::control_plane(&root()).seal(&subject, &payload);
        heard(subject, payload, Some(seal))
    }

    fn settings(concurrency: usize, read_timeout: Duration) -> FollowSettings {
        FollowSettings::new(
            Duration::from_secs(3600),
            read_timeout,
            NonZeroUsize::new(concurrency).unwrap(),
        )
        .unwrap()
    }

    fn event(tenant: TenantId, event_type: &str) -> (String, Vec<u8>) {
        let envelope = EventEnvelope {
            id: Uuid::now_v7(),
            scope: EventScope::Tenant(*tenant.as_uuid()),
            organization_id: None,
            event_type: event_type.to_owned(),
            actor: "system".to_owned(),
            payload: Value::Null,
            occurred_at: OffsetDateTime::UNIX_EPOCH,
            chain_depth: 0,
        };
        (envelope.subject(), serde_json::to_vec(&envelope).unwrap())
    }

    fn heard(subject: String, payload: Vec<u8>, seal: Option<String>) -> HeardEvent {
        HeardEvent {
            subject,
            payload,
            seal,
        }
    }

    /// Waits until `holds` is true, for at most a moment.
    async fn eventually(holds: impl Fn() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + SOON;
        while tokio::time::Instant::now() < deadline {
            if holds() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        holds()
    }

    /// Runs the follower's reloads beside `check` until it finishes. The
    /// workers never stop on their own; should they, the check failed.
    async fn while_working(follower: &ConfigFollower, check: impl Future<Output = bool>) -> bool {
        tokio::select! {
            () = follower.work() => false,
            held = check => held,
        }
    }

    /// An unsealed route event and one sealed by the wrong publisher leave
    /// the reload queue empty.
    #[test]
    fn an_unsealed_event_is_ignored() {
        let gateway = gateway(FakeSource::with(&[]), settings(1, SOON));
        let (subject, payload) = event(TenantId::new(), "routing.route_created");
        let forged = EventSeal::data_plane(&root()).seal(&subject, &payload);

        gateway
            .follower
            .heard(&heard(subject.clone(), payload.clone(), None));
        gateway
            .follower
            .heard(&heard(subject, payload, Some(forged)));

        assert!(gateway.follower.queue.waiting().is_empty());
    }

    #[test]
    fn a_sealed_change_reloads_its_tenant() {
        let gateway = gateway(FakeSource::with(&[]), settings(1, SOON));
        let acme = TenantId::new();

        gateway
            .follower
            .heard(&sealed(acme, "routing.route_created"));

        assert_eq!(
            gateway.follower.queue.waiting(),
            vec![(Target::Tenant(acme), Cause::Heard)]
        );
    }

    /// A removed client certificate authority is not trusted for the time
    /// the reload takes: the tenant is withdrawn as the event is heard.
    #[test]
    fn an_mtls_change_withdraws_the_tenant_before_the_reload() {
        let gateway = gateway(FakeSource::with(&[]), settings(1, SOON));
        let acme = TenantId::new();
        gateway.holding(acme);

        gateway
            .follower
            .heard(&sealed(acme, "tenant.mtls_config_updated"));

        assert!(!gateway.tables.serves(acme));
    }

    /// When seals cannot be checked, an unsealed mTLS change queues tenant
    /// and certificate reads while leaving the held tenant served.
    #[test]
    fn an_unvouched_event_only_asks_for_a_read() {
        let mut gateway = gateway(FakeSource::with(&[]), settings(1, SOON));
        gateway.follower.seals = Seals::default();
        let acme = TenantId::new();
        gateway.holding(acme);

        let (subject, payload) = event(acme, "tenant.mtls_config_updated");
        gateway.follower.heard(&heard(subject, payload, None));

        assert!(gateway.tables.serves(acme));
        assert_eq!(
            gateway.follower.queue.waiting(),
            vec![
                (Target::Tenant(acme), Cause::Heard),
                (Target::Certificates, Cause::Heard)
            ]
        );
    }

    /// After Acme's domain-change event, failed tenant and list reads
    /// withdraw Acme and leave a full reload owed while Globex stays served.
    #[tokio::test]
    async fn a_failed_list_after_one_tenants_change_withdraws_only_that_tenant() {
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let source = FakeSource::with(&[(acme, Answer::Fails), (globex, Answer::Fails)]);
        source.list(Listing::Fails);
        let gateway = gateway(source, settings(2, SOON));
        gateway.holding(acme);
        gateway.holding(globex);

        gateway
            .follower
            .heard(&sealed(acme, "tenant.domain_transferred"));
        let settled = while_working(
            &gateway.follower,
            eventually(|| !gateway.tables.serves(acme) && gateway.owed().is_some()),
        )
        .await;

        assert!(settled);
        assert!(gateway.tables.serves(globex));
    }

    /// A suspended organization names none of its tenants, so each one
    /// held is read on its own, and withdrawn should that read fail.
    #[test]
    fn an_organization_change_reads_each_of_its_tenants_held() {
        let gateway = gateway(FakeSource::with(&[]), settings(1, SOON));
        let acme = TenantId::new();
        gateway.holding(acme);

        gateway
            .follower
            .act_on(Effect::Organization(gateway.source.organization));

        assert_eq!(
            gateway.follower.queue.waiting(),
            vec![
                (Target::Tenant(acme), Cause::Heard),
                (Target::Everything, Cause::Heard)
            ]
        );
    }

    /// A failed reload after missed events keeps both held tenants served
    /// but clears readiness; a successful full reload restores readiness.
    #[tokio::test]
    async fn a_failed_read_after_missed_events_keeps_serving_but_is_not_ready() {
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let source = FakeSource::with(&[(acme, Answer::Serves), (globex, Answer::Serves)]);
        let gateway = gateway(source, settings(2, SOON));
        gateway.follower.feed_opened();
        gateway.follower.reload_everything(Cause::Unheard).await;
        gateway.source.list(Listing::Fails);
        gateway.source.answer(acme, Answer::Fails);
        gateway.source.answer(globex, Answer::Fails);

        gateway.follower.drain(Box::new(MissedOnce(true))).await;
        let settled =
            while_working(&gateway.follower, eventually(|| gateway.owed().is_some())).await;

        assert!(settled);
        assert!(gateway.tables.serves(acme) && gateway.tables.serves(globex));
        assert!(!gateway.follower.loaded().is_loaded());

        gateway.source.list(Listing::Lists);
        gateway.source.answer(acme, Answer::Serves);
        gateway.source.answer(globex, Answer::Serves);
        gateway.follower.reload_everything(Cause::Unheard).await;

        assert!(gateway.follower.loaded().is_loaded());
    }

    /// A feed reporting missed events queues a full reload with the
    /// unheard-events cause.
    #[tokio::test]
    async fn missed_events_reload_everything() {
        let gateway = gateway(FakeSource::with(&[]), settings(1, SOON));
        let feed: Box<dyn EventFeed> = Box::new(MissedOnce(true));

        gateway.follower.drain(feed).await;

        assert_eq!(
            gateway.follower.queue.waiting(),
            vec![(Target::Everything, Cause::Unheard)]
        );
    }

    #[tokio::test]
    async fn the_timer_reloads_everything() {
        let quick = FollowSettings::new(
            Duration::from_millis(20),
            SOON,
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        let gateway = gateway(FakeSource::with(&[]), quick);

        let _ = tokio::time::timeout(
            Duration::from_millis(200),
            gateway.follower.reload_on_timer(),
        )
        .await;

        assert_eq!(
            gateway.follower.queue.waiting(),
            vec![(Target::Everything, Cause::Routine)]
        );
    }

    /// With two workers, Globex's reload installs its tables while Acme's
    /// store read remains pending.
    #[tokio::test]
    async fn a_hung_reload_does_not_block_others() {
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let source = FakeSource::with(&[(acme, Answer::Hangs), (globex, Answer::Serves)]);
        let gateway = gateway(source, settings(2, Duration::from_secs(60)));
        gateway
            .follower
            .queue
            .ask(Target::Tenant(acme), Cause::Heard);
        gateway
            .follower
            .queue
            .ask(Target::Tenant(globex), Cause::Heard);

        let reloaded = while_working(
            &gateway.follower,
            eventually(|| gateway.tables.serves(globex)),
        )
        .await;

        assert!(reloaded);
    }

    /// With one worker, Acme's hung change reload times out and withdraws
    /// Acme, allowing Globex's queued reload to install.
    #[tokio::test]
    async fn a_hung_reload_times_out_and_withdraws_the_changed_tenant() {
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let source = FakeSource::with(&[(acme, Answer::Hangs), (globex, Answer::Serves)]);
        let gateway = gateway(source, settings(1, Duration::from_millis(50)));
        gateway.holding(acme);
        gateway
            .follower
            .queue
            .ask(Target::Tenant(acme), Cause::Heard);
        gateway
            .follower
            .queue
            .ask(Target::Tenant(globex), Cause::Heard);

        let reloaded = while_working(
            &gateway.follower,
            eventually(|| gateway.tables.serves(globex)),
        )
        .await;

        assert!(reloaded);
        assert!(!gateway.tables.serves(acme));
    }

    /// On the timer nothing is known to have changed, so a tenant that
    /// cannot be read is served as it was.
    #[tokio::test]
    async fn a_routine_reload_that_fails_keeps_the_tenants() {
        let acme = TenantId::new();
        let gateway = gateway(
            FakeSource::with(&[(acme, Answer::Fails)]),
            settings(1, SOON),
        );
        gateway.holding(acme);

        gateway.follower.reload_everything(Cause::Routine).await;

        assert!(gateway.tables.serves(acme));
        assert_eq!(gateway.owed(), Some(Cause::Routine));
    }

    /// A tenant deleted while the gateway was not listening is withdrawn
    /// by the next full reload.
    #[tokio::test]
    async fn a_full_reload_withdraws_tenants_no_longer_served() {
        let (acme, gone) = (TenantId::new(), TenantId::new());
        let gateway = gateway(
            FakeSource::with(&[(acme, Answer::Serves)]),
            settings(2, SOON),
        );
        gateway.holding(gone);

        gateway.follower.reload_everything(Cause::Routine).await;

        assert!(gateway.tables.serves(acme));
        assert!(!gateway.tables.serves(gone));
    }

    /// The readiness check says loaded only after the first full reload
    /// finished whole while the feed was followed.
    #[tokio::test]
    async fn the_tables_count_as_loaded_after_the_first_full_reload() {
        let acme = TenantId::new();
        let gateway = gateway(
            FakeSource::with(&[(acme, Answer::Serves)]),
            settings(2, SOON),
        );
        let loaded = gateway.follower.loaded();
        assert!(!loaded.is_loaded());
        gateway.follower.feed_opened();

        gateway.follower.reload_everything(Cause::Unheard).await;

        assert!(loaded.is_loaded());
        assert!(gateway.tables.serves(acme));
    }

    #[tokio::test]
    async fn a_full_reload_that_is_not_whole_leaves_the_tables_unloaded() {
        let acme = TenantId::new();
        let gateway = gateway(
            FakeSource::with(&[(acme, Answer::Fails)]),
            settings(2, SOON),
        );
        gateway.follower.feed_opened();

        gateway.follower.reload_everything(Cause::Unheard).await;

        assert!(!gateway.follower.loaded().is_loaded());
        assert_eq!(gateway.owed(), Some(Cause::Unheard));
    }

    /// A full reload without an open event feed leaves the tables marked
    /// unloaded.
    #[tokio::test]
    async fn a_full_reload_without_the_feed_does_not_count_as_loaded() {
        let gateway = gateway(FakeSource::with(&[]), settings(1, SOON));

        gateway.follower.reload_everything(Cause::Routine).await;

        assert!(!gateway.follower.loaded().is_loaded());
    }

    /// The whole loop: a sealed change published on the bus reaches the
    /// tables.
    #[tokio::test]
    async fn a_published_change_reaches_the_tables() {
        let acme = TenantId::new();
        let gateway = gateway(
            FakeSource::with(&[(acme, Answer::Serves)]),
            settings(2, SOON),
        );
        let (subject, payload) = event(acme, "routing.route_created");
        let seal = EventSeal::control_plane(&root()).seal(&subject, &payload);
        let tables = gateway.tables.clone();
        let bus = gateway.bus.clone();
        let loaded = gateway.follower.loaded();
        tokio::spawn(gateway.follower.run());
        assert!(eventually(|| loaded.is_loaded()).await);
        tables.withdraw(&acme);

        bus.publish(&ianua_infra::bus::SealedEvent {
            subject: &subject,
            id: &Uuid::now_v7().to_string(),
            payload: &payload,
            seal: &seal,
        })
        .await
        .unwrap();

        assert!(eventually(|| tables.serves(acme)).await);
    }

    /// A feed that says once that events went by unheard, then ends.
    struct MissedOnce(bool);

    #[async_trait]
    impl EventFeed for MissedOnce {
        async fn next(&mut self) -> Option<Heard> {
            std::mem::take(&mut self.0).then_some(Heard::Missed)
        }
    }
}
