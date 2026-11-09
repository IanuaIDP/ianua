//! Keeping the pools of services found by name in step with what the name
//! resolves to.
//!
//! A service whose backends are found by name starts on the addresses its
//! upstream was written with, the fallback the domain gives until the name
//! first resolves. From then on the watch asks the resolver on the
//! service's own refresh interval and puts each answer in the pool, which
//! keeps the state of every backend that stays. Nothing is rebuilt.
//!
//! An answer with no backends empties the pool, and the service's routes
//! are refused: a deployment scaled to zero has nothing behind its name,
//! and nothing stands in for it. A resolver that cannot be reached is
//! different: the last answer stays, since a resolver that blips is far
//! likelier than every replica vanishing at once.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use futures_util::{StreamExt, stream};
use ianua_app::ports::routing::BackendDiscovery;
use ianua_domain::domains::routing::backend::discovery::{DiscoveredBackends, Discovery};
use ianua_domain::domains::routing::backend::upstream::WeightedBackend;
use ianua_domain::types::{HttpUrl, ServiceId, TenantId};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use super::pool::ServicePool;
use super::settings::DiscoverySettings;
use super::{locked, period};

/// A service's pool, as one tenant's.
type PoolKey = (TenantId, ServiceId);

/// The services whose backends are found by name, and when each was last
/// looked up.
pub(crate) struct DiscoveryWatch {
    resolver: Arc<dyn BackendDiscovery>,
    settings: DiscoverySettings,
    watching: Mutex<HashMap<PoolKey, Watched>>,
}

/// One service being watched.
struct Watched {
    pool: Arc<ServicePool>,
    discovery: Discovery,
    configured: HttpUrl,
    last_resolved: Option<Instant>,
}

/// A lookup to make now.
struct Due {
    pool: Arc<ServicePool>,
    discovery: Discovery,
    configured: HttpUrl,
}

impl DiscoveryWatch {
    /// A watch asking `resolver`, held to `settings`.
    #[must_use]
    pub(crate) fn new(resolver: Arc<dyn BackendDiscovery>, settings: DiscoverySettings) -> Self {
        Self {
            resolver,
            settings,
            watching: Mutex::new(HashMap::new()),
        }
    }

    /// How many services are watched.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn watching_count(&self) -> usize {
        locked(&self.watching).len()
    }

    /// Looks up the services that are due on every tick until `cancel`
    /// fires.
    pub(crate) async fn run(self: Arc<Self>, cancel: CancellationToken) {
        let mut ticks = tokio::time::interval(period(self.settings.tick));
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            let round = async {
                ticks.tick().await;
                self.refresh_due(Instant::now()).await;
            };
            tokio::select! {
                () = cancel.cancelled() => return,
                () = round => {}
            }
        }
    }

    /// Replaces what is watched for one tenant with its pools found by
    /// name. A pool that is the same as before keeps its last lookup time;
    /// a new one is due at once.
    pub(super) fn watch_tenant(
        &self,
        tenant_id: TenantId,
        pools: &[(ServiceId, Arc<ServicePool>)],
    ) {
        let mut watching = locked(&self.watching);
        let previous = take_tenant(&mut watching, tenant_id);
        for (service_id, pool) in pools {
            let Some(discovery) = pool.upstream().discovery().cloned() else {
                continue;
            };
            let last_resolved = previous
                .get(service_id)
                .filter(|known| Arc::ptr_eq(&known.pool, pool))
                .and_then(|known| known.last_resolved);
            let watched = Watched {
                pool: Arc::clone(pool),
                discovery,
                configured: pool.upstream().url().clone(),
                last_resolved,
            };
            watching.insert((tenant_id, *service_id), watched);
        }
    }

    /// Stops watching a tenant's services.
    pub(super) fn drop_tenant(&self, tenant_id: TenantId) {
        locked(&self.watching).retain(|(tenant, _), _| *tenant != tenant_id);
    }

    /// Looks up every service whose refresh interval has passed by `now`,
    /// at most the configured number at once.
    pub(super) async fn refresh_due(&self, now: Instant) {
        let due = self.take_due(now);
        let limit = self.settings.max_in_flight.get();
        stream::iter(due)
            .for_each_concurrent(limit, |due| self.refresh(due))
            .await;
    }

    /// The services due by `now`, marked as looked up at `now`.
    fn take_due(&self, now: Instant) -> Vec<Due> {
        locked(&self.watching)
            .values_mut()
            .filter(|watched| is_due(watched, now))
            .map(|watched| {
                watched.last_resolved = Some(now);
                Due {
                    pool: Arc::clone(&watched.pool),
                    discovery: watched.discovery.clone(),
                    configured: watched.configured.clone(),
                }
            })
            .collect()
    }

    /// Looks one service up and puts the answer in its pool. A lookup that
    /// fails or takes too long leaves the pool as it was.
    async fn refresh(&self, due: Due) {
        let lookup = self.resolver.resolve(&due.discovery, &due.configured);
        let answered = tokio::time::timeout(self.settings.lookup_timeout, lookup).await;
        let Ok(Ok(answer)) = answered else {
            tracing::warn!(
                name = %due.discovery.name(),
                "a service's name could not be looked up; its backends stay as they were"
            );
            return;
        };
        if answer.is_empty() {
            tracing::warn!(
                name = %due.discovery.name(),
                "a service's name resolves to no backends; its routes are refused"
            );
        }
        due.pool.replace_backends(weighted(&answer));
    }
}

/// Removes and returns what is watched for `tenant_id`, by service.
fn take_tenant(
    watching: &mut HashMap<PoolKey, Watched>,
    tenant_id: TenantId,
) -> HashMap<ServiceId, Watched> {
    let keys: Vec<PoolKey> = watching
        .keys()
        .filter(|(tenant, _)| *tenant == tenant_id)
        .copied()
        .collect();
    keys.into_iter()
        .filter_map(|key| watching.remove(&key).map(|watched| (key.1, watched)))
        .collect()
}

/// Whether `watched` is due for a lookup by `now`.
fn is_due(watched: &Watched, now: Instant) -> bool {
    let interval = watched.discovery.refresh_secs().std_duration();
    watched
        .last_resolved
        .is_none_or(|last| now.saturating_duration_since(last) >= interval)
}

/// The backends of `answer`, a weight of zero read as the least weight: a
/// target published at zero is meant to be picked rarely, never left out.
fn weighted(answer: &DiscoveredBackends) -> Vec<WeightedBackend> {
    answer
        .as_slice()
        .iter()
        .map(|found| {
            let weight = NonZeroU32::new(found.weight).unwrap_or(NonZeroU32::MIN);
            WeightedBackend::new(found.url.clone(), weight)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use ianua_domain::domains::routing::backend::discovery::{
        DiscoveredBackend, DiscoveryKind, DiscoveryName,
    };
    use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::Seconds;

    use super::*;
    use crate::forward::error::ForwardError;
    use crate::forward::tests::support::{discovery_settings, pool_with, upstream_over};

    /// A resolver whose answer the test chooses, or which cannot be reached.
    struct Resolver {
        answer: Mutex<Option<Vec<&'static str>>>,
        calls: AtomicUsize,
    }

    impl Resolver {
        fn answering(urls: &[&'static str]) -> Arc<Self> {
            Arc::new(Self {
                answer: Mutex::new(Some(urls.to_vec())),
                calls: AtomicUsize::new(0),
            })
        }

        fn now_answers(&self, urls: &[&'static str]) {
            *self.answer.lock().unwrap() = Some(urls.to_vec());
        }

        fn goes_away(&self) {
            *self.answer.lock().unwrap() = None;
        }
    }

    #[async_trait]
    impl BackendDiscovery for Resolver {
        async fn resolve(
            &self,
            _discovery: &Discovery,
            _configured: &HttpUrl,
        ) -> Result<DiscoveredBackends, DomainError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let Some(urls) = self.answer.lock().unwrap().clone() else {
                return Err(DomainError::infra_msg("resolver unreachable"));
            };
            Ok(DiscoveredBackends::new(
                urls.into_iter()
                    .map(|url| DiscoveredBackend {
                        url: HttpUrl::new(url).unwrap(),
                        weight: 0,
                    })
                    .collect(),
            ))
        }
    }

    fn found_by_name(refresh_secs: u32) -> Arc<ServicePool> {
        let discovery = Discovery::new(
            DiscoveryKind::Address,
            DiscoveryName::new("orders.internal").unwrap(),
            Seconds::new(refresh_secs),
        )
        .unwrap();
        let upstream = upstream_over(&["http://10.0.0.1:8080"]).with_discovery(discovery);
        Arc::new(pool_with(&upstream, &HealthCheckPolicy::Disabled))
    }

    fn watching(resolver: Arc<Resolver>, pool: &Arc<ServicePool>) -> DiscoveryWatch {
        let watch = DiscoveryWatch::new(resolver, discovery_settings());
        watch.watch_tenant(TenantId::new(), &[(ServiceId::new(), Arc::clone(pool))]);
        watch
    }

    fn addresses(pool: &ServicePool) -> Vec<String> {
        pool.backends()
            .iter()
            .map(|backend| backend.url().as_str().to_owned())
            .collect()
    }

    fn later(now: Instant, secs: u64) -> Instant {
        now + Duration::from_secs(secs)
    }

    #[tokio::test]
    async fn an_answer_replaces_the_backends() {
        let resolver = Resolver::answering(&["http://10.0.0.7:8080", "http://10.0.0.8:8080"]);
        let pool = found_by_name(5);
        let watch = watching(resolver, &pool);

        watch.refresh_due(Instant::now()).await;

        assert_eq!(
            addresses(&pool),
            vec!["http://10.0.0.7:8080", "http://10.0.0.8:8080"]
        );
    }

    /// Scaled to zero: the resolver answered, and what it said is that
    /// nothing is behind the name. The route is refused, never sent to the
    /// address the service was first written with.
    #[tokio::test]
    async fn a_name_that_resolves_to_nothing_refuses_its_routes() {
        let resolver = Resolver::answering(&[]);
        let pool = found_by_name(5);
        let watch = watching(resolver, &pool);

        watch.refresh_due(Instant::now()).await;

        assert!(matches!(pool.lease(None), Err(ForwardError::NoBackends)));
    }

    #[tokio::test]
    async fn a_resolver_that_fails_leaves_the_last_answer() {
        let resolver = Resolver::answering(&["http://10.0.0.7:8080"]);
        let pool = found_by_name(5);
        let watch = watching(Arc::clone(&resolver), &pool);
        let now = Instant::now();
        watch.refresh_due(now).await;

        resolver.goes_away();
        watch.refresh_due(later(now, 60)).await;

        assert_eq!(addresses(&pool), vec!["http://10.0.0.7:8080"]);
    }

    #[tokio::test]
    async fn a_service_is_not_looked_up_again_before_its_interval() {
        let resolver = Resolver::answering(&["http://10.0.0.7:8080"]);
        let pool = found_by_name(300);
        let watch = watching(Arc::clone(&resolver), &pool);
        let now = Instant::now();

        watch.refresh_due(now).await;
        watch.refresh_due(later(now, 10)).await;
        resolver.now_answers(&["http://10.0.0.9:8080"]);
        watch.refresh_due(later(now, 301)).await;

        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        assert_eq!(addresses(&pool), vec!["http://10.0.0.9:8080"]);
    }

    #[test]
    fn a_tenant_without_named_services_is_not_watched() {
        let watch = DiscoveryWatch::new(Resolver::answering(&[]), discovery_settings());
        let tenant = TenantId::new();
        let pool = Arc::new(pool_with(
            &upstream_over(&["http://10.0.0.1:80"]),
            &HealthCheckPolicy::Disabled,
        ));

        watch.watch_tenant(tenant, &[(ServiceId::new(), pool)]);

        assert_eq!(watch.watching_count(), 0);
    }

    #[test]
    fn dropping_a_tenant_stops_watching_only_its_services() {
        let watch = DiscoveryWatch::new(Resolver::answering(&[]), discovery_settings());
        let kept = TenantId::new();
        watch.watch_tenant(kept, &[(ServiceId::new(), found_by_name(5))]);
        watch.watch_tenant(TenantId::new(), &[(ServiceId::new(), found_by_name(5))]);

        watch.drop_tenant(kept);

        assert_eq!(watch.watching_count(), 1);
    }
}
