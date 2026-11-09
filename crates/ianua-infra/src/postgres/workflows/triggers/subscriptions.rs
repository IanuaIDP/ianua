//! Workflows' registrations at the services whose events start them, and
//! the deliveries that already started a run, each table row under
//! row-level security; and the reads across every tenant that a delivery
//! and the sweeps need.
//!
//! A delivery names a registration by the id in its address, or, at an
//! app's one address, by a key such as a Slack workspace, before its
//! tenant is known, so both are read in every database a tenant lives in.
//! The secret a service signs with arrives sealed and is kept as it is.
//! A delivery is noted with one insert that writes nothing the second time,
//! so two copies arriving at once start one run. The renewal sweep reads
//! the soonest to lapse from every database and takes the soonest of all;
//! the retention sweep forgets old deliveries in each database, a page at a
//! time.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{
    DeliveryId, DeliveryLedger, DeliveryRetention, RouteKey, Routing, ServiceSubscriptionStore,
    SubscriptionAt, SubscriptionDirectory,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::triggers::subscription::ServiceSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SealedSecret, ServiceSubscriptionId, WorkflowId};
use time::OffsetDateTime;

pub(in crate::postgres::workflows::triggers) use self::record::registration_from;
use self::record::{DueHit, SubscriptionColumns, SubscriptionHit, SubscriptionRecord, route_key};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::tenant_databases::everywhere::everywhere;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of registrations at services.
pub struct PgServiceSubscriptionStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgServiceSubscriptionStore {}

impl PgServiceSubscriptionStore {
    /// A store keeping registrations in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The Postgres reads of registrations across every tenant: the one a
/// delivery's address names, those a keyed delivery is for, and those due
/// for renewal.
pub struct PgSubscriptionDirectory {
    databases: Arc<Databases>,
}

impl PgSubscriptionDirectory {
    /// Reads of the registrations kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Where the registration `id` is kept under `scope`.
    async fn named(
        &self,
        scope: RowScope,
        id: &ServiceSubscriptionId,
    ) -> Result<Vec<SubscriptionHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                SubscriptionHit,
                "queries/workflow_service_subscriptions/find.sql",
                id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// The live registrations of `integration` named by `key` under
    /// `scope`.
    async fn keyed(
        &self,
        scope: RowScope,
        integration: &IntegrationKey,
        key: &RouteKey,
    ) -> Result<Vec<SubscriptionHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                SubscriptionHit,
                "queries/workflow_service_subscriptions/routed.sql",
                integration.as_str(),
                key.as_str()
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// Up to `limit` registrations waiting on their service since before
    /// `before` under `scope`, the oldest first.
    async fn waiting_since(
        &self,
        scope: RowScope,
        before: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<SubscriptionHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                SubscriptionHit,
                "queries/workflow_service_subscriptions/stale_waiting.sql",
                before,
                limit
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// Up to `limit` live registrations lapsing before `before` under
    /// `scope`, the soonest first.
    async fn lapsing(
        &self,
        scope: RowScope,
        before: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<DueHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                DueHit,
                "queries/workflow_service_subscriptions/due.sql",
                before,
                limit
            )
            .fetch_all(connection)
            .await
        })
        .await
    }
}

#[async_trait]
impl ServiceSubscriptionStore for PgServiceSubscriptionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceSubscriptionId,
    ) -> Result<Option<ServiceSubscription<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SubscriptionRecord,
                    "queries/workflow_service_subscriptions/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record
            .map(SubscriptionRecord::into_subscription)
            .transpose()
    }

    async fn list_for_workflow(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<Vec<ServiceSubscription<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SubscriptionRecord,
                    "queries/workflow_service_subscriptions/of_workflow.sql",
                    tenant_id.as_uuid(),
                    workflow_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(SubscriptionRecord::into_subscription)
            .collect()
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        routing: &Routing,
    ) -> Result<(), DomainError> {
        let c = SubscriptionColumns::of(subscription)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_service_subscriptions/insert.sql",
                    c.id,
                    tenant_id.as_uuid(),
                    c.workflow_id,
                    c.version,
                    c.integration,
                    c.trigger,
                    c.secret_sealed,
                    c.status,
                    c.remote,
                    c.lapses_at,
                    route_key(routing),
                    c.label,
                    c.created_at,
                    c.updated_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = SubscriptionColumns::of(subscription)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_service_subscriptions/save.sql",
                    tenant_id.as_uuid(),
                    c.id,
                    c.status,
                    c.remote,
                    c.lapses_at,
                    c.updated_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        routing: &Routing,
    ) -> Result<(), DomainError> {
        let c = SubscriptionColumns::of(subscription)?;
        let taken = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_service_subscriptions/take.sql",
                    tenant_id.as_uuid(),
                    c.id,
                    c.status,
                    c.remote,
                    c.lapses_at,
                    route_key(routing),
                    c.updated_at,
                )
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
            },
        )
        .await?;
        if taken == 0 {
            return Err(DomainError::infra_msg(
                "a registration was no longer waiting when its service answered",
            ));
        }
        Ok(())
    }

    async fn take_service_secret(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceSubscriptionId,
        secret: &SealedSecret,
    ) -> Result<bool, DomainError> {
        let at = clock::now();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_service_subscriptions/take_service_secret.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid(),
                    secret.as_str(),
                    at,
                )
                .execute(connection)
                .await
                .map(|done| done.rows_affected() == 1)
            },
        )
        .await
    }

    async fn forget_waiting(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceSubscriptionId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_service_subscriptions/forget_waiting.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid(),
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[async_trait]
impl SubscriptionDirectory for PgSubscriptionDirectory {
    async fn find(
        &self,
        id: &ServiceSubscriptionId,
    ) -> Result<Option<SubscriptionAt>, DomainError> {
        let found = everywhere(
            &self.databases,
            |scope| self.named(scope, id),
            SubscriptionHit::tenant,
        )
        .await?;
        if found.len() > 1 {
            return Err(DomainError::infra_msg(
                "two tenants keep one registration's id",
            ));
        }
        Ok(found.into_iter().next().map(|hit| SubscriptionAt {
            tenant_id: hit.tenant(),
            subscription_id: ServiceSubscriptionId::from_uuid(hit.id),
        }))
    }

    async fn routed(
        &self,
        integration: &IntegrationKey,
        key: &RouteKey,
    ) -> Result<Vec<SubscriptionAt>, DomainError> {
        let found = everywhere(
            &self.databases,
            |scope| self.keyed(scope, integration, key),
            SubscriptionHit::tenant,
        )
        .await?;
        Ok(found
            .into_iter()
            .map(|hit| SubscriptionAt {
                tenant_id: hit.tenant(),
                subscription_id: ServiceSubscriptionId::from_uuid(hit.id),
            })
            .collect())
    }

    async fn due(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<SubscriptionAt>, DomainError> {
        let most = i64::from(limit);
        let mut found = everywhere(
            &self.databases,
            |scope| self.lapsing(scope, before, most),
            DueHit::tenant,
        )
        .await?;
        found.sort_by_key(|hit| (hit.lapses_at, hit.id));
        found.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(found
            .into_iter()
            .map(|hit| SubscriptionAt {
                tenant_id: hit.tenant(),
                subscription_id: ServiceSubscriptionId::from_uuid(hit.id),
            })
            .collect())
    }

    async fn stale_waiting(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<SubscriptionAt>, DomainError> {
        let most = i64::from(limit);
        let found = everywhere(
            &self.databases,
            |scope| self.waiting_since(scope, before, most),
            SubscriptionHit::tenant,
        )
        .await?;
        Ok(found
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(|hit| SubscriptionAt {
                tenant_id: hit.tenant(),
                subscription_id: ServiceSubscriptionId::from_uuid(hit.id),
            })
            .collect())
    }
}

/// The Postgres ledger of deliveries that started a run.
pub struct PgDeliveryLedger {
    databases: Arc<Databases>,
}

impl TenantScoped for PgDeliveryLedger {}

impl PgDeliveryLedger {
    /// A ledger kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The Postgres sweep forgetting, across every tenant, the deliveries no
/// service would send again.
pub struct PgDeliveryRetention {
    databases: Arc<Databases>,
}

impl PgDeliveryRetention {
    /// A sweep of the deliveries kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Forgets up to `limit` deliveries noted before `before` under
    /// `scope`, and how many it forgot.
    async fn forgotten(
        &self,
        scope: RowScope,
        before: OffsetDateTime,
        limit: i64,
    ) -> Result<u64, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file!(
                "queries/workflow_service_deliveries/forget.sql",
                before,
                limit
            )
            .execute(connection)
            .await
            .map(|done| done.rows_affected())
        })
        .await
    }
}

#[async_trait]
impl DeliveryLedger for PgDeliveryLedger {
    async fn first_time(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &ServiceSubscriptionId,
        delivery: &DeliveryId,
    ) -> Result<bool, DomainError> {
        let noted = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_service_deliveries/note.sql",
                    tenant_id.as_uuid(),
                    subscription.as_uuid(),
                    delivery.as_str(),
                    clock::now(),
                )
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
            },
        )
        .await?;
        Ok(noted == 1)
    }
}

#[async_trait]
impl DeliveryRetention for PgDeliveryRetention {
    async fn forget_before(&self, before: OffsetDateTime, limit: u32) -> Result<u64, DomainError> {
        let limit = i64::from(limit);
        let own = self.databases.with_own_database();
        let (shared, apart) = futures_util::try_join!(
            self.forgotten(RowScope::Platform, before, limit),
            try_join_all(own.into_iter().map(|tenant| self.forgotten(
                RowScope::Tenant(tenant),
                before,
                limit
            )))
        )?;
        Ok(apart.into_iter().fold(shared, u64::saturating_add))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::workflows::WorkflowStore;
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::triggers::subscription::{Lapse, RemoteRegistration};
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{IntegrationAccountId, TenantId};

    use super::*;
    use crate::postgres::workflows::PgWorkflowStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::workflows::{published_row, subscription_row};

    struct Fixture {
        db: TestDb,
        store: PgServiceSubscriptionStore,
        directory: PgSubscriptionDirectory,
        tenant: ScopedTenant,
        workflow: Workflow<ResolvedTenant>,
    }

    /// A fresh database, one tenant with a published workflow, and the
    /// store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let workflow = Workflow::reconstitute(published_row("watch", 0)).unwrap();
        PgWorkflowStore::new(Arc::clone(&db.databases))
            .insert(&tenant, &workflow)
            .await
            .unwrap();
        Fixture {
            store: PgServiceSubscriptionStore::new(Arc::clone(&db.databases)),
            directory: PgSubscriptionDirectory::new(Arc::clone(&db.databases)),
            tenant,
            workflow,
            db,
        }
    }

    impl Fixture {
        /// A registration of the published version, live at the service
        /// under `remote`, lapsing as `lapses` says.
        fn live(&self, remote: &str, lapses: Lapse) -> ServiceSubscription<ResolvedTenant> {
            let mut subscription = ServiceSubscription::reconstitute(subscription_row(
                *self.workflow.id(),
                self.workflow.version(),
                IntegrationAccountId::new(),
            ))
            .unwrap();
            subscription
                .register(RemoteRegistration::new(remote).unwrap(), lapses)
                .unwrap();
            subscription
        }
    }

    /// Ann's workflow is registered at the sheets service: the
    /// registration reads back by its id, under its workflow, and across
    /// tenants by the id its address names.
    #[tokio::test]
    async fn a_kept_registration_is_found_three_ways() {
        let fx = fixture().await;
        let kept = fx.live("watch-1", Lapse::Never);

        fx.store
            .insert(&fx.tenant, &kept, &Routing::OwnAddress)
            .await
            .unwrap();

        let by_id = fx.store.find_by_id(&fx.tenant, kept.id()).await.unwrap();
        let listed = fx
            .store
            .list_for_workflow(&fx.tenant, fx.workflow.id())
            .await
            .unwrap();
        let at = fx.directory.find(kept.id()).await.unwrap().unwrap();
        let by_id = by_id.unwrap();
        assert_eq!(by_id.trigger(), kept.trigger());
        assert_eq!(by_id.registration(), kept.registration());
        assert_eq!(listed.len(), 1);
        assert_eq!(at.tenant_id, *fx.tenant);
    }

    impl Fixture {
        /// A registration of the published version, kept waiting on its
        /// service.
        async fn waiting(&self) -> ServiceSubscription<ResolvedTenant> {
            let waiting = ServiceSubscription::reconstitute(subscription_row(
                *self.workflow.id(),
                self.workflow.version(),
                IntegrationAccountId::new(),
            ))
            .unwrap();
            self.store
                .insert(&self.tenant, &waiting, &Routing::OwnAddress)
                .await
                .unwrap();
            waiting
        }
    }

    /// Slack answered while Ann's publish was open: the registration kept
    /// waiting moves to live under Slack's name and its workspace's key,
    /// and reads back routed by it.
    #[tokio::test]
    async fn a_waiting_registration_takes_what_its_service_answered() {
        let fx = fixture().await;
        let mut waiting = fx.waiting().await;
        waiting
            .register(RemoteRegistration::new("hook-9").unwrap(), Lapse::Never)
            .unwrap();
        let key = RouteKey::new("T1".to_owned());

        fx.store
            .take(&fx.tenant, &waiting, &Routing::Keyed(key.clone()))
            .await
            .unwrap();

        let routed = fx
            .directory
            .routed(&IntegrationKey::new("google-sheets").unwrap(), &key)
            .await
            .unwrap();
        assert_eq!(routed.len(), 1);
    }

    /// The sweep gave up on a registration before its service answered.
    /// Its publish is told, and does not bring it back.
    #[tokio::test]
    async fn a_registration_no_longer_waiting_cannot_be_taken() {
        let fx = fixture().await;
        let mut waiting = fx.waiting().await;
        fx.store
            .forget_waiting(&fx.tenant, waiting.id())
            .await
            .unwrap();
        waiting
            .register(RemoteRegistration::new("hook-9").unwrap(), Lapse::Never)
            .unwrap();

        let taken = fx
            .store
            .take(&fx.tenant, &waiting, &Routing::OwnAddress)
            .await;

        assert!(taken.is_err());
    }

    /// Asana hands over its secret while the registration waits. The first
    /// is kept in place of the platform's; a second replaces nothing, and
    /// taking the service's answer leaves the secret as it stands.
    #[tokio::test]
    async fn the_first_secret_a_service_hands_over_is_the_one_kept() {
        let fx = fixture().await;
        let mut waiting = fx.waiting().await;
        let first = SealedSecret::new("v1.Zmlyc3Q").unwrap();
        let second = SealedSecret::new("v1.c2Vjb25k").unwrap();

        let took = fx
            .store
            .take_service_secret(&fx.tenant, waiting.id(), &first)
            .await
            .unwrap();
        let again = fx
            .store
            .take_service_secret(&fx.tenant, waiting.id(), &second)
            .await
            .unwrap();
        waiting
            .register(RemoteRegistration::new("hook-9").unwrap(), Lapse::Never)
            .unwrap();
        fx.store
            .take(&fx.tenant, &waiting, &Routing::OwnAddress)
            .await
            .unwrap();

        let kept = fx
            .store
            .find_by_id(&fx.tenant, waiting.id())
            .await
            .unwrap()
            .unwrap();
        assert!(took);
        assert!(!again);
        assert_eq!(kept.secret(), &first);
    }

    /// Stops: Mallory learns the address of a live registration and sends
    /// a secret of her own. It replaces nothing.
    #[tokio::test]
    async fn a_live_registration_takes_no_service_secret() {
        let fx = fixture().await;
        let live = fx.live("hook-1", Lapse::Never);
        fx.store
            .insert(&fx.tenant, &live, &Routing::OwnAddress)
            .await
            .unwrap();
        let mallorys = SealedSecret::new("v1.bWFsbG9yeQ").unwrap();

        let took = fx
            .store
            .take_service_secret(&fx.tenant, live.id(), &mallorys)
            .await
            .unwrap();

        assert!(!took);
    }

    /// Forgetting removes only a registration still waiting; a live one
    /// stays, however it came to be named.
    #[tokio::test]
    async fn only_a_waiting_registration_is_forgotten() {
        let fx = fixture().await;
        let waiting = fx.waiting().await;
        let live = fx.live("hook-1", Lapse::Never);
        fx.store
            .insert(&fx.tenant, &live, &Routing::OwnAddress)
            .await
            .unwrap();

        for id in [waiting.id(), live.id()] {
            fx.store.forget_waiting(&fx.tenant, id).await.unwrap();
        }

        let listed = fx
            .store
            .list_for_workflow(&fx.tenant, fx.workflow.id())
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id(), live.id());
    }

    /// The sweep is given only registrations waiting since before its
    /// moment.
    #[tokio::test]
    async fn the_sweep_is_given_only_registrations_left_waiting() {
        let fx = fixture().await;
        let waiting = fx.waiting().await;
        let live = fx.live("hook-1", Lapse::Never);
        fx.store
            .insert(&fx.tenant, &live, &Routing::OwnAddress)
            .await
            .unwrap();

        let stale = fx
            .directory
            .stale_waiting(waiting.created_at() + time::Duration::hours(1), 10)
            .await
            .unwrap();
        let too_soon = fx
            .directory
            .stale_waiting(waiting.created_at() - time::Duration::hours(1), 10)
            .await
            .unwrap();

        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].subscription_id, *waiting.id());
        assert!(too_soon.is_empty());
    }

    /// The version leaves service: its removed registration is no longer
    /// listed under the workflow.
    #[tokio::test]
    async fn a_removed_registration_is_no_longer_listed() {
        let fx = fixture().await;
        let mut kept = fx.live("watch-1", Lapse::Never);
        fx.store
            .insert(&fx.tenant, &kept, &Routing::OwnAddress)
            .await
            .unwrap();
        kept.remove().unwrap();

        fx.store.save(&fx.tenant, &kept).await.unwrap();

        let listed = fx
            .store
            .list_for_workflow(&fx.tenant, fx.workflow.id())
            .await
            .unwrap();
        assert!(listed.is_empty());
    }

    /// Slack sends an event for workspace T1: only the live registrations
    /// routed by that key are found.
    #[tokio::test]
    async fn a_keyed_delivery_finds_the_live_registrations_of_its_key() {
        let fx = fixture().await;
        let mine = fx.live("watch-1", Lapse::Never);
        let other = fx.live("watch-2", Lapse::Never);
        let key = RouteKey::new("T1".to_owned());
        fx.store
            .insert(&fx.tenant, &mine, &Routing::Keyed(key.clone()))
            .await
            .unwrap();
        fx.store
            .insert(
                &fx.tenant,
                &other,
                &Routing::Keyed(RouteKey::new("T2".to_owned())),
            )
            .await
            .unwrap();

        let routed = fx
            .directory
            .routed(&IntegrationKey::new("google-sheets").unwrap(), &key)
            .await
            .unwrap();

        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].subscription_id, *mine.id());
    }

    /// The renewal sweep is given the registrations lapsing soonest, and
    /// not those that never lapse or lapse later.
    #[tokio::test]
    async fn the_sweep_is_given_the_registrations_lapsing_soonest() {
        let fx = fixture().await;
        let soon = fx.live("soon", Lapse::At(clock::now() + time::Duration::hours(1)));
        let later = fx.live("later", Lapse::At(clock::now() + time::Duration::days(9)));
        let never = fx.live("never", Lapse::Never);
        for kept in [&soon, &later, &never] {
            fx.store
                .insert(&fx.tenant, kept, &Routing::OwnAddress)
                .await
                .unwrap();
        }

        let due = fx
            .directory
            .due(clock::now() + time::Duration::days(1), 10)
            .await
            .unwrap();

        assert_eq!(due.len(), 1);
        assert_eq!(due[0].subscription_id, *soon.id());
    }

    /// Looking up an unknown registration ID returns nothing.
    #[tokio::test]
    async fn an_unknown_registration_is_found_nowhere() {
        let fx = fixture().await;

        let found = fx
            .directory
            .find(&ServiceSubscriptionId::new())
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// GitHub sends a delivery twice: the ledger takes it the first time
    /// only, and the sweep forgets it a week on.
    #[tokio::test]
    async fn a_delivery_is_taken_once_and_forgotten_later() {
        let fx = fixture().await;
        let kept = fx.live("watch-1", Lapse::Never);
        fx.store
            .insert(&fx.tenant, &kept, &Routing::OwnAddress)
            .await
            .unwrap();
        let ledger = PgDeliveryLedger::new(Arc::clone(&fx.db.databases));
        let retention = PgDeliveryRetention::new(Arc::clone(&fx.db.databases));
        let delivery = DeliveryId::new("delivery-1".to_owned());

        let first = ledger
            .first_time(&fx.tenant, kept.id(), &delivery)
            .await
            .unwrap();
        let again = ledger
            .first_time(&fx.tenant, kept.id(), &delivery)
            .await
            .unwrap();
        let kept_now = retention
            .forget_before(clock::now() - time::Duration::hours(1), 100)
            .await
            .unwrap();
        let forgotten = retention
            .forget_before(clock::now() + time::Duration::seconds(1), 100)
            .await
            .unwrap();

        assert!(first);
        assert!(!again);
        assert_eq!(kept_now, 0);
        assert_eq!(forgotten, 1);
    }
}
