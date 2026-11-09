//! Accounts' channels: the one address a service sends every event of an
//! account to, each row under row-level security; and the reads across
//! every tenant that a delivery and the sweeps need.
//!
//! A delivery names a channel by the id in its address before its tenant is
//! known, so it is read in every database a tenant lives in. What proves a
//! delivery arrives sealed and is kept as it is. A channel is opened with
//! one insert that writes nothing if the account already has one, so two
//! publishes at once make one.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{AccountChannelStore, ChannelAt, ChannelDirectory};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::triggers::channel::AccountChannel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AccountChannelId, IntegrationAccountId};
use time::OffsetDateTime;

use self::record::{ChannelColumns, ChannelHit, ChannelRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::tenant_databases::everywhere::everywhere;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of accounts' channels.
pub struct PgAccountChannelStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAccountChannelStore {}

impl PgAccountChannelStore {
    /// A store keeping channels in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The Postgres reads of channels across every tenant.
pub struct PgChannelDirectory {
    databases: Arc<Databases>,
}

impl PgChannelDirectory {
    /// Reads of the channels kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Where the channel `id` is kept under `scope`.
    async fn named(
        &self,
        scope: RowScope,
        id: &AccountChannelId,
    ) -> Result<Vec<ChannelHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                ChannelHit,
                "queries/workflow_account_channels/find.sql",
                id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// Up to `limit` live channels lapsing before `before` under `scope`.
    async fn lapsing(
        &self,
        scope: RowScope,
        before: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<ChannelHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                ChannelHit,
                "queries/workflow_account_channels/due.sql",
                before,
                limit
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// Up to `limit` channels no live registration waits on, unchanged
    /// since `before`, under `scope`.
    async fn unused(
        &self,
        scope: RowScope,
        before: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<ChannelHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                ChannelHit,
                "queries/workflow_account_channels/idle.sql",
                before,
                limit
            )
            .fetch_all(connection)
            .await
        })
        .await
    }
}

/// `found` as where each channel is kept, at most `limit` of them.
fn places(found: Vec<ChannelHit>, limit: u32) -> Vec<ChannelAt> {
    found
        .into_iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(|hit| ChannelAt {
            tenant_id: hit.tenant(),
            channel_id: AccountChannelId::from_uuid(hit.id),
        })
        .collect()
}

#[async_trait]
impl AccountChannelStore for PgAccountChannelStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccountChannelId,
    ) -> Result<Option<AccountChannel<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChannelRecord,
                    "queries/workflow_account_channels/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ChannelRecord::into_channel).transpose()
    }

    async fn of_account(
        &self,
        tenant_id: &ScopedTenant,
        account: &IntegrationAccountId,
    ) -> Result<Option<AccountChannel<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChannelRecord,
                    "queries/workflow_account_channels/of_account.sql",
                    tenant_id.as_uuid(),
                    account.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ChannelRecord::into_channel).transpose()
    }

    async fn insert_if_absent(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let c = ChannelColumns::of(channel);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_account_channels/insert.sql",
                    c.id,
                    tenant_id.as_uuid(),
                    c.account_id,
                    c.integration,
                    c.secret_sealed,
                    c.setup,
                    c.status,
                    c.remote,
                    c.lapses_at,
                    c.history_cursor,
                    c.created_at,
                    c.updated_at,
                )
                .execute(connection)
                .await
                .map(|done| done.rows_affected() == 1)
            },
        )
        .await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = ChannelColumns::of(channel);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_account_channels/save.sql",
                    tenant_id.as_uuid(),
                    c.id,
                    c.secret_sealed,
                    c.status,
                    c.remote,
                    c.lapses_at,
                    c.history_cursor,
                    c.updated_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn remove(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccountChannelId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_account_channels/remove.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
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
impl ChannelDirectory for PgChannelDirectory {
    async fn find(&self, id: &AccountChannelId) -> Result<Option<ChannelAt>, DomainError> {
        let found = everywhere(
            &self.databases,
            |scope| self.named(scope, id),
            ChannelHit::tenant,
        )
        .await?;
        if found.len() > 1 {
            return Err(DomainError::infra_msg("two tenants keep one channel's id"));
        }
        Ok(places(found, 1).into_iter().next())
    }

    async fn due(&self, before: OffsetDateTime, limit: u32) -> Result<Vec<ChannelAt>, DomainError> {
        let most = i64::from(limit);
        let found = everywhere(
            &self.databases,
            |scope| self.lapsing(scope, before, most),
            ChannelHit::tenant,
        )
        .await?;
        Ok(places(found, limit))
    }

    async fn idle(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<ChannelAt>, DomainError> {
        let most = i64::from(limit);
        let found = everywhere(
            &self.databases,
            |scope| self.unused(scope, before, most),
            ChannelHit::tenant,
        )
        .await?;
        Ok(places(found, limit))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::workflows::IntegrationAccountStore as _;
    use ianua_domain::domains::workflows::account::IntegrationAccount;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::triggers::channel::{
        ChannelCursor, ChannelSetup, ChannelStatus, HistoryPlace, OpenChannel,
    };
    use ianua_domain::domains::workflows::triggers::subscription::{Lapse, RemoteRegistration};
    use ianua_domain::shared::clock;
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{SealedSecret, TenantId};
    use time::Duration;

    use super::*;
    use crate::postgres::workflows::PgIntegrationAccountStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::workflows::account_row;

    struct Fixture {
        _db: TestDb,
        store: PgAccountChannelStore,
        directory: PgChannelDirectory,
        tenant: ScopedTenant,
        account: IntegrationAccount<ResolvedTenant>,
    }

    /// A fresh database, one tenant with one account, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let account = IntegrationAccount::reconstitute(account_row("Mailbox", 0)).unwrap();
        PgIntegrationAccountStore::new(Arc::clone(&db.databases))
            .save(&tenant, &account)
            .await
            .unwrap();
        Fixture {
            store: PgAccountChannelStore::new(Arc::clone(&db.databases)),
            directory: PgChannelDirectory::new(Arc::clone(&db.databases)),
            tenant,
            account,
            _db: db,
        }
    }

    impl Fixture {
        fn opened(&self, setup: ChannelSetup) -> AccountChannel<ResolvedTenant> {
            AccountChannel::open(OpenChannel {
                id: AccountChannelId::new(),
                account: *self.account.id(),
                integration: IntegrationKey::new("gmail").unwrap(),
                secret: SealedSecret::new("v1.c2VjcmV0").unwrap(),
                setup,
            })
            .unwrap()
        }

        async fn kept(&self, id: &AccountChannelId) -> AccountChannel<ResolvedTenant> {
            self.store
                .find_by_id(&self.tenant, id)
                .await
                .unwrap()
                .unwrap()
        }
    }

    /// A mailbox's channel, registered, lapsing and holding its place in
    /// the history, reads back as it was kept, by its id and its account.
    #[tokio::test]
    async fn a_channel_reads_back_as_kept() {
        let fx = fixture().await;
        let mut channel = fx.opened(ChannelSetup::Registered);
        fx.store
            .insert_if_absent(&fx.tenant, &channel)
            .await
            .unwrap();
        let lapses = clock::now() + Duration::days(7);
        channel
            .register(
                RemoteRegistration::new("watch-1").unwrap(),
                Lapse::At(lapses),
                HistoryPlace::At(ChannelCursor::new("1200").unwrap()),
            )
            .unwrap();

        fx.store.save(&fx.tenant, &channel).await.unwrap();

        let by_id = fx.kept(channel.id()).await;
        let by_account = fx
            .store
            .of_account(&fx.tenant, fx.account.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id.status(), ChannelStatus::Live);
        assert_eq!(by_id.history().cursor().unwrap().as_str(), "1200");
        assert_eq!(by_account.id(), channel.id());
    }

    /// Two publishes open a channel for one account at once. The second
    /// insert writes nothing, and the first stays.
    #[tokio::test]
    async fn an_account_has_one_channel() {
        let fx = fixture().await;
        let first = fx.opened(ChannelSetup::Registered);
        let second = fx.opened(ChannelSetup::Registered);

        let took = fx.store.insert_if_absent(&fx.tenant, &first).await.unwrap();
        let again = fx
            .store
            .insert_if_absent(&fx.tenant, &second)
            .await
            .unwrap();

        let kept = fx
            .store
            .of_account(&fx.tenant, fx.account.id())
            .await
            .unwrap()
            .unwrap();
        assert!(took);
        assert!(!again);
        assert_eq!(kept.id(), first.id());
    }

    /// A delivery names only the channel's id, and the directory finds its
    /// tenant; an unknown id finds nothing.
    #[tokio::test]
    async fn the_directory_finds_a_channel_by_its_address() {
        let fx = fixture().await;
        let channel = fx.opened(ChannelSetup::TokenFromService);
        fx.store
            .insert_if_absent(&fx.tenant, &channel)
            .await
            .unwrap();

        let found = fx.directory.find(channel.id()).await.unwrap().unwrap();
        let unknown = fx.directory.find(&AccountChannelId::new()).await.unwrap();

        assert_eq!(found.channel_id, *channel.id());
        assert_eq!(found.tenant_id, *fx.tenant);
        assert!(unknown.is_none());
    }

    /// Only a live channel lapsing inside the window is due.
    #[tokio::test]
    async fn only_a_live_channel_lapsing_soon_is_due() {
        let fx = fixture().await;
        let mut channel = fx.opened(ChannelSetup::Registered);
        fx.store
            .insert_if_absent(&fx.tenant, &channel)
            .await
            .unwrap();
        let lapses = clock::now() + Duration::hours(2);
        channel
            .register(
                RemoteRegistration::new("watch-1").unwrap(),
                Lapse::At(lapses),
                HistoryPlace::Unknown,
            )
            .unwrap();
        fx.store.save(&fx.tenant, &channel).await.unwrap();

        let due = fx
            .directory
            .due(clock::now() + Duration::days(1), 10)
            .await
            .unwrap();
        let not_yet = fx
            .directory
            .due(clock::now() + Duration::hours(1), 10)
            .await
            .unwrap();

        assert_eq!(due.len(), 1);
        assert!(not_yet.is_empty());
    }

    /// A registered channel nothing waits on is idle once old enough. One
    /// set up by hand never is, so its owner need not redo it.
    #[tokio::test]
    async fn only_a_registered_channel_goes_idle() {
        let fx = fixture().await;
        let channel = fx.opened(ChannelSetup::Registered);
        fx.store
            .insert_if_absent(&fx.tenant, &channel)
            .await
            .unwrap();
        let later = clock::now() + Duration::hours(2);

        let idle = fx.directory.idle(later, 10).await.unwrap();
        let too_soon = fx
            .directory
            .idle(channel.created_at() - Duration::hours(1), 10)
            .await
            .unwrap();
        fx.store.remove(&fx.tenant, channel.id()).await.unwrap();
        let by_hand = fx.opened(ChannelSetup::PastedKey);
        fx.store
            .insert_if_absent(&fx.tenant, &by_hand)
            .await
            .unwrap();
        let never = fx.directory.idle(later, 10).await.unwrap();

        assert_eq!(idle.len(), 1);
        assert!(too_soon.is_empty());
        assert!(never.is_empty());
    }

    /// Stops: one tenant reading another's channel by its id.
    #[tokio::test]
    async fn another_tenant_does_not_see_a_channel() {
        let fx = fixture().await;
        let channel = fx.opened(ChannelSetup::Registered);
        fx.store
            .insert_if_absent(&fx.tenant, &channel)
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let seen = fx.store.find_by_id(&other, channel.id()).await.unwrap();

        assert!(seen.is_none());
    }
}
