//! The channels people open between a tenant's agents, each row under
//! row-level security.
//!
//! A channel names its two agents and goes with either. Once written, only
//! when a person closed it changes. A list first reads the ids of its
//! page, newest first, then reads those rows by id.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::messaging::{AgentChannelSortField, AgentChannelStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::channels::channel::AgentChannel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentChannelId, AgentId, TenantId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{ChannelColumns, ChannelRecord};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of channels between agents.
pub struct PgAgentChannelStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAgentChannelStore {}

impl PgAgentChannelStore {
    /// A store keeping channels in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The records of the channels of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<ChannelRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        ChannelRecord,
        "queries/agent_channels/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt_all(
    records: Vec<ChannelRecord>,
) -> Result<Vec<AgentChannel<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(ChannelRecord::into_channel)
        .collect()
}

impl SortColumns for AgentChannelSortField {
    fn column(self) -> &'static str {
        match self {
            Self::OpenedAt => "opened_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl AgentChannelStore for PgAgentChannelStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AgentChannel<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ChannelColumns::of(channel);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_channels/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.sender_id,
                    columns.receiver_id,
                    columns.scope_kind,
                    columns.scope_value,
                    columns.max_class,
                    columns.opened_by_kind,
                    columns.opened_by_id,
                    columns.opened_at,
                    columns.expires_at,
                    columns.closed_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentChannelId,
    ) -> Result<Option<AgentChannel<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<AgentChannel<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<AgentChannelSortField>::default();
        let keyset = page.keyset(&order)?;
        let listed =
            PageQuery::ids("id", "agent_channels").filter("tenant_id = ?", *tenant_id.as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, tenant_id, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn unclosed_between(
        &self,
        tenant_id: &ScopedTenant,
        sender: &AgentId,
        receiver: &AgentId,
    ) -> Result<Vec<AgentChannel<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChannelRecord,
                    "queries/agent_channels/between.sql",
                    tenant_id.as_uuid(),
                    sender.as_uuid(),
                    receiver.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn unclosed_into(
        &self,
        tenant_id: &ScopedTenant,
        receiver: &AgentId,
    ) -> Result<Vec<AgentChannel<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChannelRecord,
                    "queries/agent_channels/into.sql",
                    tenant_id.as_uuid(),
                    receiver.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_domain::domains::agents::authority::capability::ResourceRef;
    use ianua_domain::domains::agents::channels::channel::{AgentChannelRow, ChannelScope};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::types::Ending;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::messaging::{an_agent, channel_row};

    struct Fixture {
        db: TestDb,
        store: PgAgentChannelStore,
        tenant: ScopedTenant,
        ledger: AgentId,
        auditor: AgentId,
    }

    /// A fresh database, the store on it, and a tenant with the agents
    /// "ledger" and "auditor".
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let ledger = an_agent(&db, &tenant).await;
        let auditor = an_agent(&db, &tenant).await;
        Fixture {
            store: PgAgentChannelStore::new(Arc::clone(&db.databases)),
            tenant,
            ledger,
            auditor,
            db,
        }
    }

    fn channel(row: AgentChannelRow) -> AgentChannel<ResolvedTenant> {
        AgentChannel::reconstitute(row).unwrap()
    }

    fn ids(channels: &[AgentChannel<ResolvedTenant>]) -> Vec<AgentChannelId> {
        channels.iter().map(|channel| *channel.id()).collect()
    }

    impl Fixture {
        fn opened_by_ledger(&self, seconds: i64) -> AgentChannel<ResolvedTenant> {
            channel(AgentChannelRow {
                opened_at: at(seconds),
                expires_at: at(seconds.saturating_add(3600)),
                ..channel_row(self.ledger, self.auditor)
            })
        }

        async fn save_all(&self, channels: &[&AgentChannel<ResolvedTenant>]) {
            for channel in channels {
                self.store.save(&self.tenant, channel).await.unwrap();
            }
        }

        async fn found(&self, id: &AgentChannelId) -> Option<AgentChannel<ResolvedTenant>> {
            self.store.find_by_id(&self.tenant, id).await.unwrap()
        }
    }

    /// A channel letting two agents share one ledger, up to confidential
    /// data, is found by its id as it was saved.
    #[tokio::test]
    async fn a_saved_channel_is_found_by_its_id() {
        let fx = fixture().await;
        let shared = channel(AgentChannelRow {
            scope: ChannelScope::Resource(ResourceRef::new("ledger:2026-q1").unwrap()),
            max_class: DataClassLevel::Confidential,
            ..channel_row(fx.ledger, fx.auditor)
        });
        fx.save_all(&[&shared]).await;

        let found = fx.found(shared.id()).await.unwrap();

        assert_eq!(found.sender(), shared.sender());
        assert_eq!(found.receiver(), shared.receiver());
        assert_eq!(found.scope(), shared.scope());
        assert_eq!(found.max_class(), DataClassLevel::Confidential);
        assert_eq!(found.opened_by(), shared.opened_by());
        assert_eq!(found.opened_at(), shared.opened_at());
        assert_eq!(found.expires_at(), shared.expires_at());
        assert_eq!(found.closed_at(), None);
    }

    /// An id nobody has finds nothing, and another tenant does not find
    /// this tenant's channel.
    #[tokio::test]
    async fn a_channel_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let open = fx.opened_by_ledger(0);
        fx.save_all(&[&open]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(fx.found(&AgentChannelId::new()).await.is_none());
        assert!(
            fx.store
                .find_by_id(&other, open.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A person closes the channel: saving it again keeps when, and it no
    /// longer counts as unclosed.
    #[tokio::test]
    async fn a_closed_channel_keeps_when_it_was_closed() {
        let fx = fixture().await;
        let open = fx.opened_by_ledger(0);
        fx.save_all(&[&open]).await;
        let closed = channel(AgentChannelRow {
            id: *open.id(),
            ending: Ending::Ended { at: at(60) },
            ..channel_row(fx.ledger, fx.auditor)
        });

        fx.save_all(&[&closed]).await;

        let found = fx.found(open.id()).await.unwrap();
        assert_eq!(found.closed_at(), Some(at(60)));
        assert!(
            fx.store
                .unclosed_between(&fx.tenant, &fx.ledger, &fx.auditor)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// The tenant's channels list newest first, page by page, each page
    /// after the last.
    #[tokio::test]
    async fn channels_are_listed_newest_first() {
        let fx = fixture().await;
        let (old, middle, new) = (
            fx.opened_by_ledger(0),
            fx.opened_by_ledger(10),
            fx.opened_by_ledger(20),
        );
        fx.save_all(&[&middle, &old, &new]).await;

        let page_one = fx
            .store
            .list(&fx.tenant, &PageRequest::first(Limit::new(2).unwrap()))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.store.list(&fx.tenant, &after).await.unwrap();

        assert_eq!(ids(&page_one.items), [*new.id(), *middle.id()]);
        assert_eq!(ids(&page_two.items), [*old.id()]);
        assert!(!page_two.has_next());
    }

    /// The channels from the ledger to the auditor that no person closed
    /// are found oldest first, and none the other way.
    #[tokio::test]
    async fn the_unclosed_channels_between_two_agents_are_found() {
        let fx = fixture().await;
        let (old, new) = (fx.opened_by_ledger(0), fx.opened_by_ledger(10));
        let closed = channel(AgentChannelRow {
            ending: Ending::Ended { at: at(5) },
            ..channel_row(fx.ledger, fx.auditor)
        });
        fx.save_all(&[&new, &old, &closed]).await;

        let forward = fx
            .store
            .unclosed_between(&fx.tenant, &fx.ledger, &fx.auditor)
            .await
            .unwrap();
        let backward = fx
            .store
            .unclosed_between(&fx.tenant, &fx.auditor, &fx.ledger)
            .await
            .unwrap();

        assert_eq!(ids(&forward), [*old.id(), *new.id()]);
        assert!(backward.is_empty());
    }

    /// The unclosed channels into the auditor are found from every agent,
    /// and none into the ledger.
    #[tokio::test]
    async fn the_unclosed_channels_into_an_agent_are_found() {
        let fx = fixture().await;
        let reporter = an_agent(&fx.db, &fx.tenant).await;
        let from_ledger = fx.opened_by_ledger(0);
        let from_reporter = channel(AgentChannelRow {
            opened_at: at(10),
            expires_at: at(3610),
            ..channel_row(reporter, fx.auditor)
        });
        fx.save_all(&[&from_reporter, &from_ledger]).await;

        let into_auditor = fx
            .store
            .unclosed_into(&fx.tenant, &fx.auditor)
            .await
            .unwrap();
        let into_ledger = fx
            .store
            .unclosed_into(&fx.tenant, &fx.ledger)
            .await
            .unwrap();

        assert_eq!(ids(&into_auditor), [*from_ledger.id(), *from_reporter.id()]);
        assert!(into_ledger.is_empty());
    }

    /// Saving a channel to an unknown agent returns an infrastructure
    /// error and leaves no channel to read.
    #[tokio::test]
    async fn a_channel_to_an_unknown_agent_is_refused() {
        let fx = fixture().await;
        let nowhere = channel(channel_row(fx.ledger, AgentId::new()));

        let saved = fx.store.save(&fx.tenant, &nowhere).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
        assert!(fx.found(nowhere.id()).await.is_none());
    }

    /// A tenant with a database of its own keeps its channels there,
    /// beside its agents.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_channels_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let (sender, receiver) = (
            an_agent(&fx.db, &apart).await,
            an_agent(&fx.db, &apart).await,
        );
        let open = channel(channel_row(sender, receiver));

        fx.store.save(&apart, &open).await.unwrap();

        let there = PgAgentChannelStore::new(Arc::clone(&own.databases));
        assert!(there.find_by_id(&apart, open.id()).await.unwrap().is_some());
    }

    /// A stored channel naming topics outside the sender's namespace fails
    /// to load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_channel_is_refused() {
        let fx = fixture().await;
        let open = fx.opened_by_ledger(0);
        fx.save_all(&[&open]).await;
        fx.db
            .tamper("UPDATE agent_channels SET scope_value = 'payroll.>'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, open.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
