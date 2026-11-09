//! A tenant's agents, each table row under row-level security.
//!
//! Every read of an agent goes through one checked query and one mapping
//! into the aggregate. A list first reads the ids of its page, then reads
//! those rows by id. Stopping every agent of a tenant is one statement, so
//! a tenant-wide stop is quick and whole. A revoke is final: a copy read
//! before it never brings the agent back. A name belongs to one agent of a
//! tenant: a second agent of that name, or a rename onto it, is refused as
//! a conflict.

pub(crate) mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::{AgentSortField, AgentStore, AgentVersion};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, HumanAccount, PrincipalRef, TenantId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{AgentColumns, AgentRecord};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a name to one agent of a tenant.
const NAME_KEY: &str = "agents_name_key";

/// The Postgres agent store.
pub struct PgAgentStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAgentStore {}

impl PgAgentStore {
    /// A store keeping agents in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The kind and id columns `account` is kept in.
fn account_columns(account: HumanAccount) -> (&'static str, Uuid) {
    let principal = PrincipalRef::from(account);
    (kind_word(&principal), principal.id())
}

/// The records of the agents of `tenant` that `ids` names, in no order.
pub(crate) async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<AgentRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        AgentRecord,
        "queries/agents/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt(records: Vec<AgentRecord>) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
    records.into_iter().map(AgentRecord::into_agent).collect()
}

/// The refusal of a write that would give `agent` a name another agent of
/// its tenant holds.
fn name_taken(agent: &AgentIdentity<ResolvedTenant>) -> DomainError {
    DomainError::conflict(message!(
        "infra-an-agent-named-already-exists-in",
        format!(
            "an agent named '{}' already exists in this tenant",
            agent.name().as_str()
        )
    ))
}

/// Writes the mapped agent while preserving the tenant's unique name constraint.
async fn write_agent(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    columns: &AgentColumns<'_>,
) -> Result<Uniqueness, sqlx::Error> {
    let attempt = sqlx::query_file!(
        "queries/agents/save.sql",
        columns.id,
        tenant_id.as_uuid(),
        columns.name,
        columns.description,
        columns.owner.kind,
        columns.owner.id,
        columns.owner.person,
        columns.offered_to_kind(),
        columns.offered_to_id(),
        columns.offered_to_person(),
        columns.offered_at,
        columns.offer_expires_at,
        columns.status,
        columns.attestation_policy,
        columns.reattestation_required_since,
        columns.last_attested_at,
        columns.created_at,
        columns.updated_at,
    )
    .execute(connection)
    .await;
    unique_on(attempt, NAME_KEY)
}

/// Writes only over the version read, retaining the resulting version and name conflict.
async fn write_unchanged(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    columns: &AgentColumns<'_>,
    read: AgentVersion,
) -> Result<(Uniqueness, Option<OffsetDateTime>), sqlx::Error> {
    let attempt = sqlx::query_file_scalar!(
        "queries/agents/save_unchanged_since.sql",
        tenant_id.as_uuid(),
        columns.id,
        read.changed_at(),
        columns.name,
        columns.description,
        columns.owner.kind,
        columns.owner.id,
        columns.owner.person,
        columns.offered_to_kind(),
        columns.offered_to_id(),
        columns.offered_to_person(),
        columns.offered_at,
        columns.offer_expires_at,
        columns.status,
        columns.attestation_policy,
        columns.reattestation_required_since,
        columns.last_attested_at,
        columns.updated_at,
    )
    .fetch_optional(connection)
    .await;
    let stored = attempt.as_ref().ok().copied().flatten();
    unique_on(attempt, NAME_KEY).map(|kept| (kept, stored))
}

impl SortColumns for AgentSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl AgentStore for PgAgentStore {
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[AgentId],
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        rebuilt(records)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentId,
    ) -> Result<Option<AgentIdentity<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        Ok(rebuilt(records)?.pop())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<AgentSortField>,
        page: &PageRequest,
    ) -> Result<Page<AgentIdentity<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed = PageQuery::ids("id", "agents").filter("tenant_id = ?", *tenant_id.as_uuid());
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
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn list_owned_by(
        &self,
        tenant_id: &ScopedTenant,
        owner: HumanAccount,
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
        let (kind, id) = account_columns(owner);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AgentRecord,
                    "queries/agents/owned_by.sql",
                    tenant_id.as_uuid(),
                    kind,
                    id
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn list_offered_to(
        &self,
        tenant_id: &ScopedTenant,
        recipient: HumanAccount,
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
        let (kind, id) = account_columns(recipient);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AgentRecord,
                    "queries/agents/offered_to.sql",
                    tenant_id.as_uuid(),
                    kind,
                    id
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = AgentColumns::of(agent)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_agent(connection, tenant_id, &columns).await,
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(name_taken(agent)),
        }
    }

    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentIdentity<ResolvedTenant>,
        read: AgentVersion,
    ) -> Result<AgentVersion, DomainError> {
        let columns = AgentColumns::of(agent)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_unchanged(connection, tenant_id, &columns, read).await,
        )
        .await?;
        match written {
            (Uniqueness::Taken, _) => Err(name_taken(agent)),
            (Uniqueness::Kept, Some(changed_at)) => Ok(AgentVersion::stored(changed_at)),
            (Uniqueness::Kept, None) => Err(DomainError::conflict(message!(
                "infra-the-agent-changed-since-it-was",
                "the agent changed since it was read, or is gone"
            ))),
        }
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &AgentId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agents/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn suspend_every_active(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        let now = clock::now();
        let done = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agents/suspend_active.sql",
                    tenant_id.as_uuid(),
                    now
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(done.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_domain::domains::agents::identity::agent::{
        AgentIdentityRow, Containment, OwnershipOffer,
    };
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{Human, Label, OrgUserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::{agent_row, attesting_agent_row, human, offered_row};
    use crate::test_support::rows::at;

    fn agent(row: AgentIdentityRow) -> AgentIdentity<ResolvedTenant> {
        AgentIdentity::reconstitute(row).unwrap()
    }

    /// A fresh database, the store on it, and one tenant to keep agents in.
    async fn fixture() -> (TestDb, PgAgentStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgAgentStore::new(Arc::clone(&db.databases));
        (db, store, ScopedTenant::for_background(TenantId::new()))
    }

    async fn save_all(
        store: &PgAgentStore,
        tenant: &ScopedTenant,
        agents: &[&AgentIdentity<ResolvedTenant>],
    ) {
        for agent in agents {
            store.save(tenant, agent).await.unwrap();
        }
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn names(page: &Page<AgentIdentity<ResolvedTenant>>) -> Vec<&str> {
        page.items
            .iter()
            .map(|agent| agent.name().as_str())
            .collect()
    }

    /// Reads a known agent, failing the test if it was not stored.
    async fn found(
        store: &PgAgentStore,
        tenant: &ScopedTenant,
        id: &AgentId,
    ) -> AgentIdentity<ResolvedTenant> {
        store.find_by_id(tenant, id).await.unwrap().unwrap()
    }

    /// A rename based on the report identity and its observed version.
    fn renamed_report(
        id: AgentId,
        read: AgentVersion,
        name: &str,
    ) -> AgentIdentity<ResolvedTenant> {
        agent(AgentIdentityRow {
            id,
            name: Label::new("name", name).unwrap(),
            updated_at: read.changed_at(),
            ..agent_row("report")
        })
    }

    /// An agent that attests where it runs, is held until it re-attests and
    /// is offered to Bob is found by its id as it was saved.
    #[tokio::test]
    async fn a_saved_agent_is_found_by_its_id() {
        let (_db, store, tenant) = fixture().await;
        let held = agent(AgentIdentityRow {
            description: Some(Label::new("description", "Reconciles the ledger").unwrap()),
            containment: Containment::ReattestationRequired { since: at(20) },
            last_attested_at: Some(at(10)),
            ..offered_row(attesting_agent_row("ledger"), human("bob@acme.example"))
        });
        save_all(&store, &tenant, &[&held]).await;

        let found = store.find_by_id(&tenant, held.id()).await.unwrap().unwrap();

        assert_eq!(found.name(), held.name());
        assert_eq!(found.description(), held.description());
        assert_eq!(found.owner(), held.owner());
        assert_eq!(found.offer(), held.offer());
        assert_eq!(found.proof(), held.proof());
        assert_eq!(found.containment(), held.containment());
        assert_eq!(found.last_attested_at(), Some(at(10)));
        assert_eq!(found.updated_at(), held.updated_at());
    }

    /// An id nobody has finds nothing, and another tenant does not find this
    /// tenant's agent by id, in a list, or among what its owner owns.
    #[tokio::test]
    async fn an_agent_is_found_only_by_its_tenant() {
        let (_db, store, tenant) = fixture().await;
        let report = agent(agent_row("report"));
        save_all(&store, &tenant, &[&report]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let unknown = store.find_by_id(&tenant, &AgentId::new()).await.unwrap();
        let by_id = store.find_by_id(&other, report.id()).await.unwrap();
        let listed = store
            .list_all(&other, &SortOrder::default(), &first(10))
            .await
            .unwrap();
        let owned = store
            .list_owned_by(&other, report.owner().account())
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(by_id.is_none());
        assert!(listed.items.is_empty());
        assert!(owned.is_empty());
    }

    /// Agent hydration omits missing and foreign ids, returns duplicates
    /// once, and preserves the stored identity of every requested agent.
    #[tokio::test]
    async fn agent_batches_read_only_requested_tenant_identities() {
        let (_db, store, tenant) = fixture().await;
        let one = agent(agent_row("one"));
        let two = agent(agent_row("two"));
        let other = ScopedTenant::for_background(TenantId::new());
        let foreign = agent(agent_row("foreign"));
        save_all(&store, &tenant, &[&one, &two]).await;
        store.save(&other, &foreign).await.unwrap();

        let found = store
            .find_by_ids(
                &tenant,
                &[*one.id(), *one.id(), *foreign.id(), AgentId::new()],
            )
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), one.id());
        assert_eq!(found[0].owner(), one.owner());
        assert!(store.find_by_ids(&tenant, &[]).await.unwrap().is_empty());
    }

    /// The tenant's agents list by name page by page, each page after the
    /// last, and by status with the active ones first.
    #[tokio::test]
    async fn agents_are_listed_page_by_page() {
        let (_db, store, tenant) = fixture().await;
        let off = agent(AgentIdentityRow {
            status: AgentStatus::Suspended,
            ..agent_row("a-off")
        });
        save_all(
            &store,
            &tenant,
            &[
                &agent(agent_row("c-sync")),
                &off,
                &agent(agent_row("b-sync")),
            ],
        )
        .await;
        let by_name = SortOrder::single(Sort::ascending(AgentSortField::Name));
        let by_status = SortOrder::single(Sort::ascending(AgentSortField::Status));

        let page_one = store.list_all(&tenant, &by_name, &first(2)).await.unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = store.list_all(&tenant, &by_name, &after).await.unwrap();
        let statuses = store
            .list_all(&tenant, &by_status, &first(10))
            .await
            .unwrap();

        assert_eq!(names(&page_one), ["a-off", "b-sync"]);
        assert_eq!(names(&page_two), ["c-sync"]);
        assert!(!page_two.has_next());
        assert_eq!(names(&statuses)[2], "a-off");
    }

    /// Ann's agents are found through her tenant account; one offered to
    /// her organization account is found through that account alone.
    #[tokio::test]
    async fn agents_are_found_by_the_account_that_owns_or_was_offered_them() {
        let (_db, store, tenant) = fixture().await;
        let ann = human("ann@acme.example");
        let ann_at_org = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            ann.person().clone(),
        );
        let owned = agent(AgentIdentityRow {
            owner: ann.clone(),
            ..agent_row("owned")
        });
        let offered = agent(offered_row(agent_row("offered"), ann_at_org.clone()));
        save_all(&store, &tenant, &[&owned, &offered]).await;

        let by_owner = store.list_owned_by(&tenant, ann.account()).await.unwrap();
        let by_offer = store
            .list_offered_to(&tenant, ann_at_org.account())
            .await
            .unwrap();
        let not_to_her_tenant_account =
            store.list_offered_to(&tenant, ann.account()).await.unwrap();

        assert_eq!(by_owner.len(), 1);
        assert_eq!(by_owner[0].id(), owned.id());
        assert_eq!(by_offer.len(), 1);
        assert_eq!(by_offer[0].id(), offered.id());
        assert!(not_to_her_tenant_account.is_empty());
        assert!(matches!(by_offer[0].offer(), OwnershipOffer::Open { .. }));
    }

    /// The agent is renamed and handed to Bob: saving it again keeps the new
    /// values and the time it was made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let (_db, store, tenant) = fixture().await;
        let report = agent(agent_row("report"));
        save_all(&store, &tenant, &[&report]).await;
        let bob = human("bob@acme.example");
        let changed = agent(AgentIdentityRow {
            id: *report.id(),
            name: Label::new("name", "invoices").unwrap(),
            owner: bob.clone(),
            updated_at: at(5),
            ..agent_row("report")
        });

        save_all(&store, &tenant, &[&changed]).await;

        let found = store
            .find_by_id(&tenant, report.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "invoices");
        assert_eq!(found.owner(), &bob);
        assert_eq!(found.created_at(), report.created_at());
        assert_eq!(found.updated_at(), at(5));
    }

    /// Saving a rename based on an active copy after revocation changes the
    /// agent's name while preserving its revoked status.
    #[tokio::test]
    async fn a_revoked_agent_stays_revoked_when_an_old_copy_is_saved() {
        let (_db, store, tenant) = fixture().await;
        let report = agent(agent_row("report"));
        let revoked = agent(AgentIdentityRow {
            id: *report.id(),
            status: AgentStatus::Revoked,
            updated_at: at(5),
            ..agent_row("report")
        });
        save_all(&store, &tenant, &[&report, &revoked]).await;
        let renamed = agent(AgentIdentityRow {
            id: *report.id(),
            name: Label::new("name", "invoices").unwrap(),
            updated_at: at(6),
            ..agent_row("report")
        });

        save_all(&store, &tenant, &[&renamed]).await;

        let found = store
            .find_by_id(&tenant, report.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), AgentStatus::Revoked);
        assert_eq!(found.name().as_str(), "invoices");
    }

    /// Saving a second report agent in the same tenant returns a conflict
    /// and leaves only the original agent in the list.
    #[tokio::test]
    async fn a_second_agent_of_a_taken_name_is_refused() {
        let (_db, store, tenant) = fixture().await;
        let report = agent(agent_row("report"));
        save_all(&store, &tenant, &[&report]).await;
        let twin = agent(agent_row("report"));

        let saved = store.save(&tenant, &twin).await;

        let listed = store
            .list_all(&tenant, &SortOrder::default(), &first(10))
            .await
            .unwrap();
        assert!(matches!(saved, Err(DomainError::Conflict(_))), "{saved:?}");
        assert_eq!(listed.items.len(), 1);
        assert_eq!(listed.items[0].id(), report.id());
    }

    /// Another tenant keeps an agent of a name this tenant has taken.
    #[tokio::test]
    async fn a_name_is_taken_only_within_its_tenant() {
        let (_db, store, tenant) = fixture().await;
        save_all(&store, &tenant, &[&agent(agent_row("report"))]).await;
        let other = ScopedTenant::for_background(TenantId::new());
        let theirs = agent(agent_row("report"));

        let saved = store.save(&other, &theirs).await;

        let found = store.find_by_id(&other, theirs.id()).await.unwrap();
        assert!(saved.is_ok(), "{saved:?}");
        assert!(found.is_some());
    }

    /// Renaming ledger to the existing report name returns a conflict and
    /// leaves ledger's name unchanged.
    #[tokio::test]
    async fn a_rename_onto_a_taken_name_is_refused() {
        let (_db, store, tenant) = fixture().await;
        let ledger = agent(agent_row("ledger"));
        save_all(&store, &tenant, &[&agent(agent_row("report")), &ledger]).await;
        let read = store
            .find_by_id(&tenant, ledger.id())
            .await
            .unwrap()
            .unwrap();
        let renamed = agent(AgentIdentityRow {
            id: *ledger.id(),
            name: Label::new("name", "report").unwrap(),
            updated_at: read.updated_at(),
            ..agent_row("ledger")
        });

        let saved = store
            .save_unchanged_since(&tenant, &renamed, AgentVersion::of(&read))
            .await;

        let found = store
            .find_by_id(&tenant, ledger.id())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(saved, Err(DomainError::Conflict(_))), "{saved:?}");
        assert_eq!(found.name().as_str(), "ledger");
    }

    /// Deleting a saved report identity makes the tenant lookup return no row.
    #[tokio::test]
    async fn a_deleted_agent_is_gone() {
        let (_db, store, tenant) = fixture().await;
        let report = agent(agent_row("report"));
        save_all(&store, &tenant, &[&report]).await;

        store.delete(&tenant, report.id()).await.unwrap();

        assert!(
            store
                .find_by_id(&tenant, report.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A tenant-wide stop suspends every active agent of the tenant, leaves
    /// a revoked one and another tenant's alone, and a second stop counts
    /// none.
    #[tokio::test]
    async fn a_tenant_wide_stop_suspends_every_active_agent_once() {
        let (_db, store, tenant) = fixture().await;
        let gone = agent(AgentIdentityRow {
            status: AgentStatus::Revoked,
            ..agent_row("gone")
        });
        let [one, two] = ["one", "two"].map(|name| agent(agent_row(name)));
        save_all(&store, &tenant, &[&one, &two, &gone]).await;
        let other = ScopedTenant::for_background(TenantId::new());
        let theirs = agent(agent_row("theirs"));
        store.save(&other, &theirs).await.unwrap();

        let stopped = store.suspend_every_active(&tenant).await.unwrap();
        let again = store.suspend_every_active(&tenant).await.unwrap();

        let found = store.find_by_id(&tenant, one.id()).await.unwrap().unwrap();
        let still_revoked = store.find_by_id(&tenant, gone.id()).await.unwrap().unwrap();
        let untouched = store
            .find_by_id(&other, theirs.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped, 2);
        assert_eq!(again, 0);
        assert_eq!(found.status(), AgentStatus::Suspended);
        assert!(found.updated_at() >= one.updated_at());
        assert_eq!(still_revoked.status(), AgentStatus::Revoked);
        assert_eq!(untouched.status(), AgentStatus::Active);
    }

    /// A rename using the version read before a fleet stop returns a conflict.
    /// The agent remains suspended with its original name.
    #[tokio::test]
    async fn a_change_read_before_a_fleet_stop_is_refused() {
        let (_db, store, tenant) = fixture().await;
        let report = agent(agent_row("report"));
        save_all(&store, &tenant, &[&report]).await;
        let read = store
            .find_by_id(&tenant, report.id())
            .await
            .unwrap()
            .unwrap();
        let renamed = agent(AgentIdentityRow {
            id: *report.id(),
            name: Label::new("name", "invoices").unwrap(),
            updated_at: read.updated_at(),
            ..agent_row("report")
        });
        store.suspend_every_active(&tenant).await.unwrap();

        let saved = store
            .save_unchanged_since(&tenant, &renamed, AgentVersion::of(&read))
            .await;

        let found = store
            .find_by_id(&tenant, report.id())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(saved, Err(DomainError::Conflict(_))), "{saved:?}");
        assert_eq!(found.status(), AgentStatus::Suspended);
        assert_eq!(found.name().as_str(), "report");
    }

    /// The first rename advances the stored version, so another rename using
    /// the original version conflicts. The returned version permits a later
    /// rename to ledger.
    #[tokio::test]
    async fn of_two_changes_from_one_read_only_the_first_is_kept() {
        let (_db, store, tenant) = fixture().await;
        let report = agent(agent_row("report"));
        save_all(&store, &tenant, &[&report]).await;
        let read = AgentVersion::of(&found(&store, &tenant, report.id()).await);
        let rename = |name: &str| renamed_report(*report.id(), read, name);

        let first = store
            .save_unchanged_since(&tenant, &rename("invoices"), read)
            .await
            .unwrap();
        let second = store
            .save_unchanged_since(&tenant, &rename("payroll"), read)
            .await;
        let next = store
            .save_unchanged_since(&tenant, &rename("ledger"), first)
            .await;

        assert!(first.changed_at() > read.changed_at());
        assert!(
            matches!(second, Err(DomainError::Conflict(_))),
            "{second:?}"
        );
        assert!(next.is_ok(), "{next:?}");
        let found = store
            .find_by_id(&tenant, report.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "ledger");
    }

    /// An agent nobody stored cannot be changed over a version: the change
    /// is refused, and nothing is written.
    #[tokio::test]
    async fn a_change_to_an_agent_never_stored_is_refused() {
        let (_db, store, tenant) = fixture().await;
        let report = agent(agent_row("report"));

        let saved = store
            .save_unchanged_since(&tenant, &report, AgentVersion::of(&report))
            .await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))), "{saved:?}");
        assert!(
            store
                .find_by_id(&tenant, report.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// An agent of a tenant with a database of its own is kept there, and
    /// not in the platform database.
    #[tokio::test]
    async fn an_agent_of_a_tenant_with_its_own_database_is_kept_there() {
        let (db, store, _) = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        db.databases.register(*apart, own.as_dedicated());
        let report = agent(agent_row("report"));
        store.save(&apart, &report).await.unwrap();

        let in_its_own = store.find_by_id(&apart, report.id()).await.unwrap();
        db.databases.deregister(&apart);
        let in_the_platform = store.find_by_id(&apart, report.id()).await.unwrap();

        assert!(in_its_own.is_some());
        assert!(in_the_platform.is_none());
    }

    /// A stored agent offered to its own owner is rejected as corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_agent_is_refused() {
        let (db, store, tenant) = fixture().await;
        let report = agent(offered_row(agent_row("report"), human("bob@acme.example")));
        save_all(&store, &tenant, &[&report]).await;
        db.tamper(
            "UPDATE agents SET offered_to_kind = owner_kind, offered_to_id = owner_id, \
             offered_to_person = owner_person",
        )
        .await;

        let read = store.find_by_id(&tenant, report.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
