//! The accounts a tenant connected to integrations, each table row under
//! row-level security.
//!
//! An account's credential reaches the store already sealed by the app's
//! secret sealer, and is kept in that form: the action runner opens it for
//! the one call that needs it, so the database never holds it in clear and
//! the store never opens it. A list reads the ids of its page first, oldest
//! first, then reads those accounts through the one query by ids.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{IntegrationAccountSortField, IntegrationAccountStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::IntegrationAccountId;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{AccountColumns, AccountRecord};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of integration accounts.
pub struct PgIntegrationAccountStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgIntegrationAccountStore {}

impl PgIntegrationAccountStore {
    /// A store keeping integration accounts in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The records of the accounts of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<AccountRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        AccountRecord,
        "queries/integration_accounts/by_ids.sql",
        tenant,
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt_all(
    records: Vec<AccountRecord>,
) -> Result<Vec<IntegrationAccount<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(AccountRecord::into_account)
        .collect()
}

impl SortColumns for IntegrationAccountSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl IntegrationAccountStore for PgIntegrationAccountStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &IntegrationAccountId,
    ) -> Result<Option<IntegrationAccount<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<IntegrationAccount<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<IntegrationAccountSortField>::default();
        let keyset = page.keyset(&order)?;
        let tenant = *tenant_id.as_uuid();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = PageQuery::ids("id", "integration_accounts")
                    .filter("tenant_id = ?", tenant)
                    .fetch(&keyset, &mut *connection)
                    .await?;
                let records = records_of(connection, &tenant, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = AccountColumns::of(account)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/integration_accounts/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.integration,
                    columns.name,
                    columns.credential_sealed,
                    columns.owner,
                    columns.sharing,
                    columns.operations.as_deref(),
                    columns.status,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_domain::domains::workflows::account::{
        AccountSharing, AccountStatus, IntegrationAccountRow, OperationScope, ScopedOperations,
    };
    use ianua_domain::domains::workflows::integration::OperationKey;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::workflows::account_row;

    struct Fixture {
        db: TestDb,
        store: PgIntegrationAccountStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep accounts
    /// in.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgIntegrationAccountStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn account(row: IntegrationAccountRow) -> IntegrationAccount<ResolvedTenant> {
        IntegrationAccount::reconstitute(row).unwrap()
    }

    fn names(page: &Page<IntegrationAccount<ResolvedTenant>>) -> Vec<&str> {
        page.items.iter().map(|kept| kept.name().as_str()).collect()
    }

    /// A saved account is found by its id with its sealed credential as it
    /// was handed over, and an unknown id finds nothing.
    #[tokio::test]
    async fn a_saved_account_is_found_by_its_id() {
        let fx = fixture().await;
        let saved = account(account_row("Finance sheets", 0));

        fx.store.save(&fx.tenant, &saved).await.unwrap();

        let found = fx
            .store
            .find_by_id(&fx.tenant, saved.id())
            .await
            .unwrap()
            .unwrap();
        let unknown = fx
            .store
            .find_by_id(&fx.tenant, &IntegrationAccountId::new())
            .await
            .unwrap();
        assert!(found.credential() == saved.credential());
        assert_eq!(found.owner(), saved.owner());
        assert_eq!(found.scope(), &OperationScope::All);
        assert!(unknown.is_none());
    }

    /// An account shared, kept to two operations and disabled reads back
    /// so when saved again.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let saved = account(account_row("Finance sheets", 0));
        fx.store.save(&fx.tenant, &saved).await.unwrap();
        let scope = OperationScope::Only(
            ScopedOperations::new(vec![
                OperationKey::new("append-row").unwrap(),
                OperationKey::new("read-row").unwrap(),
            ])
            .unwrap(),
        );
        let changed = account(IntegrationAccountRow {
            id: *saved.id(),
            sharing: AccountSharing::Tenant,
            scope: scope.clone(),
            status: AccountStatus::Disabled,
            updated_at: at(5),
            ..account_row("Shared sheets", 0)
        });

        fx.store.save(&fx.tenant, &changed).await.unwrap();

        let found = fx
            .store
            .find_by_id(&fx.tenant, saved.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "Shared sheets");
        assert_eq!(found.sharing(), AccountSharing::Tenant);
        assert_eq!(found.scope(), &scope);
        assert_eq!(found.status(), AccountStatus::Disabled);
    }

    /// The tenant's accounts are read page by page, oldest first, and
    /// another tenant's are not among them.
    #[tokio::test]
    async fn accounts_are_listed_oldest_first_page_by_page() {
        let fx = fixture().await;
        for (name, created) in [("newest", 3), ("oldest", 1), ("middle", 2)] {
            fx.store
                .save(&fx.tenant, &account(account_row(name, created)))
                .await
                .unwrap();
        }
        let other = ScopedTenant::for_background(TenantId::new());
        fx.store
            .save(&other, &account(account_row("theirs", 0)))
            .await
            .unwrap();

        let page_one = fx
            .store
            .list(&fx.tenant, &PageRequest::first(Limit::new(2).unwrap()))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.store.list(&fx.tenant, &after).await.unwrap();

        assert_eq!(names(&page_one), ["oldest", "middle"]);
        assert_eq!(names(&page_two), ["newest"]);
        assert!(!page_two.has_next());
    }

    /// Another tenant does not find Acme's account, and a tenant with a
    /// database of its own keeps its accounts there.
    #[tokio::test]
    async fn another_tenants_accounts_are_invisible() {
        let fx = fixture().await;
        let saved = account(account_row("Finance sheets", 0));
        fx.store.save(&fx.tenant, &saved).await.unwrap();
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let theirs = account(account_row("Their sheets", 0));
        fx.store.save(&apart, &theirs).await.unwrap();

        let by_other = fx.store.find_by_id(&apart, saved.id()).await.unwrap();
        let in_own = PgIntegrationAccountStore::new(Arc::clone(&own.databases))
            .find_by_id(&apart, theirs.id())
            .await
            .unwrap();

        assert!(by_other.is_none());
        assert!(in_own.is_some());
    }

    /// Reading an account whose stored operation scope contains a duplicate
    /// operation returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_account_is_refused() {
        let fx = fixture().await;
        let saved = account(account_row("Finance sheets", 0));
        fx.store.save(&fx.tenant, &saved).await.unwrap();
        fx.db
            .tamper("UPDATE integration_accounts SET operations = '{append-row,append-row}'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
