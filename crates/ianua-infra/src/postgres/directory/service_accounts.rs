//! The accounts applications bind to a tenant's directory as, each table
//! row under row-level security.
//!
//! A name is unique within the tenant, since the bind DN names the account
//! by it. Every read of an account goes through one checked query and one
//! mapping into the aggregate.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::directory::DirectoryServiceAccountStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::directory_service::account::DirectoryServiceAccount;
use ianua_domain::domains::authentication::directory_service::scope::ServiceAccountName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DirectoryServiceAccountId;

use self::record::{AccountColumns, AccountRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a name to one account of a tenant.
const NAME_KEY: &str = "directory_service_accounts_name_key";

/// The Postgres store of directory service accounts.
pub struct PgDirectoryServiceAccountStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgDirectoryServiceAccountStore {}

impl PgDirectoryServiceAccountStore {
    /// A store keeping directory service accounts in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(
    record: Option<AccountRecord>,
) -> Result<Option<DirectoryServiceAccount<ResolvedTenant>>, DomainError> {
    record.map(AccountRecord::into_account).transpose()
}

#[async_trait]
impl DirectoryServiceAccountStore for PgDirectoryServiceAccountStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DirectoryServiceAccountId,
    ) -> Result<Option<DirectoryServiceAccount<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AccountRecord,
                    "queries/directory_service_accounts/by_ids.sql",
                    tenant_id.as_uuid(),
                    ids.as_slice()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records.into_iter().next())
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &ServiceAccountName,
    ) -> Result<Option<DirectoryServiceAccount<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AccountRecord,
                    "queries/directory_service_accounts/by_name.sql",
                    tenant_id.as_uuid(),
                    name.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<DirectoryServiceAccount<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AccountRecord,
                    "queries/directory_service_accounts/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(AccountRecord::into_account)
            .collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        account: &DirectoryServiceAccount<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = AccountColumns::of(account);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/directory_service_accounts/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.secret_hash,
                    columns.access,
                    columns.base_dns.as_slice(),
                    columns.status,
                    columns.created_at,
                    columns.secret_changed_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, NAME_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-account-has-this-name",
                "another account has this name"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &DirectoryServiceAccountId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/directory_service_accounts/delete.sql",
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
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::directory_service::account::{
        DirectoryServiceAccountRow, ServiceAccountStatus,
    };
    use ianua_domain::domains::authentication::directory_service::scope::{
        BaseDn, DirectoryAccess, ServiceAccountScope,
    };
    use ianua_domain::types::{TenantId, TokenHash};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::directory::service_account_row;

    struct Fixture {
        db: TestDb,
        store: PgDirectoryServiceAccountStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep accounts
    /// for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgDirectoryServiceAccountStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn account(row: DirectoryServiceAccountRow) -> DirectoryServiceAccount<ResolvedTenant> {
        DirectoryServiceAccount::reconstitute(row).unwrap()
    }

    fn named(name: &str) -> DirectoryServiceAccount<ResolvedTenant> {
        account(service_account_row(name))
    }

    fn name(text: &str) -> ServiceAccountName {
        ServiceAccountName::new(text).unwrap()
    }

    /// Builds Jira's directory account for the people and groups subtrees.
    fn jira_account() -> DirectoryServiceAccount<ResolvedTenant> {
        let scope = ServiceAccountScope::new(
            DirectoryAccess::ReadOnly,
            vec![
                BaseDn::new("ou=people,dc=acme,dc=example").unwrap(),
                BaseDn::new("ou=groups,dc=acme,dc=example").unwrap(),
            ],
        )
        .unwrap();
        account(DirectoryServiceAccountRow {
            scope,
            ..service_account_row("jira")
        })
    }

    impl Fixture {
        async fn save(&self, account: &DirectoryServiceAccount<ResolvedTenant>) {
            self.store.save(&self.tenant, account).await.unwrap();
        }
    }

    /// Jira's account, writing under two base DNs, is found by its id and
    /// by its name, as it was saved.
    #[tokio::test]
    async fn a_saved_account_is_found_by_id_and_by_name() {
        let fx = fixture().await;
        let jira = jira_account();
        fx.save(&jira).await;

        let by_id = fx
            .store
            .find_by_id(&fx.tenant, jira.id())
            .await
            .unwrap()
            .unwrap();
        let by_name = fx
            .store
            .find_by_name(&fx.tenant, &name("jira"))
            .await
            .unwrap()
            .unwrap();

        for found in [&by_id, &by_name] {
            assert_eq!(found.id(), jira.id());
            assert_eq!(found.secret_hash(), jira.secret_hash());
            assert_eq!(found.scope(), jira.scope());
            assert_eq!(found.status(), ServiceAccountStatus::Active);
            assert_eq!(found.secret_changed_at(), jira.secret_changed_at());
        }
    }

    /// An id or name nobody has finds nothing, and another tenant does not
    /// find this tenant's account.
    #[tokio::test]
    async fn an_account_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let jira = named("jira");
        fx.save(&jira).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let unknown = fx
            .store
            .find_by_name(&fx.tenant, &name("gitlab"))
            .await
            .unwrap();
        let by_id = fx.store.find_by_id(&other, jira.id()).await.unwrap();
        let listed = fx.store.list(&other).await.unwrap();

        assert!(unknown.is_none());
        assert!(by_id.is_none());
        assert!(listed.is_empty());
    }

    /// The tenant's accounts list by name.
    #[tokio::test]
    async fn the_accounts_are_listed_by_name() {
        let fx = fixture().await;
        for saved in ["sssd", "gitlab", "jira"].map(named) {
            fx.save(&saved).await;
        }

        let listed = fx.store.list(&fx.tenant).await.unwrap();

        let names: Vec<&str> = listed.iter().map(|found| found.name().as_str()).collect();
        assert_eq!(names, ["gitlab", "jira", "sssd"]);
    }

    /// Saving another directory account named Jira in the same tenant
    /// returns a conflict.
    #[tokio::test]
    async fn a_name_another_account_has_is_refused() {
        let fx = fixture().await;
        fx.save(&named("jira")).await;

        let second = fx.store.save(&fx.tenant, &named("jira")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Jira's secret is rotated and the account disabled: saving it again
    /// keeps both, and the time it was made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let jira = named("jira");
        fx.save(&jira).await;
        let changed = account(DirectoryServiceAccountRow {
            id: *jira.id(),
            secret_hash: TokenHash::from_stored("rotated".to_owned()),
            status: ServiceAccountStatus::Disabled,
            secret_changed_at: at(5),
            ..service_account_row("jira")
        });

        fx.save(&changed).await;

        let found = fx
            .store
            .find_by_id(&fx.tenant, jira.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), ServiceAccountStatus::Disabled);
        assert_eq!(found.secret_changed_at(), at(5));
        assert_eq!(found.created_at(), jira.created_at());
    }

    /// A deleted account is gone, and deleting it again succeeds.
    #[tokio::test]
    async fn a_deleted_account_is_gone() {
        let fx = fixture().await;
        let jira = named("jira");
        fx.save(&jira).await;

        fx.store.delete(&fx.tenant, jira.id()).await.unwrap();
        let again = fx.store.delete(&fx.tenant, jira.id()).await;

        assert!(again.is_ok());
        assert!(
            fx.store
                .find_by_id(&fx.tenant, jira.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// An invalid base DN in Jira's stored directory account makes the
    /// read fail as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_account_is_refused() {
        let fx = fixture().await;
        let jira = named("jira");
        fx.save(&jira).await;
        fx.db
            .tamper("UPDATE directory_service_accounts SET base_dns = '{not-a-dn}'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, jira.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
