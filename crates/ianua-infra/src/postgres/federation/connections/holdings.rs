//! What each connection's group mapping gave each person: one record per
//! connection and person, its roles and groups in tables beside it, so
//! each is a link the database keeps. Saving a record replaces its roles
//! and groups in one transaction.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::MappedHoldingsStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::federation::connection::MappedHoldings;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, UserId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{HoldingsColumns, HoldingsRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of what group mappings gave each person.
pub struct PgMappedHoldingsStore {
    databases: Arc<Databases>,
}

impl PgMappedHoldingsStore {
    /// A store keeping the records in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgMappedHoldingsStore {}

/// Writes the record `columns` describe, with exactly its roles and groups.
async fn write_holdings(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &HoldingsColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/mapped_holdings/keep.sql",
        tenant_id,
        columns.connection_id,
        columns.user_id
    )
    .execute(&mut *connection)
    .await?;
    replace_roles(&mut *connection, tenant_id, columns).await?;
    replace_groups(connection, tenant_id, columns).await
}

/// Puts exactly the roles of `columns` on the record.
async fn replace_roles(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &HoldingsColumns<'_>,
) -> Result<(), sqlx::Error> {
    let (held_through, held_by) = (columns.connection_id, columns.user_id);
    sqlx::query_file!(
        "queries/mapped_holding_roles/withdraw.sql",
        tenant_id,
        held_through,
        held_by
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query_file!(
        "queries/mapped_holding_roles/give.sql",
        tenant_id,
        held_through,
        held_by,
        &columns.role_ids
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// Puts exactly the groups of `columns` on the record.
async fn replace_groups(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &HoldingsColumns<'_>,
) -> Result<(), sqlx::Error> {
    let (held_through, held_by) = (columns.connection_id, columns.user_id);
    sqlx::query_file!(
        "queries/mapped_holding_groups/withdraw.sql",
        tenant_id,
        held_through,
        held_by
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query_file!(
        "queries/mapped_holding_groups/give.sql",
        tenant_id,
        held_through,
        held_by,
        &columns.group_ids
    )
    .execute(connection)
    .await?;
    Ok(())
}

#[async_trait]
impl MappedHoldingsStore for PgMappedHoldingsStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<Option<MappedHoldings<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    HoldingsRecord,
                    "queries/mapped_holdings/find.sql",
                    tenant_id.as_uuid(),
                    connection_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(HoldingsRecord::into_holdings).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        holdings: &MappedHoldings<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = HoldingsColumns::of(holdings);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_holdings(connection, tenant_id.as_uuid(), &columns).await,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::authorization::{GroupStore, RoleStore};
    use ianua_app::ports::federation::ConnectionStore;
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::federation::connection::{
        FederatedIdpConnection, MappedHoldingsRow,
    };
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{GroupId, RoleId};

    use super::*;
    use crate::postgres::authorization::{PgGroupStore, PgRoleStore};
    use crate::postgres::federation::PgConnectionStore;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::{group, role, tenant};
    use crate::test_support::rows::federation::{connection_row, saml_config};
    use crate::test_support::rows::identity::user_row;

    struct Fixture {
        db: TestDb,
        store: PgMappedHoldingsStore,
        tenant: ScopedTenant,
        okta: ConnectionId,
        ann: UserId,
        roles: [RoleId; 2],
        groups: [GroupId; 2],
    }

    /// Saves the two roles the fixture's group mapping can grant.
    async fn saved_roles(db: &TestDb, tenant: &ScopedTenant) -> [RoleId; 2] {
        let roles = [role("ops"), role("reviewer")];
        let store = PgRoleStore::new(Arc::clone(&db.databases));
        for held in &roles {
            store.save(tenant, held).await.unwrap();
        }
        roles.map(|held| *held.id())
    }

    /// A fresh database holding a tenant with Okta, Ann, two roles and two
    /// groups, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let okta =
            FederatedIdpConnection::reconstitute(connection_row("Okta", saml_config())).unwrap();
        PgConnectionStore::new(Arc::clone(&db.databases))
            .save(&tenant, &okta)
            .await
            .unwrap();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant, &ann)
            .await
            .unwrap();
        let roles = saved_roles(&db, &tenant).await;
        let groups = [group("ops", Vec::new()), group("platform", Vec::new())];
        let group_store = PgGroupStore::new(Arc::clone(&db.databases));
        for held in &groups {
            group_store.save(&tenant, held).await.unwrap();
        }
        Fixture {
            store: PgMappedHoldingsStore::new(Arc::clone(&db.databases)),
            okta: *okta.id(),
            ann: *ann.id(),
            roles,
            groups: groups.map(|held| *held.id()),
            tenant,
            db,
        }
    }

    impl Fixture {
        fn holdings(
            &self,
            roles: Vec<RoleId>,
            groups: Vec<GroupId>,
        ) -> MappedHoldings<ResolvedTenant> {
            MappedHoldings::reconstitute(MappedHoldingsRow {
                connection_id: self.okta,
                user_id: self.ann,
                roles,
                groups,
            })
            .unwrap()
        }

        async fn found(&self) -> Option<MappedHoldings<ResolvedTenant>> {
            self.store
                .find(&self.tenant, &self.okta, &self.ann)
                .await
                .unwrap()
        }
    }

    /// What Okta's mapping gave Ann is found as it was saved, in order.
    #[tokio::test]
    async fn saved_holdings_are_found_in_order() {
        let fx = fixture().await;
        let given = fx.holdings(vec![fx.roles[1], fx.roles[0]], vec![fx.groups[0]]);

        fx.store.save(&fx.tenant, &given).await.unwrap();

        let found = fx.found().await.unwrap();
        assert_eq!(found.roles(), [fx.roles[1], fx.roles[0]]);
        assert_eq!(found.groups(), [fx.groups[0]]);
    }

    /// Before the mapping ever gave Ann anything, there is no record.
    #[tokio::test]
    async fn no_record_is_found_before_the_first_save() {
        let fx = fixture().await;

        assert!(fx.found().await.is_none());
    }

    /// Okta drops Ann from `ops`: saving again replaces what she holds
    /// through the mapping, down to nothing, and the record stays.
    #[tokio::test]
    async fn saving_again_replaces_what_is_held() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.tenant,
                &fx.holdings(fx.roles.to_vec(), fx.groups.to_vec()),
            )
            .await
            .unwrap();

        fx.store
            .save(&fx.tenant, &MappedHoldings::none(fx.okta, fx.ann))
            .await
            .unwrap();

        let found = fx.found().await.unwrap();
        assert!(found.roles().is_empty());
        assert!(found.groups().is_empty());
    }

    /// A role that is deleted is no longer on the record: nobody holds it
    /// to take it back from.
    #[tokio::test]
    async fn a_deleted_role_leaves_the_record() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &fx.holdings(vec![fx.roles[0]], Vec::new()))
            .await
            .unwrap();

        PgRoleStore::new(Arc::clone(&fx.db.databases))
            .delete(&fx.tenant, &fx.roles[0])
            .await
            .unwrap();

        assert!(fx.found().await.unwrap().roles().is_empty());
    }

    /// Globex cannot find Ann's mapped holdings using Acme's connection
    /// and user IDs.
    #[tokio::test]
    async fn another_tenants_record_is_not_found() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &fx.holdings(vec![fx.roles[0]], Vec::new()))
            .await
            .unwrap();

        let found = fx.store.find(&tenant(), &fx.okta, &fx.ann).await.unwrap();

        assert!(found.is_none());
    }
}
