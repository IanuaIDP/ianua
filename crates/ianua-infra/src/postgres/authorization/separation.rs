//! Separation of duties: the pairs of roles nobody in a tenant holds
//! together. A rule goes with either of its roles.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::SeparationRuleStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::separation::SeparationRule;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SeparationRuleId;

use self::record::SeparationRuleRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of separation rules.
pub struct PgSeparationRuleStore {
    databases: Arc<Databases>,
}

impl PgSeparationRuleStore {
    /// A store keeping separation rules in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSeparationRuleStore {}

#[async_trait]
impl SeparationRuleStore for PgSeparationRuleStore {
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<SeparationRule<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SeparationRuleRecord,
                    "queries/separation_rules/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(SeparationRuleRecord::into_rule)
            .collect()
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SeparationRuleId,
    ) -> Result<Option<SeparationRule<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SeparationRuleRecord,
                    "queries/separation_rules/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(SeparationRuleRecord::into_rule).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rule: &SeparationRule<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let (first, second) = rule.roles();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/separation_rules/save.sql",
                    rule.id().as_uuid(),
                    tenant_id.as_uuid(),
                    rule.name().as_str(),
                    first.as_uuid(),
                    second.as_uuid(),
                    rule.created_at()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &SeparationRuleId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/separation_rules/delete.sql",
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
    use ianua_app::ports::authorization::RoleStore;
    use ianua_domain::domains::authorization::role::Role;

    use super::*;
    use crate::postgres::authorization::PgRoleStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::{role, separation, tenant};

    struct Fixture {
        db: TestDb,
        store: PgSeparationRuleStore,
        acme: ScopedTenant,
        raise: Role<ResolvedTenant>,
        approve: Role<ResolvedTenant>,
    }

    /// A fresh database, the store on it, and a tenant holding the roles
    /// "raise payments" and "approve payments".
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let roles = PgRoleStore::new(Arc::clone(&db.databases));
        let (raise, approve) = (role("raise"), role("approve"));
        roles.save(&acme, &raise).await.unwrap();
        roles.save(&acme, &approve).await.unwrap();
        let store = PgSeparationRuleStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            acme,
            raise,
            approve,
        }
    }

    /// A rule is found by its id and listed, with the two roles it keeps
    /// apart.
    #[tokio::test]
    async fn a_saved_rule_is_found_and_listed() {
        let f = fixture().await;
        let rule = separation("payments", f.raise.id(), f.approve.id());

        f.store.save(&f.acme, &rule).await.unwrap();

        let found = f
            .store
            .find_by_id(&f.acme, rule.id())
            .await
            .unwrap()
            .unwrap();
        let listed = f.store.list(&f.acme).await.unwrap();
        assert_eq!(found.roles(), (f.raise.id(), f.approve.id()));
        assert_eq!(listed.len(), 1);
    }

    /// A removed rule is gone, and an unknown id finds nothing.
    #[tokio::test]
    async fn a_removed_rule_is_gone() {
        let f = fixture().await;
        let rule = separation("payments", f.raise.id(), f.approve.id());
        f.store.save(&f.acme, &rule).await.unwrap();

        f.store.delete(&f.acme, rule.id()).await.unwrap();

        assert!(
            f.store
                .find_by_id(&f.acme, rule.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Deleting one of its roles takes the rule with it.
    #[tokio::test]
    async fn a_rule_goes_with_its_role() {
        let f = fixture().await;
        f.store
            .save(
                &f.acme,
                &separation("payments", f.raise.id(), f.approve.id()),
            )
            .await
            .unwrap();

        PgRoleStore::new(Arc::clone(&f.db.databases))
            .delete(&f.acme, f.raise.id())
            .await
            .unwrap();

        assert!(f.store.list(&f.acme).await.unwrap().is_empty());
    }

    /// Globex lists none of Acme's separation rules and cannot save a rule
    /// referring to Acme's roles.
    #[tokio::test]
    async fn another_tenants_rules_are_out_of_reach() {
        let f = fixture().await;
        let rule = separation("payments", f.raise.id(), f.approve.id());
        f.store.save(&f.acme, &rule).await.unwrap();
        let globex = tenant();

        let listed = f.store.list(&globex).await.unwrap();
        let written = f
            .store
            .save(&globex, &separation("theirs", f.raise.id(), f.approve.id()))
            .await;

        assert!(listed.is_empty());
        assert!(matches!(written, Err(DomainError::Infrastructure(_))));
    }

    /// A stored separation rule naming the same role on both sides is
    /// refused as corrupt storage.
    #[tokio::test]
    async fn a_role_kept_apart_from_itself_is_refused() {
        let f = fixture().await;
        let rule = separation("payments", f.raise.id(), f.approve.id());
        f.store.save(&f.acme, &rule).await.unwrap();
        f.db.tamper(
            "ALTER TABLE separation_rules DROP CONSTRAINT separation_rules_two_roles; \
             UPDATE separation_rules SET second_role_id = first_role_id",
        )
        .await;

        let read = f.store.find_by_id(&f.acme, rule.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
