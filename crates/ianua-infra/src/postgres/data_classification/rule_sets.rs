//! Each tenant's one classification rule set, under row-level security.
//!
//! The rules are kept whole in one column, in the order they are
//! evaluated, since a rule is read only with its set.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::data_classification::ClassificationStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::data_classification::classification::ClassificationRuleSet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

use self::record::{RuleSetColumns, RuleSetRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a tenant to one rule set.
const TENANT_KEY: &str = "classification_rule_sets_tenant_key";

/// The Postgres classification rule set store.
pub struct PgClassificationStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgClassificationStore {}

impl PgClassificationStore {
    /// A store keeping classification rule sets in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl ClassificationStore for PgClassificationStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ClassificationRuleSet<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RuleSetRecord,
                    "queries/classification_rule_sets/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(RuleSetRecord::into_rule_set).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rule_set: &ClassificationRuleSet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = RuleSetColumns::of(rule_set)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/classification_rule_sets/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.rules,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, TENANT_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-tenant-already-keeps-another-rule",
                "the tenant already keeps another rule set"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::classification::{
        ClassificationRule, ClassificationRuleSetRow, RedactionStrategy,
    };
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::types::{ClassificationRuleSetId, FieldPath, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::data_classification::{rule, rule_set_row};

    struct Fixture {
        db: TestDb,
        store: PgClassificationStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep rules for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgClassificationStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn rule_set(row: ClassificationRuleSetRow) -> ClassificationRuleSet<ResolvedTenant> {
        ClassificationRuleSet::reconstitute(row).unwrap()
    }

    fn paths(set: &ClassificationRuleSet<ResolvedTenant>) -> Vec<&str> {
        set.rules()
            .iter()
            .map(|rule| rule.field_path().as_str())
            .collect()
    }

    /// Acme's rules are found again in their order, each with its level
    /// and redaction.
    #[tokio::test]
    async fn a_saved_rule_set_is_found_in_its_order() {
        let fx = fixture().await;
        let saved = rule_set(rule_set_row(vec![
            rule("customer.email", DataClassLevel::Confidential),
            rule("card.number", DataClassLevel::Restricted),
        ]));

        fx.store.save(&fx.tenant, &saved).await.unwrap();

        let found = fx.store.find(&fx.tenant).await.unwrap().unwrap();
        assert_eq!(found.id(), saved.id());
        assert_eq!(paths(&found), ["customer.email", "card.number"]);
        assert_eq!(found.rules()[1].level(), DataClassLevel::Restricted);
        assert_eq!(found.rules()[0].id(), saved.rules()[0].id());
        assert_eq!(found.created_at(), saved.created_at());
    }

    /// A tenant without rules finds none, and another tenant does not find
    /// Acme's.
    #[tokio::test]
    async fn a_rule_set_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let before = fx.store.find(&fx.tenant).await.unwrap();
        fx.store
            .save(&fx.tenant, &rule_set(rule_set_row(Vec::new())))
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let theirs = fx.store.find(&other).await.unwrap();

        assert!(before.is_none());
        assert!(theirs.is_none());
    }

    /// A rule is added and the set saved again: the set keeps the new rule
    /// and the time it was made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_rules() {
        let fx = fixture().await;
        let saved = rule_set(rule_set_row(Vec::new()));
        fx.store.save(&fx.tenant, &saved).await.unwrap();
        let changed = rule_set(ClassificationRuleSetRow {
            id: *saved.id(),
            updated_at: at(5),
            ..rule_set_row(vec![ClassificationRule::new(
                FieldPath::new("ssn").unwrap(),
                DataClassLevel::Restricted,
                RedactionStrategy::Hash,
            )])
        });

        fx.store.save(&fx.tenant, &changed).await.unwrap();

        let found = fx.store.find(&fx.tenant).await.unwrap().unwrap();
        assert_eq!(paths(&found), ["ssn"]);
        assert_eq!(found.updated_at(), at(5));
        assert_eq!(found.created_at(), saved.created_at());
    }

    /// Saving a second classification rule set for the same tenant
    /// returns a conflict.
    #[tokio::test]
    async fn a_second_rule_set_for_a_tenant_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &rule_set(rule_set_row(Vec::new())))
            .await
            .unwrap();
        let second = rule_set(ClassificationRuleSetRow {
            id: ClassificationRuleSetId::new(),
            ..rule_set_row(Vec::new())
        });

        let saved = fx.store.save(&fx.tenant, &second).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
    }

    /// Reading stored classification rules that repeat a field path
    /// reports corrupt storage, even when their rule ids differ.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_set_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.tenant,
                &rule_set(rule_set_row(vec![rule("ssn", DataClassLevel::Restricted)])),
            )
            .await
            .unwrap();
        fx.db
            .tamper(
                "UPDATE classification_rule_sets SET rules = jsonb_set(rules, '{value}', \
                 (rules -> 'value') || jsonb_build_array(jsonb_set(rules -> 'value' -> 0, \
                 '{id}', '\"00000000-0000-0000-0000-000000000009\"')))",
            )
            .await;

        let read = fx.store.find(&fx.tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
