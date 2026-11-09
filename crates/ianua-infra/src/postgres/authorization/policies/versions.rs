//! The versions of a tenant's access policy, one row per version.
//!
//! At most one version is live and at most one open beside it, which
//! partial unique indexes keep, so a race between two approvals fails
//! rather than leaving two live versions. Enforcement reads the live one
//! through its index on every request.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::PolicyStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::shared::errors::DomainError;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{PolicyVersionColumns, PolicyVersionRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of a tenant's policy versions.
pub struct PgPolicyStore {
    databases: Arc<Databases>,
}

impl PgPolicyStore {
    /// A store keeping policy versions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgPolicyStore {}

/// Writes the version `columns` describe for `tenant_id`.
async fn write_version(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &PolicyVersionColumns<'_>,
) -> Result<(), sqlx::Error> {
    let submitted = columns.submitted_by.as_ref();
    sqlx::query_file!(
        "queries/policy_versions/save.sql",
        tenant_id,
        columns.version,
        columns.status,
        columns.based_on,
        columns.based_on_version,
        columns.default_action,
        columns.rules,
        submitted.map(|human| human.kind),
        submitted.map(|human| human.id),
        submitted.map(|human| human.person),
    )
    .execute(connection)
    .await?;
    Ok(())
}

#[async_trait]
impl PolicyStore for PgPolicyStore {
    async fn find_versions(&self, tenant_id: &ScopedTenant) -> Result<Vec<PolicySet>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PolicyVersionRecord,
                    "queries/policy_versions/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(PolicyVersionRecord::into_policy)
            .collect()
    }

    async fn find_active(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<PolicySet>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PolicyVersionRecord,
                    "queries/policy_versions/live.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(PolicyVersionRecord::into_policy).transpose()
    }

    async fn save(&self, tenant_id: &ScopedTenant, policy: &PolicySet) -> Result<(), DomainError> {
        let columns = PolicyVersionColumns::of(policy)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_version(connection, tenant_id.as_uuid(), &columns).await,
        )
        .await
    }

    async fn save_activation(
        &self,
        tenant_id: &ScopedTenant,
        activated: &PolicySet,
        replaced: Option<&PolicySet>,
    ) -> Result<(), DomainError> {
        let activated = PolicyVersionColumns::of(activated)?;
        let replaced = replaced.map(PolicyVersionColumns::of).transpose()?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let Some(replaced) = &replaced else {
                    return write_version(connection, tenant_id.as_uuid(), &activated).await;
                };
                write_version(&mut *connection, tenant_id.as_uuid(), replaced).await?;
                write_version(connection, tenant_id.as_uuid(), &activated).await
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;
    use ianua_domain::domains::authorization::policy::version::PolicyVersion;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::{policy_version, tenant};

    /// A fresh database, the store on it, and a tenant to keep a policy for.
    async fn fixture() -> (TestDb, PgPolicyStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgPolicyStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    /// A tenant that never saved a policy has no versions and none live,
    /// so enforcement denies by default.
    #[tokio::test]
    async fn a_tenant_without_a_policy_has_nothing_live() {
        let (_db, store, acme) = fixture().await;

        assert!(store.find_versions(&acme).await.unwrap().is_empty());
        assert!(store.find_active(&acme).await.unwrap().is_none());
    }

    /// A saved draft appears among policy versions with its rules, but
    /// the active-policy lookup returns nothing.
    #[tokio::test]
    async fn a_draft_is_kept_but_never_live() {
        let (_db, store, acme) = fixture().await;
        let draft = policy_version(1, PolicyStatus::Draft);

        store.save(&acme, &draft).await.unwrap();

        let versions = store.find_versions(&acme).await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].rule_count(), draft.rule_count());
        assert!(store.find_active(&acme).await.unwrap().is_none());
    }

    /// A version in review keeps who sent it, and saving it under its
    /// number replaces the row.
    #[tokio::test]
    async fn a_version_in_review_keeps_who_sent_it() {
        let (_db, store, acme) = fixture().await;
        store
            .save(&acme, &policy_version(1, PolicyStatus::Draft))
            .await
            .unwrap();
        let in_review = policy_version(1, PolicyStatus::Review);

        store.save(&acme, &in_review).await.unwrap();

        let versions = store.find_versions(&acme).await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].status(), PolicyStatus::Review);
        assert_eq!(versions[0].submitted(), in_review.submitted());
    }

    /// Approving a draft beside the live version makes it live and the old
    /// one past, in one write: one version live, the other kept.
    #[tokio::test]
    async fn an_activation_replaces_the_live_version() {
        let (_db, store, acme) = fixture().await;
        let live = policy_version(1, PolicyStatus::Active);
        store.save(&acme, &live).await.unwrap();
        store
            .save(&acme, &policy_version(2, PolicyStatus::Review))
            .await
            .unwrap();
        let approved = policy_version(2, PolicyStatus::Active);
        let archived = policy_version(1, PolicyStatus::Archived);

        store
            .save_activation(&acme, &approved, Some(&archived))
            .await
            .unwrap();

        let found = store.find_active(&acme).await.unwrap().unwrap();
        let versions = store.find_versions(&acme).await.unwrap();
        assert_eq!(found.version(), approved.version());
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version(), PolicyVersion::FIRST);
        assert_eq!(versions[0].status(), PolicyStatus::Archived);
    }

    /// Activating a second policy without replacing the tenant's active
    /// version is refused by storage.
    #[tokio::test]
    async fn a_second_live_version_is_refused() {
        let (_db, store, acme) = fixture().await;
        let live = policy_version(1, PolicyStatus::Active);
        store.save(&acme, &live).await.unwrap();
        let approved = policy_version(2, PolicyStatus::Active);

        let second = store.save_activation(&acme, &approved, None).await;

        assert!(matches!(second, Err(DomainError::Infrastructure(_))));
    }

    /// Globex cannot find Acme's active policy or list its versions.
    #[tokio::test]
    async fn another_tenants_policy_is_invisible() {
        let (_db, store, acme) = fixture().await;
        store
            .save(&acme, &policy_version(1, PolicyStatus::Active))
            .await
            .unwrap();
        let globex = tenant();

        assert!(store.find_active(&globex).await.unwrap().is_none());
        assert!(store.find_versions(&globex).await.unwrap().is_empty());
    }

    /// Duplicating a rule directly in the active policy makes its read
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_version_with_two_rules_of_one_name_is_refused() {
        let (db, store, acme) = fixture().await;
        store
            .save(&acme, &policy_version(1, PolicyStatus::Active))
            .await
            .unwrap();
        db.tamper(
            "UPDATE policy_versions SET rules = jsonb_set(rules, '{value}', \
             (rules->'value') || (rules->'value'))",
        )
        .await;

        let read = store.find_active(&acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
