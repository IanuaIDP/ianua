//! Copies of one tenant's setup into another, in the platform database: a
//! clone spans two tenants, each of which may live in a database of its
//! own, so it is read and written as platform work.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::tenant::TenantCloneStore;
use ianua_domain::domains::tenant::clone::TenantClone;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TenantCloneId, TenantId};

use self::record::{CloneColumns, CloneRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The clones between tenants.
pub struct PgTenantCloneStore {
    databases: Arc<Databases>,
}

impl PgTenantCloneStore {
    /// The clones kept in `databases`' platform database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl TenantCloneStore for PgTenantCloneStore {
    async fn find_by_id(&self, id: &TenantCloneId) -> Result<Option<TenantClone>, DomainError> {
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(CloneRecord, "queries/tenant_clones/by_id.sql", id.as_uuid())
                .fetch_optional(connection)
                .await
        })
        .await?;
        record.map(CloneRecord::into_clone).transpose()
    }

    async fn copying_into(&self, target: &TenantId) -> Result<bool, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/tenant_clones/copying_into.sql", target.as_uuid())
                .fetch_one(connection)
                .await
        })
        .await
    }

    async fn save(&self, clone: &TenantClone) -> Result<(), DomainError> {
        let columns = CloneColumns::of(clone);
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/tenant_clones/save.sql",
                columns.id,
                columns.tenant_id,
                columns.source_tenant_id,
                columns.organization_id,
                &columns.parts,
                &columns.copied,
                columns.state,
                columns.failure,
                columns.ended_at,
                columns.started_at,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::tenant::clone::{
        CloneFailure, ClonePart, CloneState, TenantCloneRow,
    };
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};

    struct Fixture {
        db: TestDb,
        store: PgTenantCloneStore,
        organization: OrganizationId,
        source: ScopedTenant,
        target: ScopedTenant,
    }

    /// Two tenants of one organization, and the store.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let source = saved_tenant_of(&db.databases, organization).await;
        let target = saved_tenant_of(&db.databases, organization).await;
        let store = PgTenantCloneStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            organization,
            source,
            target,
        }
    }

    impl Fixture {
        /// A clone of the settings and routes from the source into the
        /// target, standing as `state` with `copied` done.
        fn clone(&self, copied: Vec<ClonePart>, state: CloneState) -> TenantClone {
            TenantClone::reconstitute(TenantCloneRow {
                id: TenantCloneId::new(),
                organization_id: self.organization,
                source: *self.source,
                target: *self.target,
                parts: vec![ClonePart::Settings, ClonePart::Routes],
                copied,
                state,
                started_at: at(0),
            })
            .unwrap()
        }
    }

    /// A clone reads back as it was kept, the parts copied so far
    /// included, and is copying into its target.
    #[tokio::test]
    async fn a_saved_clone_reads_back() {
        let fx = fixture().await;
        let mut clone = fx.clone(Vec::new(), CloneState::Copying);
        fx.store.save(&clone).await.unwrap();
        clone.mark_copied(ClonePart::Settings).unwrap();

        fx.store.save(&clone).await.unwrap();

        let found = fx.store.find_by_id(clone.id()).await.unwrap().unwrap();
        assert_eq!(found.copied(), [ClonePart::Settings]);
        assert_eq!(found.state(), CloneState::Copying);
        assert!(fx.store.copying_into(&fx.target).await.unwrap());
    }

    /// A clone that ended is copying into nothing any more.
    #[tokio::test]
    async fn an_ended_clone_is_copying_no_more() {
        let fx = fixture().await;
        let done = fx.clone(
            vec![ClonePart::Settings, ClonePart::Routes],
            CloneState::Completed { at: at(5) },
        );

        fx.store.save(&done).await.unwrap();

        assert!(!fx.store.copying_into(&fx.target).await.unwrap());
        assert!(!fx.store.copying_into(&fx.source).await.unwrap());
    }

    /// A failed clone reads back failed, with why and when.
    #[tokio::test]
    async fn a_failed_clone_reads_back_failed() {
        let fx = fixture().await;
        let failed = fx.clone(
            vec![ClonePart::Settings],
            CloneState::Failed {
                at: at(5),
                reason: CloneFailure::SourceGone,
            },
        );

        fx.store.save(&failed).await.unwrap();

        let found = fx.store.find_by_id(failed.id()).await.unwrap().unwrap();
        assert_eq!(
            found.state(),
            CloneState::Failed {
                at: at(5),
                reason: CloneFailure::SourceGone
            }
        );
    }

    /// Reading a clone marked complete with no planned parts copied returns
    /// an infrastructure error for the inconsistent stored state.
    #[tokio::test]
    async fn a_clone_completed_with_a_part_missing_is_refused() {
        let fx = fixture().await;
        let clone = fx.clone(Vec::new(), CloneState::Copying);
        fx.store.save(&clone).await.unwrap();
        fx.db
            .tamper(&format!(
                "UPDATE tenant_clones SET state = 'completed', ended_at = started_at \
                 WHERE id = '{}'",
                clone.id()
            ))
            .await;

        let found = fx.store.find_by_id(clone.id()).await;

        assert!(matches!(found, Err(DomainError::Infrastructure(_))));
    }
}
