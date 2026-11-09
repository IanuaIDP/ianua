//! Passkey ceremonies in flight, each a tenant row under row-level
//! security.
//!
//! Settling one is one update that only finds a ceremony nobody settled,
//! so of two answers to one challenge only one goes through. The sweep that
//! deletes ceremonies never answered reads every tenant: those in the
//! platform database in one statement, and each tenant with a database of
//! its own in its own, all at once.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::authentication::PasskeyCeremonyStore;
use ianua_domain::domains::authentication::credentials::passkey_ceremony::PasskeyCeremony;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CeremonyId, TenantId};
use time::OffsetDateTime;

use self::record::{CeremonyColumns, CeremonyRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of passkey ceremonies.
pub struct PgPasskeyCeremonyStore {
    databases: Arc<Databases>,
}

impl PgPasskeyCeremonyStore {
    /// A store keeping ceremonies in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Deletes the lapsed ceremonies of every tenant in the platform
    /// database.
    async fn purge_shared(&self, now: OffsetDateTime) -> Result<i64, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/passkey_ceremonies/purge_lapsed.sql", now)
                .fetch_one(connection)
                .await
        })
        .await
    }

    /// Deletes the lapsed ceremonies of `tenant`, in its own database.
    async fn purge_own(&self, tenant: TenantId, now: OffsetDateTime) -> Result<i64, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/passkey_ceremonies/purge_lapsed_of_tenant.sql",
                    tenant.as_uuid(),
                    now
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }
}

#[async_trait]
impl PasskeyCeremonyStore for PgPasskeyCeremonyStore {
    async fn save(&self, ceremony: &PasskeyCeremony) -> Result<(), DomainError> {
        let columns = CeremonyColumns::of(ceremony);
        scoped(
            &self.databases,
            RowScope::Tenant(*ceremony.tenant_id()),
            async |connection| {
                sqlx::query_file!(
                    "queries/passkey_ceremonies/open.sql",
                    columns.id,
                    columns.tenant_id,
                    columns.user_id,
                    columns.purpose,
                    columns.state,
                    columns.created_at,
                    columns.expires_at,
                    columns.consumed_at,
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
        tenant_id: &TenantId,
        id: &CeremonyId,
    ) -> Result<Option<PasskeyCeremony>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::Tenant(*tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CeremonyRecord,
                    "queries/passkey_ceremonies/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(CeremonyRecord::into_ceremony).transpose()
    }

    async fn mark_consumed(&self, ceremony: &PasskeyCeremony) -> Result<(), DomainError> {
        let Some(consumed_at) = ceremony.consumed_at() else {
            return Err(DomainError::invalid(message!(
                "infra-a-challenge-is-settled-only-once",
                "a challenge is settled only once it has been used"
            )));
        };
        let settled = scoped(
            &self.databases,
            RowScope::Tenant(*ceremony.tenant_id()),
            async |connection| {
                sqlx::query_file!(
                    "queries/passkey_ceremonies/settle.sql",
                    ceremony.tenant_id().as_uuid(),
                    ceremony.id().as_uuid(),
                    consumed_at
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        if settled.rows_affected() == 0 {
            return Err(DomainError::invalid(message!(
                "infra-this-challenge-is-unknown-or-has",
                "this challenge is unknown or has already been used"
            )));
        }
        Ok(())
    }

    async fn purge_expired(&self) -> Result<u64, DomainError> {
        let now = clock::now();
        let own_databases = self.databases.with_own_database();
        let (shared, own) = futures_util::try_join!(
            self.purge_shared(now),
            try_join_all(
                own_databases
                    .into_iter()
                    .map(|tenant| self.purge_own(tenant, now))
            )
        )?;
        let purged = own.into_iter().fold(shared, i64::saturating_add);
        u64::try_from(purged).map_err(DomainError::infra)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
        CeremonyPurpose, PasskeyCeremonyRow,
    };
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{Usage, UserId};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authentication::ceremony_row;
    use crate::test_support::rows::identity::{from_now, user_row};

    /// Saves Ann in `tenant` through `db`, and answers her id.
    async fn ann_in(db: &TestDb, tenant: TenantId) -> UserId {
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&ScopedTenant::for_background(tenant), &ann)
            .await
            .unwrap();
        *ann.id()
    }

    /// A fresh database holding Ann in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgPasskeyCeremonyStore, TenantId, UserId) {
        let db = TestDb::fresh().await;
        let acme = TenantId::new();
        let ann = ann_in(&db, acme).await;
        let store = PgPasskeyCeremonyStore::new(Arc::clone(&db.databases));
        (db, store, acme, ann)
    }

    fn ceremony(row: PasskeyCeremonyRow) -> PasskeyCeremony {
        PasskeyCeremony::reconstitute(row).unwrap()
    }

    /// An unanswered ceremony whose expiry predates the sweep.
    fn lapsed_row(tenant: TenantId, ann: UserId) -> PasskeyCeremonyRow {
        PasskeyCeremonyRow {
            created_at: from_now(-600),
            expires_at: from_now(-300),
            ..ceremony_row(tenant, ann)
        }
    }

    /// The ceremony `open` stands for, answered now.
    fn answered(open: &PasskeyCeremony, tenant: TenantId, ann: UserId) -> PasskeyCeremony {
        ceremony(PasskeyCeremonyRow {
            id: *open.id(),
            usage: Usage::Used { at: from_now(0) },
            ..ceremony_row(tenant, ann)
        })
    }

    /// A ceremony opened for Ann is found again in her tenant, as it was
    /// opened.
    #[tokio::test]
    async fn an_opened_ceremony_is_found_by_its_id() {
        let (_db, store, acme, ann) = fixture().await;
        let opened = ceremony(ceremony_row(acme, ann));

        store.save(&opened).await.unwrap();

        let found = store.find_by_id(&acme, opened.id()).await.unwrap().unwrap();
        assert_eq!(found.user_id(), Some(&ann));
        assert_eq!(found.purpose(), CeremonyPurpose::Authentication);
        assert_eq!(found.state_for_storage(), opened.state_for_storage());
        assert_eq!(found.consumed_at(), None);
    }

    /// An id nobody opened finds nothing.
    #[tokio::test]
    async fn an_unknown_ceremony_is_not_found() {
        let (_db, store, acme, _) = fixture().await;

        assert!(
            store
                .find_by_id(&acme, &CeremonyId::new())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A second consumption is refused after a ceremony settles; saving
    /// its open copy leaves the stored ceremony consumed.
    #[tokio::test]
    async fn a_ceremony_is_settled_once() {
        let (_db, store, acme, ann) = fixture().await;
        let opened = ceremony(ceremony_row(acme, ann));
        store.save(&opened).await.unwrap();
        let done = answered(&opened, acme, ann);

        store.mark_consumed(&done).await.unwrap();
        let again = store.mark_consumed(&done).await;
        store.save(&opened).await.unwrap();

        let found = store.find_by_id(&acme, opened.id()).await.unwrap().unwrap();
        assert!(matches!(again, Err(DomainError::Validation(_))));
        assert!(found.consumed_at().is_some());
    }

    /// Marking an unanswered ceremony consumed fails validation.
    #[tokio::test]
    async fn an_unanswered_ceremony_is_not_settled() {
        let (_db, store, acme, ann) = fixture().await;
        let opened = ceremony(ceremony_row(acme, ann));
        store.save(&opened).await.unwrap();

        let settled = store.mark_consumed(&opened).await;

        assert!(matches!(settled, Err(DomainError::Validation(_))));
    }

    /// The sweep deletes ceremonies that lapsed unanswered and counts them;
    /// one still open and one answered stay.
    #[tokio::test]
    async fn the_sweep_deletes_only_lapsed_unanswered_ceremonies() {
        let (_db, store, acme, ann) = fixture().await;
        let lapsed = ceremony(lapsed_row(acme, ann));
        let open = ceremony(ceremony_row(acme, ann));
        let settled = ceremony(PasskeyCeremonyRow {
            created_at: from_now(-600),
            expires_at: from_now(-300),
            usage: Usage::Used { at: from_now(-400) },
            ..ceremony_row(acme, ann)
        });
        for held in [&lapsed, &open, &settled] {
            store.save(held).await.unwrap();
        }

        let purged = store.purge_expired().await.unwrap();

        assert_eq!(purged, 1);
        assert!(
            store
                .find_by_id(&acme, lapsed.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.find_by_id(&acme, open.id()).await.unwrap().is_some());
        assert!(
            store
                .find_by_id(&acme, settled.id())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The sweep reaches a tenant living in a database of its own too.
    #[tokio::test]
    async fn the_sweep_reaches_a_tenant_with_its_own_database() {
        let platform = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let acme = TenantId::new();
        platform.databases.register(acme, own.as_dedicated());
        let ann = ann_in(&platform, acme).await;
        let store = PgPasskeyCeremonyStore::new(Arc::clone(&platform.databases));
        let lapsed = ceremony(PasskeyCeremonyRow {
            created_at: from_now(-600),
            expires_at: from_now(-300),
            ..ceremony_row(acme, ann)
        });
        store.save(&lapsed).await.unwrap();

        let purged = store.purge_expired().await.unwrap();

        assert_eq!(purged, 1);
        assert!(
            store
                .find_by_id(&acme, lapsed.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A ceremony opened in Acme cannot be found through another tenant.
    #[tokio::test]
    async fn another_tenants_ceremonies_are_invisible() {
        let (_db, store, acme, ann) = fixture().await;
        let opened = ceremony(ceremony_row(acme, ann));
        store.save(&opened).await.unwrap();

        let elsewhere = store
            .find_by_id(&TenantId::new(), opened.id())
            .await
            .unwrap();

        assert!(elsewhere.is_none());
    }

    /// An unknown purpose written directly into a ceremony makes its
    /// lookup fail as corrupt storage.
    #[tokio::test]
    async fn a_ceremony_with_an_unknown_purpose_is_refused() {
        let (db, store, acme, ann) = fixture().await;
        let opened = ceremony(ceremony_row(acme, ann));
        store.save(&opened).await.unwrap();
        db.tamper(
            "ALTER TABLE passkey_ceremonies DROP CONSTRAINT passkey_ceremonies_purpose_known; \
             UPDATE passkey_ceremonies SET purpose = 'guessed'",
        )
        .await;

        let read = store.find_by_id(&acme, opened.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
