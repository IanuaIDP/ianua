//! Tenant admins acting as one of the tenant's people for support: each
//! request one row of `support_impersonations`, under row-level security.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::identity::SupportImpersonationStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::impersonation::SupportImpersonation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SupportImpersonationId, UserId};

use self::record::{ImpersonationColumns, ImpersonationRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of support impersonations.
pub struct PgSupportImpersonationStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSupportImpersonationStore {}

impl PgSupportImpersonationStore {
    /// A store keeping impersonations in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// Refuses a stale save when another decision already moved the impersonation on.
fn ensure_written(written: u64) -> Result<(), DomainError> {
    match written {
        0 => Err(DomainError::conflict(message!(
            "infra-this-impersonation-was-approved-declined-or",
            "this impersonation was approved, declined or ended meanwhile"
        ))),
        _ => Ok(()),
    }
}

fn rebuilt(
    records: Vec<ImpersonationRecord>,
) -> Result<Vec<SupportImpersonation<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(ImpersonationRecord::into_impersonation)
        .collect()
}

#[async_trait]
impl SupportImpersonationStore for PgSupportImpersonationStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        impersonation: &SupportImpersonation<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ImpersonationColumns::of(impersonation)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/support_impersonations/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.admin_id,
                    columns.user_id,
                    columns.reason,
                    columns.window_minutes,
                    columns.consent,
                    columns.status,
                    columns.since,
                    columns.requested_at,
                )
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
            },
        )
        .await?;
        ensure_written(written)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SupportImpersonationId,
    ) -> Result<Option<SupportImpersonation<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ImpersonationRecord,
                    "queries/support_impersonations/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record
            .map(ImpersonationRecord::into_impersonation)
            .transpose()
    }

    async fn list_involving(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<SupportImpersonation<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ImpersonationRecord,
                    "queries/support_impersonations/involving.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<SupportImpersonation<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ImpersonationRecord,
                    "queries/support_impersonations/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::impersonation::SupportImpersonationRow;
    use ianua_domain::domains::identity::impersonation::state::{
        ImpersonationState, ImpersonationStatus,
    };
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::identity::{impersonation_row, user_row};

    struct Fixture {
        db: TestDb,
        store: PgSupportImpersonationStore,
        tenant: ScopedTenant,
        people: [UserId; 3],
    }

    /// A fresh database holding Ann, Bob and Cid in one tenant, and the
    /// store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut people = [UserId::new(); 3];
        for (slot, email) in
            people
                .iter_mut()
                .zip(["ann@acme.example", "bob@acme.example", "cid@acme.example"])
        {
            let user: User<ResolvedTenant> = User::reconstitute(user_row(email)).unwrap();
            users.save(&tenant, &user).await.unwrap();
            *slot = *user.id();
        }
        Fixture {
            store: PgSupportImpersonationStore::new(Arc::clone(&db.databases)),
            tenant,
            people,
            db,
        }
    }

    fn impersonation(row: SupportImpersonationRow) -> SupportImpersonation<ResolvedTenant> {
        SupportImpersonation::reconstitute(row).unwrap()
    }

    /// Ann asks to act as Bob; once Bob approves, saving it again keeps
    /// that it is active and since when.
    #[tokio::test]
    async fn a_request_is_found_and_keeps_where_it_stands() {
        let db = fixture().await;
        let [ann, bob, _] = db.people;
        let asked = impersonation(impersonation_row(ann, bob, 0));
        db.store.save(&db.tenant, &asked).await.unwrap();
        let approved = impersonation(SupportImpersonationRow {
            id: *asked.id(),
            state: ImpersonationState::Active { since: at(30) },
            ..impersonation_row(ann, bob, 0)
        });

        db.store.save(&db.tenant, &approved).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, asked.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), ImpersonationStatus::Active);
        assert_eq!(found.state(), ImpersonationState::Active { since: at(30) });
        assert_eq!(found.reason(), asked.reason());
        assert_eq!(found.window(), asked.window());
    }

    /// Saving a stale approval after Ann's request ends conflicts and
    /// preserves the stored end time.
    #[tokio::test]
    async fn an_ended_request_is_not_brought_back_by_a_stale_save() {
        let db = fixture().await;
        let [ann, bob, _] = db.people;
        let asked = impersonation(impersonation_row(ann, bob, 0));
        db.store.save(&db.tenant, &asked).await.unwrap();
        let ended = impersonation(SupportImpersonationRow {
            id: *asked.id(),
            state: ImpersonationState::Ended { at: at(20) },
            ..impersonation_row(ann, bob, 0)
        });
        db.store.save(&db.tenant, &ended).await.unwrap();
        let stale = impersonation(SupportImpersonationRow {
            id: *asked.id(),
            state: ImpersonationState::Active { since: at(30) },
            ..impersonation_row(ann, bob, 0)
        });

        let saved = db.store.save(&db.tenant, &stale).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        let found = db
            .store
            .find_by_id(&db.tenant, asked.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.state(), ImpersonationState::Ended { at: at(20) });
    }

    /// The requests naming Bob, as admin or as the person, are listed
    /// newest first; one between others is left out; every request lists
    /// for the tenant.
    #[tokio::test]
    async fn requests_are_listed_newest_first() {
        let db = fixture().await;
        let [ann, bob, cid] = db.people;
        let first = impersonation(impersonation_row(ann, bob, 0));
        let second = impersonation(impersonation_row(bob, cid, 10));
        let third = impersonation(impersonation_row(ann, cid, 20));
        for request in [&first, &second, &third] {
            db.store.save(&db.tenant, request).await.unwrap();
        }

        let bobs = db.store.list_involving(&db.tenant, &bob).await.unwrap();
        let all = db.store.list_all(&db.tenant).await.unwrap();

        let ids = |found: &[SupportImpersonation<ResolvedTenant>]| -> Vec<SupportImpersonationId> {
            found.iter().map(|request| *request.id()).collect()
        };
        assert_eq!(ids(&bobs), [*second.id(), *first.id()]);
        assert_eq!(ids(&all), [*third.id(), *second.id(), *first.id()]);
    }

    /// An id nobody has finds nothing, and another tenant finds none of
    /// Acme's requests.
    #[tokio::test]
    async fn an_unknown_or_another_tenants_request_is_not_found() {
        let db = fixture().await;
        let [ann, bob, _] = db.people;
        let asked = impersonation(impersonation_row(ann, bob, 0));
        db.store.save(&db.tenant, &asked).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(
            db.store
                .find_by_id(&db.tenant, &SupportImpersonationId::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.store
                .find_by_id(&other, asked.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(db.store.list_all(&other).await.unwrap().is_empty());
    }

    /// Reading a support-impersonation row with a blank reason reports
    /// corrupt storage.
    #[tokio::test]
    async fn a_request_without_a_reason_is_refused() {
        let db = fixture().await;
        let [ann, bob, _] = db.people;
        let asked = impersonation(impersonation_row(ann, bob, 0));
        db.store.save(&db.tenant, &asked).await.unwrap();
        db.db
            .tamper("UPDATE support_impersonations SET reason = ''")
            .await;

        let read = db.store.find_by_id(&db.tenant, asked.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
