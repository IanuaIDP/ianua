//! Requests to reset a password, each found by the hash of its mailed link.
//!
//! Completing one is one update that only finds it while it is pending, so
//! of two confirms of one link only one sets a password.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::ResetRequestStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::recovery::reset::PasswordResetRequest;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TokenHash, UserId};

use self::record::{ResetColumns, ResetRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a link to one reset of a tenant.
const TOKEN_KEY: &str = "password_resets_token_key";

/// The Postgres store of password reset requests.
pub struct PgResetRequestStore {
    databases: Arc<Databases>,
}

impl PgResetRequestStore {
    /// A store keeping reset requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgResetRequestStore {}

#[async_trait]
impl ResetRequestStore for PgResetRequestStore {
    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        hash: &TokenHash,
    ) -> Result<Option<PasswordResetRequest>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ResetRecord,
                    "queries/password_resets/by_token.sql",
                    tenant_id.as_uuid(),
                    hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ResetRecord::into_request).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &PasswordResetRequest,
    ) -> Result<(), DomainError> {
        let columns = ResetColumns::of(request);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/password_resets/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.user_id,
                    columns.email,
                    columns.initiator,
                    columns.status,
                    columns.completed_at,
                    columns.token_hash,
                    columns.created_at,
                    columns.expires_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, TOKEN_KEY)
            },
        )
        .await?;
        ensure_unique_link(written)
    }

    async fn complete(
        &self,
        tenant_id: &ScopedTenant,
        request: &PasswordResetRequest,
    ) -> Result<bool, DomainError> {
        let Some(completed_at) = request.reset_state().completed_at() else {
            return Err(DomainError::invalid(message!(
                "infra-a-reset-is-stored-as-completed",
                "a reset is stored as completed only once it is"
            )));
        };
        let completed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/password_resets/complete.sql",
                    tenant_id.as_uuid(),
                    request.id().as_uuid(),
                    completed_at
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(completed.rows_affected() > 0)
    }

    async fn expire_pending_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/password_resets/expire_pending_of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn find_latest_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PasswordResetRequest>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ResetRecord,
                    "queries/password_resets/latest_of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ResetRecord::into_request).transpose()
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<PasswordResetRequest>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ResetRecord,
                    "queries/password_resets/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(ResetRecord::into_request).collect()
    }
}

/// Reports a conflicting reset link without changing other database errors.
fn ensure_unique_link(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-another-reset-of-the-tenant-has",
            "another reset of the tenant has this link"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authentication::recovery::reset::{
        PasswordResetRow, ResetState, ResetStatus,
    };
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authentication::{hash, reset_row};
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgResetRequestStore, ScopedTenant, UserId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &ann)
            .await
            .unwrap();
        let store = PgResetRequestStore::new(Arc::clone(&db.databases));
        (db, store, acme, *ann.id())
    }

    fn request(row: PasswordResetRow) -> PasswordResetRequest {
        PasswordResetRequest::reconstitute(row).unwrap()
    }

    /// The request `pending` stands for, completed a minute after it was
    /// asked for.
    fn completed(pending: &PasswordResetRequest, user: UserId, link: &str) -> PasswordResetRequest {
        request(PasswordResetRow {
            id: *pending.id(),
            state: ResetState::Completed { at: at(60) },
            ..reset_row(user, link, 0)
        })
    }

    /// Ann's reset is found by its link and as her latest, as it was saved.
    #[tokio::test]
    async fn a_saved_reset_is_found_by_its_link_and_as_the_latest() {
        let (_db, store, acme, ann) = fixture().await;
        let reset = request(reset_row(ann, "link-1", 0));
        store.save(&acme, &reset).await.unwrap();

        let by_link = store
            .find_by_token_hash(&acme, &hash("link-1"))
            .await
            .unwrap()
            .unwrap();
        let latest = store
            .find_latest_by_user(&acme, &ann)
            .await
            .unwrap()
            .unwrap();

        for found in [&by_link, &latest] {
            assert_eq!(found.id(), reset.id());
            assert_eq!(found.status(), ResetStatus::Pending);
            assert_eq!(found.email(), reset.email());
            assert_eq!(found.expires_at(), reset.expires_at());
        }
    }

    /// A link nobody was sent, or a user who never asked, finds nothing.
    #[tokio::test]
    async fn an_unknown_reset_is_not_found() {
        let (_db, store, acme, ann) = fixture().await;

        assert!(
            store
                .find_by_token_hash(&acme, &hash("nobody"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .find_latest_by_user(&acme, &ann)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A second reset using a stored reset's link hash is refused as a conflict.
    #[tokio::test]
    async fn a_link_another_reset_has_is_refused() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .save(&acme, &request(reset_row(ann, "link-1", 0)))
            .await
            .unwrap();

        let second = store
            .save(&acme, &request(reset_row(ann, "link-1", 10)))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Completing a pending reset succeeds once; repeating completion
    /// returns false and the stored reset remains completed.
    #[tokio::test]
    async fn a_reset_is_completed_once() {
        let (_db, store, acme, ann) = fixture().await;
        let pending = request(reset_row(ann, "link-1", 0));
        store.save(&acme, &pending).await.unwrap();
        let done = completed(&pending, ann, "link-1");

        let first = store.complete(&acme, &done).await.unwrap();
        let second = store.complete(&acme, &done).await.unwrap();

        let found = store
            .find_latest_by_user(&acme, &ann)
            .await
            .unwrap()
            .unwrap();
        assert!(first);
        assert!(!second);
        assert_eq!(found.status(), ResetStatus::Completed);
    }

    /// Asking again expires Ann's pending link, and the latest is the one
    /// asked for last, whatever its status.
    #[tokio::test]
    async fn expiring_supersedes_pending_links() {
        let (_db, store, acme, ann) = fixture().await;
        let older = request(reset_row(ann, "link-1", 0));
        store.save(&acme, &older).await.unwrap();

        store.expire_pending_for_user(&acme, &ann).await.unwrap();
        let newer = request(reset_row(ann, "link-2", 30));
        store.save(&acme, &newer).await.unwrap();

        let old = store
            .find_by_token_hash(&acme, &hash("link-1"))
            .await
            .unwrap()
            .unwrap();
        let latest = store
            .find_latest_by_user(&acme, &ann)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(old.status(), ResetStatus::Expired);
        assert_eq!(latest.id(), newer.id());
    }

    /// Every reset Ann asked for is listed, newest first, the expired one
    /// with the pending one, and none of another tenant's.
    #[tokio::test]
    async fn every_reset_of_a_user_is_listed_newest_first() {
        let (_db, store, acme, ann) = fixture().await;
        let older = request(reset_row(ann, "link-1", 0));
        store.save(&acme, &older).await.unwrap();
        store.expire_pending_for_user(&acme, &ann).await.unwrap();
        let newer = request(reset_row(ann, "link-2", 30));
        store.save(&acme, &newer).await.unwrap();

        let listed = store.list_by_user(&acme, &ann).await.unwrap();
        let elsewhere = store.list_by_user(&tenant(), &ann).await.unwrap();

        let ids: Vec<_> = listed.iter().map(|reset| *reset.id()).collect();
        assert_eq!(ids, [*newer.id(), *older.id()]);
        assert_eq!(listed[1].status(), ResetStatus::Expired);
        assert!(elsewhere.is_empty());
    }

    /// Completion returns false after the stored reset has been expired.
    #[tokio::test]
    async fn an_expired_reset_is_not_completed() {
        let (_db, store, acme, ann) = fixture().await;
        let pending = request(reset_row(ann, "link-1", 0));
        store.save(&acme, &pending).await.unwrap();
        store.expire_pending_for_user(&acme, &ann).await.unwrap();

        let completed = store
            .complete(&acme, &completed(&pending, ann, "link-1"))
            .await
            .unwrap();

        assert!(!completed);
    }

    /// Globex cannot find Ann's reset by its link hash or as her latest reset.
    #[tokio::test]
    async fn another_tenants_resets_are_invisible() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .save(&acme, &request(reset_row(ann, "link-1", 0)))
            .await
            .unwrap();
        let globex = tenant();

        assert!(
            store
                .find_by_token_hash(&globex, &hash("link-1"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .find_latest_by_user(&globex, &ann)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// An invalid email address written directly into a reset row makes
    /// its lookup fail as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_reset_is_refused() {
        let (db, store, acme, ann) = fixture().await;
        store
            .save(&acme, &request(reset_row(ann, "link-1", 0)))
            .await
            .unwrap();
        db.tamper("UPDATE password_resets SET email = 'not an address'")
            .await;

        let read = store.find_by_token_hash(&acme, &hash("link-1")).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
