//! Each account's recovery codes, under the tenant's row-level security.
//!
//! A set has a row of its own and each code another, so spending a code is
//! one update that finds it only while it is unused: of two sign-ins
//! offering one code at once, only one gets through. Only the codes' keyed
//! hashes are kept.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::RecoveryCodeStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::recovery::codes::RecoveryCodeSet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TokenHash, UserId};
use sqlx::PgConnection;
use time::OffsetDateTime;

use self::record::{CodeRecord, SetColumns, SetRecord, spent_at};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of each account's recovery codes.
pub struct PgRecoveryCodeStore {
    databases: Arc<Databases>,
}

impl PgRecoveryCodeStore {
    /// A store keeping recovery codes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgRecoveryCodeStore {}

/// The set `user_id` of `tenant_id` holds and its codes, if they hold one.
async fn held(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    user_id: &UserId,
) -> Result<Option<(SetRecord, Vec<CodeRecord>)>, sqlx::Error> {
    let set = sqlx::query_file_as!(
        SetRecord,
        "queries/recovery_code_sets/of_user.sql",
        tenant_id.as_uuid(),
        user_id.as_uuid()
    )
    .fetch_optional(&mut *connection)
    .await?;
    let Some(set) = set else {
        return Ok(None);
    };
    let codes = sqlx::query_file_as!(
        CodeRecord,
        "queries/recovery_codes/of_user.sql",
        tenant_id.as_uuid(),
        user_id.as_uuid()
    )
    .fetch_all(connection)
    .await?;
    Ok(Some((set, codes)))
}

/// Writes the set `columns` hold in `tenant_id`, its old codes withdrawn.
async fn hand_out(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    columns: &SetColumns,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/recovery_code_sets/save.sql",
        tenant_id.as_uuid(),
        columns.user_id,
        columns.generated_at
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query_file!(
        "queries/recovery_codes/withdraw.sql",
        tenant_id.as_uuid(),
        columns.user_id
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query_file!(
        "queries/recovery_codes/hand_out.sql",
        tenant_id.as_uuid(),
        columns.user_id,
        &columns.code_hashes,
        &columns.used_at as &[Option<OffsetDateTime>]
    )
    .execute(connection)
    .await?;
    Ok(())
}

#[async_trait]
impl RecoveryCodeStore for PgRecoveryCodeStore {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<RecoveryCodeSet<ResolvedTenant>>, DomainError> {
        let found = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| held(connection, tenant_id, user_id).await,
        )
        .await?;
        found
            .map(|(set, codes)| set.into_code_set(codes))
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        codes: &RecoveryCodeSet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = SetColumns::of(codes);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| hand_out(connection, tenant_id, &columns).await,
        )
        .await
    }

    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        codes: &RecoveryCodeSet<ResolvedTenant>,
        hash: &TokenHash,
    ) -> Result<bool, DomainError> {
        let used_at = spent_at(codes, hash)?;
        let user_id = *codes.subject_id().as_uuid();
        let spent = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/recovery_codes/spend.sql",
                    tenant_id.as_uuid(),
                    user_id,
                    hash.as_str(),
                    used_at
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(spent.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authentication::recovery::codes::{
        RecoveryCode, RecoveryCodeRow, RecoveryCodeSetRow,
    };
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::Usage;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authentication::{hash, recovery_code_set_row};
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann and Bob in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgRecoveryCodeStore, ScopedTenant, UserId, UserId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let user = User::reconstitute(user_row(email)).unwrap();
            users.save(&acme, &user).await.unwrap();
            ids.push(*user.id());
        }
        let store = PgRecoveryCodeStore::new(Arc::clone(&db.databases));
        (db, store, acme, ids[0], ids[1])
    }

    fn set(row: RecoveryCodeSetRow) -> RecoveryCodeSet<ResolvedTenant> {
        RecoveryCodeSet::reconstitute(row).unwrap()
    }

    /// `user`'s set of `hashes`, with the code `spent` used at `at_second`.
    fn with_spent(
        user: UserId,
        hashes: &[&str],
        spent: &str,
        at_second: i64,
    ) -> RecoveryCodeSet<ResolvedTenant> {
        let codes = hashes
            .iter()
            .map(|code| {
                RecoveryCode::reconstitute(RecoveryCodeRow {
                    hash: hash(code),
                    usage: Usage::from_stored((*code == spent).then(|| at(at_second))),
                })
                .unwrap()
            })
            .collect();
        set(RecoveryCodeSetRow {
            codes,
            ..recovery_code_set_row(user, hashes)
        })
    }

    fn held_hashes(codes: &RecoveryCodeSet<ResolvedTenant>) -> Vec<&str> {
        codes
            .codes()
            .iter()
            .map(|code| code.hash().as_str())
            .collect()
    }

    /// Ann's codes are found again, every one unused, with when the set was
    /// made.
    #[tokio::test]
    async fn a_saved_set_is_found_for_its_user() {
        let (_db, store, acme, ann, _) = fixture().await;
        let codes = set(recovery_code_set_row(ann, &["hash-a", "hash-b"]));

        store.save(&acme, &codes).await.unwrap();

        let found = store.find_by_user(&acme, &ann).await.unwrap().unwrap();
        assert_eq!(found.subject_id(), codes.subject_id());
        assert_eq!(held_hashes(&found), ["hash-a", "hash-b"]);
        assert_eq!(found.remaining(), 2);
        assert_eq!(found.generated_at(), at(0));
    }

    /// A user who holds no codes finds none.
    #[tokio::test]
    async fn a_user_without_codes_finds_none() {
        let (_db, store, acme, ann, _) = fixture().await;

        assert!(store.find_by_user(&acme, &ann).await.unwrap().is_none());
    }

    /// Ann makes a new set: only the new codes are held afterwards.
    #[tokio::test]
    async fn saving_a_new_set_replaces_the_old_codes() {
        let (_db, store, acme, ann, _) = fixture().await;
        store
            .save(&acme, &set(recovery_code_set_row(ann, &["old-a", "old-b"])))
            .await
            .unwrap();
        let fresh = set(RecoveryCodeSetRow {
            generated_at: at(50),
            ..recovery_code_set_row(ann, &["new-a"])
        });

        store.save(&acme, &fresh).await.unwrap();

        let found = store.find_by_user(&acme, &ann).await.unwrap().unwrap();
        assert_eq!(held_hashes(&found), ["new-a"]);
        assert_eq!(found.generated_at(), at(50));
    }

    /// Spending a recovery code succeeds once; another spend fails and
    /// preserves the first use time, leaving the other code available.
    #[tokio::test]
    async fn a_code_is_spent_once() {
        let (_db, store, acme, ann, _) = fixture().await;
        let hashes = ["hash-a", "hash-b"];
        store
            .save(&acme, &set(recovery_code_set_row(ann, &hashes)))
            .await
            .unwrap();

        let won = store
            .spend(
                &acme,
                &with_spent(ann, &hashes, "hash-a", 30),
                &hash("hash-a"),
            )
            .await
            .unwrap();
        let lost = store
            .spend(
                &acme,
                &with_spent(ann, &hashes, "hash-a", 31),
                &hash("hash-a"),
            )
            .await
            .unwrap();

        let found = store.find_by_user(&acme, &ann).await.unwrap().unwrap();
        assert!(won);
        assert!(!lost);
        assert_eq!(found.remaining(), 1);
        assert_eq!(found.codes()[0].used_at(), Some(at(30)));
    }

    /// A spend naming Bob cannot consume Ann's code, which remains available.
    #[tokio::test]
    async fn a_code_of_another_user_is_not_spent() {
        let (_db, store, acme, ann, bob) = fixture().await;
        store
            .save(&acme, &set(recovery_code_set_row(ann, &["hash-a"])))
            .await
            .unwrap();
        store
            .save(&acme, &set(recovery_code_set_row(bob, &["hash-b"])))
            .await
            .unwrap();

        let spent = store
            .spend(
                &acme,
                &with_spent(bob, &["hash-a"], "hash-a", 30),
                &hash("hash-a"),
            )
            .await
            .unwrap();

        assert!(!spent);
        let anns = store.find_by_user(&acme, &ann).await.unwrap().unwrap();
        assert_eq!(anns.remaining(), 1);
    }

    /// Recording a spend for a code still unused in the supplied set fails
    /// validation.
    #[tokio::test]
    async fn an_unspent_code_is_not_recorded() {
        let (_db, store, acme, ann, _) = fixture().await;
        let codes = set(recovery_code_set_row(ann, &["hash-a"]));
        store.save(&acme, &codes).await.unwrap();

        let spent = store.spend(&acme, &codes, &hash("hash-a")).await;

        assert!(matches!(spent, Err(DomainError::Validation(_))));
    }

    /// Looking up Ann's recovery set through another tenant finds nothing.
    #[tokio::test]
    async fn another_tenants_codes_are_invisible() {
        let (_db, store, acme, ann, _) = fixture().await;
        store
            .save(&acme, &set(recovery_code_set_row(ann, &["hash-a"])))
            .await
            .unwrap();

        assert!(store.find_by_user(&tenant(), &ann).await.unwrap().is_none());
    }

    /// Deleting every code directly from storage leaves a corrupt set that
    /// the reader refuses.
    #[tokio::test]
    async fn a_set_without_codes_is_refused() {
        let (db, store, acme, ann, _) = fixture().await;
        store
            .save(&acme, &set(recovery_code_set_row(ann, &["hash-a"])))
            .await
            .unwrap();
        db.tamper("DELETE FROM recovery_codes").await;

        let read = store.find_by_user(&acme, &ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
