//! Members' recovery codes, in the platform database.
//!
//! A set has a row of its own and each code another, so spending a code is
//! one update that finds it only while it is unused: of two sign-ins
//! offering one code at once, only one gets through.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgRecoveryCodeStore;
use ianua_domain::domains::authentication::recovery::codes::RecoveryCodeSet;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, TokenHash};
use time::OffsetDateTime;

use self::record::{CodeRecord, SetColumns, SetRecord, spent_at};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of members' recovery codes.
pub struct PgOrgRecoveryCodeStore {
    databases: Arc<Databases>,
}

impl PgOrgRecoveryCodeStore {
    /// A store keeping recovery codes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgRecoveryCodeStore for PgOrgRecoveryCodeStore {
    async fn find_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<RecoveryCodeSet<ResolvedOrganization>>, DomainError> {
        let held = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let set = sqlx::query_file_as!(
                SetRecord,
                "queries/org_recovery_code_sets/of_member.sql",
                org_user_id.as_uuid()
            )
            .fetch_optional(&mut *connection)
            .await?;
            let Some(set) = set else {
                return Ok(None);
            };
            let codes = sqlx::query_file_as!(
                CodeRecord,
                "queries/org_recovery_codes/of_member.sql",
                org_user_id.as_uuid()
            )
            .fetch_all(connection)
            .await?;
            Ok(Some((set, codes)))
        })
        .await?;
        held.map(|(set, codes)| set.into_code_set(codes))
            .transpose()
    }

    async fn save(
        &self,
        org_user_id: &OrgUserId,
        codes: &RecoveryCodeSet<ResolvedOrganization>,
    ) -> Result<(), DomainError> {
        let columns = SetColumns::of(org_user_id, codes)?;
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_recovery_code_sets/save.sql",
                columns.org_user_id,
                columns.generated_at
            )
            .execute(&mut *connection)
            .await?;
            sqlx::query_file!(
                "queries/org_recovery_codes/withdraw.sql",
                columns.org_user_id
            )
            .execute(&mut *connection)
            .await?;
            sqlx::query_file!(
                "queries/org_recovery_codes/hand_out.sql",
                columns.org_user_id,
                &columns.code_hashes,
                &columns.used_at as &[Option<OffsetDateTime>]
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    async fn spend(
        &self,
        org_user_id: &OrgUserId,
        codes: &RecoveryCodeSet<ResolvedOrganization>,
        hash: &TokenHash,
    ) -> Result<bool, DomainError> {
        let used_at = spent_at(org_user_id, codes, hash)?;
        let spent = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_recovery_codes/spend.sql",
                org_user_id.as_uuid(),
                hash.as_str(),
                used_at
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(spent.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_domain::domains::authentication::recovery::codes::{
        RecoveryCode, RecoveryCodeRow, RecoveryCodeSetRow,
    };
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::Usage;

    use super::*;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{
        org_recovery_code_set_row, org_user_row, organization_row,
    };

    /// A fresh database holding Acme and two of its members, and the store
    /// on it.
    async fn fixture() -> (TestDb, PgOrgRecoveryCodeStore, OrgUserId, OrgUserId) {
        let db = TestDb::fresh().await;
        let acme = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme)
            .await
            .unwrap();
        let members = PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let member = OrgUser::reconstitute(org_user_row(*acme.id(), email)).unwrap();
            members.save(&member).await.unwrap();
            ids.push(*member.id());
        }
        let store = PgOrgRecoveryCodeStore::new(Arc::clone(&db.databases));
        (db, store, ids.remove(0), ids.remove(0))
    }

    fn set(row: RecoveryCodeSetRow) -> RecoveryCodeSet<ResolvedOrganization> {
        RecoveryCodeSet::reconstitute(row).unwrap()
    }

    fn hash(value: &str) -> TokenHash {
        TokenHash::from_stored(value.to_owned())
    }

    /// `member`'s set of `hashes`, with the code `spent` used at
    /// `at_second`.
    fn with_spent(
        member: OrgUserId,
        hashes: &[&str],
        spent: &str,
        at_second: i64,
    ) -> RecoveryCodeSet<ResolvedOrganization> {
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
            ..org_recovery_code_set_row(member, hashes)
        })
    }

    fn held_hashes(codes: &RecoveryCodeSet<ResolvedOrganization>) -> Vec<&str> {
        codes
            .codes()
            .iter()
            .map(|code| code.hash().as_str())
            .collect()
    }

    /// Ann's codes are found again, every one unused, with when the set was
    /// made.
    #[tokio::test]
    async fn a_saved_set_is_found_for_its_member() {
        let (_db, store, ann, _) = fixture().await;
        let codes = set(org_recovery_code_set_row(ann, &["hash-a", "hash-b"]));

        store.save(&ann, &codes).await.unwrap();

        let found = store.find_by_user(&ann).await.unwrap().unwrap();
        assert_eq!(found.subject_id(), codes.subject_id());
        assert_eq!(held_hashes(&found), ["hash-a", "hash-b"]);
        assert_eq!(found.remaining(), 2);
        assert_eq!(found.generated_at(), at(0));
    }

    /// A member who holds no codes finds none.
    #[tokio::test]
    async fn a_member_without_codes_finds_none() {
        let (_db, store, ann, _) = fixture().await;

        assert!(store.find_by_user(&ann).await.unwrap().is_none());
    }

    /// Ann makes a new set: only the new codes are held afterwards.
    #[tokio::test]
    async fn saving_a_new_set_replaces_the_old_codes() {
        let (_db, store, ann, _) = fixture().await;
        store
            .save(
                &ann,
                &set(org_recovery_code_set_row(ann, &["old-a", "old-b"])),
            )
            .await
            .unwrap();
        let fresh = set(RecoveryCodeSetRow {
            generated_at: at(50),
            ..org_recovery_code_set_row(ann, &["new-a"])
        });

        store.save(&ann, &fresh).await.unwrap();

        let found = store.find_by_user(&ann).await.unwrap().unwrap();
        assert_eq!(held_hashes(&found), ["new-a"]);
        assert_eq!(found.generated_at(), at(50));
    }

    /// Spending a code records when it was used, and the others stay
    /// unused.
    #[tokio::test]
    async fn a_spent_code_reads_back_used() {
        let (_db, store, ann, _) = fixture().await;
        let hashes = ["hash-a", "hash-b"];
        store
            .save(&ann, &set(org_recovery_code_set_row(ann, &hashes)))
            .await
            .unwrap();

        let spent = store
            .spend(
                &ann,
                &with_spent(ann, &hashes, "hash-a", 30),
                &hash("hash-a"),
            )
            .await
            .unwrap();

        assert!(spent);
        let found = store.find_by_user(&ann).await.unwrap().unwrap();
        assert_eq!(found.remaining(), 1);
        assert_eq!(found.codes()[0].used_at(), Some(at(30)));
    }

    /// Spending the same stored code twice succeeds only for the first
    /// attempt.
    #[tokio::test]
    async fn a_code_is_spent_once() {
        let (_db, store, ann, _) = fixture().await;
        let hashes = ["hash-a"];
        store
            .save(&ann, &set(org_recovery_code_set_row(ann, &hashes)))
            .await
            .unwrap();
        let first = with_spent(ann, &hashes, "hash-a", 30);
        let second = with_spent(ann, &hashes, "hash-a", 31);

        let won = store.spend(&ann, &first, &hash("hash-a")).await.unwrap();
        let lost = store.spend(&ann, &second, &hash("hash-a")).await.unwrap();

        assert!(won);
        assert!(!lost);
    }

    /// Attempting to spend Ann's hash under Bob returns false and leaves
    /// Ann's code unused.
    #[tokio::test]
    async fn a_code_of_another_member_is_not_spent() {
        let (_db, store, ann, bob) = fixture().await;
        let hashes = ["hash-a"];
        store
            .save(&ann, &set(org_recovery_code_set_row(ann, &hashes)))
            .await
            .unwrap();
        store
            .save(&bob, &set(org_recovery_code_set_row(bob, &["hash-b"])))
            .await
            .unwrap();

        let spent = store
            .spend(
                &bob,
                &with_spent(bob, &hashes, "hash-a", 30),
                &hash("hash-a"),
            )
            .await
            .unwrap();

        assert!(!spent);
        let anns = store.find_by_user(&ann).await.unwrap().unwrap();
        assert_eq!(anns.remaining(), 1);
    }

    /// Saving Ann's recovery-code set under Bob returns a validation error
    /// and leaves Bob without a stored set.
    #[tokio::test]
    async fn a_set_saved_for_another_member_is_refused() {
        let (_db, store, ann, bob) = fixture().await;

        let saved = store
            .save(&bob, &set(org_recovery_code_set_row(ann, &["hash-a"])))
            .await;

        assert!(matches!(saved, Err(DomainError::Validation(_))));
        assert!(store.find_by_user(&bob).await.unwrap().is_none());
    }

    /// Recording a spend from a set whose code is still unused returns a
    /// validation error.
    #[tokio::test]
    async fn recording_a_code_not_spent_in_the_set_is_refused() {
        let (_db, store, ann, _) = fixture().await;
        let unspent = set(org_recovery_code_set_row(ann, &["hash-a"]));
        store.save(&ann, &unspent).await.unwrap();

        let spent = store.spend(&ann, &unspent, &hash("hash-a")).await;

        assert!(matches!(spent, Err(DomainError::Validation(_))));
    }

    /// Reading a code whose stored use time predates its set's creation
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_set_is_refused() {
        let (db, store, ann, _) = fixture().await;
        store
            .save(&ann, &set(org_recovery_code_set_row(ann, &["hash-a"])))
            .await
            .unwrap();
        db.tamper("UPDATE org_recovery_codes SET used_at = '2000-01-01T00:00:00Z'")
            .await;

        let read = store.find_by_user(&ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
