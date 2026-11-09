//! The second-factor step of an app sign-in, each challenge found by the
//! hash of the token in the browser's challenge cookie.
//!
//! A challenge goes with the session it finishes signing in. Saving it
//! again counts one more wrong code on what is stored, so two wrong codes
//! saved from copies read together both count, and it is removed once
//! answered or given up.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::MfaChallengeStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::sessions::mfa_challenge::MfaChallenge;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TokenHash;

use self::record::{ChallengeColumns, ChallengeRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of app sign-in second-factor challenges.
pub struct PgMfaChallengeStore {
    databases: Arc<Databases>,
}

impl PgMfaChallengeStore {
    /// A store keeping challenges in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgMfaChallengeStore {}

#[async_trait]
impl MfaChallengeStore for PgMfaChallengeStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        challenge: &MfaChallenge<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ChallengeColumns::of(challenge);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/mfa_challenges/save.sql",
                    tenant_id.as_uuid(),
                    columns.token_hash,
                    columns.session_id,
                    columns.expires_at,
                    columns.failed_attempts,
                    columns.consumed_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<MfaChallenge<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChallengeRecord,
                    "queries/mfa_challenges/by_token.sql",
                    tenant_id.as_uuid(),
                    token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ChallengeRecord::into_challenge).transpose()
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/mfa_challenges/delete.sql",
                    tenant_id.as_uuid(),
                    token_hash.as_str()
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
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::shared::SessionStore;
    use ianua_domain::domains::authentication::sessions::mfa_challenge::MfaChallengeRow;
    use ianua_domain::domains::authentication::sessions::session::Session;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::SessionId;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::postgres::shared::PgSessionStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authentication::{challenge_row, hash, session_row};
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann's session in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgMfaChallengeStore, ScopedTenant, SessionId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &ann)
            .await
            .unwrap();
        let session = Session::reconstitute(session_row(*ann.id(), "refresh-1")).unwrap();
        PgSessionStore::new(Arc::clone(&db.databases))
            .save(&acme, &session)
            .await
            .unwrap();
        let store = PgMfaChallengeStore::new(Arc::clone(&db.databases));
        (db, store, acme, *session.id())
    }

    fn challenge(row: MfaChallengeRow) -> MfaChallenge<ResolvedTenant> {
        MfaChallenge::reconstitute(row).unwrap()
    }

    /// The challenge Ann's sign-in waits on is found by its token, and a
    /// wrong code counted on it is kept.
    #[tokio::test]
    async fn a_saved_challenge_keeps_its_wrong_codes() {
        let (_db, store, acme, session) = fixture().await;
        store
            .save(&acme, &challenge(challenge_row(session, "token-1")))
            .await
            .unwrap();

        store
            .save(
                &acme,
                &challenge(MfaChallengeRow {
                    failed_attempts: 2,
                    ..challenge_row(session, "token-1")
                }),
            )
            .await
            .unwrap();

        let found = store
            .find_by_token_hash(&acme, &hash("token-1"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.session_id(), &session);
        assert_eq!(found.failed_attempts(), 2);
    }

    /// Saving the same challenge copy with one failed attempt twice
    /// increments the stored count to two.
    #[tokio::test]
    async fn wrong_codes_saved_together_all_count() {
        let (_db, store, acme, session) = fixture().await;
        store
            .save(&acme, &challenge(challenge_row(session, "token-1")))
            .await
            .unwrap();
        let counted_once = challenge(MfaChallengeRow {
            failed_attempts: 1,
            ..challenge_row(session, "token-1")
        });

        store.save(&acme, &counted_once).await.unwrap();
        store.save(&acme, &counted_once).await.unwrap();

        let found = store
            .find_by_token_hash(&acme, &hash("token-1"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.failed_attempts(), 2);
    }

    /// A token nobody holds finds nothing, and a removed challenge is gone.
    #[tokio::test]
    async fn a_removed_or_unknown_challenge_is_not_found() {
        let (_db, store, acme, session) = fixture().await;
        store
            .save(&acme, &challenge(challenge_row(session, "token-1")))
            .await
            .unwrap();

        store.delete(&acme, &hash("token-1")).await.unwrap();

        for token in ["token-1", "nobody"] {
            assert!(
                store
                    .find_by_token_hash(&acme, &hash(token))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    /// Another tenant cannot find Ann's challenge by its token hash.
    #[tokio::test]
    async fn another_tenants_challenges_are_invisible() {
        let (_db, store, acme, session) = fixture().await;
        store
            .save(&acme, &challenge(challenge_row(session, "token-1")))
            .await
            .unwrap();

        let elsewhere = store
            .find_by_token_hash(&tenant(), &hash("token-1"))
            .await
            .unwrap();

        assert!(elsewhere.is_none());
    }

    /// A failed-attempt count of 999 written directly to storage makes the
    /// challenge read fail as corrupt storage.
    #[tokio::test]
    async fn a_challenge_with_an_impossible_count_is_refused() {
        let (db, store, acme, session) = fixture().await;
        store
            .save(&acme, &challenge(challenge_row(session, "token-1")))
            .await
            .unwrap();
        db.tamper("UPDATE mfa_challenges SET failed_attempts = 999")
            .await;

        let read = store.find_by_token_hash(&acme, &hash("token-1")).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
