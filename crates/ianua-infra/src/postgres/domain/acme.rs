//! The HTTP-01 challenges a certificate authority reads, kept in the
//! platform database.
//!
//! The control plane publishes a challenge while it talks to the authority;
//! the proxy reads it when the authority arrives on the customer's
//! hostname, carrying only the token it issued. There is no tenant to
//! scope the read by, so the rows belong to none, and the token alone finds
//! one. The account the provisioner holds with each authority is kept
//! beside them, in `accounts`.

mod accounts;
mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::domain::AcmeChallengeStore;
use ianua_domain::domains::tenant::custom_domains::acme_challenge::{
    AcmeChallenge, ChallengeToken,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;

pub use self::accounts::PgAcmeAccountStore;
use self::record::ChallengeRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of ACME challenges.
pub struct PgAcmeChallengeStore {
    databases: Arc<Databases>,
}

impl PgAcmeChallengeStore {
    /// A store keeping challenges in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AcmeChallengeStore for PgAcmeChallengeStore {
    async fn publish(&self, challenge: &AcmeChallenge) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/acme_challenges/publish.sql",
                challenge.token().as_str(),
                challenge.key_authorization().as_str(),
                challenge.domain().as_str(),
                challenge.expires_at()
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }

    async fn find(&self, token: &ChallengeToken) -> Result<Option<AcmeChallenge>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ChallengeRecord,
                "queries/acme_challenges/by_token.sql",
                token.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(ChallengeRecord::into_challenge).transpose()
    }

    async fn withdraw(&self, token: &ChallengeToken) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!("queries/acme_challenges/withdraw.sql", token.as_str())
                .execute(connection)
                .await
                .map(|_| ())
        })
        .await
    }

    async fn purge_expired(&self) -> Result<u64, DomainError> {
        let now = clock::now();
        let purged = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!("queries/acme_challenges/purge_expired.sql", now)
                .execute(connection)
                .await
        })
        .await?;
        Ok(purged.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::acme_challenge::AcmeChallengeRow;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::domain::acme_challenge_row;

    /// Seconds from the fixed moment to a time long past, for expiry, which
    /// is compared against the real clock.
    const LONG_AGO: i64 = -100_000_000;

    /// A fresh database and the store on it.
    async fn fixture() -> (TestDb, PgAcmeChallengeStore) {
        let db = TestDb::fresh().await;
        let store = PgAcmeChallengeStore::new(Arc::clone(&db.databases));
        (db, store)
    }

    fn challenge(row: AcmeChallengeRow) -> AcmeChallenge {
        AcmeChallenge::reconstitute(row).unwrap()
    }

    fn token(text: &str) -> ChallengeToken {
        ChallengeToken::new(text).unwrap()
    }

    /// A published challenge is found by its token, as published, and a
    /// token nobody published finds nothing.
    #[tokio::test]
    async fn a_published_challenge_is_found_by_its_token() {
        let (_db, store) = fixture().await;
        let published = challenge(acme_challenge_row("abc", 3600));

        store.publish(&published).await.unwrap();

        assert_eq!(store.find(&token("abc")).await.unwrap(), Some(published));
        assert!(store.find(&token("other")).await.unwrap().is_none());
    }

    /// Publishing again for one token replaces the challenge.
    #[tokio::test]
    async fn publishing_again_replaces_the_challenge() {
        let (_db, store) = fixture().await;
        store
            .publish(&challenge(acme_challenge_row("abc", 3600)))
            .await
            .unwrap();
        let later = challenge(acme_challenge_row("abc", 7200));

        store.publish(&later).await.unwrap();

        let found = store.find(&token("abc")).await.unwrap().unwrap();
        assert_eq!(found.expires_at(), later.expires_at());
    }

    /// A withdrawn challenge is no longer found.
    #[tokio::test]
    async fn a_withdrawn_challenge_is_gone() {
        let (_db, store) = fixture().await;
        store
            .publish(&challenge(acme_challenge_row("abc", 3600)))
            .await
            .unwrap();

        store.withdraw(&token("abc")).await.unwrap();

        assert!(store.find(&token("abc")).await.unwrap().is_none());
    }

    /// Purging removes the expired ACME challenge and leaves the live one
    /// available by token.
    #[tokio::test]
    async fn expired_challenges_are_purged() {
        let (_db, store) = fixture().await;
        store
            .publish(&challenge(acme_challenge_row("old", LONG_AGO)))
            .await
            .unwrap();
        store
            .publish(&challenge(acme_challenge_row("live", 3600)))
            .await
            .unwrap();

        let purged = store.purge_expired().await.unwrap();

        assert_eq!(purged, 1);
        assert!(store.find(&token("old")).await.unwrap().is_none());
        assert!(store.find(&token("live")).await.unwrap().is_some());
    }

    /// An ACME challenge with an invalid stored domain name fails to load
    /// as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_challenge_is_refused() {
        let (db, store) = fixture().await;
        store
            .publish(&challenge(acme_challenge_row("abc", 3600)))
            .await
            .unwrap();
        db.tamper("UPDATE acme_challenges SET domain = 'not a domain'")
            .await;

        let read = store.find(&token("abc")).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
