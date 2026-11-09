//! Sign-ups waiting for their founder's link, kept in the platform
//! database.
//!
//! A sign-up belongs to no organization yet, so it is found by the hash of
//! its link's token alone. Taking it removes it in the same statement that
//! reads it, so of two clicks on one link only one founds anything.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::PendingSignupStore;
use ianua_domain::domains::organization::signup::PendingSignup;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TokenHash;

use self::record::{SignupColumns, SignupRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of sign-ups waiting for their link.
pub struct PgPendingSignupStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgPendingSignupStore {
    /// A store keeping sign-ups in `databases`, checking each stored name
    /// against `limits` as it is read back.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }
}

#[async_trait]
impl PendingSignupStore for PgPendingSignupStore {
    async fn save(&self, signup: &PendingSignup) -> Result<(), DomainError> {
        let row = signup.to_row();
        let columns = SignupColumns::of(&row);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/pending_signups/save.sql",
                columns.token_hash,
                columns.email,
                columns.company_name,
                columns.tenant_name,
                columns.admin_display_name,
                columns.password_hash,
                columns.timezone,
                columns.locale,
                columns.requested_at,
                columns.expires_at,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    async fn take(&self, hash: &TokenHash) -> Result<Option<PendingSignup>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                SignupRecord,
                "queries/pending_signups/take.sql",
                hash.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record
            .map(|record| record.into_signup(&self.limits))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::signup::PendingSignupRow;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::pending_signup_row;

    /// A fresh database, and the store on it.
    async fn fixture() -> (TestDb, PgPendingSignupStore) {
        let db = TestDb::fresh().await;
        let store = PgPendingSignupStore::new(Arc::clone(&db.databases), DomainLimits::default());
        (db, store)
    }

    fn signup(row: PendingSignupRow) -> PendingSignup {
        PendingSignup::reconstitute(row).unwrap()
    }

    fn hash(token: &str) -> TokenHash {
        TokenHash::from_stored(token.to_owned())
    }

    /// Ann signs up and follows her link: the sign-up comes back as it was
    /// asked for.
    #[tokio::test]
    async fn a_saved_signup_is_taken_back_by_its_link() {
        let (_db, store) = fixture().await;
        let asked = pending_signup_row("ann@acme.example", "link");

        store.save(&signup(asked.clone())).await.unwrap();

        let taken = store.take(&hash("link")).await.unwrap().unwrap();
        assert_eq!(taken.to_row(), asked);
    }

    /// Taking a saved signup by its token hash returns it once and then
    /// returns none.
    #[tokio::test]
    async fn a_signup_is_taken_once() {
        let (_db, store) = fixture().await;
        store
            .save(&signup(pending_signup_row("ann@acme.example", "link")))
            .await
            .unwrap();

        let first = store.take(&hash("link")).await.unwrap();
        let second = store.take(&hash("link")).await.unwrap();

        assert!(first.is_some());
        assert!(second.is_none());
    }

    /// A link nobody was sent finds nothing, and leaves the other sign-ups
    /// waiting.
    #[tokio::test]
    async fn an_unknown_link_takes_nothing() {
        let (_db, store) = fixture().await;
        store
            .save(&signup(pending_signup_row("ann@acme.example", "link")))
            .await
            .unwrap();

        let unknown = store.take(&hash("nobody")).await.unwrap();

        assert!(unknown.is_none());
        assert!(store.take(&hash("link")).await.unwrap().is_some());
    }

    /// Saving again under the same link keeps the new values.
    #[tokio::test]
    async fn saving_again_under_one_link_keeps_the_new_values() {
        let (_db, store) = fixture().await;
        store
            .save(&signup(pending_signup_row("ann@acme.example", "link")))
            .await
            .unwrap();
        let again = PendingSignupRow {
            requested_at: at(10),
            expires_at: at(20),
            ..pending_signup_row("bob@acme.example", "link")
        };

        store.save(&signup(again.clone())).await.unwrap();

        let taken = store.take(&hash("link")).await.unwrap().unwrap();
        assert_eq!(taken.to_row(), again);
    }

    /// Taking a signup whose stored email is invalid returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_signup_is_refused() {
        let (db, store) = fixture().await;
        store
            .save(&signup(pending_signup_row("ann@acme.example", "link")))
            .await
            .unwrap();
        db.tamper("UPDATE pending_signups SET email = 'not an address'")
            .await;

        let taken = store.take(&hash("link")).await;

        assert!(matches!(taken, Err(DomainError::Infrastructure(_))));
    }
}
