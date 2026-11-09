//! The accounts the certificate provisioner holds with each authority,
//! kept in the platform database, one per directory.
//!
//! The credentials hold the account's private key, so they are sealed by
//! the platform's secret sealer before they are written and opened as they
//! are read; the database never holds them in clear. Saving again replaces
//! them and keeps when the account was first kept. Overlapping registrations
//! may finish out of order; the recorded change time never moves backwards.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use self::record::{AccountRecord, into_credentials};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::tls::{AcmeAccountStore, AcmeDirectory};

/// Where the account held with `directory` keeps its credentials sealed:
/// the platform's, in the row of that directory, so credentials moved to
/// another directory's row do not open there.
fn account_place(directory: &AcmeDirectory) -> SealedFor {
    SealedFor::new(
        SealOwner::Platform,
        SealedField::AcmeAccountKey,
        directory.as_str(),
    )
}

/// The Postgres store of the accounts held with certificate authorities.
pub struct PgAcmeAccountStore {
    databases: Arc<Databases>,
    sealer: Arc<dyn SecretEncryptor>,
}

impl PgAcmeAccountStore {
    /// A store keeping accounts in `databases`, their credentials sealed
    /// and opened by `sealer`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, sealer: Arc<dyn SecretEncryptor>) -> Self {
        Self { databases, sealer }
    }
}

#[async_trait]
impl AcmeAccountStore for PgAcmeAccountStore {
    async fn load(&self, directory: &AcmeDirectory) -> Result<Option<Secret>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                AccountRecord,
                "queries/acme_accounts/find.sql",
                directory.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        let Some(record) = record else {
            return Ok(None);
        };
        let opened = self
            .sealer
            .decrypt(&record.sealed()?, &account_place(directory))
            .await?;
        into_credentials(opened).map(Some)
    }

    async fn save(
        &self,
        directory: &AcmeDirectory,
        credentials: &Secret,
    ) -> Result<(), DomainError> {
        let sealed = self
            .sealer
            .encrypt(credentials.expose().as_bytes(), &account_place(directory))
            .await?;
        let now = clock::now();
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/acme_accounts/save.sql",
                directory.as_str(),
                sealed.as_str(),
                now
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::authentication::FakeEncryptor;

    use super::*;
    use crate::test_support::TestDb;

    const PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
    const STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

    /// A fresh database and the store on it, sealing with the fake sealer.
    async fn fixture() -> (TestDb, PgAcmeAccountStore) {
        let db = TestDb::fresh().await;
        let store = PgAcmeAccountStore::new(Arc::clone(&db.databases), Arc::new(FakeEncryptor));
        (db, store)
    }

    fn directory(address: &str) -> AcmeDirectory {
        AcmeDirectory::parse(address).unwrap()
    }

    async fn loaded(store: &PgAcmeAccountStore, address: &str) -> Option<String> {
        store
            .load(&directory(address))
            .await
            .unwrap()
            .map(|secret| secret.expose().to_owned())
    }

    /// Kept credentials load back opened, as they were kept.
    #[tokio::test]
    async fn kept_credentials_load_back_opened() {
        let (_db, store) = fixture().await;

        store
            .save(&directory(PRODUCTION), &Secret::new("{\"id\":\"one\"}"))
            .await
            .unwrap();

        assert_eq!(
            loaded(&store, PRODUCTION).await.as_deref(),
            Some("{\"id\":\"one\"}")
        );
    }

    /// An authority no account was kept for loads none.
    #[tokio::test]
    async fn an_authority_never_kept_loads_none() {
        let (_db, store) = fixture().await;

        assert!(loaded(&store, PRODUCTION).await.is_none());
    }

    /// Saving again for one authority replaces what was kept.
    #[tokio::test]
    async fn saving_again_replaces_the_credentials() {
        let (_db, store) = fixture().await;
        store
            .save(&directory(PRODUCTION), &Secret::new("first"))
            .await
            .unwrap();

        store
            .save(&directory(PRODUCTION), &Secret::new("second"))
            .await
            .unwrap();

        assert_eq!(loaded(&store, PRODUCTION).await.as_deref(), Some("second"));
    }

    /// Saving credentials with a timestamp earlier than the first save
    /// succeeds, and the last completed save's credentials remain readable.
    #[tokio::test]
    async fn an_earlier_registration_can_finish_after_a_later_one() {
        let (_db, store) = fixture().await;
        let later = clock::now() + time::Duration::minutes(6);
        {
            let _clock = clock::freeze(later);
            store
                .save(
                    &directory(PRODUCTION),
                    &Secret::new("first completed registration"),
                )
                .await
                .unwrap();
        }
        {
            let _clock = clock::freeze(later - time::Duration::minutes(1));
            store
                .save(
                    &directory(PRODUCTION),
                    &Secret::new("later completed registration"),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            loaded(&store, PRODUCTION).await.as_deref(),
            Some("later completed registration")
        );
    }

    /// Staging and production directories each return their own saved
    /// credentials.
    #[tokio::test]
    async fn staging_and_production_are_kept_apart() {
        let (_db, store) = fixture().await;

        store
            .save(&directory(PRODUCTION), &Secret::new("production"))
            .await
            .unwrap();
        store
            .save(&directory(STAGING), &Secret::new("staging"))
            .await
            .unwrap();

        assert_eq!(
            loaded(&store, PRODUCTION).await.as_deref(),
            Some("production")
        );
        assert_eq!(loaded(&store, STAGING).await.as_deref(), Some("staging"));
    }

    /// An invalid stored sealed credential makes loading the ACME account
    /// return an infrastructure error.
    #[tokio::test]
    async fn a_corrupt_sealed_value_is_refused() {
        let (db, store) = fixture().await;
        store
            .save(&directory(PRODUCTION), &Secret::new("key"))
            .await
            .unwrap();
        db.tamper("UPDATE acme_accounts SET credentials_sealed = 'not sealed here'")
            .await;

        let result = store.load(&directory(PRODUCTION)).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }
}
