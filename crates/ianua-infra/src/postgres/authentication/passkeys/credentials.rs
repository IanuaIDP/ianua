//! Each account's passkeys, under the tenant's row-level security.
//!
//! A passkey is found at sign-in by its `WebAuthn` credential id, so that
//! id names one passkey of a tenant. Only the public key is kept.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::PasskeyStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PasskeyCredentialId, PasskeyId, UserId};

use self::record::{PasskeyColumns, PasskeyRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a credential id to one passkey of a tenant.
const CREDENTIAL_KEY: &str = "passkey_credentials_credential_key";

/// The Postgres store of each account's passkeys.
pub struct PgPasskeyStore {
    databases: Arc<Databases>,
}

impl PgPasskeyStore {
    /// A store keeping passkeys in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgPasskeyStore {}

#[async_trait]
impl PasskeyStore for PgPasskeyStore {
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PasskeyRecord,
                    "queries/passkey_credentials/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(PasskeyRecord::into_passkey)
            .collect()
    }

    async fn find_by_credential_id(
        &self,
        tenant_id: &ScopedTenant,
        credential_id: &PasskeyCredentialId,
    ) -> Result<Option<PasskeyCredential<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PasskeyRecord,
                    "queries/passkey_credentials/by_credential.sql",
                    tenant_id.as_uuid(),
                    credential_id.as_bytes()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(PasskeyRecord::into_passkey).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        credential: &PasskeyCredential<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = PasskeyColumns::of(credential);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/passkey_credentials/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.user_id,
                    columns.credential_id,
                    columns.public_key,
                    columns.sign_count,
                    columns.authenticator_type,
                    columns.attestation,
                    columns.name,
                    columns.last_used_at,
                    columns.created_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, CREDENTIAL_KEY)
            },
        )
        .await?;
        ensure_unique_credential(written)
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &PasskeyId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/passkey_credentials/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

/// Reports a credential already registered in the tenant as a conflict.
fn ensure_unique_credential(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-this-passkey-is-registered-already",
            "this passkey is registered already"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredentialRow;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::Label;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authentication::passkey_row;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann and Bob in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgPasskeyStore, ScopedTenant, UserId, UserId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let user = User::reconstitute(user_row(email)).unwrap();
            users.save(&acme, &user).await.unwrap();
            ids.push(*user.id());
        }
        let store = PgPasskeyStore::new(Arc::clone(&db.databases));
        (db, store, acme, ids[0], ids[1])
    }

    fn passkey(row: PasskeyCredentialRow) -> PasskeyCredential<ResolvedTenant> {
        PasskeyCredential::reconstitute(row).unwrap()
    }

    /// Ann's two passkeys are listed in the order she added them, and one
    /// is found by its credential id; Bob's is not among hers.
    #[tokio::test]
    async fn saved_passkeys_are_listed_and_found_by_credential() {
        let (_db, store, acme, ann, bob) = fixture().await;
        let first = passkey(passkey_row(ann, b"key-1"));
        let second = passkey(PasskeyCredentialRow {
            created_at: at(10),
            ..passkey_row(ann, b"key-2")
        });
        for key in [&first, &second, &passkey(passkey_row(bob, b"key-3"))] {
            store.save(&acme, key).await.unwrap();
        }

        let listed = store.list_by_user(&acme, &ann).await.unwrap();
        let found = store
            .find_by_credential_id(&acme, second.credential_id())
            .await
            .unwrap()
            .unwrap();

        let ids: Vec<&PasskeyId> = listed.iter().map(PasskeyCredential::id).collect();
        assert_eq!(ids, [first.id(), second.id()]);
        assert_eq!(found.id(), second.id());
        assert_eq!(found.public_key(), second.public_key());
    }

    /// A credential nobody registered finds nothing.
    #[tokio::test]
    async fn an_unknown_credential_is_not_found() {
        let (_db, store, acme, _, _) = fixture().await;
        let unknown = PasskeyCredentialId::new(b"nobody".to_vec()).unwrap();

        assert!(
            store
                .find_by_credential_id(&acme, &unknown)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Ann signs in with her key and renames it: saving again keeps the new
    /// counter, last use and name.
    #[tokio::test]
    async fn saving_again_keeps_the_new_counter_and_name() {
        let (_db, store, acme, ann, _) = fixture().await;
        let key = passkey(passkey_row(ann, b"key-1"));
        store.save(&acme, &key).await.unwrap();
        let used = passkey(PasskeyCredentialRow {
            id: *key.id(),
            sign_count: 7,
            last_used_at: Some(at(30)),
            name: Label::new("name", "Office key").unwrap(),
            ..passkey_row(ann, b"key-1")
        });

        store.save(&acme, &used).await.unwrap();

        let found = store.list_by_user(&acme, &ann).await.unwrap();
        assert_eq!(found[0].sign_count(), 7);
        assert_eq!(found[0].last_used_at(), Some(at(30)));
        assert_eq!(found[0].name().as_str(), "Office key");
    }

    /// Saving a stale passkey copy preserves the greater sign counter and
    /// later last-use time already stored for Ann's key.
    #[tokio::test]
    async fn a_stale_save_never_lowers_the_counter() {
        let (_db, store, acme, ann, _) = fixture().await;
        let key = passkey(passkey_row(ann, b"key-1"));
        store.save(&acme, &key).await.unwrap();
        let latest = passkey(PasskeyCredentialRow {
            id: *key.id(),
            sign_count: 9,
            last_used_at: Some(at(40)),
            ..passkey_row(ann, b"key-1")
        });
        let stale = passkey(PasskeyCredentialRow {
            id: *key.id(),
            sign_count: 7,
            last_used_at: Some(at(30)),
            ..passkey_row(ann, b"key-1")
        });
        store.save(&acme, &latest).await.unwrap();

        store.save(&acme, &stale).await.unwrap();

        let found = store.list_by_user(&acme, &ann).await.unwrap();
        assert_eq!(found[0].sign_count(), 9);
        assert_eq!(found[0].last_used_at(), Some(at(40)));
    }

    /// Bob's passkey is refused as a conflict when its credential ID is
    /// already registered to Ann in the same tenant.
    #[tokio::test]
    async fn a_credential_another_passkey_holds_is_refused() {
        let (_db, store, acme, ann, bob) = fixture().await;
        store
            .save(&acme, &passkey(passkey_row(ann, b"key-1")))
            .await
            .unwrap();

        let second = store
            .save(&acme, &passkey(passkey_row(bob, b"key-1")))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Ann removes her key: it is gone from her list.
    #[tokio::test]
    async fn a_deleted_passkey_is_gone() {
        let (_db, store, acme, ann, _) = fixture().await;
        let key = passkey(passkey_row(ann, b"key-1"));
        store.save(&acme, &key).await.unwrap();

        store.delete(&acme, key.id()).await.unwrap();

        assert!(store.list_by_user(&acme, &ann).await.unwrap().is_empty());
    }

    /// Globex cannot find Ann's passkey, and deleting it through Globex
    /// leaves Ann's Acme passkey list intact.
    #[tokio::test]
    async fn another_tenants_passkeys_are_invisible() {
        let (_db, store, acme, ann, _) = fixture().await;
        let key = passkey(passkey_row(ann, b"key-1"));
        store.save(&acme, &key).await.unwrap();
        let globex = tenant();

        let found = store
            .find_by_credential_id(&globex, key.credential_id())
            .await
            .unwrap();
        store.delete(&globex, key.id()).await.unwrap();

        assert!(found.is_none());
        assert_eq!(store.list_by_user(&acme, &ann).await.unwrap().len(), 1);
    }

    /// A passkey name emptied directly in storage makes Ann's passkey list
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_passkey_is_refused() {
        let (db, store, acme, ann, _) = fixture().await;
        store
            .save(&acme, &passkey(passkey_row(ann, b"key-1")))
            .await
            .unwrap();
        db.tamper("UPDATE passkey_credentials SET name = ''").await;

        let read = store.list_by_user(&acme, &ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
