//! Members' passkeys, in the platform database.
//!
//! A passkey is found by its `WebAuthn` credential id across every
//! organization, since the credential is what names its member at sign-in.
//! So that id is unique on the whole platform.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgPasskeyStore;
use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId, PasskeyCredentialId, PasskeyId};

use self::record::{PasskeyColumns, PasskeyRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a credential id to one passkey.
const CREDENTIAL_KEY: &str = "org_passkey_credentials_credential_key";

/// The Postgres store of members' passkeys.
pub struct PgOrgPasskeyStore {
    databases: Arc<Databases>,
}

impl PgOrgPasskeyStore {
    /// A store keeping passkeys in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgPasskeyStore for PgOrgPasskeyStore {
    async fn list_by_users(
        &self,
        org_user_ids: &[OrgUserId],
    ) -> Result<Vec<PasskeyCredential<ResolvedOrganization>>, DomainError> {
        if org_user_ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = org_user_ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                PasskeyRecord,
                "queries/org_passkey_credentials/of_members.sql",
                &ids
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        records
            .into_iter()
            .map(PasskeyRecord::into_passkey)
            .collect()
    }

    async fn list_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<PasskeyCredential<ResolvedOrganization>>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                PasskeyRecord,
                "queries/org_passkey_credentials/of_member.sql",
                org_user_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        records
            .into_iter()
            .map(PasskeyRecord::into_passkey)
            .collect()
    }

    async fn find_by_credential_id(
        &self,
        credential_id: &PasskeyCredentialId,
    ) -> Result<Option<PasskeyCredential<ResolvedOrganization>>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                PasskeyRecord,
                "queries/org_passkey_credentials/by_credential.sql",
                credential_id.as_bytes()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(PasskeyRecord::into_passkey).transpose()
    }

    async fn save(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        credential: &PasskeyCredential<ResolvedOrganization>,
    ) -> Result<(), DomainError> {
        let columns = PasskeyColumns::of(organization_id, org_user_id, credential)?;
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let attempt = sqlx::query_file!(
                "queries/org_passkey_credentials/save.sql",
                columns.id,
                columns.organization_id,
                columns.org_user_id,
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
        })
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-this-passkey-is-registered-already",
                "this passkey is registered already"
            ))),
        }
    }

    async fn delete(&self, id: &PasskeyId) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!("queries/org_passkey_credentials/delete.sql", id.as_uuid())
                .execute(connection)
                .await?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_domain::domains::authentication::credentials::passkey::{
        KeyAttestation, PasskeyCredentialRow,
    };
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::Label;

    use super::*;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{
        org_passkey_row, org_user_row, organization_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgOrgPasskeyStore,
        acme: OrganizationId,
        ann: OrgUserId,
        bob: OrgUserId,
    }

    /// A fresh database holding Acme with two members, Globex with none,
    /// and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organizations =
            PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let acme = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        organizations.save(&acme).await.unwrap();
        let members = PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let member = OrgUser::reconstitute(org_user_row(*acme.id(), email)).unwrap();
            members.save(&member).await.unwrap();
            ids.push(*member.id());
        }
        let store = PgOrgPasskeyStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            acme: *acme.id(),
            ann: ids.remove(0),
            bob: ids.remove(0),
        }
    }

    fn passkey(row: PasskeyCredentialRow<OrgUserId>) -> PasskeyCredential<ResolvedOrganization> {
        PasskeyCredential::reconstitute(row).unwrap()
    }

    fn credential(bytes: &[u8]) -> PasskeyCredentialId {
        PasskeyCredentialId::new(bytes.to_vec()).unwrap()
    }

    fn names(passkeys: &[PasskeyCredential<ResolvedOrganization>]) -> Vec<&str> {
        passkeys.iter().map(|key| key.name().as_str()).collect()
    }

    /// Ann's security key is found by its credential id, with the member
    /// and key it was saved with.
    #[tokio::test]
    async fn a_saved_passkey_is_found_by_its_credential_id() {
        let db = fixture().await;
        let key = passkey(PasskeyCredentialRow {
            attestation: KeyAttestation::HardwareKey,
            ..org_passkey_row(db.ann, b"ann-key")
        });

        db.store.save(&db.acme, &db.ann, &key).await.unwrap();

        let found = db
            .store
            .find_by_credential_id(&credential(b"ann-key"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id(), key.id());
        assert_eq!(found.user_id(), &db.ann);
        assert_eq!(found.public_key(), key.public_key());
        assert_eq!(found.attestation(), KeyAttestation::HardwareKey);
        assert_eq!(found.authenticator_type(), key.authenticator_type());
        assert_eq!(found.created_at(), key.created_at());
    }

    /// A credential id nobody registered finds nothing.
    #[tokio::test]
    async fn an_unknown_credential_is_not_found() {
        let db = fixture().await;

        let found = db
            .store
            .find_by_credential_id(&credential(b"nobody"))
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// Ann lists her own passkeys in the order she added them, and none of
    /// Bob's.
    #[tokio::test]
    async fn a_member_lists_only_their_own_passkeys() {
        let db = fixture().await;
        let later = passkey(PasskeyCredentialRow {
            name: Label::new("name", "Laptop").unwrap(),
            created_at: at(5),
            ..org_passkey_row(db.ann, b"ann-laptop")
        });
        let first = passkey(org_passkey_row(db.ann, b"ann-key"));
        let bobs = passkey(org_passkey_row(db.bob, b"bob-key"));
        for (owner, key) in [(db.ann, &later), (db.ann, &first), (db.bob, &bobs)] {
            db.store.save(&db.acme, &owner, key).await.unwrap();
        }

        let listed = db.store.list_by_user(&db.ann).await.unwrap();

        assert_eq!(names(&listed), ["YubiKey", "Laptop"]);
    }

    /// A batch includes only requested members, keeps each member's key order,
    /// and returns a key once even when its member is requested twice.
    #[tokio::test]
    async fn member_batches_keep_credentials_with_their_owners() {
        let db = fixture().await;
        let first = passkey(org_passkey_row(db.ann, b"ann-key"));
        let later = passkey(PasskeyCredentialRow {
            created_at: at(5),
            ..org_passkey_row(db.ann, b"ann-later")
        });
        let bobs = passkey(org_passkey_row(db.bob, b"bob-key"));
        for (owner, key) in [(db.ann, &later), (db.bob, &bobs), (db.ann, &first)] {
            db.store.save(&db.acme, &owner, key).await.unwrap();
        }

        let found = db
            .store
            .list_by_users(&[db.ann, OrgUserId::new(), db.ann])
            .await
            .unwrap();

        assert_eq!(
            found.iter().map(|key| *key.id()).collect::<Vec<_>>(),
            [*first.id(), *later.id()]
        );
        assert!(found.iter().all(|key| key.user_id() == &db.ann));
        let both = db.store.list_by_users(&[db.ann, db.bob]).await.unwrap();
        assert_eq!(both.len(), 3);
        assert!(
            both.iter()
                .any(|key| key.id() == bobs.id() && key.user_id() == &db.bob)
        );
        assert!(db.store.list_by_users(&[]).await.unwrap().is_empty());
    }

    /// A sign-in raises the counter: saving again keeps the new counter,
    /// last use and name.
    #[tokio::test]
    async fn saving_again_keeps_the_new_counter_and_name() {
        let db = fixture().await;
        let key = passkey(org_passkey_row(db.ann, b"ann-key"));
        db.store.save(&db.acme, &db.ann, &key).await.unwrap();
        let used = passkey(PasskeyCredentialRow {
            id: *key.id(),
            sign_count: 7,
            last_used_at: Some(at(60)),
            name: Label::new("name", "Office key").unwrap(),
            ..org_passkey_row(db.ann, b"ann-key")
        });

        db.store.save(&db.acme, &db.ann, &used).await.unwrap();

        let found = db
            .store
            .find_by_credential_id(&credential(b"ann-key"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.sign_count(), 7);
        assert_eq!(found.last_used_at(), Some(at(60)));
        assert_eq!(found.name().as_str(), "Office key");
    }

    /// Saving an older copy of Ann's passkey preserves the greater stored
    /// sign count and later last-use time.
    #[tokio::test]
    async fn a_stale_save_never_lowers_the_counter() {
        let db = fixture().await;
        let key = passkey(org_passkey_row(db.ann, b"ann-key"));
        db.store.save(&db.acme, &db.ann, &key).await.unwrap();
        let latest = passkey(PasskeyCredentialRow {
            id: *key.id(),
            sign_count: 9,
            last_used_at: Some(at(90)),
            ..org_passkey_row(db.ann, b"ann-key")
        });
        let stale = passkey(PasskeyCredentialRow {
            id: *key.id(),
            sign_count: 7,
            last_used_at: Some(at(60)),
            ..org_passkey_row(db.ann, b"ann-key")
        });
        db.store.save(&db.acme, &db.ann, &latest).await.unwrap();

        db.store.save(&db.acme, &db.ann, &stale).await.unwrap();

        let found = db
            .store
            .find_by_credential_id(&credential(b"ann-key"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.sign_count(), 9);
        assert_eq!(found.last_used_at(), Some(at(90)));
    }

    /// Saving Bob's passkey under Ann's existing ID leaves the stored
    /// passkey's member and name unchanged.
    #[tokio::test]
    async fn a_passkey_never_changes_its_member() {
        let db = fixture().await;
        let key = passkey(org_passkey_row(db.ann, b"ann-key"));
        db.store.save(&db.acme, &db.ann, &key).await.unwrap();
        let taken = passkey(PasskeyCredentialRow {
            id: *key.id(),
            name: Label::new("name", "Bob's now").unwrap(),
            ..org_passkey_row(db.bob, b"ann-key")
        });

        db.store.save(&db.acme, &db.bob, &taken).await.unwrap();

        let found = db
            .store
            .find_by_credential_id(&credential(b"ann-key"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.user_id(), &db.ann);
        assert_eq!(found.name().as_str(), "YubiKey");
    }

    /// Saving Bob's passkey with Ann's existing credential ID returns a
    /// conflict.
    #[tokio::test]
    async fn a_credential_id_another_passkey_holds_is_refused() {
        let db = fixture().await;
        db.store
            .save(
                &db.acme,
                &db.ann,
                &passkey(org_passkey_row(db.ann, b"shared")),
            )
            .await
            .unwrap();

        let second = db
            .store
            .save(
                &db.acme,
                &db.bob,
                &passkey(org_passkey_row(db.bob, b"shared")),
            )
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Saving Ann's passkey with Bob as the requested member returns a
    /// validation error.
    #[tokio::test]
    async fn a_passkey_saved_for_another_member_is_refused() {
        let db = fixture().await;

        let saved = db
            .store
            .save(
                &db.acme,
                &db.bob,
                &passkey(org_passkey_row(db.ann, b"ann-key")),
            )
            .await;

        assert!(matches!(saved, Err(DomainError::Validation(_))));
    }

    /// Saving Acme's member's passkey under an unknown organization ID
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_passkey_under_another_organization_is_refused() {
        let db = fixture().await;

        let saved = db
            .store
            .save(
                &OrganizationId::new(),
                &db.ann,
                &passkey(org_passkey_row(db.ann, b"ann-key")),
            )
            .await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A removed passkey is no longer found; removing it again is no error.
    #[tokio::test]
    async fn a_deleted_passkey_is_gone() {
        let db = fixture().await;
        let key = passkey(org_passkey_row(db.ann, b"ann-key"));
        db.store.save(&db.acme, &db.ann, &key).await.unwrap();

        db.store.delete(key.id()).await.unwrap();
        db.store.delete(key.id()).await.unwrap();

        assert!(db.store.list_by_user(&db.ann).await.unwrap().is_empty());
    }

    /// Listing a member's passkeys after a stored name is made blank
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_passkey_is_refused() {
        let db = fixture().await;
        let key = passkey(org_passkey_row(db.ann, b"ann-key"));
        db.store.save(&db.acme, &db.ann, &key).await.unwrap();
        db.db
            .tamper("UPDATE org_passkey_credentials SET name = ''")
            .await;

        let read = db.store.list_by_user(&db.ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
