//! Each account's password: its hash, who set it and when, one row per
//! account under the tenant's row-level security.
//!
//! Only the hash the domain hands over is kept. A rehash replaces the hash
//! alone, so who set the password and when stay as they were.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::CredentialStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::credentials::password_rules::{
    CurrentPassword, PasswordOrigin,
};
use ianua_domain::domains::identity::account::admin_password_reset::AdminPasswordReset;
use ianua_domain::domains::identity::account::import::password_hash::ImportedPasswordHash;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PasswordHash, UserId};
use time::OffsetDateTime;

use self::record::{PasswordRecord, origin_word};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of each account's password.
pub struct PgCredentialStore {
    databases: Arc<Databases>,
}

/// The replacement hash and who chose it, stored together on a password change.
struct PasswordChange<'a> {
    hash: &'a PasswordHash,
    origin: PasswordOrigin,
}

impl PgCredentialStore {
    /// A store keeping passwords in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The password `user_id` holds, if any.
    async fn held(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PasswordRecord>, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PasswordRecord,
                    "queries/user_passwords/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await
    }

    /// Replaces the account's password and records who chose it and the current time.
    async fn keep(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        change: &PasswordChange<'_>,
    ) -> Result<(), DomainError> {
        let changed_at = clock::now();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/user_passwords/keep.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    change.hash.as_str(),
                    origin_word(change.origin),
                    changed_at
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

impl TenantScoped for PgCredentialStore {}

#[async_trait]
impl CredentialStore for PgCredentialStore {
    async fn find_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PasswordHash>, DomainError> {
        let held = self.held(tenant_id, user_id).await?;
        Ok(held.map(PasswordRecord::into_hash))
    }

    async fn password_changed_at(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        let held = self.held(tenant_id, user_id).await?;
        Ok(held.map(|password| password.changed_at))
    }

    async fn current_password(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<CurrentPassword>, DomainError> {
        let held = self.held(tenant_id, user_id).await?;
        held.map(PasswordRecord::into_current_password).transpose()
    }

    async fn update_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        hash: &PasswordHash,
    ) -> Result<(), DomainError> {
        self.keep(
            tenant_id,
            user_id,
            &PasswordChange {
                hash,
                origin: PasswordOrigin::ChosenByHolder,
            },
        )
        .await
    }

    async fn import_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        hash: &ImportedPasswordHash,
    ) -> Result<(), DomainError> {
        self.keep(
            tenant_id,
            user_id,
            &PasswordChange {
                hash: hash.hash(),
                origin: PasswordOrigin::ChosenByHolder,
            },
        )
        .await
    }

    async fn rehash_password(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        replaced: &PasswordHash,
        hash: &PasswordHash,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/user_passwords/rehash.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    replaced.as_str(),
                    hash.as_str()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn reset_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        leave: &AdminPasswordReset<ResolvedTenant>,
        hash: &PasswordHash,
    ) -> Result<(), DomainError> {
        self.keep(
            tenant_id,
            leave.user_id(),
            &PasswordChange {
                hash,
                origin: PasswordOrigin::SetByAdmin,
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authorization::granter::{AccountControl, Handout};
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::stewardship::Stewardship;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann in Acme, and the store on it.
    async fn fixture() -> (
        TestDb,
        PgCredentialStore,
        ScopedTenant,
        User<ResolvedTenant>,
    ) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &ann)
            .await
            .unwrap();
        let store = PgCredentialStore::new(Arc::clone(&db.databases));
        (db, store, acme, ann)
    }

    fn hash(value: &str) -> PasswordHash {
        PasswordHash::from_stored(value.to_owned())
    }

    /// Grants an administrator permission to reset this account's password.
    fn allow_reset(ann: &mut User<ResolvedTenant>) -> AdminPasswordReset<ResolvedTenant> {
        let control = AccountControl::assumed(
            anyone_holding(&[SystemPermission::Users(UserAction::Manage)]),
            *ann.id(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        );
        ann.allow_password_reset(&control).unwrap()
    }

    /// Ann chooses a password: its hash is found, chosen by her, changed
    /// just now.
    #[tokio::test]
    async fn a_chosen_password_is_found_as_chosen_by_its_holder() {
        let (_db, store, acme, ann) = fixture().await;
        let before = clock::now().replace_nanosecond(0).unwrap();

        store
            .update_password_hash(&acme, ann.id(), &hash("$argon2id$one"))
            .await
            .unwrap();

        let found = store.find_password_hash(&acme, ann.id()).await.unwrap();
        let current = store
            .current_password(&acme, ann.id())
            .await
            .unwrap()
            .unwrap();
        let changed = store.password_changed_at(&acme, ann.id()).await.unwrap();
        assert_eq!(found, Some(hash("$argon2id$one")));
        assert_eq!(current.origin, PasswordOrigin::ChosenByHolder);
        assert!(current.changed_at >= before);
        assert_eq!(changed, Some(current.changed_at));
    }

    /// An account without a password has none, rather than a failure.
    #[tokio::test]
    async fn an_account_without_a_password_has_none() {
        let (_db, store, acme, ann) = fixture().await;

        assert!(
            store
                .find_password_hash(&acme, ann.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .current_password(&acme, ann.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .password_changed_at(&acme, ann.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Sam resets Ann's password: it is kept as set by an admin, so she must
    /// change it at her next sign-in.
    #[tokio::test]
    async fn a_reset_password_is_kept_as_set_by_an_admin() {
        let (_db, store, acme, mut ann) = fixture().await;
        let control = AccountControl::assumed(
            anyone_holding(&[SystemPermission::Users(UserAction::Manage)]),
            *ann.id(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        );
        let leave = ann.allow_password_reset(&control).unwrap();

        store
            .reset_password_hash(&acme, &leave, &hash("$argon2id$by-sam"))
            .await
            .unwrap();

        let current = store
            .current_password(&acme, ann.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.origin, PasswordOrigin::SetByAdmin);
        assert_eq!(
            store.find_password_hash(&acme, ann.id()).await.unwrap(),
            Some(hash("$argon2id$by-sam"))
        );
    }

    /// An imported hash is kept as it came, as chosen by its holder.
    #[tokio::test]
    async fn an_imported_hash_is_kept_as_it_came() {
        let (_db, store, acme, ann) = fixture().await;
        let imported = ImportedPasswordHash::parse(
            "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
        )
        .unwrap();

        store
            .import_password_hash(&acme, ann.id(), &imported)
            .await
            .unwrap();

        let current = store
            .current_password(&acme, ann.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store.find_password_hash(&acme, ann.id()).await.unwrap(),
            Some(imported.hash().clone())
        );
        assert_eq!(current.origin, PasswordOrigin::ChosenByHolder);
    }

    /// Rehashing an administrator-set password changes its stored hash
    /// while preserving its origin and change time.
    #[tokio::test]
    async fn a_rehash_keeps_who_set_the_password_and_when() {
        let (_db, store, acme, mut ann) = fixture().await;
        let leave = allow_reset(&mut ann);
        store
            .reset_password_hash(&acme, &leave, &hash("$old$hash"))
            .await
            .unwrap();
        let before = store
            .current_password(&acme, ann.id())
            .await
            .unwrap()
            .unwrap();

        store
            .rehash_password(
                &acme,
                ann.id(),
                &hash("$old$hash"),
                &hash("$argon2id$fresh"),
            )
            .await
            .unwrap();

        let after = store
            .current_password(&acme, ann.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after, before);
        assert_eq!(
            store.find_password_hash(&acme, ann.id()).await.unwrap(),
            Some(hash("$argon2id$fresh"))
        );
    }

    /// A rehash naming Ann's replaced password leaves her current hash
    /// unchanged.
    #[tokio::test]
    async fn a_rehash_never_puts_back_a_changed_password() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .update_password_hash(&acme, ann.id(), &hash("$old$hash"))
            .await
            .unwrap();
        store
            .update_password_hash(&acme, ann.id(), &hash("$argon2id$new"))
            .await
            .unwrap();

        store
            .rehash_password(
                &acme,
                ann.id(),
                &hash("$old$hash"),
                &hash("$argon2id$old-rehashed"),
            )
            .await
            .unwrap();

        assert_eq!(
            store.find_password_hash(&acme, ann.id()).await.unwrap(),
            Some(hash("$argon2id$new"))
        );
    }

    /// Looking up Ann's password through another tenant returns no hash.
    #[tokio::test]
    async fn another_tenants_passwords_are_invisible() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .update_password_hash(&acme, ann.id(), &hash("$argon2id$one"))
            .await
            .unwrap();

        let elsewhere = store.find_password_hash(&tenant(), ann.id()).await.unwrap();

        assert!(elsewhere.is_none());
    }

    /// An unknown password origin written directly to storage makes the
    /// current-password read fail as corrupt storage.
    #[tokio::test]
    async fn a_password_with_an_unknown_origin_is_refused() {
        let (db, store, acme, ann) = fixture().await;
        store
            .update_password_hash(&acme, ann.id(), &hash("$argon2id$one"))
            .await
            .unwrap();
        db.tamper(
            "ALTER TABLE user_passwords DROP CONSTRAINT user_passwords_origin_known; \
             UPDATE user_passwords SET origin = 'guessed'",
        )
        .await;

        let read = store.current_password(&acme, ann.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
