//! Finding the account a password sign-in names, by its address within the
//! tenant: one query reading the account, its password and whether it
//! holds a second factor.
//!
//! An account without a password is not a password sign-in's candidate,
//! so it is not found here.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::UserLookup;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::operations::password_login::LoginCandidate;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Email;

use self::record::CandidateRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres lookup of the account a sign-in names.
pub struct PgUserLookup {
    databases: Arc<Databases>,
}

impl PgUserLookup {
    /// A lookup reading accounts from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgUserLookup {}

#[async_trait]
impl UserLookup for PgUserLookup {
    async fn find_by_email(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<LoginCandidate>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CandidateRecord,
                    "queries/users/login_candidate.sql",
                    tenant_id.as_uuid(),
                    email.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(CandidateRecord::into_candidate).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::authentication::{CredentialStore, MfaEnrollmentStore, PasskeyStore};
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
    use ianua_domain::domains::authentication::credentials::password_rules::PasswordDue;
    use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
    use ianua_domain::domains::authentication::mfa::owed::Enrolment;
    use ianua_domain::domains::identity::account::address::AddressStanding;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::account::vouching::Vouching;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::PasswordHash;

    use super::*;
    use crate::postgres::authentication::{
        PgCredentialStore, PgMfaEnrollmentStore, PgPasskeyStore,
    };
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authentication::{enrollment_row, passkey_row};
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann in Acme with a password, and the lookup
    /// on it.
    async fn fixture() -> (TestDb, PgUserLookup, ScopedTenant, User<ResolvedTenant>) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &ann)
            .await
            .unwrap();
        PgCredentialStore::new(Arc::clone(&db.databases))
            .update_password_hash(&acme, ann.id(), &hash())
            .await
            .unwrap();
        let lookup = PgUserLookup::new(Arc::clone(&db.databases));
        (db, lookup, acme, ann)
    }

    fn hash() -> PasswordHash {
        PasswordHash::from_stored("$argon2id$ann".to_owned())
    }

    /// Ann is found by her address with her password's hash, her standing,
    /// no second factor, and her password taken as current.
    #[tokio::test]
    async fn an_account_is_found_by_its_address() {
        let (_db, lookup, acme, ann) = fixture().await;

        let found = lookup
            .find_by_email(&acme, ann.email())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found.user_id, *ann.id());
        assert_eq!(found.password_hash, hash());
        assert_eq!(found.status, UserStatus::Active);
        assert_eq!(found.email_standing, AddressStanding::Verified);
        assert_eq!(found.enrolment, Enrolment::NotEnrolled);
        assert_eq!(found.vouching, Vouching::Absent);
        assert_eq!(found.password_due, PasswordDue::Current);
    }

    /// The password lookup reports both Ann's passkey and Bob's confirmed
    /// authenticator factor as second-factor enrollment.
    #[tokio::test]
    async fn a_passkey_or_a_confirmed_factor_counts_as_enrolled() {
        let (db, lookup, acme, ann) = fixture().await;
        let passkeys = PgPasskeyStore::new(Arc::clone(&db.databases));
        passkeys
            .save(
                &acme,
                &PasskeyCredential::reconstitute(passkey_row(*ann.id(), b"key-1")).unwrap(),
            )
            .await
            .unwrap();
        let with_passkey = lookup.find_by_email(&acme, ann.email()).await.unwrap();
        let bob = User::reconstitute(user_row("bob@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &bob)
            .await
            .unwrap();
        PgCredentialStore::new(Arc::clone(&db.databases))
            .update_password_hash(&acme, bob.id(), &hash())
            .await
            .unwrap();
        PgMfaEnrollmentStore::new(Arc::clone(&db.databases))
            .save(
                &acme,
                &MfaEnrollment::reconstitute(enrollment_row(*bob.id())).unwrap(),
            )
            .await
            .unwrap();

        let with_app = lookup.find_by_email(&acme, bob.email()).await.unwrap();

        assert_eq!(with_passkey.unwrap().enrolment, Enrolment::Enrolled);
        assert_eq!(with_app.unwrap().enrolment, Enrolment::Enrolled);
    }

    /// An address nobody holds, or an account without a password, finds no
    /// candidate.
    #[tokio::test]
    async fn no_candidate_without_an_account_or_a_password() {
        let (db, lookup, acme, _) = fixture().await;
        let bob = User::reconstitute(user_row("bob@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &bob)
            .await
            .unwrap();
        let nobody = Email::new("nobody@acme.example").unwrap();

        assert!(
            lookup
                .find_by_email(&acme, &nobody)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            lookup
                .find_by_email(&acme, bob.email())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Looking up Ann's address from another tenant finds no password
    /// sign-in candidate.
    #[tokio::test]
    async fn another_tenants_accounts_are_not_found() {
        let (_db, lookup, _, ann) = fixture().await;

        assert!(
            lookup
                .find_by_email(&tenant(), ann.email())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// An unknown account status written directly to storage makes the
    /// password lookup fail as corrupt storage.
    #[tokio::test]
    async fn an_account_with_an_unknown_status_is_refused() {
        let (db, lookup, acme, ann) = fixture().await;
        db.tamper(
            "ALTER TABLE users DROP CONSTRAINT users_status_known; \
             ALTER TABLE users DROP CONSTRAINT users_joined_fits_status; \
             UPDATE users SET status = 'guessed'",
        )
        .await;

        let read = lookup.find_by_email(&acme, ann.email()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
