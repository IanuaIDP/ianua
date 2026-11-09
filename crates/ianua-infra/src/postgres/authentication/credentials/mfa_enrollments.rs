//! Each account's second factor, one per account, under the tenant's
//! row-level security.
//!
//! The row also keeps the latest code step accepted. Claiming a step is one
//! update that moves it only forward, so of two sign-ins sending one code
//! at once only one gets through. A caller that counts an answer holds the
//! row until its unit of work ends, so a second answer waits and reads the
//! first one's count.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::{FactorStanding, MfaEnrollmentStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::mfa::time_step::TimeStep;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UserId;

use self::record::{EnrollmentColumns, EnrollmentRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of each account's second factor.
pub struct PgMfaEnrollmentStore {
    databases: Arc<Databases>,
}

impl PgMfaEnrollmentStore {
    /// A store keeping second factors in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgMfaEnrollmentStore {}

/// Whether a person holds a second factor, for the freeze of a session
/// that looks taken over.
pub struct PgFactorStanding {
    databases: Arc<Databases>,
}

impl PgFactorStanding {
    /// The standing read from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgFactorStanding {}

#[async_trait]
impl FactorStanding for PgFactorStanding {
    async fn holds_active_factor(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/mfa_enrollments/holds_active.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }
}

#[async_trait]
impl MfaEnrollmentStore for PgMfaEnrollmentStore {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EnrollmentRecord,
                    "queries/mfa_enrollments/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(EnrollmentRecord::into_enrollment).transpose()
    }

    async fn hold_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EnrollmentRecord,
                    "queries/mfa_enrollments/hold.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(EnrollmentRecord::into_enrollment).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        enrollment: &MfaEnrollment<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = EnrollmentColumns::of(enrollment);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/mfa_enrollments/save.sql",
                    tenant_id.as_uuid(),
                    columns.user_id,
                    columns.method,
                    columns.sealed_secret,
                    columns.phone_number,
                    columns.status,
                    columns.verified_at,
                    columns.recovery_codes_hash,
                    columns.disabled_at,
                    columns.failed_attempts,
                    columns.last_failed_at,
                    columns.enrolled_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn claim_step(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        step: TimeStep,
    ) -> Result<bool, DomainError> {
        let step = i64::try_from(step.number()).map_err(DomainError::infra)?;
        let claimed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/mfa_enrollments/claim_step.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    step
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(claimed.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_domain::domains::authentication::mfa::enrollment::{
        EnrolledFactor, EnrollmentState, MfaEnrollmentRow,
    };
    use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authentication::enrollment_row;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann and Bob in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgMfaEnrollmentStore, ScopedTenant, UserId, UserId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let user = User::reconstitute(user_row(email)).unwrap();
            users.save(&acme, &user).await.unwrap();
            ids.push(*user.id());
        }
        let store = PgMfaEnrollmentStore::new(Arc::clone(&db.databases));
        (db, store, acme, ids[0], ids[1])
    }

    fn enrollment(row: MfaEnrollmentRow) -> MfaEnrollment<ResolvedTenant> {
        MfaEnrollment::reconstitute(row).unwrap()
    }

    /// Ann's authenticator app is found again as it was saved, and holding
    /// it reads the same.
    #[tokio::test]
    async fn a_saved_factor_is_found_and_held_for_its_user() {
        let (_db, store, acme, ann, _) = fixture().await;
        let app = enrollment(enrollment_row(ann));

        store.save(&acme, &app).await.unwrap();

        let found = store.find_by_user(&acme, &ann).await.unwrap().unwrap();
        let held = store.hold_by_user(&acme, &ann).await.unwrap().unwrap();
        for read in [&found, &held] {
            assert_eq!(read.subject_id(), app.subject_id());
            assert_eq!(read.factor(), app.factor());
            assert_eq!(read.state(), app.state());
            assert_eq!(read.failures(), app.failures());
            assert_eq!(read.enrolled_at(), app.enrolled_at());
        }
    }

    /// A user who enrolled nothing has no factor, rather than a failure.
    #[tokio::test]
    async fn a_user_without_a_factor_finds_none() {
        let (db, store, acme, ann, _) = fixture().await;
        let standing = PgFactorStanding::new(Arc::clone(&db.databases));

        assert!(store.find_by_user(&acme, &ann).await.unwrap().is_none());
        assert!(store.hold_by_user(&acme, &ann).await.unwrap().is_none());
        assert!(!standing.holds_active_factor(&acme, &ann).await.unwrap());
    }

    /// Ann confirmed an authenticator app, so she holds a factor that can
    /// lift a freeze; Bob, who enrolled nothing, does not.
    #[tokio::test]
    async fn a_confirmed_factor_counts_as_held() {
        let (db, store, acme, ann, bob) = fixture().await;
        let standing = PgFactorStanding::new(Arc::clone(&db.databases));
        store
            .save(&acme, &enrollment(enrollment_row(ann)))
            .await
            .unwrap();

        assert!(standing.holds_active_factor(&acme, &ann).await.unwrap());
        assert!(!standing.holds_active_factor(&acme, &bob).await.unwrap());
    }

    /// Ann sets up texted codes instead: saving again keeps the new kind
    /// and its number.
    #[tokio::test]
    async fn saving_again_keeps_the_new_factor() {
        let (_db, store, acme, ann, _) = fixture().await;
        store
            .save(&acme, &enrollment(enrollment_row(ann)))
            .await
            .unwrap();
        let texted = enrollment(MfaEnrollmentRow {
            factor: EnrolledFactor::SmsCode(PhoneNumber::new("+4930123456").unwrap()),
            state: EnrollmentState::Pending,
            enrolled_at: at(20),
            ..enrollment_row(ann)
        });

        store.save(&acme, &texted).await.unwrap();

        let found = store.find_by_user(&acme, &ann).await.unwrap().unwrap();
        assert_eq!(found.factor(), texted.factor());
        assert_eq!(found.state(), &EnrollmentState::Pending);
    }

    /// Ann can claim only increasing time steps, while Bob, who has no
    /// factor, cannot claim a step at all.
    #[tokio::test]
    async fn a_step_is_claimed_once_and_only_forward() {
        let (_db, store, acme, ann, bob) = fixture().await;
        store
            .save(&acme, &enrollment(enrollment_row(ann)))
            .await
            .unwrap();

        let first = store
            .claim_step(&acme, &ann, TimeStep::from_number(100))
            .await;
        let again = store
            .claim_step(&acme, &ann, TimeStep::from_number(100))
            .await;
        let earlier = store
            .claim_step(&acme, &ann, TimeStep::from_number(99))
            .await;
        let later = store
            .claim_step(&acme, &ann, TimeStep::from_number(101))
            .await;
        let none = store
            .claim_step(&acme, &bob, TimeStep::from_number(5))
            .await;

        assert!(first.unwrap());
        assert!(!again.unwrap());
        assert!(!earlier.unwrap());
        assert!(later.unwrap());
        assert!(!none.unwrap());
    }

    /// Saving Ann's factor again preserves its claimed step, so a second
    /// claim for that step fails.
    #[tokio::test]
    async fn saving_keeps_the_step_claimed() {
        let (_db, store, acme, ann, _) = fixture().await;
        let app = enrollment(enrollment_row(ann));
        store.save(&acme, &app).await.unwrap();
        assert!(
            store
                .claim_step(&acme, &ann, TimeStep::from_number(7))
                .await
                .unwrap()
        );

        store.save(&acme, &app).await.unwrap();

        assert!(
            !store
                .claim_step(&acme, &ann, TimeStep::from_number(7))
                .await
                .unwrap()
        );
    }

    /// A factor held inside a unit of work is read and saved again within
    /// it, as a sign-in counting an answer does.
    #[tokio::test]
    async fn a_held_factor_is_saved_within_its_unit() {
        let (_db, store, acme, ann, _) = fixture().await;
        store
            .save(&acme, &enrollment(enrollment_row(ann)))
            .await
            .unwrap();

        atomically(
            &PgUnitOfWork,
            async {
                let held = store.hold_by_user(&acme, &ann).await.unwrap().unwrap();
                store.save(&acme, &held).await.unwrap();
            },
            |()| Settlement::Commit,
        )
        .await
        .unwrap();

        assert!(store.find_by_user(&acme, &ann).await.unwrap().is_some());
    }

    /// Another tenant's lookup cannot read Ann's enrolled factor.
    #[tokio::test]
    async fn another_tenants_factors_are_invisible() {
        let (_db, store, acme, ann, _) = fixture().await;
        store
            .save(&acme, &enrollment(enrollment_row(ann)))
            .await
            .unwrap();

        assert!(store.find_by_user(&tenant(), &ann).await.unwrap().is_none());
    }

    /// An invalid sealed seed written directly into an enrollment makes
    /// the reader refuse the row as corrupt storage.
    #[tokio::test]
    async fn a_row_with_a_broken_seed_is_refused() {
        let (db, store, acme, ann, _) = fixture().await;
        store
            .save(&acme, &enrollment(enrollment_row(ann)))
            .await
            .unwrap();
        db.tamper("UPDATE mfa_enrollments SET sealed_secret = 'not a sealed seed'")
            .await;

        let read = store.find_by_user(&acme, &ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
