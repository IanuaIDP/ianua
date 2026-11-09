//! Members' second factors, one per member, in the platform database.
//!
//! The row also keeps the latest code step accepted. Claiming a step is one
//! update that moves it only forward, so of two sign-ins sending one code
//! at once, only one gets through. A caller that counts an answer holds the
//! row until its unit of work ends, so a second answer waits and reads the
//! first one's count.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgMfaEnrollmentStore;
use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::mfa::time_step::TimeStep;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrgUserId;

use self::record::{EnrollmentColumns, EnrollmentRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of members' second factors.
pub struct PgOrgMfaEnrollmentStore {
    databases: Arc<Databases>,
}

impl PgOrgMfaEnrollmentStore {
    /// A store keeping second factors in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgMfaEnrollmentStore for PgOrgMfaEnrollmentStore {
    async fn find_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<MfaEnrollment<ResolvedOrganization>>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                EnrollmentRecord,
                "queries/org_mfa_enrollments/of_member.sql",
                org_user_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(EnrollmentRecord::into_enrollment).transpose()
    }

    async fn hold_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<MfaEnrollment<ResolvedOrganization>>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                EnrollmentRecord,
                "queries/org_mfa_enrollments/hold.sql",
                org_user_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(EnrollmentRecord::into_enrollment).transpose()
    }

    async fn save(
        &self,
        org_user_id: &OrgUserId,
        enrollment: &MfaEnrollment<ResolvedOrganization>,
    ) -> Result<(), DomainError> {
        let columns = EnrollmentColumns::of(org_user_id, enrollment)?;
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_mfa_enrollments/save.sql",
                columns.org_user_id,
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
        })
        .await
    }

    async fn claim_step(
        &self,
        org_user_id: &OrgUserId,
        step: TimeStep,
    ) -> Result<bool, DomainError> {
        let step = i64::try_from(step.number()).map_err(DomainError::infra)?;
        let claimed = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_mfa_enrollments/claim_step.sql",
                org_user_id.as_uuid(),
                step
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(claimed.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_domain::domains::authentication::mfa::enrollment::{
        EnrolledFactor, EnrollmentState, LockoutPolicy, MfaEnrollmentRow,
    };
    use ianua_domain::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
    use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::TokenHash;

    use super::*;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{
        mfa_enrollment_row, org_user_row, organization_row,
    };

    /// A fresh database holding Acme and two of its members, and the store
    /// on it.
    async fn fixture() -> (TestDb, PgOrgMfaEnrollmentStore, OrgUserId, OrgUserId) {
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
        let store = PgOrgMfaEnrollmentStore::new(Arc::clone(&db.databases));
        (db, store, ids.remove(0), ids.remove(0))
    }

    fn enrollment(row: MfaEnrollmentRow) -> MfaEnrollment<ResolvedOrganization> {
        MfaEnrollment::reconstitute(row).unwrap()
    }

    /// Ann's authenticator app is found again as it was saved.
    #[tokio::test]
    async fn a_saved_factor_is_found_for_its_member() {
        let (_db, store, ann, _) = fixture().await;
        let app = enrollment(mfa_enrollment_row(ann));

        store.save(&ann, &app).await.unwrap();

        let found = store.find_by_user(&ann).await.unwrap().unwrap();
        assert_eq!(found.subject_id(), app.subject_id());
        assert_eq!(found.factor(), app.factor());
        assert_eq!(found.state(), app.state());
        assert_eq!(found.failures(), app.failures());
        assert_eq!(found.enrolled_at(), app.enrolled_at());
    }

    /// A member who enrolled nothing has no factor, rather than a failure.
    #[tokio::test]
    async fn a_member_without_a_factor_finds_none() {
        let (_db, store, ann, _) = fixture().await;

        assert!(store.find_by_user(&ann).await.unwrap().is_none());
        assert!(store.hold_by_user(&ann).await.unwrap().is_none());
    }

    /// Two overlapping transactions each hold Ann's factor and record a
    /// failure, leaving two failed attempts after both commit.
    #[tokio::test]
    async fn two_wrong_codes_at_once_both_count() {
        let (_db, store, ann, _) = fixture().await;
        store
            .save(&ann, &enrollment(mfa_enrollment_row(ann)))
            .await
            .unwrap();
        let policy = LockoutPolicy::new(5, time::Duration::minutes(15)).unwrap();
        let store = &store;
        let (held, first_holds) = tokio::sync::oneshot::channel();
        let first = atomically(
            &PgUnitOfWork,
            hold_then_fail(store, ann, policy, held),
            |()| Settlement::Commit,
        );
        let second = atomically(
            &PgUnitOfWork,
            async move {
                first_holds.await.unwrap();
                let mut factor = store.hold_by_user(&ann).await.unwrap().unwrap();
                factor.record_failed_attempt(policy);
                store.save(&ann, &factor).await.unwrap();
            },
            |()| Settlement::Commit,
        );

        let (first, second) = tokio::join!(first, second);

        first.unwrap();
        second.unwrap();
        let found = store.find_by_user(&ann).await.unwrap().unwrap();
        assert_eq!(found.failed_attempts(), 2);
    }

    /// Holds the factor while a competing transaction starts, then saves one failure.
    async fn hold_then_fail(
        store: &PgOrgMfaEnrollmentStore,
        member: OrgUserId,
        policy: LockoutPolicy,
        held: tokio::sync::oneshot::Sender<()>,
    ) {
        let mut factor = store.hold_by_user(&member).await.unwrap().unwrap();
        held.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        factor.record_failed_attempt(policy);
        store.save(&member, &factor).await.unwrap();
    }

    /// Ann turns her factor off and sets up texted codes instead: saving
    /// again keeps the new kind and its number.
    #[tokio::test]
    async fn saving_again_keeps_the_new_factor() {
        let (_db, store, ann, _) = fixture().await;
        store
            .save(&ann, &enrollment(mfa_enrollment_row(ann)))
            .await
            .unwrap();
        let texted = enrollment(MfaEnrollmentRow {
            factor: EnrolledFactor::SmsCode(PhoneNumber::new("+4930123456").unwrap()),
            state: EnrollmentState::Pending,
            enrolled_at: at(20),
            ..mfa_enrollment_row(ann)
        });

        store.save(&ann, &texted).await.unwrap();

        let found = store.find_by_user(&ann).await.unwrap().unwrap();
        assert_eq!(found.factor(), texted.factor());
        assert_eq!(found.state(), &EnrollmentState::Pending);
    }

    /// A disabled factor keeps when it was confirmed and when it was
    /// turned off.
    #[tokio::test]
    async fn a_disabled_factor_keeps_its_times() {
        let (_db, store, ann, _) = fixture().await;
        let disabled = enrollment(MfaEnrollmentRow {
            state: EnrollmentState::from_stored(
                MfaEnrollmentStatus::Disabled,
                Some(at(10)),
                Some(TokenHash::from_stored("codes".to_owned())),
                Some(at(30)),
            )
            .unwrap(),
            ..mfa_enrollment_row(ann)
        });

        store.save(&ann, &disabled).await.unwrap();

        let found = store.find_by_user(&ann).await.unwrap().unwrap();
        assert_eq!(found.state(), disabled.state());
    }

    /// Saving Ann's factor under Bob returns a validation error and leaves
    /// Bob without an enrollment.
    #[tokio::test]
    async fn a_factor_saved_for_another_member_is_refused() {
        let (_db, store, ann, bob) = fixture().await;

        let saved = store.save(&bob, &enrollment(mfa_enrollment_row(ann))).await;

        assert!(matches!(saved, Err(DomainError::Validation(_))));
        assert!(store.find_by_user(&bob).await.unwrap().is_none());
    }

    /// After claiming a step, the same and earlier steps cannot be claimed,
    /// while a later step succeeds.
    #[tokio::test]
    async fn a_step_is_claimed_once_and_only_forward() {
        let (_db, store, ann, _) = fixture().await;
        store
            .save(&ann, &enrollment(mfa_enrollment_row(ann)))
            .await
            .unwrap();

        let first = store.claim_step(&ann, TimeStep::from_number(100)).await;
        let again = store.claim_step(&ann, TimeStep::from_number(100)).await;
        let earlier = store.claim_step(&ann, TimeStep::from_number(99)).await;
        let later = store.claim_step(&ann, TimeStep::from_number(101)).await;

        assert!(first.unwrap());
        assert!(!again.unwrap());
        assert!(!earlier.unwrap());
        assert!(later.unwrap());
    }

    /// Saving an enrollment after claiming a step does not allow that step
    /// to be claimed again.
    #[tokio::test]
    async fn saving_keeps_the_step_claimed() {
        let (_db, store, ann, _) = fixture().await;
        let app = enrollment(mfa_enrollment_row(ann));
        store.save(&ann, &app).await.unwrap();
        assert!(
            store
                .claim_step(&ann, TimeStep::from_number(7))
                .await
                .unwrap()
        );

        store.save(&ann, &app).await.unwrap();

        assert!(
            !store
                .claim_step(&ann, TimeStep::from_number(7))
                .await
                .unwrap()
        );
    }

    /// With only Ann enrolled, claiming a step for Bob returns false.
    #[tokio::test]
    async fn no_step_is_claimed_without_a_factor() {
        let (_db, store, ann, bob) = fixture().await;
        store
            .save(&ann, &enrollment(mfa_enrollment_row(ann)))
            .await
            .unwrap();

        let claimed = store.claim_step(&bob, TimeStep::from_number(5)).await;

        assert!(!claimed.unwrap());
    }

    /// Reading an enrollment whose sealed seed was replaced with malformed
    /// text returns an infrastructure error.
    #[tokio::test]
    async fn a_row_with_a_broken_seed_is_refused() {
        let (db, store, ann, _) = fixture().await;
        store
            .save(&ann, &enrollment(mfa_enrollment_row(ann)))
            .await
            .unwrap();
        db.tamper("UPDATE org_mfa_enrollments SET sealed_secret = 'not a sealed seed'")
            .await;

        let read = store.find_by_user(&ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
