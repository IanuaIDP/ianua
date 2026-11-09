//! The signed-in member's own second-factor status.

use std::sync::Arc;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgMfaEnrollmentStore;
use crate::use_case::Query;
use crate::use_cases::authentication::mfa::Status;

/// The ports [`GetOrgStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetOrgStatusPorts {
    /// Where members' enrollments are kept.
    pub enrollment_store: Arc<dyn OrgMfaEnrollmentStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Reports the signed-in member's own second-factor status.
pub struct GetOrgStatusUseCase {
    ports: GetOrgStatusPorts,
}

impl GetOrgStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetOrgStatusPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetOrgStatusUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<Status, AppError>;

    /// The second-factor status of the member signed in to `caller`'s
    /// session.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts, or they act through a key.
    /// - `AppError::Forbidden` when the session is another member's.
    /// - `AppError::Internal` if the store fails.
    async fn execute(&self, caller: &OrgCaller, (): ()) -> Result<Status, AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        actor.signed_in()?;
        let enrollment = self
            .ports
            .enrollment_store
            .find_by_user(actor.member().id())
            .await
            .or_internal()?;
        Ok(Status::of(enrollment.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrgUserId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::FakeMfaEnrollmentStore;
    use crate::test_support::{block_on, test_org_caller};

    fn status_with(store: FakeMfaEnrollmentStore) -> Result<Status, AppError> {
        let use_case = GetOrgStatusUseCase::new(GetOrgStatusPorts {
            enrollment_store: Arc::new(store),
            ..GetOrgStatusPorts::fakes()
        });
        block_on(use_case.execute(&test_org_caller(), ()))
    }

    fn olivia() -> OrgUserId {
        *test_org_caller().member()
    }

    /// Olivia, a member, confirmed her authenticator app. Her status shows
    /// it enabled, with its method.
    #[test]
    fn a_confirmed_enrollment_is_reported_on_with_its_method() {
        let status = status_with(FakeMfaEnrollmentStore::active_for(olivia())).unwrap();

        assert!(status.enabled);
        assert_eq!(status.method.as_deref(), Some("Totp"));
    }

    /// Olivia began setting up her authenticator and never confirmed it. It
    /// protects nothing yet, so her status says it is off.
    #[test]
    fn an_enrollment_never_confirmed_is_reported_off() {
        let status = status_with(FakeMfaEnrollmentStore::pending_for(olivia())).unwrap();

        assert!(!status.enabled);
        assert_eq!(status.method, None);
    }

    /// Olivia has no second factor. Her status says so.
    #[test]
    fn no_enrollment_is_reported_off() {
        let status = status_with(FakeMfaEnrollmentStore::empty()).unwrap();

        assert!(!status.enabled);
        assert_eq!(status.method, None);
    }

    /// A signed-out session cannot read the member's second-factor status.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = GetOrgStatusUseCase::new(GetOrgStatusPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..GetOrgStatusPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_org_caller(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An API key cannot read second-factor status in place of a signed-in session.
    #[test]
    fn a_key_caller_is_refused() {
        let use_case = GetOrgStatusUseCase::new(GetOrgStatusPorts {
            org_actors: Arc::new(FakeOrgActors::through_key(OrgRole::Member, Vec::new())),
            ..GetOrgStatusPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_org_caller(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
