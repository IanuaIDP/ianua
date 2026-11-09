//! The signed-in person's own second-factor status.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::isolation::SecurityScope;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::MfaEnrollmentStore;
use crate::use_case::Query;

/// Whether a person has a working second factor, and which.
///
/// Shared by tenant users and organization members, so the two planes
/// cannot disagree about what counts as enabled.
pub struct Status {
    /// Whether a second factor is set up and confirmed.
    pub enabled: bool,
    /// The factor's method, when enabled.
    pub method: Option<String>,
}

impl Status {
    /// What an enrollment amounts to.
    ///
    /// Enabled only once confirmed: an enrollment begun and never proved
    /// with a code guards nothing, and calling it enabled would tell a
    /// person they are protected while every sign-in still takes a password
    /// alone.
    #[must_use]
    pub fn of<S: SecurityScope>(enrollment: Option<&MfaEnrollment<S>>) -> Self {
        match enrollment {
            Some(enrollment) if enrollment.is_active() => Self {
                enabled: true,
                method: Some(format!("{:?}", enrollment.method())),
            },
            _ => Self {
                enabled: false,
                method: None,
            },
        }
    }
}

/// The ports [`GetStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetStatusPorts {
    /// The person's second factor.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reports the signed-in person's own second-factor status.
pub struct GetStatusUseCase {
    ports: GetStatusPorts,
}

impl GetStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetStatusPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetStatusUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Status, AppError>;

    /// The second-factor status of the person signed in to `caller`'s
    /// session.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Internal` if the store fails.
    async fn execute(&self, caller: &CallerContext, (): ()) -> Result<Status, AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let enrollment = self
            .ports
            .enrollment_store
            .find_by_user(&caller.tenant(), person.account.id())
            .await
            .or_internal()?;
        Ok(Status::of(enrollment.as_ref()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeMfaEnrollmentStore, test_caller_id};
    use crate::test_support::{block_on, test_ctx};

    fn status_with(store: FakeMfaEnrollmentStore) -> Result<Status, AppError> {
        let use_case = GetStatusUseCase::new(GetStatusPorts {
            enrollment_store: Arc::new(store),
            ..GetStatusPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann confirmed her authenticator app. Her status shows it enabled,
    /// with its method.
    #[test]
    fn a_confirmed_factor_is_enabled_with_its_method() {
        let status = status_with(FakeMfaEnrollmentStore::active_for(test_caller_id())).unwrap();

        assert!(status.enabled);
        assert_eq!(status.method.as_deref(), Some("Totp"));
    }

    /// Ann began setting up her authenticator and never confirmed it. It
    /// protects nothing yet, so her status says it is not enabled.
    #[test]
    fn an_unconfirmed_factor_is_not_enabled() {
        let status = status_with(FakeMfaEnrollmentStore::pending_for(test_caller_id())).unwrap();

        assert!(!status.enabled);
        assert_eq!(status.method, None);
    }

    /// Ann has no second factor. Her status says so.
    #[test]
    fn no_factor_is_not_enabled() {
        let status = status_with(FakeMfaEnrollmentStore::empty()).unwrap();

        assert!(!status.enabled);
    }

    /// A signed-out caller is unauthenticated when reading second-factor status.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = GetStatusUseCase::new(GetStatusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..GetStatusPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
