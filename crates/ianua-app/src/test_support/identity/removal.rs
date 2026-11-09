//! What ends a user's standing, built over the stores a test watches.

use std::sync::Arc;

use crate::services::authorization::grant_revocation::GrantRevocation;
use crate::test_support::Fake;
use crate::test_support::agents::FakeDelegationStore;
use crate::test_support::authentication::FakeSessionStore;
use crate::use_cases::identity::users::sessions::sign_out::StandingRemoval;

/// The removal that ends sessions in `sessions` and revokes the delegations
/// in `delegations`.
#[must_use]
pub fn removal_over(
    sessions: &Arc<FakeSessionStore>,
    delegations: &Arc<FakeDelegationStore>,
) -> StandingRemoval {
    StandingRemoval {
        session_store: sessions.clone(),
        grant_revocation: GrantRevocation::new(delegations.clone()),
        exports: Fake::fake(),
        export_files: Fake::fake(),
    }
}

impl Fake for StandingRemoval {
    fn fake() -> Self {
        Self {
            session_store: Fake::fake(),
            grant_revocation: Fake::fake(),
            exports: Fake::fake(),
            export_files: Fake::fake(),
        }
    }
}
