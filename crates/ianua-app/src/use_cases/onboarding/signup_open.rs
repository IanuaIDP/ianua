//! Signup open: whether this deployment lets strangers found organizations.

use crate::use_case::Query;
use crate::use_cases::onboarding::Enrollment;

/// Answers whether this deployment takes signups.
pub struct SignupOpenUseCase {
    enrollment: Enrollment,
}

impl SignupOpenUseCase {
    /// Creates a new use case for a deployment with `enrollment`.
    #[must_use]
    pub fn new(enrollment: Enrollment) -> Self {
        Self { enrollment }
    }
}

impl Query for SignupOpenUseCase {
    type Caller = ();
    type Input = ();
    type Output = bool;

    /// Whether this deployment takes signups, so a sign-in page knows whether
    /// to offer one.
    async fn execute(&self, (): &(), (): ()) -> bool {
        self.enrollment == Enrollment::Open
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::block_on;

    /// The hosted service says it takes signups; an installation says it
    /// does not, so its sign-in page offers none.
    #[test]
    fn only_an_open_deployment_says_it_takes_signups() {
        let open = SignupOpenUseCase::new(Enrollment::Open);
        let closed = SignupOpenUseCase::new(Enrollment::Closed);

        assert!(block_on(open.execute(&(), ())));
        assert!(!block_on(closed.execute(&(), ())));
    }
}
