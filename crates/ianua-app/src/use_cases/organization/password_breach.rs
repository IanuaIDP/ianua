//! Whether a password a member sets appears in known data breaches, and
//! what the organization's setting makes of it.
//!
//! The organization decides: off, warn, or block. A breach service that
//! cannot answer refuses the password with a "try again" under block; under
//! warn the password goes through as unchecked and the gap is logged.
//! Neither the password nor anything derived from it is logged.

use ianua_domain::domains::authentication::credentials::breach::{
    BreachStatus, BreachedPasswordCheck, NewPasswordBreach,
};
use ianua_domain::domains::authentication::operations::password_login::Lookup;
use ianua_domain::shared::security::secret::Secret;

use crate::error::AppError;
use crate::ports::authentication::CredentialBreachChecker;

/// Refuses `password` when `check` blocks breached passwords and the
/// breach service finds it. A password the setting only warns about passes,
/// and the warning is logged without the password.
///
/// # Errors
///
/// Returns `AppError::Domain` when the organization blocks breached
/// passwords and this one appears in known breaches or could not be
/// looked up.
pub(crate) async fn ensure_password_unbreached(
    checker: &dyn CredentialBreachChecker,
    check: BreachedPasswordCheck,
    password: &Secret,
) -> Result<(), AppError> {
    let found = breach_of(checker, check, password).await;
    let judged = check.judge(&found).map_err(AppError::from_domain)?;
    if let NewPasswordBreach::Breached(count) = judged {
        tracing::info!(count, "a member set a password found in known breaches");
    }
    Ok(())
}

/// What the breach service says of `password`, unless the organization
/// does not check. A service that cannot be reached answers unavailable.
async fn breach_of(
    checker: &dyn CredentialBreachChecker,
    check: BreachedPasswordCheck,
    password: &Secret,
) -> Lookup<BreachStatus> {
    if !check.checks_passwords() {
        return Lookup::Unknown;
    }
    match checker.check(password).await {
        Ok(status) => Lookup::Known(status),
        Err(error) => {
            tracing::warn!(%error, "member password: the breach check could not be reached");
            Lookup::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::authentication::{FakeBreachChecker, UnreachableBreachChecker};
    use crate::test_support::block_on;

    /// Checks `password` against `checker` under `check`.
    fn judged(
        checker: &dyn CredentialBreachChecker,
        check: BreachedPasswordCheck,
    ) -> Result<(), AppError> {
        block_on(ensure_password_unbreached(
            checker,
            check,
            &Secret::new("Summer2024!".to_owned()),
        ))
    }

    /// A checker that finds every password in a breach.
    fn finding_every_password() -> FakeBreachChecker {
        FakeBreachChecker {
            status: BreachStatus::Breached(12),
        }
    }

    /// A password found in a breach is rejected when the organization
    /// blocks breached passwords.
    #[test]
    fn a_breached_password_is_refused_where_the_organization_blocks() {
        let result = judged(&finding_every_password(), BreachedPasswordCheck::Block);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Where the organization only warns, the same password is taken.
    #[test]
    fn a_breached_password_passes_where_the_organization_warns() {
        let result = judged(&finding_every_password(), BreachedPasswordCheck::Warn);

        assert!(result.is_ok());
    }

    /// An unavailable breach service causes password validation to fail
    /// when the organization blocks breached passwords.
    #[test]
    fn an_unreachable_service_refuses_the_password_where_the_organization_blocks() {
        let result = judged(
            &UnreachableBreachChecker::default(),
            BreachedPasswordCheck::Block,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// The breach service is down where the organization only warns. The
    /// password is taken unchecked rather than leaving Bob unable to set
    /// one.
    #[test]
    fn an_unreachable_service_lets_the_password_through_where_the_organization_warns() {
        let result = judged(
            &UnreachableBreachChecker::default(),
            BreachedPasswordCheck::Warn,
        );

        assert!(result.is_ok());
    }

    /// With the check off, the service is never asked.
    #[test]
    fn with_the_check_off_nothing_is_asked() {
        let checker = Arc::new(UnreachableBreachChecker::default());

        judged(checker.as_ref(), BreachedPasswordCheck::Off).unwrap();

        assert_eq!(checker.asked(), 0);
    }
}
