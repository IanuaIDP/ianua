//! Which second factors a tenant or organization lets its people set up.
//!
//! A factor that can never reach the boundary's baseline would leave its
//! holder with sign-ins that are all refused. So whether a kind of factor
//! is offered is decided once, from the boundary's settings, and setting one
//! up takes that answer.

use crate::domains::authentication::methods::MfaPolicy;
use crate::domains::authentication::mfa::enrolled_factor::MfaMethod;
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;

/// A kind of second factor the boundary offers its people now.
///
/// Only a tenant's or an organization's sign-in settings make one, through
/// [`offer_factor`]. So a factor is never set up on the caller's word that
/// it is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorOffer {
    method: MfaMethod,
}

impl FactorOffer {
    /// The kind of factor offered.
    #[must_use]
    pub fn method(&self) -> MfaMethod {
        self.method
    }
}

/// What a boundary's settings say about second factors.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FactorSettings<'a> {
    /// Whether second factors are off, optional or required.
    pub(crate) policy: MfaPolicy,
    /// The kinds the boundary lists.
    pub(crate) offered: &'a [MfaMethod],
    /// The level every sign-in must reach.
    pub(crate) baseline: AssuranceLevel,
}

/// The offer of `method` under `settings`.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when second factors are off.
/// - [`DomainError::Forbidden`] when the boundary does not list `method`.
/// - [`DomainError::Forbidden`] when `method` cannot reach the baseline.
///   Ann's tenant asks for AAL2. A mailed code reaches AAL1, so every
///   sign-in she finished with one would be refused.
pub(crate) fn offer_factor(
    settings: FactorSettings<'_>,
    method: MfaMethod,
) -> Result<FactorOffer, DomainError> {
    if settings.policy == MfaPolicy::Disabled {
        return Err(DomainError::forbidden(message!(
            "authentication-second-factors-are-switched-off",
            "second factors are switched off"
        )));
    }
    if !settings.offered.contains(&method) {
        return Err(DomainError::forbidden(message!(
            "authentication-this-kind-of-second-factor-is-2",
            "this kind of second factor is not offered here"
        )));
    }
    if !method.assurance().satisfies(settings.baseline) {
        return Err(DomainError::forbidden(message!(
            "authentication-this-kind-of-second-factor-cannot",
            "this kind of second factor cannot reach the assurance required here"
        )));
    }
    Ok(FactorOffer { method })
}

/// Refuses a list of offered factors that is empty or names one twice.
///
/// # Errors
///
/// - [`DomainError::Validation`] when no kind is listed. Someone who must
///   set up a factor would have nothing to choose.
/// - [`DomainError::Validation`] when a kind is listed twice.
pub(crate) fn ensure_offered_factors(offered: &[MfaMethod]) -> Result<(), DomainError> {
    validate_count("second_factors", offered.len(), 1..=MfaMethod::ALL.len())?;
    if first_repeat(offered).is_some() {
        return Err(DomainError::invalid(message!(
            "authentication-a-kind-of-second-factor-is",
            "a kind of second factor is listed twice"
        )));
    }
    Ok(())
}

/// An offer of `method`, for tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn offered(method: MfaMethod) -> FactorOffer {
    FactorOffer { method }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(offered: &[MfaMethod], baseline: AssuranceLevel) -> FactorSettings<'_> {
        FactorSettings {
            policy: MfaPolicy::Optional,
            offered,
            baseline,
        }
    }

    /// A tenant that lists authenticator apps and texted codes offers both.
    #[test]
    fn a_listed_factor_is_offered() {
        let listed = [MfaMethod::Totp, MfaMethod::SmsCode];

        let offer =
            offer_factor(settings(&listed, AssuranceLevel::Aal1), MfaMethod::SmsCode).unwrap();

        assert_eq!(offer.method(), MfaMethod::SmsCode);
    }

    /// A boundary listing only authenticator apps refuses to offer texted codes.
    #[test]
    fn a_factor_the_boundary_does_not_list_is_not_offered() {
        let listed = [MfaMethod::Totp];

        let refused = offer_factor(settings(&listed, AssuranceLevel::Aal1), MfaMethod::SmsCode);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Acme asks for AAL2. A mailed code reaches only AAL1, so it is not
    /// offered, while an authenticator app is.
    #[test]
    fn a_factor_below_the_baseline_is_not_offered() {
        let listed = [MfaMethod::Totp, MfaMethod::EmailCode];
        let aal2 = settings(&listed, AssuranceLevel::Aal2);

        assert!(offer_factor(aal2, MfaMethod::EmailCode).is_err());
        assert!(offer_factor(aal2, MfaMethod::Totp).is_ok());
    }

    /// With second factors switched off, nothing is offered, even a listed
    /// authenticator app.
    #[test]
    fn nothing_is_offered_while_second_factors_are_off() {
        let listed = [MfaMethod::Totp];
        let off = FactorSettings {
            policy: MfaPolicy::Disabled,
            offered: &listed,
            baseline: AssuranceLevel::Aal1,
        };

        assert!(matches!(
            offer_factor(off, MfaMethod::Totp),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A list with no kind, or one kind twice, is refused. One of each is
    /// accepted.
    #[test]
    fn the_offered_list_names_each_kind_once_and_at_least_one() {
        assert!(ensure_offered_factors(&[]).is_err());
        assert!(ensure_offered_factors(&[MfaMethod::Totp, MfaMethod::Totp]).is_err());
        assert!(ensure_offered_factors(&MfaMethod::ALL).is_ok());
    }
}
