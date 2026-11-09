//! What a deployment allows a tenant's compliance posture to be, and the
//! posture a new tenant starts with.

use std::ops::RangeInclusive;

use crate::domains::tenant::compliance::{CompliancePosture, OperatorImpersonation, Residency};
use crate::domains::tenant::provisioning::infrastructure::DeploymentRegion;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;

/// The widest audit retention any posture may hold: one day to a hundred
/// years.
///
/// A stored posture is checked against this, not the deployment's own range.
/// A deployment that narrows its range can still load the tenants it set up
/// earlier.
pub(crate) const RETENTION_DAYS_EVER: RangeInclusive<u32> = 1..=36_500;

/// The values a deployment configures its compliance limits from, checked
/// by [`ComplianceLimits::new`].
#[derive(Debug, Clone, Copy)]
pub struct ComplianceLimitsParams {
    /// Shortest audit retention a tenant may set, in days.
    pub min_retention_days: u32,
    /// Longest audit retention a tenant may set, in days.
    pub max_retention_days: u32,
    /// Retention a newly provisioned tenant starts with, in days.
    pub default_retention_days: u32,
    /// Whether operators may impersonate a new tenant's users.
    pub default_operator_impersonation: OperatorImpersonation,
    /// The jurisdiction a new tenant must keep its data in, or anywhere.
    pub default_data_residency: Residency,
    /// The region a tenant is placed in when nobody picks one.
    pub default_region: DeploymentRegion,
}

impl Default for ComplianceLimitsParams {
    fn default() -> Self {
        Self {
            min_retention_days: 30,
            max_retention_days: 3650,
            default_retention_days: 365,
            default_operator_impersonation: OperatorImpersonation::Forbidden,
            default_data_residency: Residency::Anywhere,
            default_region: DeploymentRegion::EuCentral1,
        }
    }
}

/// What a deployment allows a tenant's compliance posture to be, and the
/// posture a new tenant starts with.
///
/// It is checked when built. Its default retention lies inside its range, and
/// its range lies inside `RETENTION_DAYS_EVER`. So a tenant provisioned
/// with the defaults always holds a posture the deployment accepts.
#[derive(Debug, Clone)]
pub struct ComplianceLimits {
    retention_days: RangeInclusive<u32>,
    default_retention_days: u32,
    default_operator_impersonation: OperatorImpersonation,
    default_data_residency: Residency,
    default_region: DeploymentRegion,
}

impl ComplianceLimits {
    /// Builds the limits a deployment runs with.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::OutOfRange`] when the range is empty or falls
    ///   outside `RETENTION_DAYS_EVER`.
    /// - [`ValidationError::OutOfRange`] when the default retention falls
    ///   outside the range.
    pub fn new(params: ComplianceLimitsParams) -> Result<Self, ValidationError> {
        validate_range(
            "min_retention_days",
            params.min_retention_days,
            RETENTION_DAYS_EVER,
        )?;
        validate_range(
            "max_retention_days",
            params.max_retention_days,
            params.min_retention_days..=*RETENTION_DAYS_EVER.end(),
        )?;
        validate_range(
            "default_retention_days",
            params.default_retention_days,
            params.min_retention_days..=params.max_retention_days,
        )?;
        Ok(Self::checked(params))
    }

    /// The limits `params` describe, once they are known to hold together.
    fn checked(params: ComplianceLimitsParams) -> Self {
        Self {
            retention_days: params.min_retention_days..=params.max_retention_days,
            default_retention_days: params.default_retention_days,
            default_operator_impersonation: params.default_operator_impersonation,
            default_data_residency: params.default_data_residency,
            default_region: params.default_region,
        }
    }

    /// The audit retention a tenant may set, in days.
    #[must_use]
    pub fn retention_days(&self) -> RangeInclusive<u32> {
        self.retention_days.clone()
    }

    /// Retention a newly provisioned tenant starts with, in days.
    #[must_use]
    pub fn default_retention_days(&self) -> u32 {
        self.default_retention_days
    }

    /// Whether operators may impersonate a new tenant's users.
    #[must_use]
    pub fn default_operator_impersonation(&self) -> OperatorImpersonation {
        self.default_operator_impersonation
    }

    /// The jurisdiction new tenants must keep their data in, if the
    /// deployment sets one.
    ///
    /// The default, anywhere, lets a tenant be placed in any region the
    /// operator runs. An EU-only deployment sets this. Every placement
    /// outside the EU is then refused at creation, not found later in an
    /// audit.
    #[must_use]
    pub fn default_data_residency(&self) -> Residency {
        self.default_data_residency
    }

    /// The region a tenant is placed in when nobody picks one, as in
    /// self-serve signup.
    #[must_use]
    pub fn default_region(&self) -> DeploymentRegion {
        self.default_region
    }

    /// Refuses a posture a tenant may not change to here.
    ///
    /// Its retention must lie in this deployment's range. A deployment that
    /// keeps every tenant's data in one jurisdiction keeps it there for good.
    /// An EU-only deployment never lets a tenant drop to "anywhere".
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the retention is outside the range.
    /// - [`DomainError::Validation`] when the deployment requires a residency
    ///   and the posture declares another.
    pub fn ensure_allows(&self, posture: &CompliancePosture) -> Result<(), DomainError> {
        validate_range(
            "audit_retention_days",
            posture.audit_retention_days(),
            self.retention_days(),
        )?;
        let Residency::Within(required) = self.default_data_residency else {
            return Ok(());
        };
        if posture.data_residency() == Residency::Within(required) {
            return Ok(());
        }
        Err(DomainError::invalid(message!(
            "tenant-this-deployment-keeps-every-tenant-s",
            format!(
                "this deployment keeps every tenant's data in {}",
                required.as_str()
            )
        )))
    }
}

impl Default for ComplianceLimits {
    /// The limits of [`ComplianceLimitsParams::default`]. A test checks that
    /// [`ComplianceLimits::new`] accepts them.
    fn default() -> Self {
        Self::checked(ComplianceLimitsParams::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The built-in defaults are passed to the checking constructor. They
    /// pass, so the unchecked `Default` never holds limits `new` would
    /// refuse.
    #[test]
    fn the_default_limits_are_ones_new_accepts() {
        assert!(ComplianceLimits::new(ComplianceLimitsParams::default()).is_ok());
    }

    /// A deployment allows 90 to 730 days but starts new tenants at 30. It is
    /// refused, since every new tenant would hold a posture it cannot save.
    #[test]
    fn a_default_retention_outside_the_range_is_refused() {
        let limits = ComplianceLimits::new(ComplianceLimitsParams {
            min_retention_days: 90,
            max_retention_days: 730,
            default_retention_days: 30,
            ..ComplianceLimitsParams::default()
        });

        assert!(limits.is_err());
    }

    /// Ranges starting at zero days, running backwards from 90 to 30, or
    /// reaching 40,000 days are each refused.
    #[test]
    fn a_range_that_is_empty_or_beyond_any_posture_is_refused() {
        for (min, max) in [(0, 30), (90, 30), (30, 40_000)] {
            let limits = ComplianceLimits::new(ComplianceLimitsParams {
                min_retention_days: min,
                max_retention_days: max,
                default_retention_days: min.max(1),
                ..ComplianceLimitsParams::default()
            });

            assert!(limits.is_err(), "{min}..={max}");
        }
    }

    /// EU-only deployment limits reject a posture allowing data anywhere
    /// and accept a posture retaining EU residency.
    #[test]
    fn a_deployment_that_requires_a_residency_keeps_it() {
        let eu = Residency::Within(crate::domains::tenant::compliance::DataResidency::Eu);
        let limits = ComplianceLimits::new(ComplianceLimitsParams {
            default_data_residency: eu,
            ..ComplianceLimitsParams::default()
        })
        .unwrap();
        let posture = |residency| {
            CompliancePosture::new(residency, 365, OperatorImpersonation::Allowed, &limits).unwrap()
        };

        assert!(matches!(
            limits.ensure_allows(&posture(Residency::Anywhere)),
            Err(DomainError::Validation(_))
        ));
        assert!(limits.ensure_allows(&posture(eu)).is_ok());
    }

    /// A posture built under wider limits keeps 5,000 days. This deployment
    /// allows at most 3,650, so a change to it is refused.
    #[test]
    fn a_change_to_a_retention_outside_the_range_is_refused() {
        let wide = ComplianceLimits::new(ComplianceLimitsParams {
            max_retention_days: 5_000,
            ..ComplianceLimitsParams::default()
        })
        .unwrap();
        let long = CompliancePosture::new(
            Residency::Anywhere,
            5_000,
            OperatorImpersonation::Allowed,
            &wide,
        )
        .unwrap();

        assert!(ComplianceLimits::default().ensure_allows(&long).is_err());
    }
}
