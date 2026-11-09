//! The platform holding an organization over a debt: suspending it once a
//! payment is owed past the grace, and lifting that suspension once the
//! debt is settled.
//!
//! Paying lifts only a suspension made for not paying. One an operator
//! made, or took over, stays until an operator lifts it.

use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::status::{OrgSuspensionReason, OrganizationStatus, Suspension};
use crate::message;
use crate::shared::errors::DomainError;

/// The suspension the billing sweep makes, and settling the debt lifts.
const UNPAID: Suspension = Suspension::ByPlatform(OrgSuspensionReason::NonPayment);

impl Organization {
    /// Whether the platform suspended the organization for not paying, a
    /// suspension that settling the debt lifts.
    #[must_use]
    pub fn suspended_for_non_payment(&self) -> bool {
        self.suspended_by == UNPAID
    }

    /// Suspends the organization for a payment owed past the grace. Raises
    /// `organization.status_changed`.
    ///
    /// A suspension a member made is taken over, as an operator's
    /// suspension takes it over: Acme's owner pausing Acme ahead of the
    /// notice does not keep the platform from holding it for the debt.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the organization is closed,
    ///   or the platform holds it suspended already.
    pub fn suspend_for_non_payment(&mut self) -> Result<(), DomainError> {
        if matches!(self.suspended_by, Suspension::ByPlatform(_)) {
            return Err(DomainError::invalid_transition(message!(
                "organization-the-platform-holds-this-organization-suspended",
                "the platform holds this organization suspended already"
            )));
        }
        let from = self.status;
        if self.suspended_by == Suspension::NotSuspended {
            self.status = self.status.try_transition(OrganizationStatus::Suspended)?;
        }
        self.suspended_by = UNPAID;
        self.touch();
        self.raise_status_change(from);
        Ok(())
    }

    /// Lifts the suspension made for not paying, once the debt is settled.
    /// Raises `organization.status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the organization is not
    ///   suspended for not paying: it is active or closed, or a member or an
    ///   operator holds it.
    pub fn lift_non_payment_suspension(&mut self) -> Result<(), DomainError> {
        if !self.suspended_for_non_payment() {
            return Err(DomainError::invalid_transition(message!(
                "organization-paying-lifts-only-a-suspension-made",
                "paying lifts only a suspension made for not paying"
            )));
        }
        let from = self.status;
        self.status = self.status.try_transition(OrganizationStatus::Active)?;
        self.suspended_by = Suspension::NotSuspended;
        self.touch();
        self.raise_status_change(from);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::billing::plan::OrganizationPlan;
    use crate::domains::organization::lifecycle::CreateOrganizationParams;
    use crate::shared::config::{DisplayNameLimits, SlugLimits};
    use crate::test_support::events::raised_complete_names;
    use crate::types::{ActedBy, DisplayName, Email, Label, OrganizationId, TenantSlug};

    /// Acme as just founded, its creation taken out already.
    fn acme() -> Organization {
        let (mut acme, _) = Organization::create(CreateOrganizationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Acme Corp").unwrap(),
            contact_email: Email::new("admin@acme.com").unwrap(),
            display_name: DisplayName::new("Acme Corporation", &DisplayNameLimits::default())
                .unwrap(),
            plan: OrganizationPlan::Starter,
        })
        .unwrap();
        raised_complete_names(&mut acme);
        acme
    }

    /// Acme owes a payment past the grace. The platform suspends it for not
    /// paying, and the move is raised.
    #[test]
    fn a_debt_past_its_grace_suspends_for_non_payment() {
        let mut o = acme();

        o.suspend_for_non_payment().unwrap();

        assert_eq!(o.status(), OrganizationStatus::Suspended);
        assert!(o.suspended_for_non_payment());
        assert_eq!(
            raised_complete_names(&mut o),
            ["organization.status_changed"]
        );
    }

    /// Acme pays what it owed. The suspension made for the debt is lifted
    /// and Acme is active again.
    #[test]
    fn settling_the_debt_lifts_a_suspension_for_non_payment() {
        let mut o = acme();
        o.suspend_for_non_payment().unwrap();

        o.lift_non_payment_suspension().unwrap();

        assert_eq!(o.status(), OrganizationStatus::Active);
        assert_eq!(o.suspended_by(), Suspension::NotSuspended);
    }

    /// Lifting a non-payment suspension is refused when an operator holds
    /// the organization; it remains suspended.
    #[test]
    fn paying_never_lifts_an_operators_suspension() {
        let mut o = acme();
        o.change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();

        let lifted = o.lift_non_payment_suspension();

        assert!(matches!(lifted, Err(DomainError::InvalidTransition(_))));
        assert_eq!(o.status(), OrganizationStatus::Suspended);
    }

    /// An operator can take over a non-payment suspension. The reason
    /// becomes operator-held, so debt settlement cannot lift it.
    #[test]
    fn an_operator_takes_over_a_suspension_for_non_payment() {
        let mut o = acme();
        o.suspend_for_non_payment().unwrap();

        o.change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();

        assert_eq!(
            o.suspended_by(),
            Suspension::ByPlatform(OrgSuspensionReason::Operator)
        );
        assert!(o.lift_non_payment_suspension().is_err());
    }

    /// Suspending Acme for non-payment a second time is refused as an
    /// invalid transition.
    #[test]
    fn a_second_suspension_for_non_payment_is_refused() {
        let mut o = acme();
        o.suspend_for_non_payment().unwrap();

        let again = o.suspend_for_non_payment();

        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
    }

    /// A non-payment suspension cannot replace Acme's closed status; the
    /// refused operation leaves it closed.
    #[test]
    fn a_closed_organization_is_not_suspended_for_non_payment() {
        let mut o = acme();
        o.change_status(OrganizationStatus::Closed, ActedBy::Platform)
            .unwrap();

        let refused = o.suspend_for_non_payment();

        assert!(refused.is_err());
        assert_eq!(o.status(), OrganizationStatus::Closed);
    }
}
