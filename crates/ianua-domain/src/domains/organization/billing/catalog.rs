//! What each plan costs and what it is sold as.
//!
//! **This is the only place plans are written.** The pricing page reads it
//! through the API and keeps no copy of its own. So a tier cannot say one
//! thing on the website and enforce another in the product. A price or
//! tagline changed here is what customers see. Nothing else needs updating.
//!
//! Limits are not written here. Each tier asks [`PlanLimits`] for them, so
//! the limits shown are always the limits enforced. A second hand-written
//! copy could promise twenty-four auth clients on a plan that allows two.

use crate::domains::organization::billing::plan::{OrganizationPlan, PlanLimits};
use crate::shared::model::two_cases::two_cases;

/// The currency every price is quoted in.
///
/// It is a constant, not a field, because there is one price list.
pub const CURRENCY: &str = "USD";

/// What a tier costs, in cents.
///
/// Cents, not a decimal, so sums and transport carry no rounding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PlanPrice {
    /// Cost per month when billed monthly, in cents.
    pub monthly_cents: u64,
    /// Cost per year when billed annually, in cents.
    ///
    /// Written out, not worked out from the monthly figure. An annual discount
    /// is a pricing decision.
    pub annual_cents: u64,
}

/// What the button on a pricing card does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PlanCallToAction {
    /// Send them to sign up. The tier can be self-served.
    SignUp,
    /// Send them to sales. The tier is negotiated.
    ContactSales,
}

two_cases! {
    /// Whether a plan card is the one shown with emphasis.
    pub enum Emphasis {
        /// The emphasised card.
        Highlighted => true,
        /// An ordinary card.
        Plain => false,
    }
}

/// One tier as it is sold and as it is enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PlanTier {
    /// The plan this describes, and the value stored against an organization.
    pub plan: OrganizationPlan,

    /// The name shown on the pricing card.
    pub display_name: &'static str,

    /// Who the tier is for, shown under the name.
    pub tagline: &'static str,

    /// A short label above the card, for the one being pushed.
    pub badge: Option<&'static str>,

    /// A large headline in place of a price, for a tier that has none.
    pub heading: Option<&'static str>,

    /// A supporting paragraph saying what a negotiated tier can cover.
    pub requirements_description: Option<&'static str>,

    /// A small caption under the card's button.
    pub footnote: Option<&'static str>,

    /// Whether this card is the visually emphasised one.
    pub highlighted: Emphasis,

    /// What it costs, or `None` when the price is negotiated. `None` is what
    /// tells a "contact us" card apart from a free one.
    pub price: Option<PlanPrice>,

    /// What the card's button should do.
    pub call_to_action: PlanCallToAction,

    /// The limits this tier actually enforces.
    pub limits: PlanLimits,
}

/// Every tier, in the order they should be shown.
///
/// A function, not a constant, because [`PlanLimits`] owns a `Vec` of
/// isolation levels, which a constant cannot build.
#[must_use]
pub fn plan_catalog() -> Vec<PlanTier> {
    vec![free_tier(), starter_tier(), business_tier(), custom_tier()]
}

fn free_tier() -> PlanTier {
    PlanTier {
        plan: OrganizationPlan::Free,
        display_name: "Free",
        tagline: "For developers, personal projects, and prototypes",
        badge: None,
        heading: None,
        requirements_description: None,
        footnote: Some("No credit card required"),
        highlighted: Emphasis::Plain,
        price: Some(PlanPrice {
            monthly_cents: 0,
            annual_cents: 0,
        }),
        call_to_action: PlanCallToAction::SignUp,
        limits: PlanLimits::free(),
    }
}

fn starter_tier() -> PlanTier {
    PlanTier {
        plan: OrganizationPlan::Starter,
        display_name: "Starter",
        tagline: "For startups and small teams",
        badge: Some("Most Popular"),
        heading: None,
        requirements_description: None,
        footnote: Some("Cancel anytime"),
        highlighted: Emphasis::Highlighted,
        price: Some(PlanPrice {
            monthly_cents: 10_000,
            annual_cents: 120_000,
        }),
        call_to_action: PlanCallToAction::SignUp,
        limits: PlanLimits::starter(),
    }
}

fn business_tier() -> PlanTier {
    PlanTier {
        plan: OrganizationPlan::Business,
        display_name: "Business",
        tagline: "For growing teams that need advanced security and scale.",
        badge: None,
        heading: None,
        requirements_description: None,
        footnote: Some("Cancel anytime"),
        highlighted: Emphasis::Plain,
        price: Some(PlanPrice {
            monthly_cents: 40_000,
            annual_cents: 480_000,
        }),
        call_to_action: PlanCallToAction::SignUp,
        limits: PlanLimits::business(),
    }
}

fn custom_tier() -> PlanTier {
    PlanTier {
        plan: OrganizationPlan::Custom,
        display_name: "Custom",
        tagline: "For organizations with complex scale, compliance, or deployment needs",
        badge: None,
        heading: Some("Let's talk"),
        requirements_description: Some(
            "Get custom limits, deployment options, data isolation, and support built \
             around your organization.",
        ),
        footnote: Some("We'll tailor a plan for you"),
        highlighted: Emphasis::Plain,
        price: None,
        call_to_action: PlanCallToAction::ContactSales,
        limits: PlanLimits::business(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Free, Starter, Business and Custom each appear once in the catalog. A
    /// missing tier gets no pricing card, and a doubled one gets two.
    #[test]
    fn every_plan_appears_exactly_once() {
        let catalog = plan_catalog();

        for plan in [
            OrganizationPlan::Free,
            OrganizationPlan::Starter,
            OrganizationPlan::Business,
            OrganizationPlan::Custom,
        ] {
            assert_eq!(
                catalog.iter().filter(|tier| tier.plan == plan).count(),
                1,
                "{plan:?} has to be listed once: a tier missing here cannot be \
                 shown, and one listed twice renders two cards for the same plan"
            );
        }
    }

    /// Each listed tier but Custom shows the limits its plan enforces. So the
    /// pricing page never promises more than the product allows.
    #[test]
    fn the_limits_shown_are_the_limits_enforced() {
        for tier in plan_catalog() {
            if tier.plan == OrganizationPlan::Custom {
                continue;
            }

            assert_eq!(
                tier.limits,
                tier.plan.default_limits(),
                "{:?} advertises limits the product does not enforce, which is \
                 the drift this catalog exists to stop",
                tier.plan
            );
        }
    }

    /// Every tier with a published price sends its button to sign-up, not to
    /// sales. Nobody is asked to negotiate a number already on the card.
    #[test]
    fn every_priced_tier_can_be_bought_without_talking_to_anyone() {
        for tier in plan_catalog() {
            if tier.price.is_none() {
                continue;
            }

            assert_eq!(
                tier.call_to_action,
                PlanCallToAction::SignUp,
                "{:?} has a published price, so sending people to sales asks them \
                 to negotiate a number already on the card",
                tier.plan
            );
        }
    }

    /// A tier without a price carries a headline and its paragraph in the
    /// price's place. A priced tier carries neither, so no card shows both
    /// or nothing.
    #[test]
    fn exactly_the_unpriced_tiers_carry_a_heading_and_its_description() {
        for tier in plan_catalog() {
            let unpriced = tier.price.is_none();

            assert_eq!(tier.heading.is_some(), unpriced, "{:?}", tier.plan);
            assert_eq!(
                tier.requirements_description.is_some(),
                unpriced,
                "{:?}",
                tier.plan
            );
        }
    }

    /// Every tier in the catalog carries a caption for under its button, such
    /// as "Cancel anytime".
    #[test]
    fn every_tier_has_a_footnote_under_its_button() {
        for tier in plan_catalog() {
            assert!(tier.footnote.is_some(), "{:?} has no footnote", tier.plan);
        }
    }

    /// The Custom tier has no price and sends people to sales. A price of zero
    /// would make it look free.
    #[test]
    fn a_negotiated_tier_carries_no_price() {
        let custom = plan_catalog()
            .into_iter()
            .find(|tier| tier.plan == OrganizationPlan::Custom)
            .expect("custom is in the catalog");

        assert!(
            custom.price.is_none(),
            "a negotiated tier priced at zero would render as free"
        );
        assert_eq!(custom.call_to_action, PlanCallToAction::ContactSales);
    }

    /// The Free tier is priced at zero cents both monthly and annually, not
    /// left without a price like a negotiated tier.
    #[test]
    fn the_free_tier_costs_nothing() {
        let free = plan_catalog()
            .into_iter()
            .find(|tier| tier.plan == OrganizationPlan::Free)
            .expect("free is in the catalog");

        assert_eq!(
            free.price,
            Some(PlanPrice {
                monthly_cents: 0,
                annual_cents: 0
            })
        );
    }

    /// For every priced tier, a year paid up front costs no more than twelve
    /// monthly payments.
    #[test]
    fn annual_never_costs_more_than_paying_monthly() {
        for tier in plan_catalog() {
            let Some(price) = tier.price else { continue };

            assert!(
                price.annual_cents <= price.monthly_cents * 12,
                "{:?} charges more to commit for a year than to pay month to \
                 month, which reads as a mistake to anyone comparing them",
                tier.plan
            );
        }
    }

    /// Exactly one pricing card is shown with emphasis. Emphasising several
    /// would emphasise none.
    #[test]
    fn only_one_tier_is_highlighted() {
        assert_eq!(
            plan_catalog()
                .iter()
                .filter(|tier| tier.highlighted == Emphasis::Highlighted)
                .count(),
            1,
            "highlighting several cards emphasises none of them"
        );
    }
}
