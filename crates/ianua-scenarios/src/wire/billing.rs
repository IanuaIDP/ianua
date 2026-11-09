//! What a company pays: the plans on sale, its subscription, what it uses
//! against what its plan allows, and the plan an operator arranges.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `GET /api/v1/plans`: every plan on sale.
#[derive(Debug, Clone, Deserialize)]
pub struct PlanCatalog {
    /// The currency every price is quoted in, such as `USD`.
    pub currency: String,
    /// The plans in the order the pricing page shows them.
    pub plans: Vec<PlanOnSale>,
}

/// One plan on the pricing page.
#[derive(Debug, Clone, Deserialize)]
pub struct PlanOnSale {
    /// `Free`, `Starter`, `Business` or `Custom`.
    pub plan: String,
    /// The name printed on its card.
    pub display_name: String,
    /// What it costs; none for a plan whose price is negotiated.
    #[serde(default)]
    pub price: Option<PlanPrice>,
    /// `sign_up` or `contact_sales`.
    pub call_to_action: String,
    /// Every limit the plan enforces, by name, read whole so a scenario
    /// can send a limit set back to the API.
    pub limits: Value,
}

/// What a plan costs, in cents of the catalog's currency.
#[derive(Debug, Clone, Deserialize)]
pub struct PlanPrice {
    /// The price per month when billed monthly.
    pub monthly_cents: u64,
    /// The price per year when billed annually.
    pub annual_cents: u64,
}

/// `GET …/subscription`: the bill's standing.
#[derive(Debug, Clone, Deserialize)]
pub struct Subscription {
    /// Which plan the company pays for, such as `Free`.
    pub plan: String,
    /// `monthly` or `annual`.
    pub cycle: String,
    /// `trialing`, `active` or `past_due`.
    pub state: String,
    /// When the trial ends, while one runs.
    #[serde(default)]
    pub trial_ends_at: Option<String>,
    /// When a payment fell due, while one is owed.
    #[serde(default)]
    pub past_due_since: Option<String>,
    /// Whether a payment method is on file.
    pub payment_method_on_file: bool,
    /// Whether its one trial was used.
    pub trial_used: bool,
}

/// `GET …/usage`: what is used next to what the plan allows.
#[derive(Debug, Clone, Deserialize)]
pub struct PlanUsage {
    /// The plan the limits come from.
    pub plan: String,
    /// The limits the company works under, by name.
    pub limits: Value,
    /// What it uses now.
    pub usage: Usage,
}

/// The counts on the billing page a scenario reads.
#[derive(Debug, Clone, Deserialize)]
pub struct Usage {
    /// People, across the organization and its tenants.
    pub users: u64,
    /// How many tenants the company has made.
    pub tenants: u32,
}

/// `POST …/subscription/checkout`: the provider's page to go to.
#[derive(Debug, Clone, Deserialize)]
pub struct Checkout {
    /// The address the member goes to.
    pub checkout_url: String,
}

/// `POST …/plan`: the plan sales agreed.
#[derive(Debug, Clone, Serialize)]
pub struct ArrangePlan {
    /// `Free`, `Starter`, `Business` or `Custom`.
    pub plan: String,
    /// The billing cycle, `monthly` when left out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycle: Option<String>,
    /// Limits negotiated for a Custom plan, every field of a plan's limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<Value>,
}
