//! Billing bodies: the plans on sale, the organization's subscription and
//! usage, choosing a plan, the checkout, and the plan an operator
//! arranges.

use ianua_app::use_cases::organization::billing::{ArrangePlanRequest, PlanUsageReport};
use ianua_domain::domains::organization::billing::catalog::{
    CURRENCY, PlanCallToAction, PlanPrice, PlanTier,
};
use ianua_domain::domains::organization::billing::negotiated::{NegotiatedLimits, PlanTerms};
use ianua_domain::domains::organization::billing::payment::{
    BillingCycle, PaymentMethod, SubscriptionState, TrialUse,
};
use ianua_domain::domains::organization::billing::plan::{OrganizationPlan, PlanLimits};
use ianua_domain::domains::organization::billing::subscription::{
    Arrangement, OrgSubscription, PlanChoice,
};
use ianua_domain::domains::organization::billing::usage::PlanUsage;
use ianua_domain::domains::tenant::provisioning::infrastructure::IsolationLevel;
use ianua_domain::types::{HttpsUrl, OrganizationId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ApiError;

/// Every plan on sale, in the order the pricing page shows them.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PlanCatalogResponse {
    /// The currency every price is in, such as `USD`.
    pub currency: String,
    /// The plans: Free, Starter, Business, Custom.
    pub plans: Vec<PlanTierResponse>,
}

impl From<Vec<PlanTier>> for PlanCatalogResponse {
    fn from(plans: Vec<PlanTier>) -> Self {
        Self {
            currency: CURRENCY.to_owned(),
            plans: plans.into_iter().map(PlanTierResponse::from).collect(),
        }
    }
}

/// One plan as it is sold and as it is enforced.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PlanTierResponse {
    /// `Free`, `Starter`, `Business` or `Custom`.
    #[schema(schema_with = crate::dto::schemas::organization_plan)]
    pub plan: OrganizationPlan,
    /// The name on the pricing card.
    pub display_name: String,
    /// Who the plan is for.
    pub tagline: String,
    /// A short label above the card, for the one being pushed.
    pub badge: Option<String>,
    /// A headline in place of a price, for a plan that has none.
    pub heading: Option<String>,
    /// What a negotiated plan can cover.
    pub requirements_description: Option<String>,
    /// A caption under the card's button.
    pub footnote: Option<String>,
    /// Whether this card is the emphasised one.
    pub highlighted: bool,
    /// What it costs, or `null` when the price is negotiated.
    pub price: Option<PlanPriceResponse>,
    /// What the card's button does: `sign_up` or `contact_sales`.
    pub call_to_action: CallToAction,
    /// The limits the plan enforces.
    #[schema(value_type = Object)]
    pub limits: PlanLimits,
}

impl From<PlanTier> for PlanTierResponse {
    fn from(tier: PlanTier) -> Self {
        Self {
            plan: tier.plan,
            display_name: tier.display_name.to_owned(),
            tagline: tier.tagline.to_owned(),
            badge: tier.badge.map(str::to_owned),
            heading: tier.heading.map(str::to_owned),
            requirements_description: tier.requirements_description.map(str::to_owned),
            footnote: tier.footnote.map(str::to_owned),
            highlighted: tier.highlighted.into(),
            price: tier.price.map(PlanPriceResponse::from),
            call_to_action: tier.call_to_action.into(),
            limits: tier.limits,
        }
    }
}

/// A plan's price.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PlanPriceResponse {
    /// Cost per month when billed monthly, in cents.
    pub monthly_cents: u64,
    /// Cost per year when billed annually, in cents.
    pub annual_cents: u64,
}

impl From<PlanPrice> for PlanPriceResponse {
    fn from(price: PlanPrice) -> Self {
        Self {
            monthly_cents: price.monthly_cents,
            annual_cents: price.annual_cents,
        }
    }
}

/// What a plan card's button does.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CallToAction {
    /// Sign up: the plan is sold as it is.
    SignUp,
    /// Talk to sales: the plan is negotiated.
    ContactSales,
}

impl From<PlanCallToAction> for CallToAction {
    fn from(action: PlanCallToAction) -> Self {
        match action {
            PlanCallToAction::SignUp => Self::SignUp,
            PlanCallToAction::ContactSales => Self::ContactSales,
        }
    }
}

/// How often a plan is billed.
#[derive(Deserialize, utoipa::ToSchema, Default)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CycleBody {
    /// Once a month.
    #[default]
    Monthly,
    /// Once a year, at the annual price.
    Annual,
}

impl From<CycleBody> for BillingCycle {
    fn from(cycle: CycleBody) -> Self {
        match cycle {
            CycleBody::Monthly => Self::Monthly,
            CycleBody::Annual => Self::Annual,
        }
    }
}

/// Where a subscription stands.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StandingResponse {
    /// `trialing`, `active` or `past_due`.
    pub state: String,
    /// When the trial ends, while one runs.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub trial_ends_at: Option<OffsetDateTime>,
    /// Since when a payment is owed, while one is.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub past_due_since: Option<OffsetDateTime>,
}

impl From<SubscriptionState> for StandingResponse {
    fn from(state: SubscriptionState) -> Self {
        let (trial_ends_at, past_due_since) = match state {
            SubscriptionState::Trialing { ends_at } => (Some(ends_at), None),
            SubscriptionState::Active => (None, None),
            SubscriptionState::PastDue { since } => (None, Some(since)),
        };
        Self {
            state: state.as_str().to_owned(),
            trial_ends_at,
            past_due_since,
        }
    }
}

/// The organization's subscription.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SubscriptionResponse {
    /// The subscription tier that determines the organization's entitlements.
    #[schema(schema_with = crate::dto::schemas::organization_plan)]
    pub plan: OrganizationPlan,
    /// `monthly` or `annual`.
    pub cycle: String,
    /// Where it stands.
    #[serde(flatten)]
    pub standing: StandingResponse,
    /// Whether a payment method is on file at the payment provider.
    pub payment_method_on_file: bool,
    /// Whether the organization has had its one free trial.
    pub trial_used: bool,
    /// When it started.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<OrgSubscription> for SubscriptionResponse {
    fn from(subscription: OrgSubscription) -> Self {
        Self {
            plan: subscription.plan(),
            cycle: subscription.cycle().as_str().to_owned(),
            standing: StandingResponse::from(subscription.state()),
            payment_method_on_file: matches!(subscription.payment(), PaymentMethod::OnFile(_)),
            trial_used: subscription.trial() == TrialUse::Used,
            created_at: subscription.created_at(),
            updated_at: subscription.updated_at(),
        }
    }
}

/// Request body choosing a sold plan.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChoosePlanBody {
    /// `Free`, `Starter` or `Business`. Custom is arranged with sales.
    #[schema(schema_with = crate::dto::schemas::organization_plan)]
    pub plan: OrganizationPlan,
    /// `monthly` (the default) or `annual`.
    #[serde(default)]
    pub cycle: CycleBody,
}

impl From<ChoosePlanBody> for PlanChoice {
    fn from(body: ChoosePlanBody) -> Self {
        Self {
            plan: body.plan,
            cycle: body.cycle.into(),
        }
    }
}

/// What the organization uses next to what its plan allows.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PlanUsageResponse {
    /// The tier whose allowances are compared with the reported usage.
    #[schema(schema_with = crate::dto::schemas::organization_plan)]
    pub plan: OrganizationPlan,
    /// What it may use: its plan's limits, or those negotiated for it.
    #[schema(value_type = Object)]
    pub limits: PlanLimits,
    /// What it uses now.
    pub usage: UsageResponse,
}

impl From<PlanUsageReport> for PlanUsageResponse {
    fn from(report: PlanUsageReport) -> Self {
        Self {
            plan: report.plan,
            limits: report.limits,
            usage: UsageResponse::from(report.usage),
        }
    }
}

/// What an organization uses now. The users and tenants are the whole
/// organization's; every other count is the most any one tenant holds,
/// as those limits apply per tenant.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UsageResponse {
    /// Registered users across all tenants.
    pub users: u64,
    /// The total number of tenants belonging to the organization.
    pub tenants: u32,
    /// Proxy routes.
    pub routes: u32,
    /// The largest number of DNS record sets held by any one tenant.
    pub dns_record_sets: u32,
    /// The largest number of registered domains held by any one tenant.
    pub domains: u32,
    /// The largest number of API credentials held by any one tenant.
    pub api_keys: u32,
    /// The largest number of registered OAuth applications held by any one tenant.
    pub oauth_clients: u32,
    /// The largest number of authorization roles held by any one tenant.
    pub roles: u32,
    /// The largest number of membership groups held by any one tenant.
    pub groups: u32,
    /// Webhook subscriptions.
    pub webhooks: u32,
    /// The largest number of external identity connections held by any one tenant.
    pub federation_connections: u32,
    /// The largest number of external machine callers held by any one tenant.
    pub consumers: u32,
    /// The largest number of upstream service definitions held by any one tenant.
    pub services: u32,
    /// The largest number of transport routes held by any one tenant.
    pub stream_routes: u32,
    /// The largest number of outbound access policies held by any one tenant.
    pub egress_policies: u32,
    /// The largest number of resource schemas held by any one tenant.
    pub resource_types: u32,
    /// Custom user attributes.
    pub user_attributes: u32,
    /// Agent identities.
    pub agents: u32,
    /// Registered agent tools.
    pub agent_tools: u32,
    /// Connected model providers.
    pub model_providers: u32,
    /// The largest number of tenant automation definitions held by any one tenant.
    pub workflows: u32,
    /// SAML apps the tenant signs people in to.
    pub saml_service_providers: u32,
    /// Accounts applications bind to the LDAP directory as.
    pub directory_service_accounts: u32,
    /// The largest number of topic readers registered by any one tenant.
    pub message_subscriptions: u32,
    /// Private network connectors.
    pub connectors: u32,
    /// Places request records are shipped to.
    pub log_targets: u32,
    /// Places the audit trail streams to.
    pub audit_streams: u32,
    /// Channels notifications are posted to.
    pub notification_destinations: u32,
    /// The longest audit retention any tenant keeps, in days.
    pub audit_retention_days: u32,
    /// Every isolation level a tenant is placed on.
    #[schema(schema_with = crate::dto::schemas::isolation_level_list)]
    pub isolation_in_use: Vec<IsolationLevel>,
}

impl From<PlanUsage> for UsageResponse {
    /// Keeps every field of the flat usage contract mapped explicitly from its reported value.
    #[allow(clippy::too_many_lines)]
    fn from(usage: PlanUsage) -> Self {
        Self {
            users: usage.users,
            tenants: usage.tenants,
            routes: usage.routes,
            dns_record_sets: usage.dns_record_sets,
            domains: usage.domains,
            api_keys: usage.api_keys,
            oauth_clients: usage.oauth_clients,
            roles: usage.roles,
            groups: usage.groups,
            webhooks: usage.webhooks,
            federation_connections: usage.federation_connections,
            consumers: usage.consumers,
            services: usage.services,
            stream_routes: usage.stream_routes,
            egress_policies: usage.egress_policies,
            resource_types: usage.resource_types,
            user_attributes: usage.user_attributes,
            agents: usage.agents,
            agent_tools: usage.agent_tools,
            model_providers: usage.model_providers,
            workflows: usage.workflows,
            saml_service_providers: usage.saml_service_providers,
            directory_service_accounts: usage.directory_service_accounts,
            message_subscriptions: usage.message_subscriptions,
            connectors: usage.connectors,
            log_targets: usage.log_targets,
            audit_streams: usage.audit_streams,
            notification_destinations: usage.notification_destinations,
            audit_retention_days: usage.audit_retention_days,
            isolation_in_use: usage.isolation_in_use,
        }
    }
}

/// The payment provider's page the member is sent to.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CheckoutResponse {
    /// Where to send the member to add the payment method.
    pub checkout_url: String,
}

impl From<HttpsUrl> for CheckoutResponse {
    fn from(page: HttpsUrl) -> Self {
        Self {
            checkout_url: page.as_str().to_owned(),
        }
    }
}

/// Request body for the plan an operator arranges.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ArrangePlanBody {
    /// `Free`, `Starter`, `Business` or `Custom`.
    #[schema(schema_with = crate::dto::schemas::organization_plan)]
    pub plan: OrganizationPlan,
    /// `monthly` (the default) or `annual`.
    #[serde(default)]
    pub cycle: CycleBody,
    /// Limits negotiated for a Custom plan, every field of a plan's limits.
    /// Leave it out for the limits the plan sets.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub limits: Option<PlanLimits>,
}

impl ArrangePlanBody {
    /// The arrangement asked for `organization_id`.
    ///
    /// # Errors
    ///
    /// `422` when negotiated limits fall below the free plan's or are out
    /// of range.
    pub(crate) fn for_organization(
        self,
        organization_id: OrganizationId,
    ) -> Result<ArrangePlanRequest, ApiError> {
        let terms = match self.limits {
            None => PlanTerms::Standard,
            Some(limits) => {
                PlanTerms::Negotiated(NegotiatedLimits::new(limits).map_err(ApiError::validation)?)
            }
        };
        Ok(ArrangePlanRequest {
            organization_id,
            arrangement: Arrangement {
                plan: self.plan,
                cycle: self.cycle.into(),
                terms,
            },
        })
    }
}
