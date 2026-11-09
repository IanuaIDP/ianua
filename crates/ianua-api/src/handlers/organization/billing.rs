//! Billing handlers: the plans on sale, the organization's subscription and
//! usage, choosing a plan, the checkout, the payment provider's notices,
//! and the plan an operator arranges.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::organization::OrganizationState;

use crate::dto::organization::billing::{
    ArrangePlanBody, CheckoutResponse, ChoosePlanBody, PlanCatalogResponse, PlanUsageResponse,
    StandingResponse, SubscriptionResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::OrgMember;
use crate::extractors::json::Json;
use crate::extractors::organization::billing::PaymentNoticeRequest;
use crate::extractors::organization::platform::OrgOperator;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/plans",
    tag = "Organizations",
    responses(
        (status = 200, description = "The plans on sale", body = PlanCatalogResponse),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List the plans
///
/// Every plan on sale, in the order the pricing page shows them (Free,
/// Starter, Business, Custom), with its price in `currency` cents and the
/// limits it enforces. A negotiated plan has no `price`. Public: anyone
/// may read what is for sale.
pub(crate) async fn list_plans(
    State(organization): State<OrganizationState>,
) -> Json<PlanCatalogResponse> {
    let plans = organization.billing.plans.execute(&(), ()).await;
    Json(PlanCatalogResponse::from(plans))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/subscription",
    tag = "Organizations",
    responses(
        (status = 200, description = "The subscription", body = SubscriptionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "The organization has no subscription", body = ErrorBody)
    )
)]
/// Get the subscription
///
/// The organization's plan and billing cycle, where it stands (`trialing`
/// until `trial_ends_at`, `active`, or `past_due` since `past_due_since`),
/// whether a payment method is on file and whether its one trial was used.
/// Read-only. The app decides whether the caller may read the bill.
pub(crate) async fn get_subscription(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    let subscription = organization
        .billing
        .subscription
        .execute(&member.caller, ())
        .await?;
    Ok(Json(SubscriptionResponse::from(subscription)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/subscription",
    tag = "Organizations",
    request_body = ChoosePlanBody,
    responses(
        (status = 200, description = "Where the subscription stands now", body = StandingResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or a plan that is not sold here", body = ErrorBody),
        (status = 404, description = "The organization has no subscription", body = ErrorBody),
        (status = 409, description = "The organization uses more than the plan allows, has no payment method and no trial left, or owes a payment", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Choose a plan
///
/// Moves the organization to `Free`, `Starter` or `Business`, billed
/// `monthly` or `annual`. What it uses must fit the plan (`409` otherwise).
/// A paid plan needs a payment method on file (`…/subscription/checkout`),
/// or starts the organization's one trial: the answer is then `trialing`
/// with `trial_ends_at`. Custom is arranged with sales, never chosen here.
/// Choosing the plan and cycle it is already on changes nothing. Records
/// `organization.subscription_changed` and, when the plan changed,
/// `organization.plan_changed`. The app decides whether the caller may
/// change what the organization pays.
pub(crate) async fn choose_plan(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<ChoosePlanBody>,
) -> Result<Json<StandingResponse>, ApiError> {
    let state = organization
        .billing
        .choose_plan
        .execute(&member.caller, &member.auditor, body.into())
        .await?;
    Ok(Json(StandingResponse::from(state)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/usage",
    tag = "Organizations",
    responses(
        (status = 200, description = "Usage against the plan's limits", body = PlanUsageResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Get usage against the plan
///
/// What the organization uses now, counted fresh, next to the limits it
/// works under: its plan's, or those negotiated for it. Users and tenants
/// are counted across the organization; every other count is the most any
/// one tenant holds, as those limits apply per tenant. Read-only. The app
/// decides whether the caller may read the bill.
pub(crate) async fn get_usage(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<PlanUsageResponse>, ApiError> {
    let report = organization
        .billing
        .usage
        .execute(&member.caller, ())
        .await?;
    Ok(Json(PlanUsageResponse::from(report)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/subscription/checkout",
    tag = "Organizations",
    responses(
        (status = 200, description = "The payment provider's page", body = CheckoutResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "The deployment has no payment provider", body = ErrorBody),
        (status = 500, description = "The payment provider did not answer", body = ErrorBody)
    )
)]
/// Start a checkout
///
/// Opens a page at the payment provider where the member adds the card or
/// mandate the organization is charged through, with receipts going to
/// the member's address. Send the member to `checkout_url`. Nothing
/// changes here: the method is recorded when the provider reports it.
/// Records `organization.checkout_started`. The app decides whether the
/// caller may change what the organization pays.
pub(crate) async fn start_checkout(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<CheckoutResponse>, ApiError> {
    let page = organization
        .billing
        .checkout
        .execute(&member.caller, &member.auditor, ())
        .await?;
    Ok(Json(CheckoutResponse::from(page)))
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/payment-notices",
    tag = "Organizations",
    request_body(content = String, description = "The provider's notice, byte for byte, signed in the `Stripe-Signature` header", content_type = "application/json"),
    responses(
        (status = 204, description = "The notice was taken"),
        (status = 403, description = "The signature does not verify, or the notice is too old", body = ErrorBody),
        (status = 404, description = "The organization it names has no subscription", body = ErrorBody),
        (status = 409, description = "A charge failed while a trial runs", body = ErrorBody),
        (status = 422, description = "A verified notice could not be read", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Receive a payment notice
///
/// Where the payment provider posts what happened: a payment method added,
/// a charge failed, or what was owed is paid. Nobody signs in: the
/// provider's signature over the exact body is what lets a notice in, and
/// it is checked before anything in it is read. A notice the platform does
/// not act on is taken and changes nothing. Settling what was owed lifts a
/// suspension the platform made for not paying, never one an operator
/// made. Records `organization.payment_method_changed`,
/// `organization.payment_failed` or `organization.payment_settled`.
pub(crate) async fn receive_payment_notice(
    State(organization): State<OrganizationState>,
    notice: PaymentNoticeRequest,
) -> Result<NoContent, ApiError> {
    organization
        .billing
        .payment_notice
        .execute(&(), &notice.auditor, notice.webhook)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/plan",
    tag = "Organizations",
    request_body = ArrangePlanBody,
    responses(
        (status = 204, description = "Plan arranged"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The organization uses more than the arranged limits allow", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Arrange the organization's plan
///
/// Moves the organization to the `plan` sales agreed (`Free`, `Starter`,
/// `Business` or `Custom`), billed `monthly` (the default) or `annual`. A
/// Custom plan may carry `limits` negotiated for it, every field of a
/// plan's limits, none below the free plan's; without them it works under
/// the Business limits. An arranged plan is invoiced by hand, so no payment
/// method or trial is asked for, but what the organization uses must fit
/// (`409`). Requires an operator's own key: members choose a sold plan with
/// `PUT …/subscription`. Arranging what the organization already has
/// changes nothing. Records `organization.subscription_changed` and
/// `organization.plan_changed`.
pub(crate) async fn arrange_plan(
    State(organization): State<OrganizationState>,
    operator: OrgOperator,
    Json(body): Json<ArrangePlanBody>,
) -> Result<NoContent, ApiError> {
    let request = body.for_organization(operator.organization)?;
    organization
        .billing
        .arrange_plan
        .execute(&operator.caller, &operator.auditor, request)
        .await?;
    Ok(NoContent)
}
