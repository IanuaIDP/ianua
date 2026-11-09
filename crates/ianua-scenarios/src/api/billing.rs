//! What a company pays: the plans on sale, its subscription and usage,
//! the checkout, the notices its payment provider posts, and the plan an
//! operator arranges.

use super::{OrgPath, Request};
use crate::net::Call;
use crate::wire::billing::{ArrangePlan, Checkout, PlanCatalog, PlanUsage, Subscription};

/// The header the payment provider signs its notices in.
pub const SIGNATURE_HEADER: &str = "stripe-signature";

/// `GET /api/v1/plans`: every plan on sale. Public.
#[must_use]
pub fn plans() -> Request<PlanCatalog> {
    Request::of(Call::get("/api/v1/plans"))
}

/// `GET …/subscription`.
#[must_use]
pub fn subscription(org: &OrgPath) -> Request<Subscription> {
    Request::of(Call::get(org.at("/subscription")))
}

/// `GET …/usage`.
#[must_use]
pub fn usage(org: &OrgPath) -> Request<PlanUsage> {
    Request::of(Call::get(org.at("/usage")))
}

/// `POST …/subscription/checkout`: a page at the payment provider.
#[must_use]
pub fn checkout(org: &OrgPath) -> Request<Checkout> {
    Request::of(Call::post(org.at("/subscription/checkout")))
}

/// `POST …/plan`: an operator moves the company to a plan sales agreed.
#[must_use]
pub fn arrange(org: &OrgPath, plan: &ArrangePlan) -> Request<()> {
    Request::of(Call::post(org.at("/plan")).json(plan))
}

/// `POST /api/v1/billing/payment-notices`: the provider's notice, byte
/// for byte, with the signature it came with, or none.
#[must_use]
pub fn payment_notice(body: &str, signature: Option<&str>) -> Request<()> {
    let call = Call::post("/api/v1/billing/payment-notices").raw("application/json", body);
    let Some(signature) = signature else {
        return Request::of(call);
    };
    Request::of(call.header(SIGNATURE_HEADER, signature))
}
