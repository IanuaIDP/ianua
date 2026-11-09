//! The plans anyone may read; the plan Bob the operator arranges for
//! Ann's company, which only an operator can arrange; and the checkout,
//! refused with nothing recorded where no payment provider is set up, as
//! the stack has none to reach.

use ianua_scenarios::api::{billing, organizations, tenants};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::billing::{ArrangePlan, PlanCatalog, PlanOnSale};
use ianua_scenarios::wire::organization::{OrgRole, PlanChoice};
use ianua_scenarios::wire::tenants::NewTenant;
use ianua_scenarios::world::World;

use crate::support::{bob_signed_in, colleague_signed_in, twin_usable};

/// The record a moved plan leaves.
const PLAN_CHANGED: &str = "organization.plan_changed";

/// The record of the subscription moving with it.
const SUBSCRIPTION_CHANGED: &str = "organization.subscription_changed";

/// The record of a checkout opened.
const CHECKOUT_STARTED: &str = "organization.checkout_started";

/// A generous figure negotiated for Ann's users.
const NEGOTIATED_USERS: u64 = 777_777;

/// Nobody signed in reads the plans on sale, in the order the pricing
/// page shows them, priced in dollars. Custom has no price and sends its
/// buyers to sales. The limits on the Free plan's card are the limits
/// Ann's new company works under.
#[tokio::test]
async fn anyone_reads_the_plans_and_the_card_shows_the_limits_enforced() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let catalog = billing::plans().send(world.anonymous().client()).await.ok();
    assert_eq!(catalog.currency, "USD", "prices are in dollars");
    let order: Vec<&str> = catalog
        .plans
        .iter()
        .map(|tier| tier.plan.as_str())
        .collect();
    assert_eq!(
        order,
        ["Free", "Starter", "Business", "Custom"],
        "the plans read in the pricing page's order"
    );
    let custom = plan_on_sale(&catalog, "Custom");
    assert!(custom.price.is_none(), "a negotiated plan has no price");
    assert_eq!(
        custom.call_to_action, "contact_sales",
        "a negotiated plan sends the buyer to sales"
    );
    let starter = plan_on_sale(&catalog, "Starter");
    let priced = starter.price.as_ref().expect("Starter has a price");
    assert!(priced.monthly_cents > 0, "Starter is not free");
    assert_eq!(starter.call_to_action, "sign_up", "Starter is self served");

    let report = billing::usage(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        report.limits,
        plan_on_sale(&catalog, "Free").limits,
        "the Free card's limits are the ones enforced"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The plan named `plan` on the page.
///
/// # Panics
///
/// When the catalog does not sell it.
fn plan_on_sale<'c>(catalog: &'c PlanCatalog, plan: &str) -> &'c PlanOnSale {
    catalog
        .plans
        .iter()
        .find(|tier| tier.plan == plan)
        .unwrap_or_else(|| panic!("the catalog sells {plan}"))
}

/// Bob arranges a Custom plan with limits negotiated for Ann's company:
/// the bill reads Custom, active, on a monthly cycle, with no payment
/// method asked for, and Ann works under the negotiated limits. Saying
/// the same again changes nothing and records nothing more. The move is
/// recorded once, against the company.
#[tokio::test]
async fn bob_arranges_a_negotiated_plan_and_ann_works_under_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let bob = bob_signed_in(&stack).await;
    let arrangement = custom_arrangement(&world, NEGOTIATED_USERS).await;

    arrange_custom_plan(&world, &bob, &arrangement).await;
    billing::arrange(world.org(), &arrangement)
        .send(&bob)
        .await
        .ok();
    assert_eq!(
        world.trail().count(PLAN_CHANGED).await,
        1,
        "the plan's move is recorded once"
    );
    assert_eq!(
        world.trail().count(SUBSCRIPTION_CHANGED).await,
        1,
        "the bill's move is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A Custom plan copying the Business plan's limits, with `users` for
/// its user limit.
async fn custom_arrangement(world: &World<'_>, users: u64) -> ArrangePlan {
    let catalog = billing::plans().send(world.anonymous().client()).await.ok();
    let mut limits = plan_on_sale(&catalog, "Business").limits.clone();
    limits["max_users"] = serde_json::json!(users);
    ArrangePlan {
        plan: "Custom".to_owned(),
        cycle: None,
        limits: Some(limits),
    }
}

/// Bob's arrangement moves the bill to Custom and Ann's limits to the
/// ones he named, with no payment method asked for.
async fn arrange_custom_plan(world: &World<'_>, bob: &Client, arrangement: &ArrangePlan) {
    billing::arrange(world.org(), arrangement)
        .send(bob)
        .await
        .ok();
    let bill = billing::subscription(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(bill.plan, "Custom", "the bill reads Custom");
    assert_eq!(bill.state, "active", "the arranged plan is active at once");
    assert!(
        !bill.payment_method_on_file,
        "an arranged plan asks for no card"
    );
    let report = billing::usage(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(report.plan, "Custom", "Ann works under Custom");
    assert_eq!(
        report.limits["max_users"], NEGOTIATED_USERS,
        "Ann works under the negotiated limits"
    );
}

/// Ann herself, Uma an administrator, Sam and nobody signed in cannot
/// arrange a plan: it needs an operator's own key. The bill stays Free,
/// nothing is recorded, and Sam's company is untouched.
#[tokio::test]
async fn only_an_operator_arranges_a_plan() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = colleague_signed_in(&world, "uma", OrgRole::Admin).await;
    let arrangement = custom_arrangement(&world, NEGOTIATED_USERS).await;

    Matrix::new(
        "arranging a plan",
        billing::arrange(world.org(), &arrangement).call(),
    )
    .refused(world.owner().client(), Status::FORBIDDEN, "forbidden")
    .refused(uma.client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;

    let bill = billing::subscription(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(bill.plan, "Free", "the bill is as it was");
    assert_eq!(
        world.trail().count(PLAN_CHANGED).await,
        0,
        "a refused arrangement records nothing"
    );
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Bob cannot arrange limits below what the Free plan allows, nor a plan
/// Ann's company has outgrown: with two tenants, moved to Business with
/// its one trial, the Free plan does not fit, and Ann's plan stays.
#[tokio::test]
async fn bob_arranges_nothing_the_company_does_not_fit() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let bob = bob_signed_in(&stack).await;

    let mut below_free = custom_arrangement(&world, NEGOTIATED_USERS).await;
    let limits = below_free.limits.as_mut().expect("the copied limits");
    limits["max_users"] = serde_json::json!(1);
    billing::arrange(world.org(), &below_free)
        .send(&bob)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    grow_past_the_free_plan(&world).await;
    let shrink = ArrangePlan {
        plan: "Free".to_owned(),
        cycle: None,
        limits: None,
    };
    let refused = billing::arrange(world.org(), &shrink)
        .send(&bob)
        .await
        .refused(Status::CONFLICT, "conflict");
    assert!(
        refused.message().contains("allow"),
        "the refusal says the plan does not allow it: {}",
        refused.message()
    );
    let bill = billing::subscription(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(bill.plan, "Business", "the plan stays what it was");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann moves to Business with her company's one trial, then makes a
/// second tenant, which the Free plan does not allow.
async fn grow_past_the_free_plan(world: &World<'_>) {
    let business = PlanChoice {
        plan: "Business".to_owned(),
    };
    organizations::choose_plan(world.org(), &business)
        .send(world.owner().client())
        .await
        .ok();
    let staging = NewTenant {
        slug: "staging".to_owned(),
        display_name: "Staging Team".to_owned(),
        contact_email: world.address("tenant-contact"),
        timezone: "Europe/Berlin".to_owned(),
        locale: "en-US".to_owned(),
    };
    tenants::create(world.org(), &staging)
        .send(world.owner().client())
        .await
        .ok();
}

/// Where no payment provider is set up, Ann asks for a checkout and the
/// platform refuses it as a failure of its own, with nothing recorded
/// and the bill as it was. Uma the administrator, who may not change
/// what the company pays, Tess, Max, Sam and nobody signed in are refused
/// before any of that.
#[tokio::test]
async fn a_checkout_cannot_be_opened_where_no_payment_provider_is_set_up() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = colleague_signed_in(&world, "uma", OrgRole::Admin).await;

    billing::checkout(world.org())
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    Matrix::new("opening a checkout", billing::checkout(world.org()).call())
        .refused(uma.client(), Status::FORBIDDEN, "forbidden")
        .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
        .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .run()
        .await;

    assert_eq!(
        world.trail().count(CHECKOUT_STARTED).await,
        0,
        "no checkout is recorded"
    );
    let bill = billing::subscription(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert!(!bill.payment_method_on_file, "no card appeared");

    stack.stop().await.expect("the stack stops cleanly");
}
