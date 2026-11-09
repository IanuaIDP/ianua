//! Stripe as a workflow step: Tess connects the team's restricted key,
//! which Stripe is asked about first by listing one customer, and Ann
//! publishes a workflow that reads a payment and refunds part of it. A
//! refund moves money, so it waits for two administrators to approve what
//! they were shown, each with a fresh code. A stand-in for Stripe shows
//! what arrived: the key, the API version every call is pinned to, and the
//! refund as Stripe's form for the payment the first step read, only once
//! both had approved. A key Stripe refuses is never connected, and a
//! customer Stripe refuses fails the run.

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::{eventually, no_secret_leaked};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Node, Step, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{
    Action, ApprovalStep, Approver, account_at, action, drafted, ended, published, read, run,
    started, written,
};

/// The team's restricted key: a sentence, so no scanner takes it for a
/// key.
const KEY: &str = "acme stripe restricted key for workflows";

/// The API version every call is pinned to.
const VERSION: &str = "2026-09-30.endive";

/// Where customers are listed, which proves a key, and added.
const CUSTOMERS: &str = "/customers";

/// Where the payment the workflow reads is.
const PAYMENT: &str = "/payment_intents/pi_acme_order_42";

/// Where a refund is made.
const REFUNDS: &str = "/refunds";

/// The key of the approval before the refund.
const APPROVAL_STEP: &str = "approve-refund";

/// Tess connects the key, which Stripe takes for listing one customer.
/// Ann publishes a workflow reading order 42's payment and refunding 5.00
/// of it, with an approval for money moving right before the refund. Tess
/// runs it: the payment is read and the run waits. Bea's approval alone
/// refunds nothing; once Cal approves too, Stripe receives the refund as a
/// form naming the payment the first step read, signed with the key and
/// pinned to Stripe's version, and the run succeeds. The key is nowhere in
/// the trail.
#[tokio::test]
async fn a_refund_reaches_stripe_only_after_two_approvals() {
    let stripe = stripe_answering(Canned::json(&json!({ "id": "cus_dana" }))).await;
    let stack = Stack::start(profile(&stripe))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "stripe", KEY).await;
    assert_eq!(
        only_call(&stripe, "GET", CUSTOMERS).query.as_deref(),
        Some("limit=1")
    );
    let draft = drafted(&world, Trigger::Manual, refund_graph(&account)).await;
    let workflow = published(&world, &draft).await;
    let decided = started(&world, &workflow).await;
    approve_twice(&world, &stripe, &decided.execution_id).await;
    ended(&world, &decided.execution_id, "succeeded").await;
    check_refund(&stripe);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[KEY]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Stripe refuses the customer with 400, as for an address it cannot
/// read. The step and the run fail after one request.
#[tokio::test]
async fn a_customer_stripe_refuses_fails_the_run() {
    let stripe = stripe_answering(Canned::refusing(400)).await;
    let stack = Stack::start(profile(&stripe))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "stripe", KEY).await;

    let run = ran(&world, chain(vec![customer_step(&account)]), "failed").await;

    failed_step(&run, "stripe-create-customer");
    let refused = only_call(&stripe, "POST", CUSTOMERS);
    assert_eq!(refused.body, "email=dana%40customer.test&name=Dana+Diaz");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Stripe does not know Tess's mistyped key: asked once, it answers 401,
/// and no account is connected.
#[tokio::test]
async fn a_key_stripe_refuses_is_never_connected() {
    let stripe = CannedApp::start([(CUSTOMERS, Canned::refusing(401))])
        .await
        .expect("the Stripe stand-in starts");
    let stack = Stack::start(profile(&stripe))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "stripe",
        credential: "a mistyped stripe key",
    };

    never_connected(&world, offered).await;

    assert_eq!(
        stripe.asked_for(CUSTOMERS),
        1,
        "Stripe was asked about the key"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The run waits at the refund's approval; Bea's yes alone refunds
/// nothing, and Cal's second yes lets it go on.
async fn approve_twice(world: &World<'_>, stripe: &CannedApp, execution_id: &str) {
    held_at_the_approval(world, execution_id).await;
    let shown = workflows::approval(world.tenant(), execution_id, APPROVAL_STEP)
        .send(world.owner().client())
        .await
        .ok();
    let mut bea = Approver::joined(world, "bea", "Bea Approver").await;
    let mut cal = Approver::joined(world, "cal", "Cal Approver").await;
    let target = ApprovalStep {
        execution_id,
        step: APPROVAL_STEP,
    };
    bea.approve(world, target, &shown.shown).await;
    assert_eq!(stripe.asked_for(REFUNDS), 0, "one yes moves no money");
    cal.approve(world, target, &shown.shown).await;
}

/// Waits until the run `execution_id` is held at the refund's approval.
async fn held_at_the_approval(world: &World<'_>, execution_id: &str) {
    let held = eventually("the run to wait for a yes, or end", || async {
        let execution = run(world, execution_id).await;
        let waiting = execution
            .steps
            .iter()
            .any(|step| step.key == APPROVAL_STEP && step.phase == "running");
        (waiting || execution.status != "running").then_some(execution)
    })
    .await;
    assert_eq!(held.status, "running", "the run waits for a yes: {held:?}");
}

/// The workflow reads order 42's payment and, once approved, refunds 5.00
/// of the payment it read.
fn refund_graph(account: &str) -> Graph {
    let read_payment = action(
        Action {
            integration: "stripe",
            operation: "get-payment",
        },
        account,
        "read",
        vec![("payment", written("pi_acme_order_42"))],
    );
    let refund = action(
        Action {
            integration: "stripe",
            operation: "refund-payment",
        },
        account,
        "financial",
        vec![
            ("payment", read("stripe-get-payment.json.id")),
            ("amount", written(500)),
            ("reason", written("requested_by_customer")),
        ],
    );
    chain(vec![read_payment, refund_approval(), refund])
}

/// The approval for money moving that the refund waits for.
fn refund_approval() -> Node {
    Node {
        key: APPROVAL_STEP.to_owned(),
        name: "Approve the refund".to_owned(),
        step: Step::Approval {
            summary: "Refund 5.00 of order 42".to_owned(),
            action_class: "financial".to_owned(),
            window_seconds: 120,
        },
    }
}

/// The step adding Dana as a customer.
fn customer_step(account: &str) -> Node {
    action(
        Action {
            integration: "stripe",
            operation: "create-customer",
        },
        account,
        "write",
        vec![
            ("email", written("dana@customer.test")),
            ("name", written("Dana Diaz")),
        ],
    )
}

/// Stripe received the payment's read and then one refund for it as a
/// form, each signed with the key and pinned to Stripe's version.
fn check_refund(stripe: &CannedApp) {
    let payment = only_call(stripe, "GET", PAYMENT);
    let refund = only_call(stripe, "POST", REFUNDS);
    for call in [&payment, &refund] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {KEY}").as_str())
        );
        assert_eq!(call.header("stripe-version"), Some(VERSION));
    }
    assert_eq!(
        refund.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        refund.body,
        "amount=500&payment_intent=pi_acme_order_42&reason=requested_by_customer"
    );
}

/// A Stripe stand-in that lists one customer for the probe, answers a new
/// customer with `customer`, shows order 42's payment and takes a refund.
async fn stripe_answering(customer: Canned) -> CannedApp {
    CannedApp::start([
        (
            "GET /customers",
            Canned::json(&json!({ "data": [], "has_more": false })),
        ),
        ("POST /customers", customer),
        (
            PAYMENT,
            Canned::json(
                &json!({ "id": "pi_acme_order_42", "amount": 4200, "status": "succeeded" }),
            ),
        ),
        (
            REFUNDS,
            Canned::json(&json!({ "id": "re_acme_1", "amount": 500, "status": "succeeded" })),
        ),
    ])
    .await
    .expect("the Stripe stand-in starts")
}

/// The standard deployment, its Stripe steps calling `stripe`.
fn profile(stripe: &CannedApp) -> Profile {
    Profile::standard().with("STRIPE_API_URL", &stripe.url())
}
