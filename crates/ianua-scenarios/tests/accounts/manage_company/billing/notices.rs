//! The payment provider tells the platform what happened with nobody
//! signed in: a card saved, a charge failed, what was owed paid. Only a
//! notice signed under the endpoint's secret just now is read; every
//! delivery of the same event counts once; a late event changes nothing
//! newer; and a notice nobody can verify changes nothing at all. The
//! stack holds only the provider's signing secret, so nothing here ever
//! reaches a real payment service.

use hmac::{Hmac, Mac as _};
use ianua_scenarios::api::{billing, organizations};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::billing::Subscription;
use ianua_scenarios::wire::organization::PlanChoice;
use ianua_scenarios::world::World;
use serde_json::{Value, json};
use sha2::Sha256;
use time::OffsetDateTime;

use crate::support::{company_id, twin_usable};

/// The made-up account key the stack holds, a sentence so nothing takes
/// it for a real key.
const ACCOUNT_KEY: &str = "a made up payment account for the scenarios";

/// The signing secret both the stack and the provider hold, a sentence
/// for the same reason.
const SIGNING_SECRET: &str = "a made up notice signing phrase for the scenarios";

/// A card saved through a checkout.
const METHOD_SAVED: &str = "setup_intent.succeeded";

/// A charge the provider could not take.
const CHARGE_FAILED: &str = "invoice.payment_failed";

/// What was owed, paid.
const PAID: &str = "invoice.paid";

/// The record a saved card leaves.
const METHOD_RECORDED: &str = "organization.payment_method_changed";

/// The record of a failed charge.
const FAILED_RECORDED: &str = "organization.payment_failed";

/// The record of a settled debt.
const SETTLED_RECORDED: &str = "organization.payment_settled";

/// The stack with the payment provider's account set up, which the
/// checkout scenarios never open.
fn with_payment_provider() -> Profile {
    Profile::standard()
        .with("STRIPE_SECRET_KEY", ACCOUNT_KEY)
        .with("STRIPE_WEBHOOK_SECRET", SIGNING_SECRET)
}

/// The notice `event_id` for `kind`, about the object `object`, created at
/// `created`, as the provider writes it.
fn notice(event_id: &str, created: i64, kind: &str, object: &Value) -> String {
    json!({
        "id": event_id,
        "created": created,
        "type": kind,
        "data": { "object": object },
    })
    .to_string()
}

/// The object about Ann's company `company`, carrying the card `method`
/// when one is named.
fn about(company: &str, method: Option<&str>) -> Value {
    let mut object = json!({ "metadata": { "organization_id": company } });
    if let Some(method) = method {
        object["payment_method"] = json!(method);
    }
    object
}

/// The signature the provider puts over `body` at `moment` with `secret`.
fn signature(secret: &str, moment: i64, body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key is taken");
    mac.update(format!("{moment}.{body}").as_bytes());
    let bytes: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("t={moment},v1={bytes}")
}

/// Now, in seconds.
fn moment() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// `body`, signed now under the secret the stack holds, posted by the
/// provider, who is nobody signed in.
async fn post_notice(world: &World<'_>, body: &str) -> ianua_scenarios::wire::Answer<()> {
    let signed = signature(SIGNING_SECRET, moment(), body);
    billing::payment_notice(body, Some(&signed))
        .send(world.anonymous().client())
        .await
}

/// The bill as Ann reads it.
async fn bill(world: &World<'_>) -> Subscription {
    billing::subscription(world.org())
        .send(world.owner().client())
        .await
        .ok()
}

/// The provider reports the card Ann saved, then delivers the same event
/// again as it does when an answer is lost. The card is on file once and
/// recorded once, and the provider is told both deliveries were taken.
#[tokio::test]
async fn a_saved_card_counts_once_however_often_the_provider_repeats_it() {
    let stack = Stack::start(with_payment_provider())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let company = company_id(&world).await;
    let saved = notice(
        "evt_card_saved",
        1_700_000_100,
        METHOD_SAVED,
        &about(&company, Some("pm_card_one")),
    );

    post_notice(&world, &saved).await.ok();
    post_notice(&world, &saved).await.ok();

    assert!(
        bill(&world).await.payment_method_on_file,
        "the card is on file"
    );
    assert_eq!(
        world.trail().count(METHOD_RECORDED).await,
        1,
        "the saved card is recorded once"
    );
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A failed charge puts Ann's company past due, from when it fell due;
/// paying it settles the bill. A failed charge delivered after the
/// payment that settled it, older by its own date, leaves the company
/// paid up and records nothing more.
#[tokio::test]
async fn a_failed_charge_is_settled_by_the_payment_and_a_late_failure_is_ignored() {
    let stack = Stack::start(with_payment_provider())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let company = company_id(&world).await;

    let failed = notice(
        "evt_charge_failed",
        1_700_000_100,
        CHARGE_FAILED,
        &about(&company, None),
    );
    post_notice(&world, &failed).await.ok();
    let owing = bill(&world).await;
    assert_eq!(owing.state, "past_due", "the company owes a payment");
    assert!(owing.past_due_since.is_some(), "it says since when");

    let paid = notice(
        "evt_invoice_paid",
        1_700_000_300,
        PAID,
        &about(&company, None),
    );
    post_notice(&world, &paid).await.ok();
    let settled = bill(&world).await;
    assert_eq!(settled.state, "active", "the payment settles it");
    assert!(settled.past_due_since.is_none(), "nothing is owed");

    let late = notice(
        "evt_charge_failed_late",
        1_700_000_200,
        CHARGE_FAILED,
        &about(&company, None),
    );
    post_notice(&world, &late).await.ok();
    assert_eq!(
        bill(&world).await.state,
        "active",
        "a failure older than the payment changes nothing"
    );
    assert_eq!(
        world.trail().count(FAILED_RECORDED).await,
        1,
        "the failure is recorded once"
    );
    assert_eq!(
        world.trail().count(SETTLED_RECORDED).await,
        1,
        "the settlement is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory posts the card-saved notice with no signature, with her own
/// secret, with a signature too old to count, and with a good signature
/// over other bytes. Each is refused, and Ann's bill never changes.
#[tokio::test]
async fn mallory_cannot_forge_a_notice() {
    let stack = Stack::start(with_payment_provider())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let company = company_id(&world).await;
    let saved = notice(
        "evt_forged",
        1_700_000_100,
        METHOD_SAVED,
        &about(&company, Some("pm_stolen")),
    );

    refuse_unsigned(&world, &saved).await;
    refuse_wrongly_signed(&world, &saved).await;

    assert!(
        !bill(&world).await.payment_method_on_file,
        "no forged card is on file"
    );
    assert_eq!(
        world.trail().count(METHOD_RECORDED).await,
        0,
        "no forged notice is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A notice with no signature, or a malformed one, is refused.
async fn refuse_unsigned(world: &World<'_>, body: &str) {
    for signature in [None, Some("not a signature")] {
        billing::payment_notice(body, signature)
            .send(world.anonymous().client())
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
}

/// A notice signed under another secret, too long ago, or over other
/// bytes is refused.
async fn refuse_wrongly_signed(world: &World<'_>, body: &str) {
    let now = moment();
    let wrong_secret = signature("mallory's own secret phrase", now, body);
    let stale = signature(SIGNING_SECRET, now - 3_600, body);
    let other_bytes = signature(SIGNING_SECRET, now, "{\"other\":\"bytes\"}");
    for signature in [wrong_secret, stale, other_bytes] {
        billing::payment_notice(body, Some(&signature))
            .send(world.anonymous().client())
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
}

/// A verified notice is still checked. A company the platform never made
/// is not found, a body that is not a notice cannot be read, and a kind
/// the platform does not act on is taken and changes nothing.
#[tokio::test]
async fn a_verified_notice_for_nobody_or_of_no_interest_changes_nothing() {
    let stack = Stack::start(with_payment_provider())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let company = company_id(&world).await;

    let no_company = notice(
        "evt_no_company",
        1_700_000_100,
        METHOD_SAVED,
        &about("00000000-0000-7000-8000-000000000000", Some("pm_card_two")),
    );
    post_notice(&world, &no_company)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    post_notice(&world, "{\"not\":\"a notice\"}")
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let ignored = notice(
        "evt_ignored",
        1_700_000_100,
        "customer.updated",
        &about(&company, None),
    );
    post_notice(&world, &ignored).await.ok();

    assert_eq!(
        world.trail().count(METHOD_RECORDED).await,
        0,
        "nothing is recorded"
    );
    assert!(
        !bill(&world).await.payment_method_on_file,
        "the bill is as it was"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's company runs its one trial, so nothing is charged: a charge the
/// provider says failed during it is refused, and the bill stays
/// trialing with nothing recorded.
#[tokio::test]
async fn a_failed_charge_during_the_trial_is_refused() {
    let stack = Stack::start(with_payment_provider())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let company = company_id(&world).await;
    let business = PlanChoice {
        plan: "Business".to_owned(),
    };
    organizations::choose_plan(world.org(), &business)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        bill(&world).await.state,
        "trialing",
        "choosing a paid plan with no card starts the trial"
    );

    let failed = notice(
        "evt_trial_charge_failed",
        1_700_000_100,
        CHARGE_FAILED,
        &about(&company, None),
    );
    post_notice(&world, &failed)
        .await
        .refused(Status::CONFLICT, "conflict");

    assert_eq!(bill(&world).await.state, "trialing", "the trial runs on");
    assert_eq!(
        world.trail().count(FAILED_RECORDED).await,
        0,
        "no failure is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Where the platform bills nobody, a notice is refused unread: there is
/// no signing secret to check it against, whatever signature it carries.
#[tokio::test]
async fn a_deployment_without_a_payment_provider_reads_no_notice() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let company = company_id(&world).await;
    let saved = notice(
        "evt_unread",
        1_700_000_100,
        METHOD_SAVED,
        &about(&company, Some("pm_nothing")),
    );
    let signed = signature(SIGNING_SECRET, moment(), &saved);

    billing::payment_notice(&saved, Some(&signed))
        .send(world.anonymous().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    assert!(
        !bill(&world).await.payment_method_on_file,
        "the bill is as it was"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
