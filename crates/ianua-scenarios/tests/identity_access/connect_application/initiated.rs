//! Signing in to Ledger from the tenant's side, such as from an app tile,
//! with no request from Ledger: the platform answers only the person
//! signed in, only for an app that is on, and Ledger takes the answer
//! only as one it did not ask for.

use ianua_scenarios::api::saml_apps;
use ianua_scenarios::services::saml::signature::Broken;
use ianua_scenarios::services::saml::{App, PERSISTENT, Refusal};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;
use uuid::Uuid;

use crate::saml::changed;
use crate::support::{pat, registered, the_tenant};

/// The record an answer to an app leaves.
const ISSUED: &str = "federation.saml_assertion_issued";

/// Pat opens the tenant's link for Ledger, and the browser is sent on to
/// the dashboard's sign-in page for it. Nobody signed in gets no answer,
/// and Sam from the other company neither. Pat gets a signed answer for
/// Ledger's own address, carrying no page to come back to. Ledger accepts
/// it as an answer it did not ask for, naming Pat by a lasting id with her
/// address. Offered as the answer to a request Ledger did make, it is
/// refused, so an unasked answer cannot pass for an asked one; and with
/// a word of it changed the signature fails. One answer is on record.
#[tokio::test]
async fn pat_opens_ledger_from_the_tenants_side_and_ledger_takes_the_answer_as_unasked() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ledger = App::at("ledger.example");
    let made = registered(&world, &ledger, "Ledger").await;
    let tenant = the_tenant(&world).await;
    let pat = pat(&world).await;

    let link = saml_apps::initiate(world.tenant(), &made.id)
        .send(world.anonymous().client())
        .await;
    assert!(
        link.status().is_redirection(),
        "the browser goes on: {}",
        link.summary()
    );
    let page = link.header("location").expect("a redirect says where");
    assert!(
        page.contains(&format!("/saml/apps/{}/sign-in", made.id)),
        "to the dashboard's sign-in page for Ledger: {page}"
    );

    saml_apps::sign_in_to(world.tenant(), &made.id)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    saml_apps::sign_in_to(world.tenant(), &made.id)
        .send(world.stranger().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let answer = saml_apps::sign_in_to(world.tenant(), &made.id)
        .send(pat.client())
        .await
        .ok();
    assert_eq!(answer.destination, ledger.acs_url(), "posted to Ledger");
    assert_eq!(answer.parameter, "SAMLResponse");
    assert_eq!(answer.relay_state, None, "no page to come back to");

    let accepted = ledger
        .accepted_unsolicited(&tenant, &answer.message)
        .expect("Ledger accepts the answer it did not ask for");
    assert_eq!(accepted.name_id_format, PERSISTENT);
    assert!(!accepted.name_id.is_empty(), "Pat is named by a lasting id");
    assert_eq!(
        accepted.attributes.get("email"),
        Some(&vec![pat.email().to_owned()]),
        "Ledger learns Pat's address"
    );

    let asked = ledger.sign_in_request(&tenant, "/reports");
    assert_eq!(
        ledger
            .accepted(&tenant, &asked, &answer.message)
            .map(|_| ()),
        Err(Refusal::Request),
        "an unasked answer does not pass for an asked one"
    );
    let tampered = changed(&answer.message, pat.email(), "mallory@ledger.example");
    assert_eq!(
        ledger.accepted_unsolicited(&tenant, &tampered).map(|_| ()),
        Err(Refusal::Signature(Broken::DigestDiffers)),
        "a changed answer fails Ledger's check"
    );

    assert_eq!(
        world.trail().count(ISSUED).await,
        1,
        "one answer is on record"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess switches Ledger off: Pat's tile gets no answer and none is
/// recorded. An app the tenant never had is not found. Tess switches
/// Ledger on again and Pat's next answer is taken.
#[tokio::test]
async fn no_answer_comes_for_a_switched_off_or_unknown_app() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ledger = App::at("ledger.example");
    let made = registered(&world, &ledger, "Ledger").await;
    let tenant = the_tenant(&world).await;
    let pat = pat(&world).await;

    saml_apps::disable(world.tenant(), &made.id)
        .send(world.admin().client())
        .await
        .ok();
    saml_apps::sign_in_to(world.tenant(), &made.id)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert_eq!(
        world.trail().count(ISSUED).await,
        0,
        "a refusal is not an answer"
    );

    saml_apps::sign_in_to(world.tenant(), &Uuid::now_v7().to_string())
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    saml_apps::activate(world.tenant(), &made.id)
        .send(world.admin().client())
        .await
        .ok();
    let answer = saml_apps::sign_in_to(world.tenant(), &made.id)
        .send(pat.client())
        .await
        .ok();
    ledger
        .accepted_unsolicited(&tenant, &answer.message)
        .expect("Ledger, on again, takes its answer");
    stack.stop().await.expect("the stack stops cleanly");
}
