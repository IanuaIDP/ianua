//! Pat's passkey at the shop: the shop's sign-in address takes the answer
//! of a passkey registered at the shared relying party once, and a copy of
//! that answer, replayed from another browser, opens no second session.

use ianua_scenarios::actors::Person;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::AssertionCheck;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::app_sign_in::AppSignedIn;
use ianua_scenarios::wire::factors::PasskeyChallenge;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::json;

use crate::support::{Shop, ShopOwner, customer, profile, word};

/// Pat, who registered a passkey at the shared relying party, asks the
/// shop's sign-in address for a challenge and answers it with the
/// passkey: she is signed in at the shop and reaches her account page,
/// the shop seeing an assertion naming her. Mallory replays the same
/// answer from another browser: it is refused and her browser reaches
/// nothing. This proves the protocol, not a browser's navigation between
/// the shop and the relying party.
#[tokio::test]
async fn a_passkey_signs_pat_in_at_the_shop_once_and_a_replayed_answer_never() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = Shop::opened(
        &stack,
        &ShopOwner {
            tenant: world.tenant(),
            admin: world.admin().client(),
            word: &word(),
        },
    )
    .await;
    let mut pat = customer(&world, "pat", "Pat Customer").await;
    pat.sign_in(&stack).await;
    pat.add_passkey(&stack, "Pat's shared relying-party key")
        .await;
    let answer = passkey_answer(&stack, &shop, &pat).await;
    let signed_in = pat.client().send::<AppSignedIn>(answer.clone()).await.ok();
    assert!(signed_in.signed_in, "the passkey's answer signs Pat in");
    let mallory = Client::new(&stack, "Mallory, replaying the answer").expect("a client");
    mallory
        .send::<IgnoredAny>(answer)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    mallory
        .get::<IgnoredAny>(&shop.page("/account/orders"))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_pat_arrives(&shop, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat answers the shop's challenge with her key at the shared relying party.
async fn passkey_answer(stack: &Stack, shop: &Shop, pat: &Person) -> Call {
    let asking = Call::post(shop.page("/.ianua/passkey"))
        .json(&json!({ "email": pat.email() }))
        .header("origin", &format!("https://{}", shop.host))
        .header("sec-fetch-site", "same-origin");
    let challenge = pat.client().send::<PasskeyChallenge>(asking).await.ok();
    let Some(key) = pat.passkey() else {
        panic!("Pat just added a passkey");
    };
    let assertion = key.on_page(&stack.app_url()).sign_in(&challenge.challenge);
    Call::post(shop.page("/.ianua/passkey"))
        .json(&json!({
            "ceremony_id": challenge.ceremony_id,
            "credential_id": assertion.credential_id,
            "response": assertion.response,
        }))
        .header("origin", &format!("https://{}", shop.host))
        .header("sec-fetch-site", "same-origin")
}

/// The shop sees only Pat's request and a verified assertion naming her.
async fn assert_pat_arrives(shop: &Shop, pat: &Person) {
    shop.app.forget();
    pat.client()
        .get::<IgnoredAny>(&shop.page("/account/orders"))
        .await
        .ok();
    let arrivals = shop.app.arrivals();
    assert_eq!(arrivals.len(), 1, "only Pat reached the shop");
    let AssertionCheck::Verified { caller } = &arrivals[0].assertion else {
        panic!("the shop could not check the gateway's assertion: {arrivals:?}");
    };
    assert_eq!(caller.sub, pat.id(), "the assertion names Pat");
}
