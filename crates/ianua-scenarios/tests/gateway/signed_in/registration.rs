//! Pat registering at the shop through its own host: the form is taken
//! only while Tess's tenant keeps registration open, the mailed link leads
//! back to the shop and to no other, and Pat gets in once she followed it
//! there.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, registration, tenants};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::registration::TenantSignup;
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::json;
use url::Url;

use crate::signed_in::{asserted_as, open_shop, open_twin_shop};
use crate::support::{Shop, profile, signed_in_at};

/// Opens the tenant's registration, as Ann does through the tenant's
/// sign-in settings, so the shop's form is taken.
async fn open_registration(world: &World<'_>) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings
        .rest
        .insert("self_registration".to_owned(), json!(true));
    tenants::replace_sign_in_settings(
        world.tenant(),
        &ReplaceSignInSettings {
            settings,
            proof: PasswordAgain {
                password: world.owner().password().to_owned(),
                code: None,
            },
        },
    )
    .send(world.owner().client())
    .await
    .ok();
}

/// The shop's registration form as `call` sends it from the shop's own
/// page: Pat's address, name and password.
fn registration_form(shop: &Shop, form: &TenantSignup) -> Call {
    Call::post(shop.page("/.ianua/signup"))
        .json(form)
        .header("origin", &format!("https://{}", shop.host))
        .header("sec-fetch-site", "same-origin")
}

/// Ann opens the tenant's registration. Pat fills in the shop's form; the
/// shop accepts it, Tess sees her waiting for her mailbox, and the form
/// alone gets her into no account page. The mailed link leads to the
/// shop's host: moved to the twin tenant's shop it finds nothing, and
/// followed at the shop it confirms her. Pat signs in and reaches her
/// account page, the shop seeing an assertion naming her and none of her
/// cookies.
#[tokio::test]
async fn pat_registers_at_the_shop_and_gets_in_once_the_mailed_link_is_followed_there() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    open_registration(&world).await;
    let shop = open_shop(&world).await;
    let twin_shop = open_twin_shop(&world).await;
    let pat = world.newcomer("selfregistered", "Pat New Customer");
    let form = TenantSignup {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        password: pat.password().to_owned(),
    };
    submit_form(&pat, &shop, &form).await;
    let link = verification_link(&stack, &pat, &shop).await;
    let user_id = assert_waiting(&world, &shop, &pat).await;
    confirm_at_own_shop(&pat, &twin_shop, &link).await;
    signed_in_at(&shop, &pat).await;
    shop.app.forget();
    pat.client()
        .get::<IgnoredAny>(&shop.page("/account/orders"))
        .await
        .ok();
    asserted_as(&shop.app, &user_id);
    stack.stop().await.expect("the stack stops cleanly");
}

/// The open shop accepts Pat's registration form.
async fn submit_form(pat: &Person, shop: &Shop, form: &TenantSignup) {
    let accepted = pat
        .client()
        .send::<IgnoredAny>(registration_form(shop, form))
        .await;
    assert_eq!(
        accepted.status(),
        Status::ACCEPTED,
        "the shop takes Pat's form: {}",
        accepted.summary()
    );
}

/// Pat's mailed verification link names the shop where she registered.
async fn verification_link(stack: &Stack, pat: &Person, shop: &Shop) -> Url {
    let mail = stack.mailbox().next_for(pat.email()).await;
    let link = mail.link_to("/.ianua/verify");
    assert_eq!(
        link.host_str(),
        Some(shop.host.as_str()),
        "the mailed link leads to the shop"
    );
    link
}

/// Tess sees one pending account while Pat's form alone grants no shop access.
async fn assert_waiting(world: &World<'_>, shop: &Shop, pat: &Person) -> String {
    let waiting = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(waiting.items.len(), 1, "Tess sees one account for Pat");
    assert_eq!(
        waiting.items[0].status, "PendingVerification",
        "Pat's account waits for her mailbox"
    );
    Matrix::new(
        "reading an account page with the form alone",
        Call::get(shop.page("/account/orders")),
    )
    .refused(pat.client(), Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
    waiting.items[0].id.clone()
}

/// The link fails at the twin tenant's shop and confirms Pat at its own host.
async fn confirm_at_own_shop(pat: &Person, twin_shop: &Shop, link: &Url) {
    let mut moved = link.clone();
    moved
        .set_host(Some(&twin_shop.host))
        .expect("the twin's host is a host");
    let wrong = pat
        .client()
        .send::<IgnoredAny>(Call::get(moved.as_str()))
        .await;
    assert_eq!(
        wrong.status(),
        Status::NOT_FOUND,
        "the link finds nothing at the twin tenant's shop: {}",
        wrong.summary()
    );
    let confirmed = pat
        .client()
        .send::<IgnoredAny>(Call::get(link.as_str()))
        .await;
    assert_eq!(
        confirmed.status(),
        Status::ACCEPTED,
        "the link confirms Pat at the shop: {}",
        confirmed.summary()
    );
}

/// The shop refuses Pat's registration form while the tenant keeps registration
/// closed. Tess sees no account for her, and the
/// tenant's rules say registration is closed. Ann opens registration, and
/// the same form is taken and mails Pat a link leading to the shop.
#[tokio::test]
async fn the_shops_form_refuses_registration_while_the_tenant_keeps_it_closed() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = open_shop(&world).await;
    let pat = world.newcomer("selfregistered", "Pat New Customer");
    let form = TenantSignup {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        password: pat.password().to_owned(),
    };
    assert_closed(&world, &shop, &pat, &form).await;
    open_registration(&world).await;
    accept_when_open(&stack, &shop, &pat, &form).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Closed registration refuses Pat's form, creates no account and reports closed rules.
async fn assert_closed(world: &World<'_>, shop: &Shop, pat: &Person, form: &TenantSignup) {
    let refused = pat
        .client()
        .send::<IgnoredAny>(registration_form(shop, form))
        .await;
    assert_eq!(
        refused.status(),
        Status::FORBIDDEN,
        "the shop refuses the form while registration is closed: {}",
        refused.summary()
    );
    let listed = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert!(listed.items.is_empty(), "no account was made for Pat");
    let rules = registration::rules(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(!rules.open, "the tenant's rules say registration is closed");
}

/// Once registration opens, the same form is accepted and mails a shop-bound link.
async fn accept_when_open(stack: &Stack, shop: &Shop, pat: &Person, form: &TenantSignup) {
    let accepted = pat
        .client()
        .send::<IgnoredAny>(registration_form(shop, form))
        .await;
    assert_eq!(
        accepted.status(),
        Status::ACCEPTED,
        "the shop takes the same form once registration is open: {}",
        accepted.summary()
    );
    let link = stack
        .mailbox()
        .next_for(pat.email())
        .await
        .link_to("/.ianua/verify");
    assert_eq!(
        link.host_str(),
        Some(shop.host.as_str()),
        "the mailed link leads to the shop"
    );
}
