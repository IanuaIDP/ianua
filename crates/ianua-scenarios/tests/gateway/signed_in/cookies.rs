//! Pat's session cookie on the shop's own host: it lets her into the
//! shop's account pages until she signs out, does nothing on another
//! host, cannot be spent by a page from another site, and a sign-in that
//! still owes a code is finished only in her own browser with her phone.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::app_sign_in;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, Records, eventually};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::app_sign_in::{AppLogIn, AppSignedIn};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::json;

use crate::signed_in::{asserted_as, open_shop};
use crate::support::{Shop, customer, profile, signed_in_at};

/// Pat signs in on the shop's own host and reaches its account pages; the
/// shop sees a signed assertion naming Pat and none of Pat's cookies.
/// Nobody signed in, and Sam from another organization, are refused, the
/// shop seeing nothing of them. Mallory copies Pat's session cookie to the
/// tenant's other host, where it does nothing. Pat signs out, and the copy
/// Mallory kept stops working within seconds. The gateway records Pat's
/// request as allowed.
#[tokio::test]
async fn a_person_signed_in_on_the_apps_host_reaches_it_until_signing_out() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = open_shop(&world).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_at(&shop, &pat).await;
    shop.app.forget();

    let account = shop.page("/account/orders");
    assert_account_access(&world, &shop, &pat, &account).await;
    let cookie = pat
        .client()
        .cookies_for(&account.parse().expect("the page is a URL"))
        .expect("Pat holds the shop's session cookie");
    let mallory = Client::new(&stack, "Mallory, with Pat's cookie").expect("a client");
    refuse_cookie_on_api(&shop, &mallory, &cookie).await;
    app_sign_in::log_out(&shop.host)
        .send(pat.client())
        .await
        .ok();
    let copied = Call::get(account.as_str()).header("cookie", &cookie);
    eventually("Pat's ended session to stop working", || async {
        let answer = mallory.send::<IgnoredAny>(copied.clone()).await;
        (answer.status() == Status::UNAUTHORIZED).then_some(())
    })
    .await;
    assert_allowed_record(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat alone reaches her account and the shop sees the expected trusted identity.
async fn assert_account_access(world: &World<'_>, shop: &Shop, pat: &Person, account: &str) {
    Matrix::new("reading Pat's account page", Call::get(account))
        .allowed(pat.client())
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .refused(
            world.stranger().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .run()
        .await;
    let arrived = asserted_as(&shop.app, pat.id());
    assert_eq!(
        arrived.path, "/account/orders",
        "the shop got the page Pat asked for"
    );
    assert_eq!(shop.app.arrivals().len(), 1, "only Pat reached the shop");
}

/// Copying the shop's cookie to its API host authenticates no request.
async fn refuse_cookie_on_api(shop: &Shop, mallory: &Client, cookie: &str) {
    let elsewhere = shop.endpoint("/orders/1");
    Matrix::new(
        "using Pat's cookie on another host",
        Call::get(elsewhere.as_str()).header("cookie", cookie),
    )
    .refused(mallory, Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
    assert!(
        shop.api.arrivals().is_empty(),
        "nothing reached the API: {:?}",
        shop.api.arrivals()
    );
}

/// The successful account request records Pat as an allowed tenant user.
async fn assert_allowed_record(world: &World<'_>, pat: &Person) {
    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where("/account/orders", "Pat's", |record| {
            record.subject.id.as_deref() == Some(pat.id())
        })
        .await;
    assert_eq!(
        record.subject.kind, "user",
        "the record names a tenant user"
    );
    assert_eq!(record.decision, "allowed", "Pat's request is allowed");
}

/// A page on another site posts to the shop's sign-out and token addresses
/// while Pat's browser carries the shop's cookie.
/// Both are refused as cross-site and Pat's session is untouched; she
/// still reads her account page after each. Then Pat signs out from the
/// shop's own page, and is refused the account page.
#[tokio::test]
async fn a_page_from_another_site_cannot_sign_pat_out_or_fetch_a_token() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = open_shop(&world).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_at(&shop, &pat).await;
    refuse_foreign_page(&shop, &pat).await;
    app_sign_in::log_out(&shop.host)
        .send(pat.client())
        .await
        .ok();
    pat.client()
        .get::<IgnoredAny>(&shop.page("/account/orders"))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Foreign logout and token posts are refused while Pat's account remains readable.
async fn refuse_foreign_page(shop: &Shop, pat: &Person) {
    for (path, body) in [
        ("/.ianua/logout", json!({})),
        ("/.ianua/token", json!({ "audience": shop.api_audience })),
    ] {
        pat.client()
            .send::<IgnoredAny>(
                Call::post(shop.page(path))
                    .json(&body)
                    .header("origin", "https://unrelated.example")
                    .header("sec-fetch-site", "cross-site"),
            )
            .await
            .refused(Status::FORBIDDEN, "cross_site");
        pat.client()
            .get::<IgnoredAny>(&shop.page("/account/orders"))
            .await
            .ok();
    }
}

/// Pat, who set up an authenticator app, signs in at the shop with her
/// password: the sign-in owes a code and she is refused the account page
/// meanwhile. Mallory, in a browser that never began the sign-in, answers
/// with Pat's code and is refused. Pat's own browser answers with her
/// phone, is signed in, and reaches the account page; the shop sees an
/// assertion naming her and none of her cookies.
#[tokio::test]
async fn a_sign_in_owing_a_code_is_finished_only_by_pats_browser_and_phone() {
    let _clock = Clock::controlled();
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = open_shop(&world).await;
    let mut pat = customer(&world, "pat", "Pat Customer").await;
    pat.sign_in(&stack).await;
    pat.set_up_authenticator().await;
    let mut phone = pat.lose_phone();
    begin_mfa(&shop, &pat).await;
    let answer = Call::post(shop.page("/.ianua/mfa"))
        .json(&json!({ "code": phone.code().await }))
        .header("origin", &format!("https://{}", shop.host))
        .header("sec-fetch-site", "same-origin");
    let mallory = Client::new(&stack, "Mallory, who never began the sign-in").expect("a client");
    mallory
        .send::<IgnoredAny>(answer.clone())
        .await
        .refused(Status::BAD_REQUEST, "missing_challenge");
    assert!(
        shop.app.arrivals().is_empty(),
        "nothing reached the shop before the code was answered"
    );
    finish_mfa(&shop, &pat, answer).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's password starts a pending sign-in and grants no access before her code.
async fn begin_mfa(shop: &Shop, pat: &Person) {
    let waiting = app_sign_in::log_in(
        &shop.host,
        &AppLogIn {
            email: pat.email().to_owned(),
            password: pat.password().to_owned(),
        },
    )
    .send(pat.client())
    .await
    .ok();
    assert!(waiting.mfa_required, "the sign-in owes a code");
    assert!(
        !waiting.signed_in,
        "Pat is not in until the code is answered"
    );
    shop.app.forget();
    pat.client()
        .get::<IgnoredAny>(&shop.page("/account/orders"))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Pat's original browser completes MFA and reaches the shop as herself.
async fn finish_mfa(shop: &Shop, pat: &Person, answer: Call) {
    let completed = pat.client().send::<AppSignedIn>(answer).await.ok();
    assert!(
        completed.signed_in,
        "Pat's own browser finishes the sign-in"
    );
    pat.client()
        .get::<IgnoredAny>(&shop.page("/account/orders"))
        .await
        .ok();
    asserted_as(&shop.app, pat.id());
}
