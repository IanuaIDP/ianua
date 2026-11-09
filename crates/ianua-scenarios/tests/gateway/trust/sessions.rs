//! What Mallory brings instead of a session: a cookie she made up, a real
//! one she altered, one from another tenant's app, two at once, a token
//! she signed with nothing, and a real token with its signature changed.
//! Each is refused before the app sees anything.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_scenarios::actors::Person;
use ianua_scenarios::expect::{Matrix, Records};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::World;

use crate::support::{
    HostedApp, Shop, ShopOwner, api_token, app_host, customer, last_caller, profile, signed_in_at,
    signed_in_on, twin_customer, word,
};

/// The cookie an app session is kept in.
const SESSION_COOKIE: &str = "__Host-ianua_app";

/// The page every step reads.
const ACCOUNT_PAGE: &str = "/vault/account";

/// Pat is signed in on the vault app. Mallory, with a browser of her own,
/// brings a session cookie she made up, then Pat's real cookie with its
/// signature changed, then a cookie Rita holds at another tenant's shop:
/// each is told to sign in, the app seeing nothing, and the gateway records
/// the first as an invalid credential. Pat's own cookie still works, so
/// none of it harmed her.
#[tokio::test]
async fn a_made_up_altered_or_foreign_session_cookie_lets_nobody_in() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = vault_app(&world).await;
    let app = opened_vault(&world, &echo).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_on(&app.host, &pat).await;
    let foreign = foreign_cookie(&world).await;
    let mallory = Client::new(&stack, "Mallory, with cookies of her own").expect("a client");
    let page = app.page(ACCOUNT_PAGE);
    let real = session_value(&pat, &page);
    echo.forget();

    for (what, value) in [
        ("a made-up cookie", "not-a-session-anyone-issued".to_owned()),
        ("an altered cookie", altered(&real)),
        ("another tenant's cookie", foreign),
    ] {
        Matrix::new(what, with_cookie(&page, &value))
            .refused(&mallory, Status::UNAUTHORIZED, "unauthenticated")
            .run()
            .await;
    }
    assert!(
        echo.arrivals().is_empty(),
        "nothing of Mallory's got through"
    );
    let refused = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(ACCOUNT_PAGE, "the made-up cookie's refused", |record| {
            record.reason.as_deref() == Some("credential_invalid")
        })
        .await;
    assert_eq!(refused.decision, "refused", "the record says refused");
    assert_eq!(
        refused.subject.kind, "anonymous",
        "the cookie proved nobody"
    );

    Matrix::new("reading Pat's account", Call::get(page.as_str()))
        .allowed(pat.client())
        .run()
        .await;
    assert_eq!(last_caller(&echo).sub, pat.id(), "Pat goes on as herself");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory sends two session cookies at once, hoping the gateway reads
/// one and the app the other. The gateway will not pick between them and
/// refuses the request as malformed, the app seeing nothing, even though
/// one of the two is Pat's real cookie.
#[tokio::test]
async fn two_session_cookies_at_once_are_refused_as_malformed() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = vault_app(&world).await;
    let app = opened_vault(&world, &echo).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_on(&app.host, &pat).await;
    let page = app.page(ACCOUNT_PAGE);
    let real = session_value(&pat, &page);
    let mallory = Client::new(&stack, "Mallory, with two cookies").expect("a client");
    echo.forget();

    Matrix::new(
        "sending two session cookies",
        Call::get(page.as_str()).header(
            "cookie",
            &format!("{SESSION_COOKIE}=forged-value; {SESSION_COOKIE}={real}"),
        ),
    )
    .refused(&mallory, Status::BAD_REQUEST, "bad_request")
    .run()
    .await;
    assert!(echo.arrivals().is_empty(), "the app saw nothing");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's page fetches a real token for the shop's API. Mallory rewrites
/// its header to say it is signed with nothing, keeping everything it
/// claims, and separately changes its signature. Both are told to sign
/// in, the API seeing nothing, and the gateway records an invalid
/// credential. The real token still reaches the API.
#[tokio::test]
async fn a_token_signed_with_nothing_or_altered_reaches_nothing() {
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
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_at(&shop, &pat).await;
    let token = api_token(&shop, &pat).await;
    let mallory = Client::new(&stack, "Mallory, with forged tokens").expect("a client");
    let orders = shop.endpoint("/orders/9");
    shop.api.forget();

    for (what, forged) in [
        ("a token signed with nothing", unsigned(&token)),
        ("a token with its signature changed", altered(&token)),
    ] {
        Matrix::new(
            what,
            Call::get(orders.as_str()).header("authorization", &format!("Bearer {forged}")),
        )
        .refused(&mallory, Status::UNAUTHORIZED, "unauthenticated")
        .run()
        .await;
    }
    assert!(shop.api.arrivals().is_empty(), "the API saw nothing");
    let refused = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where("/orders/9", "a forged token's refused", |record| {
            record.decision == "refused"
        })
        .await;
    assert_eq!(
        refused.reason.as_deref(),
        Some("credential_invalid"),
        "the record says the credential was invalid"
    );
    Matrix::new(
        "reading orders with the real token",
        Call::get(orders.as_str()).header("authorization", &format!("Bearer {token}")),
    )
    .allowed(&mallory)
    .run()
    .await;
    assert_eq!(shop.api.arrivals().len(), 1, "the real token got through");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The vault app, its assertions checked against the tenant's keys.
async fn vault_app(world: &World<'_>) -> Echo {
    Echo::start(world.stack(), &app_host(world).await)
        .await
        .expect("the vault app starts")
}

/// Tess puts the vault app behind a signed-in route on its own host.
async fn opened_vault(world: &World<'_>, echo: &Echo) -> HostedApp {
    let spec = RouteSpec::public("vault", "/vault/*").asking(RoutePolicy::Authenticated);
    HostedApp::opened(world, "vault", spec, &echo.url()).await
}

/// A session cookie Rita holds at the twin tenant's shop, its value alone.
async fn foreign_cookie(world: &World<'_>) -> String {
    let shop = Shop::opened(
        world.stack(),
        &ShopOwner {
            tenant: world.twin(),
            admin: world.stranger().client(),
            word: &word(),
        },
    )
    .await;
    let rita = twin_customer(world, "rita", "Rita Elsewhere").await;
    signed_in_at(&shop, &rita).await;
    session_value(&rita, &shop.page("/account/orders"))
}

/// The value of the session cookie `person` holds for `page`.
fn session_value(person: &Person, page: &str) -> String {
    let cookies = person
        .client()
        .cookies_for(&page.parse().expect("the page is a URL"))
        .expect("the person holds the app's cookies");
    let wanted = format!("{SESSION_COOKIE}=");
    let found = cookies
        .split("; ")
        .find_map(|pair| pair.strip_prefix(wanted.as_str()));
    let Some(value) = found else {
        panic!("no session cookie among those held");
    };
    value.to_owned()
}

/// A request for `page` carrying `value` as the session cookie.
fn with_cookie(page: &str, value: &str) -> Call {
    Call::get(page).header("cookie", &format!("{SESSION_COOKIE}={value}"))
}

/// `credential` with the first letter of its signature changed to another
/// one that reads: every bit of that letter counts, as the last letter's
/// may not.
fn altered(credential: &str) -> String {
    let signature_at = credential.rfind('.').map_or(0, |dot| dot + 1);
    let (kept, signature) = credential.split_at(signature_at);
    let replaced = if signature.starts_with('A') { 'B' } else { 'A' };
    format!("{kept}{replaced}{}", &signature[1..])
}

/// `token` with its header rewritten to say it is signed with nothing and
/// its signature left off, everything it claims kept.
fn unsigned(token: &str) -> String {
    let Some((_, rest)) = token.split_once('.') else {
        panic!("the token is a compact JWT");
    };
    let Some((claims, _)) = rest.split_once('.') else {
        panic!("the token carries a signature");
    };
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    format!("{header}.{claims}.")
}
