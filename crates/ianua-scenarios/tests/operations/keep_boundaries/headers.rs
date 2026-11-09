//! What every answer tells the browser of a visitor that receives it: to
//! keep to HTTPS, never to guess what an answer is, never to show it
//! inside another site's frame, never to pass the address on, and never
//! to keep an answer that may hold an account's data.

use ianua_scenarios::api::{OrgPath, members, sessions};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Answer;
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use serde::de::IgnoredAny;

/// A year, the shortest a browser should hold to HTTPS for the platform.
const A_YEAR_OF_SECONDS: u64 = 365 * 24 * 60 * 60;

/// An address nobody holds, for a sign-in that is refused.
const NOBODY: &str = "nobody@example.test";

/// The password tried at it: a sentence, so no scanner takes it for a
/// key.
const NOBODYS_PASSWORD: &str = "Not anybody's password at all 4127";

/// The headers every answer carries, whatever it answers a visitor: the
/// health check, a refusal of a caller who is not signed in, a refused
/// sign-in, and a path that never existed.
#[tokio::test]
async fn every_answer_carries_the_security_headers() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let visitor = Client::new(&stack, "a visitor").expect("a client");
    let calls = [
        ("the health check", Call::get("/health")),
        (
            "a refusal of nobody signed in",
            members::list(&OrgPath::new("acme"), None).call(),
        ),
        (
            "a refused sign-in",
            sessions::member_sign_in(&PasswordSignIn::of(NOBODY, NOBODYS_PASSWORD)).call(),
        ),
        (
            "a path that never existed",
            Call::get("/api/v1/never-existed"),
        ),
    ];

    for (what, call) in calls {
        let answer = visitor.send::<IgnoredAny>(call).await;
        security_headers_carried(what, &answer);
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// An answer about an account, a visitor's refused sign-in, is kept by no
/// cache on the way and by no browser.
#[tokio::test]
async fn an_answer_about_an_account_is_never_kept() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let visitor = Client::new(&stack, "a visitor").expect("a client");

    let answer = sessions::member_sign_in(&PasswordSignIn::of(NOBODY, NOBODYS_PASSWORD))
        .send(&visitor)
        .await;
    let caching = answer.header("cache-control").unwrap_or_default();
    assert!(
        caching.contains("no-store"),
        "a sign-in's answer is never kept: {caching:?}"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Asserts `answer`, to `what`, carries every security header.
fn security_headers_carried<T>(what: &str, answer: &Answer<T>) {
    let header = |name: &str| answer.header(name).unwrap_or_default().to_ascii_lowercase();

    let transport = header("strict-transport-security");
    let held = transport
        .split(';')
        .find_map(|part| part.trim().strip_prefix("max-age="))
        .and_then(|seconds| seconds.parse::<u64>().ok());
    assert!(
        held.is_some_and(|seconds| seconds >= A_YEAR_OF_SECONDS),
        "{what}: browsers hold to HTTPS for a year: {transport:?}"
    );
    assert!(
        transport.contains("includesubdomains"),
        "{what}: and for every name under the platform's: {transport:?}"
    );
    assert_eq!(
        header("x-content-type-options"),
        "nosniff",
        "{what}: no browser guesses what the answer is"
    );
    let framing = header("x-frame-options");
    let policy = header("content-security-policy");
    assert!(
        framing == "deny" || policy.contains("frame-ancestors 'none'"),
        "{what}: no other site shows it in a frame: {framing:?} {policy:?}"
    );
    assert_eq!(
        header("referrer-policy"),
        "no-referrer",
        "{what}: no address is passed on from it"
    );
}
