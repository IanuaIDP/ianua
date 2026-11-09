//! What Mallory learns by probing the front door with requests no client
//! sends: paths dressed to reach the internal doors, methods nobody uses,
//! and error answers read for what they give away. Each is refused as any
//! unknown request is, none is a server error, and no answer names the
//! software, a file, a query or a stack behind it.

use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::{Answer, Status};
use reqwest::Method;
use serde::de::IgnoredAny;
use serde_json::json;

/// Paths that dress an internal door up as a public one: an encoded slash,
/// an encoded parent step, and the door's name in a different case. A
/// client resolves a plain `..` before sending, so only these reach the
/// platform as written.
const DRESSED_PATHS: [&str; 6] = [
    "/internal%2Fapp-sign-in",
    "/api/v1/..%2Finternal/app-sign-in",
    "/api/v1/%2e%2e%2Finternal/agent-approvals",
    "/INTERNAL/app-sign-in",
    "/health%2Fready",
    "/api/v1/organizations/%2E%2E%2F%2E%2E%2Fmetrics",
];

/// Words that would tell Mallory what runs behind an answer, in any case.
const GIVEAWAYS: [&str; 10] = [
    "panicked",
    "stack backtrace",
    "src/",
    ".rs:",
    "sqlx",
    "postgres",
    "select ",
    "tokio",
    "axum",
    "hyper",
];

/// A marker Mallory puts in a header, to see whether any answer echoes
/// her request back.
const ECHO_MARKER: &str = "marker-4127";

/// A password Mallory tries at an address nobody holds: a sentence, so no
/// scanner takes it for a key.
const NOBODYS_PASSWORD: &str = "Not anybody's password at all 4127";

/// Mallory dresses the internal doors up with encoded slashes, encoded
/// parent steps and a different case. Each is refused as a path that
/// never existed is, or, where the dressed path reads as a name in a
/// public address that needs a caller (an organization named
/// `../../metrics`), as unauthenticated; none reaches a door.
#[tokio::test]
async fn a_dressed_up_path_reaches_no_internal_door() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mallory = Client::new(&stack, "Mallory, dressing paths up").expect("a client");

    for path in DRESSED_PATHS {
        for call in [Call::get(path), Call::post(path).json(&json!({}))] {
            let answer = mallory.send::<IgnoredAny>(call).await;
            assert!(
                matches!(
                    answer.status(),
                    Status::BAD_REQUEST
                        | Status::UNAUTHORIZED
                        | Status::NOT_FOUND
                        | Status::METHOD_NOT_ALLOWED
                ),
                "{path} is refused as no door: {}",
                answer.summary()
            );
            gives_nothing_away(path, &answer);
        }
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory sends methods no client of the platform uses: `TRACE`, which
/// would echo her request back with its headers, a WebDAV method, and a
/// method she made up. Each is refused, none echoes what she sent, and
/// none is a server error.
#[tokio::test]
async fn a_method_nobody_uses_is_refused_and_echoes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mallory = Client::new(&stack, "Mallory, trying methods").expect("a client");
    let methods = [
        Method::TRACE,
        Method::from_bytes(b"PROPFIND").expect("a method"),
        Method::from_bytes(b"MALLORY").expect("a method"),
    ];

    for method in methods {
        for path in ["/health", "/api/v1/login"] {
            let what = format!("{method} {path}");
            let call = Call::with_method(method.clone(), path).header("x-echo-me", ECHO_MARKER);
            let answer = mallory.send::<IgnoredAny>(call).await;
            assert_method_refusal(&what, &answer);
        }
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// An unsupported method gets a clean refusal without echoing the marked header.
fn assert_method_refusal(what: &str, answer: &Answer<IgnoredAny>) {
    assert!(
        matches!(
            answer.status(),
            Status::BAD_REQUEST
                | Status::NOT_FOUND
                | Status::METHOD_NOT_ALLOWED
                | Status::NOT_IMPLEMENTED
        ),
        "{what} is refused: {}",
        answer.summary()
    );
    assert!(
        !answer.exchange().response_body().contains(ECHO_MARKER),
        "{what} echoes nothing Mallory sent"
    );
    gives_nothing_away(what, answer);
}

/// Mallory puts a script in the address and in a query. The refusal is
/// JSON the browser may not guess at, and never her script as she wrote
/// it, so a page showing the answer cannot run it.
#[tokio::test]
async fn a_script_in_the_address_comes_back_as_nothing_a_browser_runs() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mallory = Client::new(&stack, "Mallory, with a script").expect("a client");
    let script = "<script>alert(1)</script>";
    let paths = [
        format!("/api/v1/{}", percent_encoded(script)),
        format!("/api/v1/organizations?q={}", percent_encoded(script)),
    ];

    for path in paths {
        let answer = mallory.send::<IgnoredAny>(Call::get(&path)).await;
        assert_script_refusal(&path, script, &answer);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Refused script probes remain non-sniffable JSON without the script text.
fn assert_script_refusal(path: &str, script: &str, answer: &Answer<IgnoredAny>) {
    assert!(
        answer.status().is_client_error(),
        "{path} is refused: {}",
        answer.summary()
    );
    let kind = answer.header("content-type").unwrap_or_default();
    assert!(
        kind.starts_with("application/json") || kind.starts_with("application/problem+json"),
        "{path} is answered as JSON, not a page: {kind:?}"
    );
    assert_eq!(
        answer.header("x-content-type-options"),
        Some("nosniff"),
        "{path}: no browser guesses it is a page"
    );
    assert!(
        !answer.exchange().response_body().contains(script),
        "{path}: the script never comes back as written"
    );
}

/// Every refusal Mallory can provoke before signing in names no software,
/// version, file, query or stack: the headers carry no `Server` version
/// or `X-Powered-By`, and the body no word of what runs behind it.
#[tokio::test]
async fn no_refusal_tells_what_runs_behind_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mallory = Client::new(&stack, "Mallory, reading refusals").expect("a client");
    for (what, call) in private_error_probes() {
        let answer = mallory.send::<IgnoredAny>(call).await;
        assert!(
            answer.status().is_client_error(),
            "{what} is refused, not a server error: {}",
            answer.summary()
        );
        gives_nothing_away(what, &answer);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Malformed requests exercise paths, identifiers, body shapes and query parsing.
fn private_error_probes() -> [(&'static str, Call); 5] {
    [
        (
            "a path that never existed",
            Call::get("/api/v1/never-existed"),
        ),
        (
            "an id that is no id",
            Call::get("/api/v1/organizations/acme/tenants/not-a-uuid/users/x"),
        ),
        (
            "a body of the wrong shape",
            Call::post("/api/v1/login").json(&json!({"email": 7, "password": []})),
        ),
        (
            "a sign-in with a field nobody reads",
            Call::post("/api/v1/login").json(&json!({
                "email": "nobody@example.test",
                "password": NOBODYS_PASSWORD,
                "is_admin": true,
            })),
        ),
        (
            "a query of the wrong shape",
            Call::get("/api/v1/organizations/acme/users?limit=lots&cursor=%00"),
        ),
    ]
}

/// Asserts `answer`, to `what`, names no software behind it.
fn gives_nothing_away<T>(what: &str, answer: &Answer<T>) {
    assert_eq!(
        answer.header("x-powered-by"),
        None,
        "{what}: no X-Powered-By"
    );
    let server = answer.header("server").unwrap_or_default();
    assert!(
        !server.chars().any(|letter| letter.is_ascii_digit()),
        "{what}: the Server header names no version: {server:?}"
    );
    let body = answer.exchange().response_body().to_ascii_lowercase();
    for word in GIVEAWAYS {
        assert!(
            !body.contains(word),
            "{what}: the body says {word:?}: {body}"
        );
    }
}

/// `text` percent-encoded for a path segment or a query value.
fn percent_encoded(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}
