//! Arbitrary HTTP requests at the real router, signed in.
//!
//! The unauthenticated target next door never gets past the door, and that is
//! not a shortcoming of it but a fact about axum: a handler's arguments are
//! extracted in order, `Scope` comes before `Json`, so an anonymous request to
//! an authenticated endpoint is refused before its body is ever read. Every
//! interesting parser — the DTOs, the path and query extractors, the
//! use cases behind them — sits on the far side of that refusal.
//!
//! So this one signs in first. The caller is the ordinary owner the rest of
//! the suite uses, which means 2xx is an expected answer here and the
//! invariants are the two that hold whatever the answer:
//!
//! **Nothing reaches a 5xx.** Now that requests get as far as parsing bodies,
//! resolving ids and calling use cases, this is the question with teeth: a
//! malformed UUID, a timestamp that ends mid-digit, a JSON number where a
//! string belongs, a YAML document nested a thousand deep. Each should be a
//! 4xx naming the field, not a 500.
//!
//! **No error says how it broke.** Same reasoning as the anonymous target,
//! but reached through code that actually touched a store.

#![no_main]

use std::sync::OnceLock;

use axum::Router;
use axum::body::Body;
use http::{Method, Request, StatusCode};
use libfuzzer_sys::fuzz_target;
use tower::ServiceExt;

/// Words that only appear in a message the outside was never meant to read.
const INTERNAL_MARKERS: &[&str] = &[
    "postgres", "sqlx", "panicked", "/users/", "src/", ".rs:", "backtrace",
];

/// One request, parsed from the wire form: a request line, headers, a body.
struct Wire<'a> {
    method: &'a str,
    path: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    body: &'a [u8],
}

/// Reads the text form, and gives up rather than guessing.
fn parse(data: &[u8]) -> Option<Wire<'_>> {
    let text = std::str::from_utf8(data).ok()?;
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));

    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?;
    let path = request_line.next()?;

    if method.is_empty() || path.is_empty() {
        return None;
    }

    let headers = lines
        .filter_map(|line| line.split_once(": "))
        .collect::<Vec<_>>();

    Some(Wire {
        method,
        path,
        headers,
        body: body.as_bytes(),
    })
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
    })
}

/// Seeded once, and signed in as the owner of the seeded organization.
///
/// State accumulates across iterations — every agent the fuzzer manages to
/// create is still there for the next one — which is welcome: a store with
/// things in it exercises more than an empty one.
fn router() -> &'static Router {
    static ROUTER: OnceLock<Router> = OnceLock::new();
    ROUTER.get_or_init(|| {
        runtime().block_on(async {
            ianua_api::test_support::TestWorld::setup()
                .await
                .authenticated_router()
        })
    })
}

fuzz_target!(|data: &[u8]| {
    let Some(wire) = parse(data) else {
        return;
    };
    let Ok(method) = Method::from_bytes(wire.method.as_bytes()) else {
        return;
    };

    let mut builder = Request::builder().method(method).uri(wire.path);
    for (name, value) in &wire.headers {
        builder = builder.header(*name, *value);
    }

    let Ok(request) = builder.body(Body::from(wire.body.to_vec())) else {
        return;
    };

    // Outside `block_on`: seeding the world is itself async, and starting
    // that runtime from inside this one is not allowed.
    let router = router().clone();

    let response = runtime().block_on(async move {
        router
            .oneshot(request)
            .await
            .expect("the router is infallible")
    });

    let status = response.status();
    assert!(
        status != StatusCode::INTERNAL_SERVER_ERROR,
        "a request a signed-in caller can send reached a 500: {} {}",
        status,
        wire.path
    );

    let body = runtime().block_on(async move {
        axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap_or_default()
    });
    let Ok(text) = std::str::from_utf8(&body) else {
        return;
    };
    let lowered = text.to_ascii_lowercase();

    for marker in INTERNAL_MARKERS {
        assert!(
            !lowered.contains(marker),
            "the response to {} names {marker:?}, which is inside talk: {text}",
            wire.path
        );
    }
});
