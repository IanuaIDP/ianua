//! Arbitrary HTTP requests at the real router, unauthenticated.
//!
//! Two invariants, neither of which needs the request to be well-formed —
//! which is the point, because nothing makes a caller send a well-formed one.
//!
//! **Nothing malformed reaches a 5xx.** A 500 from a request anybody can send
//! is an unhandled error path: the difference between "that slug is too long"
//! and "the server fell over" is the difference between a 404 and an outage
//! somebody can cause on purpose. The rate limiter's deliberate 503 is the one
//! allowed 5xx, and it is allowed because failing closed without a client
//! address is the safe direction.
//!
//! **No error says how it broke.** An error body that names Postgres, `sqlx`,
//! or a source path hands a caller the shape of the inside. The existing
//! integration test checks a handful of routes; this checks whatever the
//! fuzzer can reach.
//!
//! The input is the request as text, rather than a derived `Arbitrary` struct,
//! so that a seed is a file anybody can read and write. Reaching a handler by
//! mutating bytes alone is hopeless — the fuzzer would have to guess a path
//! like `/api/v1/organizations/acme/tenants/acme-tenant/agents` — so the
//! corpus is what carries it past the router's matcher, and the corpus has to
//! be writable by hand for that.
//!
//! The seeds live in `fuzz/seeds/`, outside the corpus directory because the
//! corpus is generated and ignored while these are written by hand. Copy them
//! in before a run, and use the slugs the harness seeds (`acme`,
//! `acme-tenant`) or the request will stop at the router:
//!
//! ```sh
//! mkdir -p fuzz/corpus/api_request
//! cp fuzz/seeds/* fuzz/corpus/api_request/
//! cargo +nightly fuzz run api_request -- -max_total_time=300 -rss_limit_mb=4096
//! ```

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
///
/// Deliberately lenient about everything except the request line: a fuzzer
/// that had to produce a well-formed message would spend its budget on the
/// parser rather than on the router behind it.
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

/// Seeded once: the world is expensive to build and the invariants hold
/// whatever state earlier iterations left behind.
fn router() -> &'static Router {
    static ROUTER: OnceLock<Router> = OnceLock::new();
    ROUTER.get_or_init(|| {
        runtime().block_on(async {
            ianua_api::test_support::TestWorld::setup()
                .await
                .unauthenticated_router()
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
        "a request anybody can send reached a 500: {} {}",
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
