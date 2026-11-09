//! What Mallory finds at the front door before signing in: the internal
//! doors are not there, the relay listener takes nobody without a
//! certificate and answers nobody without its key, a broken or oversized body is refused with a proper problem and
//! harms nothing, and a foreign site's script in Ann's browser is not let
//! in.

use ianua_scenarios::api::sessions;
use ianua_scenarios::expect::assert_clean_refusal;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Presenting, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use serde::de::IgnoredAny;
use serde_json::{Value, json};

/// The doors only the internal and relay listeners have: the probes, the
/// scrape and the gateway's relays.
const INTERNAL_DOORS: [(&str, &str); 5] = [
    ("GET", "/health/ready"),
    ("GET", "/health/live"),
    ("GET", "/metrics"),
    ("POST", "/internal/app-sign-in"),
    ("POST", "/internal/agent-approvals"),
];

/// A site that is not the dashboard.
const FOREIGN_ORIGIN: &str = "https://evil.example";

/// The header a relayed question carries its seal in.
const SEAL_HEADER: &str = "x-ianua-seal";

/// A password the foreign page guesses at Ann's address: a sentence, so
/// no scanner takes it for a key.
const FOREIGN_GUESS: &str = "Not anybody's password at all 4127";

/// Mallory looks for the internal doors on the public address: none is
/// there, and each answers exactly as a path that never existed does, so
/// the answer tells her nothing.
#[tokio::test]
async fn the_internal_doors_are_not_on_the_public_address() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mallory = Client::new(&stack, "Mallory, probing").expect("a client");

    let never_existed = mallory
        .send::<IgnoredAny>(Call::get("/api/v1/never-existed"))
        .await;
    assert_eq!(
        never_existed.status(),
        Status::NOT_FOUND,
        "an unknown path is not found"
    );

    for (method, path) in INTERNAL_DOORS {
        let call = match method {
            "POST" => Call::post(path).json(&json!({})),
            _ => Call::get(path),
        };
        let answer = mallory.send::<IgnoredAny>(call).await;
        assert_eq!(
            answer.status(),
            never_existed.status(),
            "{method} {path} on the public address answers as no door: {}",
            answer.summary()
        );
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// How a relay says no.
#[derive(Debug, Clone, Copy)]
enum RelayRefusal {
    /// With a refusing status, as the app sign-in relay does.
    Status,
    /// With `Status::OK` and `{"result": "refused"}`, as the approval relay
    /// does for everything that fails, so the gateway learns no reason.
    RefusedResult,
}

/// The gateway's relays, and how each says no.
const RELAYS: [(&str, RelayRefusal); 2] = [
    ("/internal/app-sign-in", RelayRefusal::Status),
    ("/internal/agent-approvals", RelayRefusal::RefusedResult),
];

/// Mallory reaches the relay listener itself, as anyone on the internal
/// network could. Without a certificate of the internal authority she
/// gets no handshake, and nothing in the clear; the probes' listener has
/// no relay at all.
#[tokio::test]
async fn the_relay_listener_takes_nobody_without_a_certificate() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let stranger = stack.internal_client(Presenting::Nothing);
    let plain = reqwest::Client::new();

    for (path, _) in RELAYS {
        let body = r#"{"ctx":{},"fields":{}}"#;
        let relayed = format!("https://{}{path}", stack.api_relay());
        let in_clear = format!("http://{}{path}", stack.api_relay());
        let on_probes = format!("http://{}{path}", stack.internal_api());

        let without_certificate = stranger.post(&relayed).body(body).send().await;
        let unprotected = plain.post(&in_clear).body(body).send().await;
        let beside_the_probes = plain.post(&on_probes).body(body).send().await;

        assert!(
            without_certificate.is_err(),
            "POST {path} gets no handshake without a certificate"
        );
        assert!(
            unprotected.is_err(),
            "POST {path} gets no answer in the clear"
        );
        assert_eq!(
            beside_the_probes
                .expect("the probes' listener answers")
                .status(),
            reqwest::StatusCode::NOT_FOUND,
            "POST {path} is no door beside the probes"
        );
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory holds a certificate the relay takes, as a compromised worker
/// would, but no relay key: a relayed sign-in or approval with no seal,
/// or a made-up one, is refused.
#[tokio::test]
async fn the_internal_relays_answer_nobody_without_their_key() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let inside = stack.internal_client(Presenting::WorkersCertificate);
    let base = format!("https://{}", stack.api_relay());

    for (path, refusal) in RELAYS {
        for seal in [None, Some("t=1,v1=made-up")] {
            let mut request = inside
                .post(format!("{base}{path}"))
                .header("content-type", "application/json")
                .body(r#"{"ctx":{},"fields":{}}"#);
            if let Some(seal) = seal {
                request = request.header(SEAL_HEADER, seal);
            }
            let answer = request.send().await.expect("the relay listener answers");
            let what = format!("POST {path} with seal {seal:?}");
            refused_as(&what, refusal, answer).await;
        }
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Asserts `answer`, to `what`, is the refusal `refusal` describes.
async fn refused_as(what: &str, refusal: RelayRefusal, answer: reqwest::Response) {
    let status = answer.status();
    match refusal {
        RelayRefusal::Status => {
            assert!(status.is_client_error(), "{what} is refused, got {status}");
        }
        RelayRefusal::RefusedResult => {
            let body: Value = answer.json().await.expect("the answer is JSON");
            assert_eq!(
                body["result"], "refused",
                "{what} is refused, got {status} {body}"
            );
        }
    }
}

/// Mallory sends the sign-in what no client would: JSON cut off half way,
/// JSON nested ten thousand deep, a form instead of JSON, and a body past
/// the size the API takes. Each is refused with a problem body, none is a
/// server error, and the platform still answers afterwards.
#[tokio::test]
async fn a_broken_or_oversized_body_is_refused_and_harms_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mallory = Client::new(&stack, "Mallory, with broken bodies").expect("a client");
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    let oversized = format!(r#"{{"email":"{}"}}"#, "a".repeat(2 * 1024 * 1024));

    let attempts = [
        (
            "JSON cut off",
            "application/json",
            r#"{"email":"ann@"#.to_owned(),
        ),
        ("JSON nested ten thousand deep", "application/json", deep),
        (
            "a form, not JSON",
            "application/x-www-form-urlencoded",
            "email=a&password=b".to_owned(),
        ),
        ("a body of two megabytes", "application/json", oversized),
    ];
    for (what, content_type, text) in attempts {
        let answer = mallory
            .send::<IgnoredAny>(Call::post("/api/v1/login").raw(content_type, text))
            .await;
        assert_clean_refusal(what, &answer);
    }

    let health = mallory.get::<IgnoredAny>("/health").await;
    assert_eq!(health.status(), Status::OK, "the platform still answers");

    stack.stop().await.expect("the stack stops cleanly");
}

/// A page on a foreign site asks, through Ann's browser, whether it may
/// call the sign-in: the platform never says yes, neither to the browser's
/// preflight nor on the answer to a sign-in the page sends, so the page
/// cannot read what comes back.
#[tokio::test]
async fn a_foreign_site_is_never_allowed_across_origins() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let browser = Client::new(&stack, "Ann's browser on a foreign page").expect("a client");
    assert_foreign_preflight(&browser).await;
    let guess = PasswordSignIn::of("ann@example.test", FOREIGN_GUESS);
    let answer = sessions::member_sign_in(&guess)
        .header("origin", FOREIGN_ORIGIN)
        .send(&browser)
        .await;
    assert_eq!(
        answer.header("access-control-allow-origin"),
        None,
        "the answer allows no foreign origin"
    );
    assert_eq!(
        answer.header("access-control-allow-credentials"),
        None,
        "the answer offers a foreign origin no credentials"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The browser's preflight receives no permission for the foreign origin.
async fn assert_foreign_preflight(browser: &Client) {
    let preflight = browser
        .send::<IgnoredAny>(
            Call::options("/api/v1/login")
                .header("origin", FOREIGN_ORIGIN)
                .header("access-control-request-method", "POST")
                .header("access-control-request-headers", "content-type"),
        )
        .await;
    assert_eq!(
        preflight.header("access-control-allow-origin"),
        None,
        "the preflight allows no foreign origin"
    );
}
