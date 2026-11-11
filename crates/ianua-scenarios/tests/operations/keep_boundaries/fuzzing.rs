//! Mallory, holding Tess's administrator session, throws hostile input at
//! every endpoint the platform's own API description lists: each request
//! body filled with null characters, enormous text, extreme numbers and
//! long lists, and every path id replaced by something no id looks like.
//! However wrong the input, the answer is a refusal or a success, never a
//! server error, and nothing takes longer than a person would wait.
//!
//! Requests that would end Tess's own session or remove the company are
//! left out, so the sweep keeps reaching everything else.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use ianua_scenarios::api::{members, organizations};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::PlanChoice;
use ianua_scenarios::world::World;
use reqwest::Method;
use serde::de::IgnoredAny;
use serde_json::{Map, Value, json};
use tokio::time::timeout;

/// Where the platform publishes its API description when asked to.
const DESCRIPTION: &str = "/api/v1/docs/openapi.json";

/// A path id that names nothing.
const NO_SUCH_ID: &str = "7f1c2b9e-4d3a-4c5b-9e8f-0a1b2c3d4e5f";

/// What a path id is replaced with: null characters, a climb out of the
/// path, an id far too long, a reversing mark and a quote.
const HOSTILE_IDS: [&str; 5] = [
    "%00",
    "..%2F..%2F",
    "999999999999999999999999999999",
    "%E2%80%AE",
    "%27",
];

/// Paths whose requests would end Tess's session, change how she signs in,
/// or remove the company, which would stop the sweep reaching the rest.
const LEFT_OUT: [&str; 14] = [
    "/ws/",
    "sign-out",
    "logout",
    "/sessions",
    "password",
    "/email",
    "factors",
    "erasure",
    "suspend",
    "/delete",
    "/close",
    "/leave",
    "ownership",
    "/passkeys",
];

/// The longest any answer may take.
const PATIENCE: Duration = Duration::from_secs(10);

/// How long the sweep waits for one answer before it counts the request
/// as hanging and goes on.
const GIVEN_UP_AFTER: Duration = Duration::from_secs(30);

/// How the hostile values are chosen.
#[derive(Clone, Copy, Debug)]
enum Hostility {
    /// Null characters in text, negative numbers.
    NullCharacters,
    /// Text of a fifth of a megabyte, the largest numbers JSON writes.
    Enormous,
    /// Templates, quotes and markup in text, the smallest integers, long
    /// lists.
    Tricky,
}

/// One answer that broke a promise.
struct Broken {
    what: String,
    why: String,
}

/// What one sweep came to.
struct Sweep {
    /// How many requests it sent.
    tried: usize,
    /// How many met the rate limit instead of their endpoint.
    slowed: usize,
    /// The answers that broke a promise.
    broken: Vec<Broken>,
}

impl Sweep {
    /// Fails the scenario unless the sweep reached the API, met no rate
    /// limit and broke nothing.
    fn held(&self) {
        let mut report = String::new();
        for found in &self.broken {
            let _ = writeln!(report, "{}: {}", found.what, found.why);
        }
        let tried = self.tried;
        assert!(tried > 1_000, "the sweep reached the API: {tried} requests");
        assert_eq!(self.slowed, 0, "every request reached its endpoint");
        assert!(
            self.broken.is_empty(),
            "{} of {tried} broke:\n{report}",
            self.broken.len()
        );
    }
}

/// Ann starts her company's Business trial, whose budget of ten thousand
/// requests a minute the sweep stays far under. With Tess's session,
/// every endpoint the description lists gets each kind of hostile body,
/// and every endpoint with an id in its path gets each hostile id. No
/// answer is a server error or slower than ten seconds, and Tess is still
/// signed in at the end.
#[tokio::test]
async fn no_hostile_input_from_tess_breaks_the_platform() {
    let stack = Stack::start(fuzzed()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let business = PlanChoice {
        plan: "Business".to_owned(),
    };
    organizations::choose_plan(world.org(), &business)
        .send(world.owner().client())
        .await
        .ok();

    let sweep = swept(&world, tess).await;

    members::me(world.org()).send(tess).await.ok();
    sweep.held();
    stack.stop().await.expect("the stack stops cleanly");
}

/// The same sweep from someone signed in nowhere, as anyone on the
/// internet: the public doors take the hostile input, the others turn it
/// away, and none of them breaks.
#[tokio::test]
async fn no_hostile_input_from_a_stranger_breaks_the_platform() {
    let stack = Stack::start(fuzzed()).await.expect("the stack starts");
    let world = World::new(&stack).await;

    let sweep = swept(&world, world.anonymous().client()).await;

    sweep.held();
    stack.stop().await.expect("the stack stops cleanly");
}

/// The deployment the sweeps run against: its API description published,
/// its per-address and per-person limits lifted, and a plan's limit read
/// again within a second, so the sweep meets endpoints rather than limits.
fn fuzzed() -> Profile {
    Profile::standard()
        .with("ENABLE_API_DOCS", "true")
        .with("RATE_LIMIT_CACHE_SECONDS", "1")
        .with("RATE_LIMIT_DEFAULT_PER_MINUTE", "1000000")
        .with("RATE_LIMIT_SENSITIVE_PER_WINDOW", "100000")
        .with("RATE_LIMIT_USER_PER_WINDOW", "100000")
        .with("RATE_LIMIT_LOGIN_PER_MINUTE", "100000")
        .with("RATE_LIMIT_SSO_PER_WINDOW", "100000")
        .with("WEBHOOK_SENDS_PER_WINDOW", "10000")
        .with("SIGNAL_VERIFICATIONS_PER_WINDOW", "10000")
}

/// Sends every hostile request the description makes possible as
/// `client`, each as soon as the one before is answered.
async fn swept(world: &World<'_>, client: &Client) -> Sweep {
    let description: Value = world
        .admin()
        .client()
        .send(Call::get(DESCRIPTION))
        .await
        .ok();
    let schemas = description["components"]["schemas"].clone();
    let slugs = Slugs {
        org: world.org().slug().to_owned(),
        tenant: world.tenant().slug().to_owned(),
    };
    let mut sweep = Vec::new();
    for (path, operations) in endpoints(&description) {
        for (method, operation) in operations {
            if left_out(&path, &method) {
                continue;
            }
            let endpoint = Endpoint {
                path: &path,
                method: &method,
                operation,
            };
            sweep.extend(calls(&endpoint, &schemas, &slugs));
        }
    }
    let tried = sweep.len();
    tracing::info!(requests = tried, "the sweep starts");
    let slowed = AtomicUsize::new(0);
    let mut broken = Vec::new();
    for (what, call) in sweep {
        broken.extend(answered(client, what, call, &slowed).await);
    }
    let slowed = slowed.into_inner();
    tracing::info!(slowed, "the sweep ends");
    Sweep {
        tried,
        slowed,
        broken,
    }
}

/// Mallory sends two dozen bodies past the size limit at once while Tess
/// reads her own record beside them. Every oversized body is refused as
/// too large and every read is served: nobody's request is dropped
/// unanswered because a refused body left its connection broken.
#[tokio::test]
async fn oversized_bodies_sent_at_once_are_refused_and_drop_nobody() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let oversized = json!({ "name": "a".repeat(2 * 1024 * 1024) });
    let group = world.tenant().at("/authorization/groups");

    let sent = (0..24).map(|at| {
        let call = match at % 2 {
            0 => Call::post(group.as_str()).json(&oversized),
            _ => members::me(world.org()).call(),
        };
        tess.attempt::<IgnoredAny>(call)
    });
    let answers = futures_util::future::join_all(sent).await;

    let unanswered: Vec<String> = answers
        .iter()
        .filter_map(|answer| match answer {
            Err(failed) => Some(failed.clone()),
            Ok(answer) if answer.status().is_server_error() => Some(answer.summary()),
            Ok(_) => None,
        })
        .collect();
    assert!(
        unanswered.is_empty(),
        "{} dropped: {unanswered:#?}",
        unanswered.len()
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory sends three hundred large bodies, eight at once, well past the
/// company's two hundred a minute. Each is taken, refused as too many, or
/// refused as too large: none is dropped unanswered because a refusal left
/// its connection broken for the next request.
#[tokio::test]
async fn large_bodies_past_the_rate_limit_are_refused_and_drop_nobody() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let large = json!({ "name": "a".repeat(600 * 1024) });
    let group = world.tenant().at("/authorization/groups");

    let answers: Vec<_> = futures_util::stream::iter(0..300)
        .map(|_| tess.attempt::<IgnoredAny>(Call::post(group.as_str()).json(&large)))
        .buffer_unordered(8)
        .collect()
        .await;

    let dropped: Vec<String> = answers
        .iter()
        .filter_map(|answer| match answer {
            Err(failed) => Some(failed.clone()),
            Ok(answer) if answer.status().is_server_error() => Some(answer.summary()),
            Ok(_) => None,
        })
        .collect();
    let slowed = answers
        .iter()
        .filter(|answer| {
            answer
                .as_ref()
                .is_ok_and(|answer| answer.status() == Status::TOO_MANY_REQUESTS)
        })
        .count();
    assert!(slowed > 0, "the rate limit was reached");
    assert!(
        dropped.is_empty(),
        "{} of 300 dropped: {:#?}",
        dropped.len(),
        &dropped[..dropped.len().min(3)]
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory, signed in nowhere, posts bodies from a few kilobytes to four
/// times the size limit to an operator's door, five times each. The door
/// turns every one away with an answer, however much of the body was still
/// on its way: none is dropped unanswered.
#[tokio::test]
async fn a_large_body_turned_away_unread_is_still_answered() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mallory = world.anonymous().client();
    let door = format!("/api/v1/operators/{NO_SUCH_ID}/grants");

    let mut dropped = Vec::new();
    for size in [4 * 1024, 256 * 1024, 1000 * 1024, 2048 * 1024, 4096 * 1024] {
        for _ in 0..5 {
            let body = json!({ "role": "a".repeat(size) });
            let answer = mallory
                .attempt::<IgnoredAny>(Call::post(door.as_str()).json(&body))
                .await;
            match answer {
                Err(failed) => dropped.push(format!("{size} bytes: {failed}")),
                Ok(answer) if answer.status().is_server_error() => {
                    dropped.push(format!("{size} bytes: {}", answer.summary()));
                }
                Ok(_) => {}
            }
        }
    }

    assert!(
        dropped.is_empty(),
        "{} of 25 dropped: {dropped:#?}",
        dropped.len()
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The organization and tenant the paths are filled with.
struct Slugs {
    org: String,
    tenant: String,
}

/// Every path the description lists with its operations, in order.
fn endpoints(description: &Value) -> Vec<(String, Vec<(Method, &Value)>)> {
    let Some(paths) = description["paths"].as_object() else {
        panic!("the description lists paths");
    };
    paths
        .iter()
        .map(|(path, item)| {
            let operations = [
                ("get", Method::GET),
                ("post", Method::POST),
                ("put", Method::PUT),
                ("patch", Method::PATCH),
                ("delete", Method::DELETE),
            ]
            .into_iter()
            .filter_map(|(name, method)| item.get(name).map(|operation| (method, operation)))
            .collect();
            (path.clone(), operations)
        })
        .collect()
}

/// Whether the sweep leaves `method` on `path` alone: one that ends
/// Tess's session or removes the company, or a delete naming nothing but
/// the company and the tenant.
fn left_out(path: &str, method: &Method) -> bool {
    if LEFT_OUT.iter().any(|part| path.contains(part)) {
        return true;
    }
    let names_more = path
        .split('/')
        .any(|part| part.starts_with('{') && !part.contains("slug"));
    *method == Method::DELETE && !names_more
}

/// One operation the description lists: the method on the path, and what
/// the description says of it.
struct Endpoint<'a> {
    path: &'a str,
    method: &'a Method,
    operation: &'a Value,
}

/// The hostile calls for `endpoint`, each with what it is: one per kind of
/// hostile body when it takes one, and one per hostile id when its path
/// names one.
fn calls(endpoint: &Endpoint<'_>, schemas: &Value, slugs: &Slugs) -> Vec<(String, Call)> {
    let Endpoint {
        path,
        method,
        operation,
    } = *endpoint;
    let mut calls = Vec::new();
    let body = operation["requestBody"]["content"]["application/json"]["schema"].clone();
    if !body.is_null() {
        let at = filled(path, slugs, NO_SUCH_ID);
        for hostility in [
            Hostility::NullCharacters,
            Hostility::Enormous,
            Hostility::Tricky,
        ] {
            let value = hostile(&body, schemas, hostility, 0);
            let what = format!("{method} {path} with a {hostility:?} body");
            calls.push((
                what,
                Call::with_method(method.clone(), at.clone()).json(&value),
            ));
        }
    }
    let names_an_id = path
        .split('/')
        .any(|part| part.starts_with('{') && !part.contains("slug"));
    if names_an_id && *method == Method::GET {
        for id in HOSTILE_IDS {
            let what = format!("{method} {path} with the id {id}");
            calls.push((
                what,
                Call::with_method(method.clone(), filled(path, slugs, id)),
            ));
        }
    }
    calls
}

/// `path` with the company and tenant filled in and every other id `id`.
fn filled(path: &str, slugs: &Slugs, id: &str) -> String {
    path.split('/')
        .map(|part| match part {
            "{org_slug}" => slugs.org.clone(),
            "{tenant_slug}" => slugs.tenant.clone(),
            other if other.starts_with('{') => id.to_owned(),
            other => other.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// A value for `schema` made `hostility`'s way, refs followed, nested at
/// most six deep.
fn hostile(schema: &Value, schemas: &Value, hostility: Hostility, depth: usize) -> Value {
    let schema = resolved(schema, schemas);
    if depth > 6 {
        return Value::Null;
    }
    if let Some(first) = schema["enum"].as_array().and_then(|values| values.first()) {
        return match hostility {
            Hostility::NullCharacters => json!("\u{0}"),
            Hostility::Enormous | Hostility::Tricky => first.clone(),
        };
    }
    match kind_of(schema) {
        "object" => object(schema, schemas, hostility, depth),
        "array" => array(schema, schemas, hostility, depth),
        "integer" => integer(hostility),
        "number" => number(hostility),
        "boolean" => json!(true),
        _ => text(schema, hostility),
    }
}

/// An object with every property made `hostility`'s way.
fn object(schema: &Value, schemas: &Value, hostility: Hostility, depth: usize) -> Value {
    let mut made = Map::new();
    if let Some(properties) = schema["properties"].as_object() {
        for (name, property) in properties {
            made.insert(
                name.clone(),
                hostile(property, schemas, hostility, depth + 1),
            );
        }
    }
    Value::Object(made)
}

/// A list of hostile items: one, or five hundred for the tricky kind at
/// the body's own level, so lists inside lists do not multiply.
fn array(schema: &Value, schemas: &Value, hostility: Hostility, depth: usize) -> Value {
    let item = hostile(&schema["items"], schemas, hostility, depth + 1);
    let count = match (hostility, depth) {
        (Hostility::Tricky, 0 | 1) => 500,
        _ => 1,
    };
    Value::Array(vec![item; count])
}

/// A hostile integer.
fn integer(hostility: Hostility) -> Value {
    match hostility {
        Hostility::NullCharacters => json!(-1),
        Hostility::Enormous => json!(u64::MAX),
        Hostility::Tricky => json!(i64::MIN),
    }
}

/// A hostile number.
fn number(hostility: Hostility) -> Value {
    match hostility {
        Hostility::NullCharacters => json!(-1.0e300),
        Hostility::Enormous => json!(1.0e308),
        Hostility::Tricky => json!(0.0),
    }
}

/// Hostile text, shaped like an id or a time when the schema asks so, so
/// the request gets past its first check.
fn text(schema: &Value, hostility: Hostility) -> Value {
    let format = schema["format"].as_str().unwrap_or_default();
    match (format, hostility) {
        ("uuid", Hostility::NullCharacters) => json!("\u{0}"),
        ("uuid", _) => json!(NO_SUCH_ID),
        ("date-time", Hostility::Enormous) => json!("9999-12-31T23:59:59Z"),
        ("date-time", _) => json!("0001-01-01T00:00:00Z"),
        (_, Hostility::NullCharacters) => json!("Night\u{0}shift"),
        (_, Hostility::Enormous) => json!("a".repeat(200_000)),
        (_, Hostility::Tricky) => json!("{{ secrets }} '\"; <x> ../../ \u{202e} ${HOME}"),
    }
}

/// `schema` with its ref followed, and the first branch of a choice taken.
fn resolved<'a>(schema: &'a Value, schemas: &'a Value) -> &'a Value {
    if let Some(name) = schema["$ref"].as_str().and_then(|r| r.rsplit('/').next()) {
        return resolved(&schemas[name], schemas);
    }
    for choice in ["allOf", "oneOf", "anyOf"] {
        if let Some(first) = schema[choice].as_array().and_then(|branches| {
            branches
                .iter()
                .find(|branch| branch.get("type").and_then(Value::as_str) != Some("null"))
        }) {
            return resolved(first, schemas);
        }
    }
    schema
}

/// The schema's type, the first that is not null when it names several.
fn kind_of(schema: &Value) -> &str {
    match &schema["type"] {
        Value::String(kind) => kind,
        Value::Array(kinds) => kinds
            .iter()
            .filter_map(Value::as_str)
            .find(|kind| *kind != "null")
            .unwrap_or("string"),
        _ if schema.get("properties").is_some() => "object",
        _ => "string",
    }
}

/// What broke when `client` sent `call`, described as `what`: a server
/// error, or an answer slower than [`PATIENCE`]. A refusal to go faster
/// is counted in `slowed`, since it reached no endpoint.
async fn answered(
    client: &Client,
    what: String,
    call: Call,
    slowed: &AtomicUsize,
) -> Option<Broken> {
    let started = Instant::now();
    let answer = timeout(GIVEN_UP_AFTER, client.attempt::<IgnoredAny>(call)).await;
    let took = started.elapsed();
    if let Ok(Ok(refused)) = &answer
        && refused.status() == Status::TOO_MANY_REQUESTS
    {
        slowed.fetch_add(1, Ordering::Relaxed);
    }
    let why = match answer {
        Err(_) => Some(format!("no answer within {GIVEN_UP_AFTER:?}")),
        Ok(Err(failed)) => Some(format!("no answer: {failed}")),
        Ok(Ok(answer)) if answer.status().is_server_error() => Some(answer.summary()),
        Ok(Ok(_)) if took > PATIENCE => Some(format!("took {took:?}")),
        Ok(Ok(_)) => None,
    }?;
    tracing::warn!(%what, %why, "a hostile request broke a promise");
    Some(Broken { what, why })
}
