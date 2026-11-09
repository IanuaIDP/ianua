//! What the data protection scenarios share: the patient record the
//! records app serves, the rules Tess classifies its fields with, a
//! redaction stage as the API writes one, routes in front of the app, and
//! reading an answer through the gateway.

use ianua_scenarios::api::{Request, classification, routing};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::classification::{
    Classification, DataClass, NewClassificationRule, Redaction,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

/// The social security number on Pat's record.
pub(crate) const SSN: &str = "123-45-6789";

/// Pat's address on the record.
pub(crate) const EMAIL: &str = "pat@records.example";

/// The card number on the record.
pub(crate) const CARD: &str = "4111 1111 1111 1111";

/// What the gateway puts in place of a masked field.
pub(crate) const MASK: &str = "***";

/// Pat's record as the records app holds it: a name, an address, a social
/// security number and a note, a card, and two visits with diagnoses.
pub(crate) fn patient_record() -> Value {
    json!({
        "patient": {
            "name": "Pat Doe",
            "email": EMAIL,
            "ssn": SSN,
            "notes": "prefers morning appointments"
        },
        "card": { "number": CARD, "holder": "Pat Doe" },
        "visits": [
            { "date": "2026-10-01", "diagnosis": "influenza" },
            { "date": "2026-10-15", "diagnosis": "sprained ankle" }
        ]
    })
}

/// Tess's rules for the record: the number Restricted and removed, the
/// diagnoses Restricted and masked, the address Confidential and masked,
/// the card number Confidential and replaced by a digest, the note Internal
/// and masked.
pub(crate) fn patient_rules() -> Vec<NewClassificationRule> {
    [
        ("patient.ssn", DataClass::Restricted, Redaction::Remove),
        ("visits.diagnosis", DataClass::Restricted, Redaction::Mask),
        ("patient.email", DataClass::Confidential, Redaction::Mask),
        ("card.number", DataClass::Confidential, Redaction::Hash),
        ("patient.notes", DataClass::Internal, Redaction::Mask),
    ]
    .into_iter()
    .map(|(field_path, level, redaction)| NewClassificationRule {
        field_path: field_path.to_owned(),
        level,
        redaction,
    })
    .collect()
}

/// The tenant's rule set once Tess has added `rules`.
///
/// # Panics
///
/// When a rule is refused.
pub(crate) async fn classified(
    world: &World<'_>,
    rules: &[NewClassificationRule],
) -> Classification {
    for rule in rules {
        classification::add(world.tenant(), rule)
            .send(world.admin().client())
            .await
            .ok();
    }
    classification::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok()
}

/// A redaction stage, as the API writes one, redacting fields of
/// `rule_set_id` classified `min_class` or above.
pub(crate) fn redacting(rule_set_id: &str, min_class: DataClass) -> Value {
    json!({ "Redact": { "rule_set_id": rule_set_id, "min_class": min_class } })
}

/// The records app, serving Pat's record at `/<prefix>/patient` for each
/// of `prefixes`, and an empty record where each route is probed.
///
/// # Panics
///
/// When it cannot listen.
pub(crate) async fn records_app(prefixes: &[&str], extra: Vec<(String, Canned)>) -> CannedApp {
    let record = patient_record();
    let mut answers: Vec<(String, Canned)> = prefixes
        .iter()
        .flat_map(|prefix| {
            [
                (format!("/{prefix}/patient"), Canned::json(&record)),
                (format!("/{prefix}/probe"), Canned::json(&json!({}))),
            ]
        })
        .collect();
    answers.extend(extra);
    CannedApp::start(
        answers
            .iter()
            .map(|(path, canned)| (path.as_str(), canned.clone())),
    )
    .await
    .expect("the records app starts")
}

/// The tenant's random root under the apps domain, where its routes answer.
pub(crate) async fn app_host(world: &World<'_>) -> String {
    let names = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    names.slug_subdomain.unwrap_or(names.uuid_subdomain)
}

/// A public route named `prefix` at `/<prefix>/*`, for Tess to add stages
/// to.
pub(crate) fn public_route(prefix: &str) -> RouteSpec {
    RouteSpec::public(prefix, &format!("/{prefix}/*"))
}

/// `spec` in front of `app`, made by Tess and served by the gateway on
/// `host`.
pub(crate) async fn route(world: &World<'_>, app: &CannedApp, host: &str, spec: RouteSpec) {
    spec.applied(
        world.admin().client(),
        &probe(world.stack()),
        Placement {
            tenant: world.tenant(),
            upstream: &app.url(),
            host,
        },
    )
    .await;
}

/// A client signed in nowhere.
pub(crate) fn probe(stack: &Stack) -> Client {
    Client::new(stack, "a probe").expect("a client for the probe")
}

/// The JSON answer `client` reads at `path` on `host` through the gateway.
///
/// # Panics
///
/// When the gateway does not answer with JSON.
pub(crate) async fn read(client: &Client, host: &str, path: &str) -> Value {
    Request::<Value>::of(Call::get(format!("https://{host}{path}")))
        .send(client)
        .await
        .ok()
}
