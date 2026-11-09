//! An answer the gateway cannot redact is held back, never passed on with
//! the fields it exists to hide: one sent compressed, one that does not
//! parse, and one larger than the gateway reads. An answer that is not JSON
//! has no fields and passes as it came. A stage that would redact by a rule
//! set that is not the tenant's is refused before it can run at all.

use ianua_scenarios::api::{classification, routing};
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::classification::{DataClass, NewClassificationRule, Redaction};
use ianua_scenarios::wire::routing::{NewPipeline, NewStage};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{
    SSN, app_host, classified, patient_record, patient_rules, probe, public_route, records_app,
    redacting, route,
};

/// How much of an answer the gateway reads to redact it by default.
const READ_LIMIT: usize = 64 * 1024;

/// Tess's partner route redacts from Confidential up. The records app
/// sends Pat's record compressed, then a record cut short, then one far
/// longer than the gateway reads with the number at its end: each is
/// withheld as a bad gateway, the number never reaching the reader. The
/// same record as plain text is no JSON, so it passes as the app sent it.
#[tokio::test]
async fn an_answer_the_gateway_cannot_redact_is_withheld() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let rules = classified(&world, &patient_rules()).await;
    let rule_set = rules.id.expect("the first rule makes the rule set");
    let app = malformed_answers().await;
    let partner = public_route("partner").with_stage(redacting(&rule_set, DataClass::Confidential));
    route(&world, &app, &host, partner).await;
    let reader = probe(&stack);

    for path in ["/partner/compressed", "/partner/cut-short", "/partner/long"] {
        let answer = reader
            .send_text(Call::get(format!("https://{host}{path}")))
            .await;
        assert_eq!(answer.status(), Status::BAD_GATEWAY, "{path} is withheld");
        assert_eq!(app.asked_for(path), 1, "the app answered {path}");
    }

    let text = reader
        .send_text(Call::get(format!("https://{host}/partner/text")))
        .await
        .ok();
    assert!(
        text.contains(SSN),
        "a text answer has no fields to redact and passes"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Serves compressed, truncated and oversized records alongside plain text.
async fn malformed_answers() -> CannedApp {
    let record = patient_record();
    let padding = "x".repeat(READ_LIMIT * 2);
    let long = json!({ "padding": padding, "patient": { "ssn": SSN } });
    records_app(
        &["partner"],
        vec![
            (
                "/partner/compressed".to_owned(),
                Canned::compressed_json(&record),
            ),
            (
                "/partner/cut-short".to_owned(),
                Canned::raw_json(&format!("{{\"patient\": {{\"ssn\": \"{SSN}\"")),
            ),
            ("/partner/long".to_owned(), Canned::json(&long)),
            (
                "/partner/text".to_owned(),
                Canned::text(&record.to_string()),
            ),
        ],
    )
    .await
}

/// Sam classifies a field in his own company. Tess cannot add a stage
/// that redacts her pipeline's answers with his rule set. A stage using
/// Tess's own rule set is accepted.
#[tokio::test]
async fn a_stage_naming_another_tenants_rule_set_is_refused_when_saved() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let own = classified(&world, &patient_rules())
        .await
        .id
        .expect("the first rule makes the rule set");
    let theirs = their_rule_set(&world).await;
    assert_stage_ownership(&world, &own, &theirs).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The pipeline refuses Sam's rules and accepts Tess's own rules afterward.
async fn assert_stage_ownership(world: &World<'_>, own: &str, theirs: &str) {
    let pipeline = NewPipeline {
        name: "partner-pipeline".to_owned(),
    };
    let pipeline_id = routing::create_pipeline(world.tenant(), &pipeline)
        .send(world.admin().client())
        .await
        .ok()
        .id;

    routing::add_stage(
        world.tenant(),
        &pipeline_id,
        &NewStage {
            kind: redacting(theirs, DataClass::Confidential),
        },
    )
    .send(world.admin().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    routing::add_stage(
        world.tenant(),
        &pipeline_id,
        &NewStage {
            kind: redacting(own, DataClass::Confidential),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
}

/// The rule set of Sam's tenant, once he has classified a field in it.
async fn their_rule_set(world: &World<'_>) -> String {
    let rule = NewClassificationRule {
        field_path: "customer.ssn".to_owned(),
        level: DataClass::Restricted,
        redaction: Redaction::Remove,
    };
    classification::add(world.twin(), &rule)
        .send(world.stranger().client())
        .await
        .ok();
    classification::get(world.twin())
        .send(world.stranger().client())
        .await
        .ok()
        .id
        .expect("Sam's first rule makes his rule set")
}
