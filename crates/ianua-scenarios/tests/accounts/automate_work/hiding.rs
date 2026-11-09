//! Hiding sensitive fields in a workflow: the fields the tenant classifies
//! are hidden as their rules say, as the gateway hides them in an app's
//! answer, and the rest goes on.

use ianua_scenarios::api::classification;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::classification::{DataClass, NewClassificationRule, Redaction};
use ianua_scenarios::wire::workflows::{Graph, MappedField, Node, Step, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{drafted, ended, published, started_with, written};

/// A graph of one company step hiding what is confidential or above in
/// `data`.
fn hiding(data: serde_json::Value) -> Graph {
    Graph {
        nodes: vec![Node {
            key: "hide".to_owned(),
            name: "Hide the card number".to_owned(),
            step: Step::Action {
                integration: "ianua".to_owned(),
                operation: "hide-fields".to_owned(),
                account_id: None,
                effect: "read".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![MappedField {
                    field: "data".to_owned(),
                    source: written(data),
                }],
            },
        }],
        edges: vec![],
    }
}

/// Tess classifies an order's card number as restricted, to be removed,
/// and its email as confidential, to be masked. Her workflow hides what
/// is confidential or above in an order: the card is gone, the email
/// masked, and the item kept, with two fields hidden.
#[tokio::test]
async fn a_run_hides_the_fields_the_company_classifies() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    classify_order(&world).await;
    let order = json!({"order": {
        "card": "4111 1111 1111 1111",
        "email": "lee@acme.com",
        "item": "standing desk"
    }});
    let draft = drafted(&world, Trigger::Manual, hiding(order)).await;
    let workflow = published(&world, &draft).await;

    let started = started_with(&world, &workflow, json!({})).await;
    let run = ended(&world, &started.execution_id, "succeeded").await;

    let output = run.steps[0].output.clone().expect("the step answered");
    assert_eq!(output["hidden"].as_f64(), Some(2.0));
    assert_eq!(output["data"]["order"].get("card"), None);
    assert_eq!(output["data"]["order"]["email"], json!("***"));
    assert_eq!(output["data"]["order"]["item"], json!("standing desk"));
}

/// The tenant removes restricted card fields and masks confidential email fields.
async fn classify_order(world: &World<'_>) {
    let tess = world.admin().client();
    for (path, level, redaction) in [
        ("order.card", DataClass::Restricted, Redaction::Remove),
        ("order.email", DataClass::Confidential, Redaction::Mask),
    ] {
        let rule = NewClassificationRule {
            field_path: path.to_owned(),
            level,
            redaction,
        };
        classification::add(world.tenant(), &rule)
            .send(tess)
            .await
            .ok();
    }
}
