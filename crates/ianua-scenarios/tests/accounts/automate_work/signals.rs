//! Sending a security signal from a workflow: the report is recorded as
//! Pat's, through the run, for every signal stream that takes it.

use ianua_scenarios::api::{audit, workflows};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::workflows::{Graph, MappedField, Node, StartExecution, Step, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{drafted, ended, invited, published, written};

/// What Pat may do by hand: run workflows, view people and update signal
/// streams.
const REPORTS_SIGNALS: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "View"),
    ("Signals", "Update"),
];

/// A graph of one company step reporting the person at `address` as high
/// risk.
fn reporting_high_risk(address: &str) -> Graph {
    let field = |name: &str, value: &str| MappedField {
        field: name.to_owned(),
        source: written(value),
    };
    Graph {
        nodes: vec![Node {
            key: "report".to_owned(),
            name: "Report Lee as high risk".to_owned(),
            step: Step::Action {
                integration: "ianua".to_owned(),
                operation: "send-signal".to_owned(),
                account_id: None,
                effect: "write".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![field("person", address), field("signal", "risk_high")],
            },
        }],
        edges: vec![],
    }
}

/// Pat's workflow reports Lee as high risk. The run succeeds, and the
/// audit trail records the report as Pat's, through the run.
#[tokio::test]
async fn pat_s_run_reports_lee_as_high_risk() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), REPORTS_SIGNALS).await;
    let lee = invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;
    let draft = drafted(&world, Trigger::Manual, reporting_high_risk(lee.email())).await;
    let workflow = published(&world, &draft).await;
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };

    let started = pat
        .send(workflows::start(world.tenant(), &workflow.id, &start))
        .await
        .ok();
    let run = ended(&world, &started.execution_id, "succeeded").await;
    check_signal_author(&world, &run.id, pat.email()).await;
}

/// The signal audit record identifies its run and the person the run acts for.
async fn check_signal_author(world: &World<'_>, execution_id: &str, email: &str) {
    let log = audit::tenant_log(world.tenant(), "signals.signal_reported")
        .send(world.admin().client())
        .await
        .ok();
    let entry = log
        .items
        .iter()
        .find(|entry| {
            entry
                .acted_through
                .as_ref()
                .is_some_and(|through| through.execution_id.as_deref() == Some(execution_id))
        })
        .expect("the report names the run it came through");
    assert!(entry.actor.contains(email), "{}", entry.actor);
}
