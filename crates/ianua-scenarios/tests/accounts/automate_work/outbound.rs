//! Mallory tries to turn a workflow's HTTP step against the platform: to
//! make it fetch the cloud's metadata or the company's private network,
//! with the address written in disguise; to have an allowed service bounce
//! the call somewhere else; and to carry a connected account's token to a
//! server of her own. Every attempt fails at the step, and nothing she
//! points it at is reached.

use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Execution, Graph, MappedField, Node, Step, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::service::{CREDENTIAL, Service};
use crate::support::{
    connected_account, drafted, ended, published, read, run, started_with, written,
};

/// The key of the step Mallory points.
const FETCH_STEP: &str = "fetch";

/// The cloud's metadata address, and private ones, each in the forms an
/// address parser accepts: dotted, decimal, hexadecimal, as an IPv6
/// mapping, and the private ranges of both families.
const FORBIDDEN: [&str; 7] = [
    "http://169.254.169.254/latest/meta-data/",
    "http://2852039166/latest/meta-data/",
    "http://0xA9FEA9FE/latest/meta-data/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://[fd00::1]/",
];

/// A workflow fetching whatever address its trigger names runs once for
/// each disguise of the metadata and private addresses. Every run fails at
/// the fetch, saying the address is one the deployment may not reach.
#[tokio::test]
async fn a_workflow_reaches_no_internal_address_however_it_is_written() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let graph = fetching(Step::Action {
        integration: "http".to_owned(),
        operation: "get".to_owned(),
        account_id: None,
        effect: "read".to_owned(),
        ceiling: "internal".to_owned(),
        inputs: vec![MappedField {
            field: "url".to_owned(),
            source: read("trigger.url"),
        }],
    });
    let workflow = published(&world, &drafted(&world, Trigger::Manual, graph).await).await;

    for address in FORBIDDEN {
        let run = started_with(&world, &workflow, json!({ "url": address })).await;
        let run = ended(&world, &run.execution_id, "failed").await;
        let detail = fetch_failure(&run);
        assert!(
            detail.contains("may not reach") || detail.contains("not a valid"),
            "{address} was refused for what it is: {detail}"
        );
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// A service the deployment may reach answers Mallory's fetch with a
/// redirect to a second one, which holds what she wants. The step takes the
/// redirect as the answer and goes no further: the second service is never
/// asked.
#[tokio::test]
async fn a_redirect_from_an_allowed_service_is_not_followed() {
    let hidden = CannedApp::start([("/secret", Canned::text("the company's secret"))])
        .await
        .expect("the hidden service starts");
    let bounce = format!("{}/secret", hidden.url());
    let bouncer = CannedApp::start([("/bounce", Canned::redirect(&bounce))])
        .await
        .expect("the bouncing service starts");
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let graph = fetching(Step::Action {
        integration: "http".to_owned(),
        operation: "get".to_owned(),
        account_id: None,
        effect: "read".to_owned(),
        ceiling: "internal".to_owned(),
        inputs: vec![MappedField {
            field: "url".to_owned(),
            source: written(format!("{}/bounce", bouncer.url())),
        }],
    });
    let workflow = published(&world, &drafted(&world, Trigger::Manual, graph).await).await;

    let run = started_with(&world, &workflow, json!({})).await;
    let run = ended_either_way(&world, &run.execution_id).await;

    assert_eq!(
        bouncer.asked_for("/bounce"),
        1,
        "the allowed service was asked"
    );
    assert_eq!(
        hidden.asked_for("/secret"),
        0,
        "the redirect was not followed"
    );
    assert!(
        !format!("{:?}", run.steps).contains("the company's secret"),
        "nothing of the hidden service came back"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess connected an account for the outside service. Mallory's step uses
/// that account but points it at her own server. The step fails, saying
/// the address is not the account's origin, and her server is never
/// asked, so the token never reaches her.
#[tokio::test]
async fn an_account_s_token_is_never_carried_to_another_server() {
    let service = Service::start().await;
    let mallory = CannedApp::start([("/collect", Canned::text("thanks"))])
        .await
        .expect("Mallory's server starts");
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let graph = fetching(Step::Action {
        integration: "http".to_owned(),
        operation: "get-with-account".to_owned(),
        account_id: Some(account),
        effect: "read".to_owned(),
        ceiling: "internal".to_owned(),
        inputs: vec![MappedField {
            field: "url".to_owned(),
            source: written(format!("{}/collect", mallory.url())),
        }],
    });
    let workflow = published(&world, &drafted(&world, Trigger::Manual, graph).await).await;

    let run = started_with(&world, &workflow, json!({})).await;
    let run = ended(&world, &run.execution_id, "failed").await;

    assert!(
        fetch_failure(&run).contains("not the origin"),
        "{:?}",
        run.steps
    );
    assert!(
        mallory.received().is_empty(),
        "Mallory's server was never asked"
    );
    assert!(
        mallory
            .received()
            .iter()
            .all(|request| !format!("{request:?}").contains(CREDENTIAL)),
        "the token never reached her"
    );
    assert_eq!(service.calls(), 0, "the real service was not called either");
    stack.stop().await.expect("the stack stops cleanly");
}

/// A graph of the one fetch step doing `step`.
fn fetching(step: Step) -> Graph {
    Graph {
        nodes: vec![Node {
            key: FETCH_STEP.to_owned(),
            name: "Fetch".to_owned(),
            step,
        }],
        edges: Vec::new(),
    }
}

/// Why the fetch step of `run` failed.
fn fetch_failure(run: &Execution) -> String {
    run.steps
        .iter()
        .find(|step| step.key == FETCH_STEP)
        .and_then(|step| step.failure.as_ref())
        .map(|failure| failure.detail.clone())
        .unwrap_or_else(|| panic!("the fetch failed: {:?}", run.steps))
}

/// The run `execution_id` once it ended, whichever way.
async fn ended_either_way(world: &World<'_>, execution_id: &str) -> Execution {
    eventually("the run to end", || async {
        let execution = run(world, execution_id).await;
        (execution.status != "running").then_some(execution)
    })
    .await
}
