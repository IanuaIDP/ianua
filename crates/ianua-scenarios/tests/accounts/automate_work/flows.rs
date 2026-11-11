//! Agent flows: stages of agent runs, each stage starting once every run
//! of the one before has answered, and handed those answers. The scripted
//! model answers the report only when it hears both counts, so a finished
//! report proves the hand-over. An ended flow cannot be cancelled, only
//! deleted, and nobody without the right to view workflows lists flows.

use ianua_scenarios::agent::model::{ModelBackend, Reply, Script, Steering, Turn, When};
use ianua_scenarios::api::agents::lifecycle;
use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::identity::NewAgent;
use ianua_scenarios::wire::workflows::{Flow, FlowRun, NewFlow};
use ianua_scenarios::world::World;

use crate::spending::connect_priced_model;

/// What the open-orders agent answers.
const OPEN: &str = "Seven orders are open.";

/// What the late-orders agent answers.
const LATE: &str = "Two orders are late.";

/// What the report agent answers once it hears both.
const REPORT: &str = "Report: seven open, two of them late.";

/// Ann lays out a flow of her own agents: Olive counts the open orders
/// while Lars counts the late ones, then Rita writes the report from both
/// answers. The flow completes with each run's answer, Rita's being the
/// report she could only write from both counts, and the model was asked
/// three times. Max cannot list flows. Cancelling the ended flow is
/// refused; Ann deletes it, and it is gone.
#[tokio::test]
async fn each_stage_hands_its_answers_to_the_next_and_an_ended_flow_is_deleted() {
    let script = Script::new()
        .then(Turn::when(When::heard(OPEN), Reply::text(REPORT)))
        .then(Turn::when(When::heard("open orders"), Reply::text(OPEN)))
        .then(Turn::when(When::heard("late orders"), Reply::text(LATE)));
    let backend = ModelBackend::for_steering(&Steering::Scripted(script))
        .await
        .expect("the scripted model listens");
    let networks = backend.private_networks().unwrap_or("127.0.0.0/8");
    let stack = Stack::start(Profile::standard().with("ALLOW_PRIVATE_MODEL_ENDPOINTS", networks))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let provider = connect_priced_model(&world, &backend).await;
    let olive = agent(&world, "Olive").await;
    let lars = agent(&world, "Lars").await;
    let rita = agent(&world, "Rita").await;
    let laid_out = NewFlow {
        name: "Order report".to_owned(),
        stages: vec![
            vec![
                run(&olive, &provider, "Count the open orders."),
                run(&lars, &provider, "Count the late orders."),
            ],
            vec![run(&rita, &provider, "Write the report from both counts.")],
        ],
    };

    let made = workflows::create_flow(world.tenant(), &laid_out)
        .send(world.owner().client())
        .await
        .ok();
    let done = completed(&world, &made.id).await;
    workflows::flows(world.tenant())
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    workflows::cancel_flow(world.tenant(), &made.id)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    workflows::delete_flow(world.tenant(), &made.id)
        .send(world.owner().client())
        .await
        .ok();
    workflows::flow(world.tenant(), &made.id)
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let answers: Vec<Vec<Option<&str>>> = done
        .stages
        .iter()
        .map(|stage| stage.iter().map(|run| run.output.as_deref()).collect())
        .collect();
    assert_eq!(answers, [vec![Some(OPEN), Some(LATE)], vec![Some(REPORT)]]);
    let asked = backend
        .server()
        .expect("the scenario runs against the scripted model")
        .received()
        .await;
    assert_eq!(asked.len(), 3, "each run asked the model once");
    stack.stop().await.expect("the stack stops cleanly");
}

/// An agent Ann makes, named `name`, run by the platform with no tools.
async fn agent(world: &World<'_>, name: &str) -> String {
    let made = NewAgent {
        name: name.to_owned(),
        description: Some(format!("{name} works on the order report.")),
        ..NewAgent::default()
    };
    lifecycle::create(world.tenant(), &made)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// A run of `agent_id` on `provider_id` with `goal`, reading only.
fn run(agent_id: &str, provider_id: &str, goal: &str) -> FlowRun {
    FlowRun {
        agent_id: agent_id.to_owned(),
        provider_id: provider_id.to_owned(),
        goal: goal.to_owned(),
        purpose: vec!["read".to_owned()],
    }
}

/// The flow `flow_id` once it completed.
///
/// # Panics
///
/// When it ends any other way.
async fn completed(world: &World<'_>, flow_id: &str) -> Flow {
    eventually("the flow to end", || async {
        let flow = workflows::flow(world.tenant(), flow_id)
            .send(world.owner().client())
            .await
            .ok();
        match flow.status.as_deref() {
            Some("Running") | None => None,
            Some("Completed") => Some(flow),
            Some(other) => panic!("the flow ended {other}: {:?}", flow.stages),
        }
    })
    .await
}
