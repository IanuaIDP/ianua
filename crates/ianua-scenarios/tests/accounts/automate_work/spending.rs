//! A workflow's agent step held to the spending cap its author set: the
//! run stops, over budget, once its model calls cost more, and the step
//! fails with it. A fair cap lets the same step finish.
//!
//! The scripted model counts every answer at a quarter of the characters
//! each way, and the provider charges one millionth per token, so a call
//! costs a few hundred millionths.

use ianua_scenarios::agent::model::{ModelBackend, Reply, Script, Steering, Turn};
use ianua_scenarios::api::agents::{lifecycle, models};
use ianua_scenarios::api::workflows;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::agents::identity::NewAgent;
use ianua_scenarios::wire::agents::models::{ConnectProvider, Pricing};
use ianua_scenarios::wire::workflows::{
    Execution, ExecutionDecided, Graph, NewWorkflow, Node, Publication, StartExecution, Step,
    Trigger, Workflow,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::ended;

/// What the model answers each run.
const ANSWER: &str = "Two orders are open.";

/// The key of the step the agent runs in.
const SUMMARY_STEP: &str = "summarise";

/// What the provider charges for a million tokens either way: one
/// currency unit, a millionth a token.
const PER_MILLION: u64 = 1_000_000;

/// A cap no model call can stay under: one millionth.
const NEXT_TO_NOTHING: u64 = 1;

/// A cap the one call stays far under: one currency unit.
const FAIR_CAP: u64 = 1_000_000;

/// The longest one execution may run: five minutes, longer than any run
/// here takes.
const RUN_LIMIT_SECONDS: u32 = 300;

/// Ann caps the summary step at one millionth. Its run asks the model
/// once, the call costs more than that, and the run stops over budget:
/// the step and the execution fail, and the model is not asked again. The
/// same step capped at one currency unit finishes with the model's
/// answer.
#[tokio::test]
async fn an_agent_step_stops_once_it_spends_its_cap() {
    let script = Script::new()
        .then(Turn::answer(Reply::text(ANSWER)))
        .then(Turn::answer(Reply::text(ANSWER)));
    let backend = ModelBackend::for_steering(&Steering::Scripted(script))
        .await
        .expect("the scripted model listens");
    let networks = backend.private_networks().unwrap_or("127.0.0.0/8");
    let stack = Stack::start(Profile::standard().with("ALLOW_PRIVATE_MODEL_ENDPOINTS", networks))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let provider_id = connect_priced_model(&world, &backend).await;
    let agent = summariser(&world).await;

    let capped = capped_workflow(&world, &agent, &provider_id, NEXT_TO_NOTHING).await;
    let stopped = started(&world, &capped).await;
    let stopped = ended(&world, &stopped.execution_id, "failed").await;
    let fair = capped_workflow(&world, &agent, &provider_id, FAIR_CAP).await;
    let finished = started(&world, &fair).await;
    let finished = ended(&world, &finished.execution_id, "succeeded").await;
    over_budget(&stopped);
    check_model_spending(&backend, &finished).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann connects a model charging one millionth per input or output token.
pub(crate) async fn connect_priced_model(world: &World<'_>, backend: &ModelBackend) -> String {
    let ann = world.owner().client();
    let priced = ConnectProvider {
        pricing: Some(Pricing {
            input_micros_per_million: PER_MILLION,
            output_micros_per_million: PER_MILLION,
        }),
        ..backend.provider("Priced model")
    };
    models::connect(world.tenant(), &priced)
        .send(ann)
        .await
        .ok()
        .id
}

/// Each run makes one model call, and the fair cap allows its answer through.
async fn check_model_spending(backend: &ModelBackend, finished: &Execution) {
    let Some(server) = backend.server() else {
        panic!("the scenario runs against the scripted model");
    };
    assert_eq!(
        server.received().await.len(),
        2,
        "the model was asked once by each run"
    );
    assert!(
        finished.steps[0]
            .output
            .as_ref()
            .is_some_and(|output| output.to_string().contains(ANSWER)),
        "the fair cap let the run answer: {:?}",
        finished.steps
    );
}

/// Summariser, an agent Ann makes, run by the platform with no tools.
async fn summariser(world: &World<'_>) -> String {
    let made = NewAgent {
        name: "Summariser".to_owned(),
        description: Some("Sums up the open orders.".to_owned()),
        ..NewAgent::default()
    };
    lifecycle::create(world.tenant(), &made)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// A workflow Ann drafts and publishes, started by hand, whose one step
/// runs `agent` on `provider_id` with its spending capped at `cap`
/// millionths.
async fn capped_workflow(world: &World<'_>, agent: &str, provider_id: &str, cap: u64) -> Workflow {
    let workflow = NewWorkflow {
        name: format!("Order summary capped at {cap}"),
        trigger: Trigger::Manual,
        graph: Graph {
            nodes: vec![summary_step(agent, provider_id, cap)],
            edges: Vec::new(),
        },
        run_limit_seconds: RUN_LIMIT_SECONDS,
    };
    let ann = world.owner().client();
    let draft = workflows::create_draft(world.tenant(), &workflow)
        .send(ann)
        .await
        .ok();
    let publication = Publication {
        revision: draft.revision,
    };
    workflows::publish(world.tenant(), &draft.id, &publication)
        .send(ann)
        .await
        .ok()
}

/// The summary agent step carries the cap the workflow's author chose.
fn summary_step(agent: &str, provider_id: &str, cap: u64) -> Node {
    Node {
        key: SUMMARY_STEP.to_owned(),
        name: "Sum up the orders".to_owned(),
        step: Step::AgentRun {
            agent_id: agent.to_owned(),
            provider_id: provider_id.to_owned(),
            goal: "Say how many orders are open.".to_owned(),
            inputs: Vec::new(),
            purpose: vec!["read".to_owned()],
            tools: Vec::new(),
            approval_classes: Vec::new(),
            max_steps: 3,
            spend_cap_micros: Some(cap),
            checks: None,
        },
    }
}

/// Ann starts `workflow` by hand.
async fn started(world: &World<'_>, workflow: &Workflow) -> ExecutionDecided {
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };
    workflows::start(world.tenant(), &workflow.id, &start)
        .send(world.owner().client())
        .await
        .ok()
}

/// The summary step failed because its run ended over budget.
fn over_budget(execution: &Execution) {
    let step = &execution.steps[0];
    assert_eq!(step.key, SUMMARY_STEP);
    let Some(failure) = &step.failure else {
        panic!("the step failed with a reason: {step:?}");
    };
    assert_eq!(failure.code, "reported");
    assert!(
        failure.detail.contains("over_budget"),
        "the run ended over budget: {}",
        failure.detail
    );
}
