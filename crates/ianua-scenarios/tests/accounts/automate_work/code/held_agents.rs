//! Agents held by rules in a sandbox: Pat's team saves a version holding
//! their reply agent and Python that checks each reply, then a workflow's
//! code step runs it. The scripted model plays the agent, so the
//! scenario reads from the model itself what the check sent back. A reply
//! promising a refund breaks the team's rule: the check turns it back
//! with what it broke, the agent answers again in the same run, and the
//! polite reply is the step's output. When every try breaks the rule, the
//! step fails and no reply leaves. The checks run in real containers
//! through `docker`.

use ianua_scenarios::agent::model::{ModelBackend, Reply, Script, Steering, Turn};
use ianua_scenarios::api::agents::lifecycle;
use ianua_scenarios::api::{sandboxes, workflows};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::agents::identity::NewAgent;
use ianua_scenarios::wire::sandboxes::{HeldAgent, HeldAgentVersion, NewSandbox};
use ianua_scenarios::wire::workflows::{Execution, Graph, MappedField, StartExecution, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::code::images::settled;
use crate::code::running::{code_step, finished, step_of};
use crate::spending::connect_priced_model;
use crate::support::{drafted, published, read};

/// A reply breaking the team's rule.
const PROMISE: &str = "Dear Pat, we will refund your order today.";

/// A reply keeping it.
const POLITE: &str = "Dear Pat, we are looking into your order.";

/// What the check says a reply promising a refund broke.
const RULE: &str = "no promises of refunds";

/// Python checking each reply the agent gives against the team's rule.
const CHECK: &str = "def main(input):\n\
\tif 'refund' in input['answer'].lower():\n\
\t\treturn {'pass': False, 'broken': ['no promises of refunds']}\n\
\treturn {'pass': True}\n";

/// The key of the step running the held agent.
const REPLY_STEP: &str = "reply";

/// How many answers the agent may give.
const TRIES: u8 = 2;

/// The scripted model answering `first`, then `second`; the stack running
/// code through `docker` and reaching it, and the backend.
async fn stack_with_model(first: &str, second: &str) -> (Stack, ModelBackend) {
    let script = Script::new()
        .then(Turn::answer(Reply::text(first)))
        .then(Turn::answer(Reply::text(second)));
    let backend = ModelBackend::for_steering(&Steering::Scripted(script))
        .await
        .expect("the scripted model listens");
    let networks = backend.private_networks().unwrap_or("127.0.0.0/8");
    let profile = Profile::standard()
        .with("SANDBOX_CONTAINER_COMMAND", "docker")
        .with("ALLOW_PRIVATE_MODEL_ENDPOINTS", networks);
    let stack = Stack::start(profile).await.expect("the stack starts");
    (stack, backend)
}

/// Replier, the agent Ann makes for the team's replies.
async fn replier(world: &World<'_>) -> String {
    let made = NewAgent {
        name: "Replier".to_owned(),
        description: Some("Writes replies to customers.".to_owned()),
        ..NewAgent::default()
    };
    lifecycle::create(world.tenant(), &made)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// Ann makes a Python sandbox and Tess saves a version holding Replier on
/// the priced model, with the check; the version's id once it is ready.
async fn held_version(world: &World<'_>, backend: &ModelBackend) -> String {
    let provider_id = connect_priced_model(world, backend).await;
    let agent = HeldAgent {
        agent_id: replier(world).await,
        provider_id,
        goal: "Reply to the customer about their order.".to_owned(),
        purpose: vec!["read".to_owned()],
        max_steps: 5,
        spend_cap_micros: 1_000_000,
        tries: TRIES,
    };
    let sandbox = NewSandbox {
        name: "Reply rules".to_owned(),
        language: "python".to_owned(),
    };
    let sandbox_id = sandboxes::create(world.tenant(), &sandbox)
        .send(world.owner().client())
        .await
        .ok()
        .id;
    save_held(world, &sandbox_id, agent).await;
    let version = settled(world, &sandbox_id).await;
    assert_eq!(version.build.status, "ready", "{:?}", version.build);
    version.id
}

/// Tess saves the version holding `agent`, checked by [`CHECK`].
async fn save_held(world: &World<'_>, sandbox_id: &str, agent: HeldAgent) {
    let version = HeldAgentVersion {
        runtime: "python-3.13".to_owned(),
        code: CHECK.to_owned(),
        run_seconds: 20,
        memory_mib: 128,
        agent,
    };
    sandboxes::save_held_agent_version(world.tenant(), sandbox_id, &version)
        .send(world.admin().client())
        .await
        .ok();
}

/// Tess drafts and Ann publishes a workflow whose code step runs version
/// `version_id` for the trigger's customer; Ann starts it for Pat, and
/// the run once it has ended.
async fn replied(world: &World<'_>, version_id: &str) -> Execution {
    let customer = MappedField {
        field: "customer".to_owned(),
        source: read("trigger.customer"),
    };
    let graph = Graph {
        nodes: vec![code_step(REPLY_STEP, version_id, vec![customer])],
        edges: Vec::new(),
    };
    let draft = drafted(world, Trigger::Manual, graph).await;
    let workflow = published(world, &draft).await;
    let start = StartExecution {
        input: json!({"customer": "Pat"}),
        exposure: "internal".to_owned(),
    };
    let started = workflows::start(world.tenant(), &workflow.id, &start)
        .send(world.owner().client())
        .await
        .ok();
    finished(world, &started.execution_id).await
}

/// Replier first promises Pat a refund. The check turns the reply back,
/// and the model is asked again with what the check said: no promises of
/// refunds. Replier's second reply keeps the rule, so the run succeeds
/// with that reply as the step's answer, and the model was asked twice.
#[tokio::test]
async fn an_answer_turned_back_by_the_check_is_tried_again_and_passes() {
    let (stack, backend) = stack_with_model(PROMISE, POLITE).await;
    let world = World::new(&stack).await;
    let version_id = held_version(&world, &backend).await;

    let execution = replied(&world, &version_id).await;

    assert_eq!(execution.status, "succeeded", "{:?}", execution.steps);
    let output = step_of(&execution, REPLY_STEP).output.clone();
    assert_eq!(
        output.map(|answer| answer["answer"].clone()),
        Some(json!(POLITE))
    );
    let asked = backend
        .server()
        .expect("the scripted model")
        .received()
        .await;
    assert_eq!(asked.len(), 2, "one ask per try");
    let retold = asked[1].last_user_text();
    assert!(
        retold.contains(RULE),
        "the check's words reached the agent: {retold}"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Replier promises Pat a refund on both of its two tries. The check
/// turns back each, so the run ends on the last try: the step and the
/// workflow fail, the step hands no reply on, and the model was asked
/// exactly twice.
#[tokio::test]
async fn when_every_try_breaks_the_rule_the_step_fails() {
    let (stack, backend) = stack_with_model(PROMISE, PROMISE).await;
    let world = World::new(&stack).await;
    let version_id = held_version(&world, &backend).await;

    let execution = replied(&world, &version_id).await;

    assert_eq!(execution.status, "failed", "{:?}", execution.steps);
    let step = step_of(&execution, REPLY_STEP);
    assert_eq!(step.phase, "failed");
    assert!(step.failure.is_some(), "the step names why it failed");
    assert!(step.output.is_none(), "no reply left: {:?}", step.output);
    let asked = backend
        .server()
        .expect("the scripted model")
        .received()
        .await;
    assert_eq!(asked.len(), 2, "no third try");
    stack.stop().await.expect("the stack stops cleanly");
}
