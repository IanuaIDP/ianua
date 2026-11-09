//! Having another agent check an agent's work: the Triage bot proposes a
//! fix, the Code reviewer, another agent with no tool, checks it, and the
//! run hands on its verdict and reasons for the steps after it.

use ianua_scenarios::agent::model::{ModelBackend, Received, Reply, Script, Steering, Turn};
use ianua_scenarios::api::agents::{lifecycle, models};
use ianua_scenarios::api::workflows;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::agents::identity::NewAgent;
use ianua_scenarios::wire::workflows::{
    Edge, Execution, Graph, MappedField, NewWorkflow, Node, Publication, StartExecution, Step,
    Trigger, Workflow,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{ended, read};

/// What the Triage bot proposes.
const FIX: &str = "Raise the upload timeout to 30 seconds.";

/// What the Code reviewer answers.
const REVIEW: &str = "NOT OK\nThe change has no test.";

/// The key of the step proposing the fix.
const FIX_STEP: &str = "fix";

/// The key of the step checking it.
const CHECK_STEP: &str = "check";

/// An agent called `name`, made by Ann, run by the platform with no tool.
async fn agent(world: &World<'_>, name: &str) -> String {
    let made = NewAgent {
        name: name.to_owned(),
        description: Some(format!("{name} for the scenario.")),
        ..NewAgent::default()
    };
    lifecycle::create(world.tenant(), &made)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// One agent run step of the graph.
struct RunStep<'a> {
    /// Its key.
    key: &'a str,
    /// The agent it runs.
    agent: &'a str,
    /// The model provider it reasons with.
    provider: &'a str,
    /// Its instruction.
    goal: &'a str,
    /// What of its input it is given.
    inputs: Vec<MappedField>,
    /// The step whose work it checks, if any.
    checks: Option<&'a str>,
}

impl RunStep<'_> {
    /// The step as the graph holds it.
    fn node(self) -> Node {
        Node {
            key: self.key.to_owned(),
            name: self.goal.to_owned(),
            step: Step::AgentRun {
                agent_id: self.agent.to_owned(),
                provider_id: self.provider.to_owned(),
                goal: self.goal.to_owned(),
                inputs: self.inputs,
                purpose: vec!["read".to_owned()],
                tools: Vec::new(),
                approval_classes: Vec::new(),
                max_steps: 3,
                spend_cap_micros: None,
                checks: self.checks.map(str::to_owned),
            },
        }
    }
}

/// Pat's workflow has the Triage bot propose a fix and the Code reviewer
/// check it. The reviewer is asked for a verdict line after the fix it is
/// given, answers NOT OK with its reason, and the check hands on `not_ok`
/// and the reason; the run succeeds for a later step to send it to a
/// person.
#[tokio::test]
async fn another_agent_checks_the_fix_and_its_verdict_is_handed_on() {
    let script = Script::new()
        .then(Turn::answer(Reply::text(FIX)))
        .then(Turn::answer(Reply::text(REVIEW)));
    let backend = ModelBackend::for_steering(&Steering::Scripted(script))
        .await
        .expect("the scripted model listens");
    let networks = backend.private_networks().unwrap_or("127.0.0.0/8");
    let stack = Stack::start(Profile::standard().with("ALLOW_PRIVATE_MODEL_ENDPOINTS", networks))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let workflow = publish_review(&world, &backend).await;
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };
    let started = workflows::start(world.tenant(), &workflow.id, &start)
        .send(world.owner().client())
        .await
        .ok();
    let run = ended(&world, &started.execution_id, "succeeded").await;
    check_verdict(&run);
    check_review_prompt(&backend).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann connects the model and publishes a proposal followed by an independent review.
async fn publish_review(world: &World<'_>, backend: &ModelBackend) -> Workflow {
    let ann = world.owner().client();
    let provider = models::connect(world.tenant(), &backend.provider("Model"))
        .send(ann)
        .await
        .ok();
    let triage = agent(world, "Triage bot").await;
    let reviewer = agent(world, "Code reviewer").await;
    let made = NewWorkflow {
        name: "Fix and check".to_owned(),
        trigger: Trigger::Manual,
        graph: review_graph(&triage, &reviewer, &provider.id),
        run_limit_seconds: 300,
    };
    let draft = workflows::create_draft(world.tenant(), &made)
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

/// The review consumes the proposing agent's answer and declares which step it checks.
fn review_graph(triage: &str, reviewer: &str, provider: &str) -> Graph {
    Graph {
        nodes: vec![
            RunStep {
                key: FIX_STEP,
                agent: triage,
                provider,
                goal: "Propose a fix for the slow uploads.",
                inputs: Vec::new(),
                checks: None,
            }
            .node(),
            RunStep {
                key: CHECK_STEP,
                agent: reviewer,
                provider,
                goal: "Check this proposed fix.",
                inputs: vec![MappedField {
                    field: "work".to_owned(),
                    source: read(&format!("{FIX_STEP}.answer")),
                }],
                checks: Some(FIX_STEP),
            }
            .node(),
        ],
        edges: vec![Edge {
            from: FIX_STEP.to_owned(),
            to: CHECK_STEP.to_owned(),
        }],
    }
}

/// The check step returns the reviewer's refusal and reason for later steps to consume.
fn check_verdict(run: &Execution) {
    let check = run
        .steps
        .iter()
        .find(|step| step.key == CHECK_STEP)
        .and_then(|step| step.output.clone())
        .expect("the check answered");
    assert_eq!(check["verdict"], json!("not_ok"));
    assert_eq!(check["notes"], json!("The change has no test."));
}

/// The model receives both verdict-format instructions and the proposed fix to review.
async fn check_review_prompt(backend: &ModelBackend) {
    let Some(server) = backend.server() else {
        panic!("the scenario runs against the scripted model");
    };
    let asked = server.received().await;
    let reviewer_asked = asked.last().map(Received::text).unwrap_or_default();
    assert!(
        reviewer_asked.contains("Start your answer with one line"),
        "{reviewer_asked}"
    );
    assert!(
        reviewer_asked.contains("upload timeout"),
        "the reviewer was given the fix"
    );
}
