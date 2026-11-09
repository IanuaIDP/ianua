//! Company steps about agents: Pat's workflow ends a run of Triage's that
//! hangs on its model, through the cancel Pat could make by hand, and a
//! workflow pausing Triage for someone who may not touch agents fails and
//! leaves Triage active. Pat's workflow also takes the team rota out of
//! the task Ann gave Triage, through the same removal Pat could make by
//! hand, after which Triage may no longer read the rota; for someone who
//! may not touch agents the narrowing fails and the task stays whole.
//! Reading an agent's runs and pausing it are also steps of the workflow
//! `company_events` starts when a run goes over budget.

use std::time::Duration;

use ianua_scenarios::api::agents::delegation::{self, Holder};
use ianua_scenarios::api::agents::{lifecycle, models, runs};
use ianua_scenarios::expect::{Waiting, eventually, eventually_paced};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::Hanging;
use ianua_scenarios::wire::agents::authority::{
    Capabilities, Delegation, Grant, Limits, ResourceGrant, ResourceRight,
};
use ianua_scenarios::wire::agents::identity::NewAgent;
use ianua_scenarios::wire::agents::models::ConnectProvider;
use ianua_scenarios::wire::agents::runs::StartRun;
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;

use super::{company_step, in_order, output, phase, started_by, through_run};
use crate::support::{ended, invited, written};

/// The key of the step ending Triage's run.
const END_STEP: &str = "end-run";

/// The key of the step pausing Triage.
const PAUSE_STEP: &str = "pause";

/// The networks a model may be reached in here: loopback, where the stuck
/// model listens.
const LOOPBACK: &str = "127.0.0.0/8";

/// What Pat may do when she manages agents.
const MANAGES_AGENTS: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Agents", "Manage"),
];

/// What Pat may do when she may only run workflows.
const RUNS_ONLY: &[(&str, &str)] = &[("Workflows", "View"), ("Workflows", "Run")];

/// Triage, an agent Ann makes; its id.
async fn triage(world: &World<'_>) -> String {
    let made = NewAgent {
        name: "Triage".to_owned(),
        description: Some("Sorts the support tickets.".to_owned()),
        ..NewAgent::default()
    };
    lifecycle::create(world.tenant(), &made)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// Ann connects a model at `stuck`, which takes every call and never
/// answers; the provider's id.
async fn stuck_model(world: &World<'_>, stuck: &Hanging) -> String {
    let provider = ConnectProvider {
        name: "Stuck model".to_owned(),
        kind: "self_hosted".to_owned(),
        endpoint: stuck.url(),
        model: "stuck".to_owned(),
        api_key: None,
        clearance: Some("Internal".to_owned()),
        pricing: None,
    };
    models::connect(world.tenant(), &provider)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// Ann starts Triage on a ticket through the stuck model; the run's id,
/// once its model call hangs.
async fn hanging_run(world: &World<'_>, agent_id: &str, stuck: &Hanging) -> String {
    let provider_id = stuck_model(world, stuck).await;
    let start = StartRun {
        goal: "Sort ticket 4821.".to_owned(),
        provider_id,
        purpose: vec!["read".to_owned()],
        tool_names: Vec::new(),
        max_steps: 3,
        spend_limit_micros: None,
        ask_past_micros: None,
    };
    let run_id = runs::start(world.tenant(), agent_id, &start)
        .send(world.owner().client())
        .await
        .ok()
        .id;
    eventually("Triage's model call to hang", || async {
        (stuck.connections() > 0).then_some(())
    })
    .await;
    run_id
}

/// How long, in seconds, a model call waits before it gives up.
const MODEL_GIVES_UP_AFTER: &str = "3";

/// Waits until Triage's run `run_id` has ended, cancelled or failed, as
/// Ann reads it, asking twice a second.
async fn run_ended(world: &World<'_>, agent_id: &str, run_id: &str) {
    let paced = Waiting {
        patience: Duration::from_secs(20),
        every: Duration::from_millis(500),
    };
    eventually_paced("Triage's run to end", paced, || async {
        let run = runs::get(world.tenant(), agent_id, run_id)
            .send(world.owner().client())
            .await
            .ok();
        matches!(run.status.as_str(), "cancelled" | "failed").then_some(())
    })
    .await;
}

/// End Triage's run `run_id`.
fn ending(agent_id: &str, run_id: &str) -> Graph {
    in_order(vec![company_step(
        END_STEP,
        "end-agent-run",
        "write",
        vec![("agent", written(agent_id)), ("run", written(run_id))],
    )])
}

/// Triage's run hangs on a model that never answers. Pat, who manages
/// agents, runs a workflow ending that run: it runs at once, as ending
/// only narrows, and the trail says Pat asked for the cancel, through the
/// run. A stop is honoured between steps, so the run ends once its model
/// call gives up, here after three seconds: cancelled, or failed when the
/// call's giving up ends it first.
#[tokio::test]
async fn pat_s_run_ends_a_run_stuck_on_its_model() {
    let stuck = Hanging::start().await.expect("the stuck model listens");
    let profile = Profile::standard()
        .with("ALLOW_PRIVATE_MODEL_ENDPOINTS", LOOPBACK)
        .with("AGENT_MODEL_TIMEOUT_SECONDS", MODEL_GIVES_UP_AFTER);
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_AGENTS).await;
    let agent_id = triage(&world).await;
    let run_id = hanging_run(&world, &agent_id, &stuck).await;

    let execution_id = started_by(&world, &mut pat, ending(&agent_id, &run_id)).await;
    let finished = ended(&world, &execution_id, "succeeded").await;

    assert!(output(&finished, END_STEP)["status"].is_string());
    run_ended(&world, &agent_id, &run_id).await;
    through_run(
        &world,
        "agents.run_cancel_requested",
        &execution_id,
        pat.email(),
    )
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat may only run workflows, so she could not pause Triage by hand. Her
/// workflow pausing Triage fails at that step, and Triage is still active.
#[tokio::test]
async fn a_pause_the_run_s_person_could_not_make_leaves_the_agent_active() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), RUNS_ONLY).await;
    let agent_id = triage(&world).await;
    let graph = in_order(vec![company_step(
        PAUSE_STEP,
        "pause-agent",
        "write",
        vec![("agent", written(&*agent_id))],
    )]);

    let execution_id = started_by(&world, &mut pat, graph).await;
    let finished = ended(&world, &execution_id, "failed").await;

    assert_eq!(phase(&finished, PAUSE_STEP), "failed");
    let agent = lifecycle::get(world.tenant(), &agent_id)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(agent.status, "Active");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The key of the step narrowing Triage's task.
const NARROW_STEP: &str = "narrow";

/// The relation Triage's task holds: reading the team rota.
fn reading_the_rota() -> ResourceRight {
    ResourceRight {
        relation: "reader".to_owned(),
        resource: "calendar:team-rota".to_owned(),
    }
}

/// Take the team rota out of every task of the agent `agent_id`.
fn narrowing(agent_id: &str) -> Graph {
    in_order(vec![company_step(
        NARROW_STEP,
        "narrow-agent",
        "write",
        vec![
            ("agent", written(agent_id)),
            ("shared", written(reading_the_rota().resource)),
        ],
    )])
}

/// Ann gives Triage a task to read people for an hour, records in the
/// resource graph that she herself reads the team rota, and adds reading
/// it to the task, as an administrator would through the dashboard; the
/// task's id.
async fn rota_task(world: &World<'_>, agent_id: &str) -> String {
    let ann = world.owner().client();
    let grant = Grant {
        granted: Capabilities::http(&["users:view"]),
        limits: Limits {
            ttl_seconds: 3600,
            ..Limits::default()
        },
        name: Some("Plan the week".to_owned()),
    };
    let task = delegation::grant(world.tenant(), agent_id, &grant)
        .send(ann)
        .await
        .ok()
        .delegation_id;
    let held = task_of(world, agent_id, &task).await;
    let seeded = ResourceGrant {
        subject: held.delegator,
        right: reading_the_rota(),
    };
    delegation::grant_relation(world.tenant(), &seeded)
        .send(ann)
        .await
        .ok();
    let holder = Holder {
        agent_id,
        delegation_id: &task,
    };
    let widened = delegation::add_resource(world.tenant(), holder, &reading_the_rota())
        .send(ann)
        .await
        .ok();
    assert_eq!(widened.granted.resources, vec![reading_the_rota()]);
    task
}

/// The task `task` of the agent `agent_id`, as Ann reads it.
async fn task_of(world: &World<'_>, agent_id: &str, task: &str) -> Delegation {
    delegation::list(world.tenant(), agent_id)
        .send(world.owner().client())
        .await
        .ok()
        .into_iter()
        .find(|held| held.delegation_id == task)
        .expect("Triage holds the task")
}

/// Whether Triage may read the team rota, as Ann asks the platform with
/// nothing happening: `allow` or `deny`.
async fn may_read_the_rota(world: &World<'_>, agent_id: &str) -> String {
    delegation::authorize_resource(world.tenant(), agent_id, &reading_the_rota())
        .send(world.owner().client())
        .await
        .ok()
        .decision
}

/// Ann gave Triage a task to read people and the team rota, and the
/// platform says Triage may read the rota. Pat, who manages agents, runs
/// a workflow taking the rota out of Triage's tasks: it runs at once, as
/// narrowing only takes away, and takes one relation. The task still
/// stands and still reads people, but holds the rota no more, and the
/// platform now refuses Triage the rota. The trail says Pat took it,
/// through the run.
#[tokio::test]
async fn pat_s_run_takes_the_rota_out_of_triage_s_task() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_AGENTS).await;
    let agent_id = triage(&world).await;
    let task = rota_task(&world, &agent_id).await;
    let before = may_read_the_rota(&world, &agent_id).await;

    let execution_id = started_by(&world, &mut pat, narrowing(&agent_id)).await;
    let finished = ended(&world, &execution_id, "succeeded").await;

    assert_eq!(before, "allow");
    assert_eq!(output(&finished, NARROW_STEP)["relations_taken"], 1.0);
    let narrowed = task_of(&world, &agent_id, &task).await;
    assert!(!narrowed.revoked, "the task still stands");
    assert_eq!(narrowed.granted.http, vec!["users:view".to_owned()]);
    assert!(narrowed.granted.resources.is_empty(), "{narrowed:?}");
    assert_eq!(may_read_the_rota(&world, &agent_id).await, "deny");
    through_run(
        &world,
        "agents.delegation_resource_revoked",
        &execution_id,
        pat.email(),
    )
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat may only run workflows, so she could not narrow Triage's task by
/// hand. Her workflow taking the rota out fails at that step, the task
/// still holds the rota, and the platform still lets Triage read it.
#[tokio::test]
async fn a_narrowing_the_run_s_person_could_not_make_leaves_the_task_whole() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), RUNS_ONLY).await;
    let agent_id = triage(&world).await;
    let task = rota_task(&world, &agent_id).await;

    let execution_id = started_by(&world, &mut pat, narrowing(&agent_id)).await;
    let finished = ended(&world, &execution_id, "failed").await;

    assert_eq!(phase(&finished, NARROW_STEP), "failed");
    let whole = task_of(&world, &agent_id, &task).await;
    assert_eq!(whole.granted.resources, vec![reading_the_rota()]);
    assert_eq!(may_read_the_rota(&world, &agent_id).await, "allow");
    stack.stop().await.expect("the stack stops cleanly");
}
