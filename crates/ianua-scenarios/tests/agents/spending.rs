//! Triage, run by the platform, held to what Ann lets it spend before she
//! is asked: it pauses once its model calls cost that much, and goes on
//! only when a person who may resume it says so.
//!
//! The scripted model counts every answer at a quarter of its characters
//! each way, and the provider charges one millionth a token, so each call
//! costs a few hundred millionths.

use std::time::Duration;

use ianua_scenarios::agent::model::{ModelBackend, Reply, Script, Steering, Turn, When};
use ianua_scenarios::agent::tool_upstream::{Answering, ToolUpstream};
use ianua_scenarios::api::TenantPath;
use ianua_scenarios::api::agents::{models, runs};
use ianua_scenarios::expect::eventually_within;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::models::{ConnectProvider, Pricing};
use ianua_scenarios::wire::agents::runs::{Run, StartRun};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::platform_runs::{READ_TICKET, registered_tools, triage_agent};
use crate::support::{Witness, profile, with_model, with_tools};

/// What the provider charges for a million tokens either way: a
/// millionth a token.
const PER_MILLION: u64 = 1_000_000;

/// What Triage may spend before Ann is asked: one millionth, less than
/// any call costs.
const ASK_PAST: u64 = 1;

/// The most Triage may spend in all: one currency unit, far more than
/// the run takes.
const SPEND_LIMIT: u64 = 1_000_000;

/// The longest the run is waited for at each stop.
const RUN_WAIT: Duration = Duration::from_secs(90);

/// What the model answers once it read the ticket.
const ANSWER: &str = "Ticket 4821: the printer on floor 3 jams.";

/// The model reads the ticket, then sums it up.
fn reading_then_answering() -> Script {
    Script::new()
        .then(Turn::when(
            When::offered(READ_TICKET),
            Reply::call(READ_TICKET, json!({"id": "4821"})),
        ))
        .then(Turn::answer(Reply::text(ANSWER)))
}

/// Ann lets Triage spend one millionth before she is asked. Its first
/// model call costs more, so after reading the ticket it pauses before
/// asking its model again, and records why. Sam may not resume it. Ann
/// resumes it, it asks its model once more and answers, and it is not
/// held again.
#[tokio::test]
async fn a_run_pauses_once_it_spent_what_it_may_unasked_until_ann_lets_it_go_on() {
    let backend = ModelBackend::for_steering(&Steering::Scripted(reading_then_answering()))
        .await
        .expect("the scripted model listens");
    let ticket = json!({"id": "4821", "subject": "Printer on floor 3 jams"});
    let upstream = ToolUpstream::start(vec![Answering::ok("GET", "/tickets/4821", &ticket)])
        .await
        .expect("the tool app listens");
    let stack = Stack::start(with_tools(with_model(profile(), &backend), &upstream))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut witness = Witness::of(&world).await;
    let run = start_priced_run(&world, &backend).await;
    let watching = Watching {
        tenant: world.tenant(),
        reader: world.owner().client(),
        agent_id: &run.agent_id,
        run_id: &run.run_id,
    };
    resume_and_assert(&world, &mut witness, &watching, &backend).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The agent and run identifiers needed to observe the spending pause.
struct PricedRun {
    agent_id: String,
    run_id: String,
}

/// Ann connects the priced provider and starts Triage with a spending approval threshold.
async fn start_priced_run(world: &World<'_>, backend: &ModelBackend) -> PricedRun {
    let ann = world.owner().client();
    registered_tools(world.tenant(), ann).await;
    let priced = ConnectProvider {
        pricing: Some(Pricing {
            input_micros_per_million: PER_MILLION,
            output_micros_per_million: PER_MILLION,
        }),
        ..backend.provider("Priced model")
    };
    let provider = models::connect(world.tenant(), &priced)
        .send(ann)
        .await
        .ok();
    let triage = triage_agent(world.tenant(), ann).await;
    let started = runs::start(world.tenant(), &triage, &capped_run(&provider.id))
        .send(ann)
        .await
        .ok();
    PricedRun {
        agent_id: triage,
        run_id: started.id,
    }
}

/// The pause is recorded, only Ann resumes it and the second model call completes the run.
async fn resume_and_assert(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    watching: &Watching<'_>,
    backend: &ModelBackend,
) {
    let paused = watching.until("paused", |run| run.status == "paused").await;
    witness.recorded("agents.run_held_at_spend").await;
    runs::resume(world.tenant(), watching.agent_id, watching.run_id)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    runs::resume(world.tenant(), watching.agent_id, watching.run_id)
        .send(world.owner().client())
        .await
        .ok();
    let finished = watching
        .until("answered", |run| run.status == "completed")
        .await;
    assert_paused_after_read(&paused);
    assert_eq!(finished.answer.as_deref(), Some(ANSWER));
    let Some(server) = backend.server() else {
        panic!("the scenario runs against the scripted model");
    };
    assert_eq!(
        server.received().await.len(),
        2,
        "the model was asked once before the pause and once after"
    );
    witness.recorded("agents.run_resumed").await;
}

/// The paused run contains one allowed read and an approval request for its actual spend.
fn assert_paused_after_read(paused: &Run) {
    let read: Vec<(Option<&str>, &str)> = paused
        .steps
        .iter()
        .map(|step| (step.tool.as_deref(), step.outcome.as_str()))
        .collect();
    assert_eq!(
        read,
        [(Some(READ_TICKET), "allowed")],
        "it paused after the read"
    );
    assert!(
        paused.spent_micros > ASK_PAST,
        "it had spent past the amount"
    );
    assert_eq!(
        paused
            .spend_check
            .as_ref()
            .map(|check| check.state.as_str()),
        Some("asked")
    );
}

/// Triage on the ticket with `read_ticket`, asking Ann past one millionth
/// and capped at one unit.
fn capped_run(provider_id: &str) -> StartRun {
    StartRun {
        goal: "Triage ticket 4821 and say what it is about.".to_owned(),
        provider_id: provider_id.to_owned(),
        purpose: vec!["read".to_owned()],
        tool_names: vec![READ_TICKET.to_owned()],
        max_steps: 5,
        spend_limit_micros: Some(SPEND_LIMIT),
        ask_past_micros: Some(ASK_PAST),
    }
}

/// One run, read by one person until it stands as a scenario expects.
struct Watching<'a> {
    tenant: &'a TenantPath,
    reader: &'a Client,
    agent_id: &'a str,
    run_id: &'a str,
}

impl Watching<'_> {
    /// The run once `stands` holds, named `what` in a timeout.
    async fn until(&self, what: &str, stands: impl Fn(&Run) -> bool) -> Run {
        let request = runs::get(self.tenant, self.agent_id, self.run_id);
        eventually_within(&format!("the run to be {what}"), RUN_WAIT, || {
            let request = request.clone();
            let stands = &stands;
            async move {
                let run = request.send(self.reader).await.ok();
                stands(&run).then_some(run)
            }
        })
        .await
    }
}
