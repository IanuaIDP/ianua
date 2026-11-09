//! Company events as triggers: something happens in Acme and the version
//! of a workflow in service that starts on it runs once, for its
//! publisher, handed the event's details. An archived version starts on
//! nothing.
//!
//! - Summariser's capped workflow step goes over budget: Ann's workflow on
//!   `agents.run_stopped_over_budget` reads Summariser's recent runs and
//!   pauses it, the archived copy running not at all.
//! - The gateway turns Lee away from the orders app: Ann's workflow on
//!   `proxy.person_turned_away` reads the app's requests and tells Bea
//!   which app it was; Lee's retry starts nothing more, and once the
//!   version is archived, Quinn turned away starts nothing.
//!
//! `authentication.risky_sign_in` and `oauth.api_key_used_from_new_country`
//! need the caller placed in a country, so their scenarios are in
//! `places`, on a stack that writes a city database of its own.

use std::time::{Duration, Instant};

use ianua_scenarios::actors::Person;
use ianua_scenarios::agent::model::{ModelBackend, Reply, Script, Steering, Turn};
use ianua_scenarios::api::agents::{lifecycle, models};
use ianua_scenarios::api::{Request, app_sign_in, notifications, people, routing, workflows};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{Placement, RouteSpec, domain};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::identity::NewAgent;
use ianua_scenarios::wire::agents::models::{ConnectProvider, Pricing};
use ianua_scenarios::wire::app_sign_in::{AppLogIn, AppSignInSettings, ConfigureAppSignIn};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::routing::{CustomPermission, RoutePolicy};
use ianua_scenarios::wire::workflows::{
    ExecutionSummary, Graph, NewWorkflow, Node, Publication, StartExecution, Step, Trigger,
    Workflow,
};
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde::de::IgnoredAny;
use serde_json::{Value, json};

use crate::company_steps::{company_step, in_order, output, through_run};
use crate::support::{drafted, ended, invited, published, read, written};

/// The event an agent's run raises when it stops over budget.
const OVER_BUDGET: &str = "agents.run_stopped_over_budget";

/// The event the gateway raises when it turns a signed-in person away.
const TURNED_AWAY: &str = "proxy.person_turned_away";

/// What the provider charges for a million tokens either way: a
/// millionth a token, so a call costs a few hundred millionths.
const PER_MILLION: u64 = 1_000_000;

/// A cap no model call stays under: one millionth.
const NEXT_TO_NOTHING: u64 = 1;

/// The route of the orders app, as the gateway names it in its records.
const ORDERS_APP: &str = "orders-app";

/// What Ann's workflow tells Bea.
const NOTICE_TITLE: &str = "Someone was turned away";

/// How long the platform is watched for a start that must not come:
/// three of the worker's one-second sweeps.
const QUIET: Duration = Duration::from_secs(3);

/// Waits out [`QUIET`] on the real clock, the worker sweeping meanwhile.
pub(crate) async fn watched_quietly() {
    let since = Instant::now();
    eventually("the watch for a start that must not come", || async {
        (since.elapsed() > QUIET).then_some(())
    })
    .await;
}

/// The runs of `workflow_id`, as Ann reads them.
pub(crate) async fn runs_of(world: &World<'_>, workflow_id: &str) -> Vec<ExecutionSummary> {
    workflows::executions(world.tenant(), workflow_id)
        .send(world.owner().client())
        .await
        .ok()
        .items
}

/// The runs of `workflow_id`, once an event started one.
pub(crate) async fn started_runs(world: &World<'_>, workflow_id: &str) -> Vec<ExecutionSummary> {
    eventually("the event to start a run", || async {
        let runs = runs_of(world, workflow_id).await;
        (!runs.is_empty()).then_some(runs)
    })
    .await
}

/// Tess drafts a workflow starting on `event` running `graph`, and Ann
/// publishes it.
pub(crate) async fn on_event(world: &World<'_>, event: &str, graph: Graph) -> Workflow {
    let trigger = Trigger::Event {
        event: event.to_owned(),
    };
    published(world, &drafted(world, trigger, graph).await).await
}

/// Ann archives the version `workflow` is.
async fn archived(world: &World<'_>, workflow: &Workflow) {
    workflows::archive_version(world.tenant(), &workflow.id, workflow.version)
        .send(world.owner().client())
        .await
        .ok();
}

/// Read the recent runs of the agent the event names, then pause it.
fn reading_and_pausing() -> Graph {
    in_order(vec![
        company_step(
            "recent",
            "agent-actions",
            "read",
            vec![
                ("agent", read("trigger.agent.id")),
                ("since", written("hour")),
            ],
        ),
        company_step(
            "pause",
            "pause-agent",
            "write",
            vec![("agent", read("trigger.agent.id"))],
        ),
    ])
}

/// Ann's workflow on a run stopping over budget is in service; an older
/// copy of it was archived. Summariser's workflow step, capped at one
/// millionth, goes over budget. Ann's workflow starts once, on the event,
/// reads Summariser's one run, stopped over budget, and pauses
/// Summariser, which the trail records as Ann's, through that run. The
/// archived copy starts nothing, and nothing more starts afterwards.
#[tokio::test]
async fn an_agent_over_budget_starts_the_workflow_in_service_once() {
    let backend = scripted_model().await;
    let networks = backend.private_networks().unwrap_or("127.0.0.0/8");
    let stack = Stack::start(Profile::standard().with("ALLOW_PRIVATE_MODEL_ENDPOINTS", networks))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let old = on_event(&world, OVER_BUDGET, reading_and_pausing()).await;
    archived(&world, &old).await;
    let current = on_event(&world, OVER_BUDGET, reading_and_pausing()).await;
    let agent_id = summariser(&world).await;

    let capped = capped_summary(&world, &backend, &agent_id).await;
    ended(&world, &start_by_ann(&world, &capped).await, "failed").await;
    let runs = started_runs(&world, &current.id).await;
    let reacted = ended(&world, &runs[0].id, "succeeded").await;
    watched_quietly().await;

    assert_eq!(runs[0].cause, "event");
    check_recent_runs(&output(&reacted, "recent"));
    assert_eq!(agent_status(&world, &agent_id).await, "Suspended");
    through_run(
        &world,
        "agents.agent_suspended",
        &reacted.id,
        world.owner().email(),
    )
    .await;
    only_the_copy_in_service_ran(&world, &old, &current).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The archived copy `old` started nothing, and the copy in service
/// `current` ran once for the one event.
async fn only_the_copy_in_service_ran(world: &World<'_>, old: &Workflow, current: &Workflow) {
    assert!(
        runs_of(world, &old.id).await.is_empty(),
        "the archived copy starts nothing"
    );
    assert_eq!(
        runs_of(world, &current.id).await.len(),
        1,
        "one event, one run"
    );
}

/// A scripted model answering one call.
async fn scripted_model() -> ModelBackend {
    let script = Script::new().then(Turn::answer(Reply::text("Two orders are open.")));
    ModelBackend::for_steering(&Steering::Scripted(script))
        .await
        .expect("the scripted model listens")
}

/// Summariser, an agent Ann makes; its id.
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

/// Summariser's status, as Ann reads it.
async fn agent_status(world: &World<'_>, agent_id: &str) -> String {
    lifecycle::get(world.tenant(), agent_id)
        .send(world.owner().client())
        .await
        .ok()
        .status
}

/// The agent's recent runs: its one run, stopped over budget.
fn check_recent_runs(recent: &Value) {
    assert_eq!(recent["count"], 1.0, "{recent}");
    assert_eq!(recent["runs"][0]["status"], "over_budget", "{recent}");
}

/// Ann connects a model charging a millionth a token, and drafts and
/// publishes a workflow whose one step runs Summariser on it, capped at
/// one millionth.
async fn capped_summary(world: &World<'_>, backend: &ModelBackend, agent_id: &str) -> Workflow {
    let ann = world.owner().client();
    let provider_id = priced_model(world, backend).await;
    let workflow = NewWorkflow {
        name: "Order summary".to_owned(),
        trigger: Trigger::Manual,
        graph: Graph {
            nodes: vec![summary_step(agent_id, &provider_id)],
            edges: Vec::new(),
        },
        run_limit_seconds: 300,
    };
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

/// Ann connects `backend` as a model charging a millionth a token; its id.
async fn priced_model(world: &World<'_>, backend: &ModelBackend) -> String {
    let priced = ConnectProvider {
        pricing: Some(Pricing {
            input_micros_per_million: PER_MILLION,
            output_micros_per_million: PER_MILLION,
        }),
        ..backend.provider("Priced model")
    };
    models::connect(world.tenant(), &priced)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// Summariser's step on `provider_id`, capped at one millionth.
fn summary_step(agent_id: &str, provider_id: &str) -> Node {
    Node {
        key: "summarise".to_owned(),
        name: "Sum up the orders".to_owned(),
        step: Step::AgentRun {
            agent_id: agent_id.to_owned(),
            provider_id: provider_id.to_owned(),
            goal: "Say how many orders are open.".to_owned(),
            inputs: Vec::new(),
            purpose: vec!["read".to_owned()],
            tools: Vec::new(),
            approval_classes: Vec::new(),
            max_steps: 3,
            spend_cap_micros: Some(NEXT_TO_NOTHING),
            checks: None,
        },
    }
}

/// Ann starts `workflow` by hand; the run's id.
async fn start_by_ann(world: &World<'_>, workflow: &Workflow) -> String {
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };
    workflows::start(world.tenant(), &workflow.id, &start)
        .send(world.owner().client())
        .await
        .ok()
        .execution_id
}

/// Read the requests to the app the event names, then tell the person at
/// `address` which app turned someone away.
fn reporting_to(address: &str) -> Graph {
    in_order(vec![
        company_step(
            "requests",
            "read-requests",
            "read",
            vec![
                ("app", read("trigger.route.id")),
                ("since", written("hour")),
            ],
        ),
        company_step(
            "tell",
            "notify",
            "communicate",
            vec![
                ("person", written(address)),
                ("title", written(NOTICE_TITLE)),
                ("message", read("trigger.route.label")),
            ],
        ),
    ])
}

/// Ann's workflow on people turned away is in service. Lee, signed in at
/// the orders app but without the right to read orders, is turned away,
/// twice. Ann's workflow starts once: it reads the app's requests and
/// tells Bea it was the orders app. Ann archives the version; Quinn is
/// turned away too, and the gateway records it, but nothing more starts.
#[tokio::test]
async fn a_person_turned_away_starts_the_workflow_in_service_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let bea = invited(&world, ("bea", "Bea On Call"), &[("Workflows", "View")]).await;
    let host = orders_app_signing_in(&world).await;
    let workflow = on_event(&world, TURNED_AWAY, reporting_to(bea.email())).await;
    let lee = customer(&world, ("lee", "Lee Lost")).await;

    turned_away(&host, &lee).await;
    turned_away(&host, &lee).await;
    let runs = started_runs(&world, &workflow.id).await;
    let reported = ended(&world, &runs[0].id, "succeeded").await;
    assert_eq!(runs[0].cause, "event");
    assert!(output(&reported, "requests")["denied"].is_number());
    check_bea_told(&world, &bea).await;
    archived(&world, &workflow).await;
    let quinn = customer(&world, ("quinn", "Quinn Contractor")).await;
    turned_away(&host, &quinn).await;
    recorded_twice(&world).await;
    watched_quietly().await;

    assert_eq!(
        runs_of(&world, &workflow.id).await.len(),
        1,
        "one run in all"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Bea finds the notice naming the orders app in her inbox.
async fn check_bea_told(world: &World<'_>, bea: &Person) {
    let inbox = notifications::inbox(world.tenant())
        .send(bea.client())
        .await
        .ok();
    let notice = inbox
        .items
        .iter()
        .find(|notice| notice.title == NOTICE_TITLE)
        .expect("Bea was told");
    assert_eq!(notice.body.as_deref(), Some(ORDERS_APP));
}

/// Waits until the gateway has recorded two people turned away: Lee once
/// for both his tries, and Quinn.
async fn recorded_twice(world: &World<'_>) {
    eventually("both refusals to be recorded", || async {
        (world.trail().count(TURNED_AWAY).await >= 2).then_some(())
    })
    .await;
    assert_eq!(
        world.trail().count(TURNED_AWAY).await,
        2,
        "Lee's retry is recorded once"
    );
}

/// Someone Tess invites with the Member role, who accepts from the mailed
/// link and signs in nowhere yet.
async fn customer(world: &World<'_>, who: (&str, &str)) -> Person {
    let (handle, name) = who;
    let mut person = world.newcomer(handle, name);
    let invitation = InviteUser {
        email: person.email().to_owned(),
        display_name: name.to_owned(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    person.record_invitation(&made.id);
    person.accept_invitation(world.stack()).await;
    person
}

/// `person` signs in on the orders app's own host, then asks for order 7
/// until the gateway turns them away.
async fn turned_away(host: &str, person: &Person) {
    let log_in = AppLogIn {
        email: person.email().to_owned(),
        password: person.password().to_owned(),
    };
    let signed_in = app_sign_in::log_in(host, &log_in)
        .send(person.client())
        .await
        .ok();
    assert!(signed_in.signed_in && !signed_in.mfa_required);
    let order = format!("https://{host}/orders/7");
    eventually("the gateway to turn them away", || async {
        let answer = person
            .client()
            .send::<IgnoredAny>(Call::get(order.as_str()))
            .await;
        (answer.status() == Status::FORBIDDEN).then_some(())
    })
    .await;
}

/// Tess puts Acme's orders app on a domain of its own behind the gateway,
/// signing people in there and letting in only those who may read
/// orders; the app's host, once it answers its sign-in address.
async fn orders_app_signing_in(world: &World<'_>) -> String {
    let word = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("orders-{}.{}", &word[..8], world.stack().customer_domain());
    let host = domain::brought(world.stack(), world.admin().client(), world.tenant(), &name).await;
    let app = Echo::start(world.stack(), &host)
        .await
        .expect("the orders app starts");
    let probe = Client::new(world.stack(), "a visitor of the orders app").expect("a client");
    let route = RouteSpec::public(ORDERS_APP, "/orders/*")
        .asking(orders_read_policy(world).await)
        .pinned(ORDERS_APP)
        .on_hosts(std::slice::from_ref(&host))
        .applied(
            world.admin().client(),
            &probe,
            Placement {
                tenant: world.tenant(),
                upstream: &app.url(),
                host: &host,
            },
        )
        .await;
    signing_in_at(world, &route.service_id, &host).await;
    let login = format!("https://{host}/.ianua/login");
    eventually(
        "the gateway to answer the app's sign-in address",
        || async {
            let answer = probe.send::<IgnoredAny>(Call::get(login.as_str())).await;
            (answer.status() == Status::OK).then_some(())
        },
    )
    .await;
    host
}

/// Tess has the service `service_id` sign people in on `host`, refusing
/// browsers that are signed out.
async fn signing_in_at(world: &World<'_>, service_id: &str, host: &str) {
    let signing_in = ConfigureAppSignIn {
        app_sign_in: Some(AppSignInSettings {
            hosts: vec![host.to_owned()],
            signed_out_browsers: "refuse".to_owned(),
        }),
        accepts_app_sign_in_of: None,
        delivery: None,
    };
    routing::configure_app_sign_in(world.tenant(), service_id, &signing_in)
        .send(world.admin().client())
        .await
        .ok();
}

/// Tess declares Acme's orders and requires reading them on the route.
async fn orders_read_policy(world: &World<'_>) -> RoutePolicy {
    let declared: Request<Value> = Request::of(
        Call::post(world.tenant().at("/resource-types")).json(&json!({
            "key": "orders",
            "display_name": "Orders",
            "actions": [{"key": "read", "display_name": "Read", "implies": []}],
            "data_class": "Internal",
        })),
    );
    declared.send(world.admin().client()).await.ok();
    RoutePolicy::RequireCustomPermission(vec![CustomPermission {
        resource: "orders".to_owned(),
        action: "read".to_owned(),
    }])
}
