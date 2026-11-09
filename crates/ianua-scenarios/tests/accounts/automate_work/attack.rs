//! Attack mode on one app: a workflow puts Acme's orders app in attack
//! mode, and from then on the gateway holds each address to attack mode's
//! limit before the app's own pipeline; ended early, the app is checked as
//! before.

use ianua_scenarios::api::routing;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{Execution, Graph, MappedField, Node, Step, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{drafted, ended, published, started_with, written};

/// The most requests one address may send in a minute in attack mode.
const ATTACK_LIMIT: usize = 60;

/// How many requests the visitor sends to find the limit: enough to pass
/// it while the gateway learns of attack mode.
const BURST: usize = 400;

/// A graph of one company step putting the app `route_id` in attack mode
/// for fifteen minutes.
fn attack_mode_for(route_id: &str) -> Graph {
    Graph {
        nodes: vec![Node {
            key: "calm".to_owned(),
            name: "Turn on attack mode".to_owned(),
            step: Step::Action {
                integration: "ianua".to_owned(),
                operation: "attack-mode".to_owned(),
                account_id: None,
                effect: "write".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![
                    MappedField {
                        field: "app".to_owned(),
                        source: written(route_id),
                    },
                    MappedField {
                        field: "minutes".to_owned(),
                        source: written("15"),
                    },
                ],
            },
        }],
        edges: vec![],
    }
}

/// The statuses the gateway answers `visitor` with, one per request to
/// `url`, stopping at the first refusal for too many requests.
async fn burst(visitor: &Client, url: &str) -> Vec<Status> {
    let mut statuses = Vec::new();
    for _ in 0..BURST {
        let answer = visitor
            .attempt::<serde::de::IgnoredAny>(Call::get(url))
            .await
            .expect("the gateway answers");
        statuses.push(answer.status());
        if answer.status() == Status::TOO_MANY_REQUESTS {
            break;
        }
    }
    statuses
}

/// Tess's workflow puts the public orders app in attack mode for fifteen
/// minutes. A visitor sending request after request is let through until
/// attack mode's limit, then refused with 429 by attack mode, never by the
/// app; once Tess ends attack mode, the visitor gets through again.
#[tokio::test]
async fn a_workflow_puts_the_orders_app_in_attack_mode() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = orders_app(&world).await;
    let draft = drafted(&world, Trigger::Manual, attack_mode_for(&app.route_id)).await;
    let workflow = published(&world, &draft).await;
    let started = started_with(&world, &workflow, json!({})).await;
    let run = ended(&world, &started.execution_id, "succeeded").await;
    let statuses = burst(&app.visitor, &app.url).await;
    check_attack_limit(&run, &statuses);
    end_attack_mode(&world, &app).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The live orders app and the visitor whose requests exercise its gateway policy.
struct OrdersApp {
    _upstream: Echo,
    visitor: Client,
    route_id: String,
    url: String,
}

/// Publishes a public orders route while keeping its upstream alive throughout the scenario.
async fn orders_app(world: &World<'_>) -> OrdersApp {
    let tess = world.admin().client();
    let names = routing::hostnames(world.tenant()).send(tess).await.ok();
    let host = names.slug_subdomain.unwrap_or(names.uuid_subdomain);
    let upstream = Echo::start(world.stack(), &host)
        .await
        .expect("the orders app starts");
    let visitor = Client::new(world.stack(), "a busy visitor").expect("a client");
    let route = RouteSpec::public("orders-app", "/orders/*")
        .applied(
            tess,
            &visitor,
            Placement {
                tenant: world.tenant(),
                upstream: &upstream.url(),
                host: &host,
            },
        )
        .await;
    let url = format!("https://{host}/orders/7");
    OrdersApp {
        _upstream: upstream,
        visitor,
        route_id: route.route_id,
        url,
    }
}

/// Attack mode reports its expiry, admits the allowed burst and then returns the first 429.
fn check_attack_limit(run: &Execution, statuses: &[Status]) {
    let output = run.steps[0].output.clone().expect("the step answered");
    assert!(output["until"].is_string(), "{output}");
    assert_eq!(
        statuses.last(),
        Some(&Status::TOO_MANY_REQUESTS),
        "{statuses:?}"
    );
    assert!(
        statuses.len() > ATTACK_LIMIT,
        "the limit let {ATTACK_LIMIT} through first: {}",
        statuses.len()
    );
    assert!(
        statuses[..statuses.len() - 1]
            .iter()
            .all(|status| *status == Status::OK),
        "every request before the limit reached the app: {statuses:?}"
    );
}

/// Ending attack mode restores successful requests for the same visitor.
async fn end_attack_mode(world: &World<'_>, app: &OrdersApp) {
    routing::end_attack_mode(world.tenant(), &app.route_id)
        .send(world.admin().client())
        .await
        .ok();
    ianua_scenarios::expect::eventually("the orders app to take the visitor again", || async {
        let answer = app
            .visitor
            .attempt::<serde::de::IgnoredAny>(Call::get(app.url.as_str()))
            .await
            .ok()?;
        (answer.status() == Status::OK).then_some(())
    })
    .await;
}
