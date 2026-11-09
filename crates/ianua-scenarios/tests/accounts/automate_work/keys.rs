//! Pausing an API key from a workflow: the key stops signing in at once,
//! and once someone resumes it, it works again as before.

use ianua_scenarios::actors::{KeyHolder, KeyRequest};
use ianua_scenarios::api::{api_keys, people};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{Graph, MappedField, Node, Step, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{drafted, ended, published, started_with, written};

/// A graph of one company step pausing the API key `key_id`.
fn pausing(key_id: &str) -> Graph {
    Graph {
        nodes: vec![Node {
            key: "pause".to_owned(),
            name: "Pause the deploy key".to_owned(),
            step: Step::Action {
                integration: "ianua".to_owned(),
                operation: "pause-key".to_owned(),
                account_id: None,
                effect: "write".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![MappedField {
                    field: "key".to_owned(),
                    source: written(key_id),
                }],
            },
        }],
        edges: vec![],
    }
}

/// Whether the deploy program's key still lets it read people.
async fn key_reads(world: &World<'_>, deploy: &KeyHolder) -> Status {
    people::list(world.tenant(), None)
        .send(deploy.client())
        .await
        .status()
}

/// The deploy program reads people with its key. Tess's workflow pauses
/// the key: it runs at once, as pausing only narrows, and the key is
/// refused. Tess resumes it, and it reads people again.
#[tokio::test]
async fn a_run_pauses_a_key_until_someone_resumes_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin();
    let deploy = KeyHolder::issued_by(
        &stack,
        tess,
        world.tenant(),
        KeyRequest {
            name: "deploy",
            scopes: &["idp:users:view"],
        },
    )
    .await;
    assert_eq!(key_reads(&world, &deploy).await, Status::OK);
    let draft = drafted(&world, Trigger::Manual, pausing(deploy.key_id())).await;
    let workflow = published(&world, &draft).await;

    let started = started_with(&world, &workflow, json!({})).await;
    ended(&world, &started.execution_id, "succeeded").await;
    let while_paused = key_reads(&world, &deploy).await;
    api_keys::resume(world.tenant(), deploy.key_id())
        .send(tess.client())
        .await
        .ok();

    assert_eq!(while_paused, Status::UNAUTHORIZED);
    assert_eq!(key_reads(&world, &deploy).await, Status::OK);
}
