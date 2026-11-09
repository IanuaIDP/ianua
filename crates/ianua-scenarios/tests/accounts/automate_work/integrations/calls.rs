//! What the scenarios of outside services share: Tess offering a credential
//! the service refuses, Ann's published run of a chain of the service's
//! steps, and the one call of a kind that reached a stand-in.

use ianua_scenarios::api::workflows;
use ianua_scenarios::upstreams::{CannedApp, Received};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{Edge, Execution, Graph, NewAccount, Node, Trigger};
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::{drafted, ended, published, started};

/// The credential Tess offers for an account at an integration.
#[derive(Clone, Copy)]
pub(super) struct Offered<'a> {
    /// The integration, such as `gitlab`.
    pub(super) integration: &'a str,
    /// What the account would hold, such as a token or a grant as JSON.
    pub(super) credential: &'a str,
}

/// Tess offers `offered`, which the service or the platform refuses: the
/// connection is refused as invalid and no account-connected record is
/// written.
pub(super) async fn never_connected(world: &World<'_>, offered: Offered<'_>) {
    let before = world.trail().count("workflows.account_connected").await;
    let account = NewAccount {
        integration: offered.integration.to_owned(),
        name: format!("Mistyped {} account", offered.integration),
        credential: offered.credential.to_owned(),
        sharing: "tenant".to_owned(),
    };
    workflows::connect_account(world.tenant(), &account)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert_eq!(
        world.trail().count("workflows.account_connected").await,
        before,
        "no account was connected"
    );
}

/// Ann publishes Tess's manual workflow running `graph`, and Tess runs it
/// once; the run once it ended as `expected`, such as `succeeded`.
pub(super) async fn ran(world: &World<'_>, graph: Graph, expected: &str) -> Execution {
    let draft = drafted(world, Trigger::Manual, graph).await;
    let workflow = published(world, &draft).await;
    let decided = started(world, &workflow).await;
    ended(world, &decided.execution_id, expected).await
}

/// A graph of `steps` run one after another, each later step able to read
/// what the earlier ones gave back.
pub(super) fn chain(steps: Vec<Node>) -> Graph {
    let edges = steps
        .windows(2)
        .map(|pair| Edge {
            from: pair[0].key.clone(),
            to: pair[1].key.clone(),
        })
        .collect();
    Graph {
        nodes: steps,
        edges,
    }
}

/// The one request with `method` at `path` that reached `service`.
pub(super) fn only_call(service: &CannedApp, method: &str, path: &str) -> Received {
    let mut calls: Vec<Received> = service
        .received()
        .into_iter()
        .filter(|call| call.method == method && call.path == path)
        .collect();
    assert_eq!(calls.len(), 1, "{method} {path} reached the service once");
    calls.remove(0)
}

/// What the step `key` of `run` gave back.
pub(super) fn output_of(run: &Execution, key: &str) -> Value {
    run.steps
        .iter()
        .find(|step| step.key == key)
        .and_then(|step| step.output.clone())
        .unwrap_or_else(|| panic!("the step {key} gave back an output"))
}

/// The step `key` of `run` failed.
pub(super) fn failed_step(run: &Execution, key: &str) {
    let step = run
        .steps
        .iter()
        .find(|step| step.key == key)
        .unwrap_or_else(|| panic!("the step {key} is in the run"));
    assert_eq!(step.phase, "failed", "the step {key} failed");
}
