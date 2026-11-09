//! A workflow that delivers to an [`OutsideService`], as the scenarios
//! outside the workflows' own target need one: the account connected, the
//! draft, Ann's publication and reading a run until it ends.

use serde_json::json;

use crate::api::workflows;
use crate::expect::eventually;
use crate::net::Client;
use crate::upstreams::OutsideService;
use crate::wire::workflows::{
    Execution, ExecutionDecided, Graph, MappedField, NewAccount, NewWorkflow, Node, Publication,
    Source, StartExecution, Step, Trigger, Workflow,
};
use crate::world::World;

/// The key of the step that calls the outside service.
const DELIVERY_STEP: &str = "deliver";

/// The longest a run may take: longer than any scenario's run.
const RUN_LIMIT_SECONDS: u32 = 300;

/// Tess connects an account for `service`, shared with the whole tenant;
/// its id.
///
/// # Panics
///
/// When the account is refused.
pub async fn connected_account(world: &World<'_>, service: &OutsideService) -> String {
    let account = NewAccount {
        integration: "http".to_owned(),
        name: "Tenant http account".to_owned(),
        credential: service.credential(),
        sharing: "tenant".to_owned(),
    };
    workflows::connect_account(world.tenant(), &account)
        .send(world.admin().client())
        .await
        .ok()
        .id
}

/// A workflow of one step, reading `service` through `account_id`: a run
/// that reaches the end called the outside service once.
#[must_use]
pub fn delivery_graph(service: &OutsideService, account_id: &str) -> Graph {
    Graph {
        nodes: vec![Node {
            key: DELIVERY_STEP.to_owned(),
            name: "Deliver externally".to_owned(),
            step: Step::Action {
                integration: "http".to_owned(),
                operation: "get-with-account".to_owned(),
                account_id: Some(account_id.to_owned()),
                effect: "read".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![MappedField {
                    field: "url".to_owned(),
                    source: Source::Literal {
                        value: service.url().into(),
                    },
                }],
            },
        }],
        edges: vec![],
    }
}

/// Tess drafts a workflow started by `trigger` running `graph`.
///
/// # Panics
///
/// When the draft is refused.
pub async fn drafted(world: &World<'_>, trigger: Trigger, graph: Graph) -> Workflow {
    let workflow = NewWorkflow {
        name: "Outside delivery workflow".to_owned(),
        trigger,
        graph,
        run_limit_seconds: RUN_LIMIT_SECONDS,
    };
    workflows::create_draft(world.tenant(), &workflow)
        .send(world.admin().client())
        .await
        .ok()
}

/// Ann, not the drafter, publishes exactly the revision of `draft` she
/// reviewed.
///
/// # Panics
///
/// When the publication is refused.
pub async fn published(world: &World<'_>, draft: &Workflow) -> Workflow {
    let publication = Publication {
        revision: draft.revision.clone(),
    };
    workflows::publish(world.tenant(), &draft.id, &publication)
        .send(world.owner().client())
        .await
        .ok()
}

/// `by` starts the published `workflow` by hand.
///
/// # Panics
///
/// When the start is refused.
pub async fn started(world: &World<'_>, by: &Client, workflow: &Workflow) -> ExecutionDecided {
    let start = StartExecution {
        input: json!({"order": "visible-order"}),
        exposure: "internal".to_owned(),
    };
    workflows::start(world.tenant(), &workflow.id, &start)
        .send(by)
        .await
        .ok()
}

/// The run `execution_id`, read by `reader`, once it ended, as `expected`
/// says, such as `succeeded`.
///
/// # Panics
///
/// When it ended another way, or did not end within
/// [`eventually`]'s patience.
pub async fn ended(
    world: &World<'_>,
    reader: &Client,
    execution_id: &str,
    expected: &str,
) -> Execution {
    eventually("the run to end", || async {
        let execution = workflows::execution(world.tenant(), execution_id)
            .send(reader)
            .await
            .ok();
        if execution.status == "running" {
            return None;
        }
        assert_eq!(
            execution.status, expected,
            "the run ended as expected: {:?}",
            execution.steps
        );
        Some(execution)
    })
    .await
}
