//! An operation the company counts as riskier than its integration says.
//! Once raised, a step must say what the operation now counts as and have
//! the approval that class needs before it can be published, and a
//! workflow published before the raise stops at that step rather than run
//! it as it was. Raising needs the right to change workflows; removing,
//! which lowers the risk again, needs full control of them.

use ianua_scenarios::api::workflows;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{
    DraftEdit, Edge, Graph, MappedField, NewRisk, Node, Publication, Step, Trigger, Workflow,
};
use ianua_scenarios::world::World;

use crate::service::Service;
use crate::support::{
    DELIVERY_STEP, connected_account, delivery_graph, drafted, ended, invited, published, started,
    written,
};

/// What the company raises the service's read to.
const FINANCIAL: &str = "financial";

/// The key of the approval before a financial delivery.
const SIGN_OFF: &str = "sign-off";

/// Ann published a workflow reading the service, and a run delivers. Max
/// cannot raise the read; Uma, who may change workflows, raises it to a
/// financial action. The older workflow's next run fails at that step as
/// an operation that changed, and the service is not called. Tess's new
/// draft still calling it a read is refused at publish, and so is her edit
/// calling it financial with no approval; her edit with a financial
/// approval before it is published. Uma cannot remove the raise; Tess does, and the older
/// workflow delivers again.
#[tokio::test]
async fn a_raised_operation_needs_its_approval_and_stops_older_runs_until_removed() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let draft = drafted(&world, Trigger::Manual, delivery_graph(&service, &account)).await;
    let older = published(&world, &draft).await;
    let first = started(&world, &older).await.execution_id;
    ended(&world, &first, "succeeded").await;
    let uma = invited(
        &world,
        ("uma", "Uma Builder"),
        &[("Workflows", "View"), ("Workflows", "Update")],
    )
    .await;
    let raise = NewRisk {
        integration: "http".to_owned(),
        operation: "get-with-account".to_owned(),
        effect: FINANCIAL.to_owned(),
    };

    workflows::raise_risk(world.tenant(), &raise)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let raised = workflows::raise_risk(world.tenant(), &raise)
        .send(uma.client())
        .await
        .ok();
    let stopped = started(&world, &older).await.execution_id;
    let stopped = ended(&world, &stopped, "failed").await;
    let draft = drafted(&world, Trigger::Manual, delivery_graph(&service, &account)).await;
    refused_at_publish(&world, &draft).await;
    let draft = edited(&world, &draft, unapproved_payment(&service, &account)).await;
    refused_at_publish(&world, &draft).await;
    let draft = edited(&world, &draft, approved_payment(&service, &account)).await;
    let approved = published(&world, &draft).await;
    workflows::remove_risk(world.tenant(), &raised.id)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    workflows::remove_risk(world.tenant(), &raised.id)
        .send(world.admin().client())
        .await
        .ok();
    let again = started(&world, &older).await.execution_id;
    ended(&world, &again, "succeeded").await;

    assert_eq!(raised.effect, FINANCIAL);
    let failure = stopped
        .steps
        .iter()
        .find(|step| step.key == DELIVERY_STEP)
        .and_then(|step| step.failure.as_ref())
        .map(|failure| (failure.code.as_str(), failure.detail.as_str()));
    assert_eq!(
        failure,
        Some(("refused", "operation_changed")),
        "{:?}",
        stopped.steps
    );
    assert_eq!(approved.status, "published");
    assert_eq!(
        service.calls(),
        2,
        "only the runs outside the raise called it"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's publication of `draft` as it stands is refused.
async fn refused_at_publish(world: &World<'_>, draft: &Workflow) {
    let publication = Publication {
        revision: draft.revision.clone(),
    };
    workflows::publish(world.tenant(), &draft.id, &publication)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// Tess replaces the steps of `draft` with `graph`; the new revision.
async fn edited(world: &World<'_>, draft: &Workflow, graph: Graph) -> Workflow {
    workflows::edit_draft(
        world.tenant(),
        &draft.id,
        &DraftEdit::ReplaceSteps { graph },
    )
    .send(world.admin().client())
    .await
    .ok()
}

/// The delivery, said to be a financial action, with nothing before it.
fn unapproved_payment(service: &Service, account_id: &str) -> Graph {
    Graph {
        nodes: vec![payment(service, account_id)],
        edges: Vec::new(),
    }
}

/// The delivery, said to be a financial action, after an approval of
/// financial actions.
fn approved_payment(service: &Service, account_id: &str) -> Graph {
    let sign_off = Node {
        key: SIGN_OFF.to_owned(),
        name: "Sign off the payment".to_owned(),
        step: Step::Approval {
            summary: "Approve this payment".to_owned(),
            action_class: FINANCIAL.to_owned(),
            window_seconds: 120,
        },
    };
    Graph {
        nodes: vec![sign_off, payment(service, account_id)],
        edges: vec![Edge {
            from: SIGN_OFF.to_owned(),
            to: DELIVERY_STEP.to_owned(),
        }],
    }
}

/// The step reading `service` through `account_id`, said to be a
/// financial action.
fn payment(service: &Service, account_id: &str) -> Node {
    Node {
        key: DELIVERY_STEP.to_owned(),
        name: "Pay".to_owned(),
        step: Step::Action {
            integration: "http".to_owned(),
            operation: "get-with-account".to_owned(),
            account_id: Some(account_id.to_owned()),
            effect: FINANCIAL.to_owned(),
            ceiling: "internal".to_owned(),
            inputs: vec![MappedField {
                field: "url".to_owned(),
                source: written(service.url()),
            }],
        },
    }
}
