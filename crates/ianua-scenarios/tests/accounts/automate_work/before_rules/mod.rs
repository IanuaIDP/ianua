//! Rules that run before a change: Ann publishes a workflow that starts
//! before a guarded change and ends in the company step Allow or Refuse.
//! Tess makes the change by hand, and whether it happened shows what the
//! rule decided.
//!
//! - `admin`: a rule on admin roles, asked on every road one takes.
//! - `changes`: rules on access given, apps opened to workflows and audit
//!   exports, each handed what the change would do.
//! - `standing`: a rule that may not start refuses the change it guards.

mod admin;
mod changes;
mod standing;

use ianua_scenarios::api::{Request, policies, workflows};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::policies::NewGroup;
use ianua_scenarios::wire::workflows::{Execution, Graph, Node, Step, Trigger, Workflow};
use ianua_scenarios::world::World;
use serde::de::DeserializeOwned;

use crate::support::{drafted, ended, published};

/// The key of the step deciding the change.
const VERDICT_STEP: &str = "decide";

/// What Tess is told when a rule refuses her change.
const REFUSED_BY_A_RULE: &str = "a company rule refused this change";

/// The company step `operation`, `allow` or `refuse`, deciding the change.
fn verdict(operation: &str) -> Node {
    Node {
        key: VERDICT_STEP.to_owned(),
        name: format!("{operation} the change"),
        step: Step::Action {
            integration: "ianua".to_owned(),
            operation: operation.to_owned(),
            account_id: None,
            effect: "read".to_owned(),
            ceiling: "internal".to_owned(),
            inputs: Vec::new(),
        },
    }
}

/// The rule's graph: one step deciding the change with `operation`.
fn deciding(operation: &str) -> Graph {
    Graph {
        nodes: vec![verdict(operation)],
        edges: Vec::new(),
    }
}

/// The trigger of a rule run before `change`, such as `admin_given`.
fn before(change: &str) -> Trigger {
    Trigger::Before {
        change: change.to_owned(),
    }
}

/// Tess drafts and Ann publishes a rule run before `change`, deciding it
/// with `operation`; the published rule.
async fn rule_on(world: &World<'_>, change: &str, operation: &str) -> Workflow {
    let draft = drafted(world, before(change), deciding(operation)).await;
    published(world, &draft).await
}

/// The one run `rule` made, once it ended as `expected`.
async fn only_run(world: &World<'_>, rule: &Workflow, expected: &str) -> Execution {
    let runs = workflows::executions(world.tenant(), &rule.id)
        .send(world.admin().client())
        .await
        .ok()
        .items;
    assert_eq!(runs.len(), 1, "the rule ran once, for the change");
    ended(world, &runs[0].id, expected).await
}

/// Tess sends `request`: a company rule refuses it with a 403 saying so.
async fn refused_by_the_rule<T: DeserializeOwned>(world: &World<'_>, request: Request<T>) {
    let problem = request
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert!(
        problem.message().to_lowercase().contains(REFUSED_BY_A_RULE),
        "{}",
        problem.message()
    );
}

/// Tess makes a group named `name`; its id.
async fn group(world: &World<'_>, name: &str) -> String {
    let made = NewGroup {
        name: name.to_owned(),
    };
    policies::create_group(world.tenant(), &made)
        .send(world.admin().client())
        .await
        .ok()
        .id
}
