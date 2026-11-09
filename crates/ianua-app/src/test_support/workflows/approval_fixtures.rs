//! Executions the tests of deciding, showing and stopping them start from:
//! one waiting for an approval at a chosen sensitivity, one whose agent run
//! is under way, one whose loop is under way, one whose loop asks one
//! approval for every item, and the test caller's second factor.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, ResourceCapability};
use ianua_domain::domains::agents::authority::delegation::HeldResources;
use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::agents::oversight::approval::Presence;
use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::control::StepApprover;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::execution::{
    ActingAuthority, AgentRunStart, ManualStartParams, PassStart, RunAuthority, WorkflowExecution,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{ActionClass, AgentId, Human};

use crate::context::CallerIdentity;
use crate::services::authentication::approver_presence::ApproverPresence;
use crate::test_support::agents::{agent_owned_by, enrolled_presence};
use crate::test_support::authentication::FakeMfaEnrollmentStore;
use crate::test_support::test_ctx;
use crate::test_support::workflows::graphs::{
    agent_step, approval_step, draft_by, every_item_loop_step, listing_step, loop_step, managing,
    next, person, published_by, step, test_provider,
};
use crate::test_support::workflows::runs::{approval_workflow, started_by, trigger_data};

/// An execution `acting_for` started at `exposure` of the approval workflow
/// `author` wrote for actions of `class`, waiting at `check`.
///
/// # Panics
///
/// Panics if the execution cannot start or ask for the approval.
#[must_use]
pub fn awaiting_approval_at(
    author: &Human,
    acting_for: &Human,
    class: ActionClass,
    exposure: DataClassLevel,
) -> WorkflowExecution<ResolvedTenant> {
    let (mut execution, _) = WorkflowExecution::start_by_hand(
        &approval_workflow(author, class),
        managing(acting_for),
        ManualStartParams {
            resources: HeldResources::answered(acting_for.principal(), Vec::new()),
            input: trigger_data(),
            exposure,
        },
    )
    .expect("someone managing workflows starts a published one");
    execution
        .request_approval(&step("check"))
        .expect("the approval step is ready");
    execution
}

/// The presence check, with the test caller's second factor enrolled.
///
/// # Panics
///
/// Panics if the test caller is not a tenant user.
#[must_use]
pub fn caller_presence() -> Arc<ApproverPresence> {
    let caller = test_ctx();
    let CallerIdentity::TenantUser(user) = caller.identity() else {
        panic!("the test caller is a tenant user");
    };
    let store = Arc::new(FakeMfaEnrollmentStore::empty());
    store.enroll(*user);
    Arc::new(enrolled_presence(store))
}

/// An execution `acting_for` started of a workflow whose one step has an
/// agent summarise the orders, with that agent's run under way.
///
/// # Panics
///
/// Panics if the agent run does not start.
#[must_use]
pub fn agent_run_under_way(
    acting_for: &Human,
) -> (WorkflowExecution<ResolvedTenant>, AgentRun<ResolvedTenant>) {
    let author = person("author@corp.test");
    let agent = agent_owned_by(AgentId::new(), person("owner@corp.test"));
    let workflow = published_by(
        &author,
        draft_by(
            &author,
            vec![agent_step("summarise", *agent.id())],
            Vec::new(),
        ),
    );
    let mut execution = started_by(acting_for, &workflow);
    let holds = CapabilitySet::new(
        vec![SystemPermission::Workflows(WorkflowAction::Run)],
        Vec::new(),
    )
    .with_resources(vec![ResourceCapability::use_of_provider(&test_provider())]);
    let started = execution
        .start_agent_run(
            &step("summarise"),
            &RunAuthority::NoDelegation,
            &agent,
            &ActingAuthority::assumed(acting_for.clone(), holds),
        )
        .expect("the agent step is ready");
    let AgentRunStart::Started(run, _) = started else {
        panic!("the agent run step was refused");
    };
    (execution, *run)
}

/// A run `acting_for` started of a workflow that lists `issues` and loops
/// over them one at a time, each pass waiting for Bob at its approval
/// `check`, with its loop `each` begun, and the passes that began.
///
/// # Panics
///
/// Panics if the loop does not begin.
#[must_use]
pub fn loop_under_way(
    acting_for: &Human,
    issues: &[&str],
) -> (
    WorkflowExecution<ResolvedTenant>,
    Vec<PassStart<ResolvedTenant>>,
) {
    let author = person("author@corp.test");
    let body = vec![approval_step("check", ActionClass::Communicate)];
    let workflow = published_by(
        &author,
        draft_by(
            &author,
            vec![
                listing_step("search", issues),
                loop_step("each", "search.issues", body),
            ],
            vec![next("search", "each")],
        ),
    );
    let mut execution = started_by(acting_for, &workflow);
    let moves = execution
        .begin_loop(&step("each"))
        .expect("the loop step is ready");
    let mut started = moves.started;
    for pass in &mut started {
        pass.execution
            .request_approval(&step("check"))
            .expect("the pass's approval is ready");
    }
    (execution, started)
}

/// A run `acting_for` started of a workflow that lists `issues` and loops
/// over them, two at a time, its first step `approve-all` asking one
/// approval of `class` for every issue, then tidying each: the loop `each`
/// begun and waiting for that approval.
///
/// # Panics
///
/// Panics if the loop does not begin.
#[must_use]
pub fn loop_asking_for_every_item(
    acting_for: &Human,
    issues: &[&str],
    class: ActionClass,
) -> WorkflowExecution<ResolvedTenant> {
    let author = person("author@corp.test");
    let workflow = published_by(
        &author,
        draft_by(
            &author,
            vec![
                listing_step("search", issues),
                every_item_loop_step("each", "search.issues", class),
            ],
            vec![next("search", "each")],
        ),
    );
    let mut execution = started_by(acting_for, &workflow);
    let moves = execution
        .begin_loop(&step("each"))
        .expect("the loop step is ready");
    assert!(
        moves.started.is_empty(),
        "no pass starts before the approval"
    );
    execution
}

/// Bob approves the waiting approval step `name` of `execution`, having
/// been shown what it lets through.
///
/// # Panics
///
/// Panics if the step is not waiting for an approval Bob may give.
pub fn approve(execution: &mut WorkflowExecution<ResolvedTenant>, name: &str) {
    let bob = person("bob@corp.test");
    let deciding =
        StepApprover::assumed(managing(&bob), DataClassLevel::Restricted, Presence::Proven);
    let shown = execution
        .approval_input(&step(name))
        .expect("the step waits for an approval");
    execution
        .approve(&step(name), &deciding, &shown)
        .expect("Bob may approve");
}

/// The approval workflow `author` wrote, and a run of it `acting_for`
/// started that failed when Bob refused its approval `check`.
///
/// # Panics
///
/// Panics if the approval cannot be asked for or refused.
#[must_use]
pub fn failed_run(
    author: &Human,
    acting_for: &Human,
) -> (Workflow<ResolvedTenant>, WorkflowExecution<ResolvedTenant>) {
    let workflow = approval_workflow(author, ActionClass::Communicate);
    let mut execution = started_by(acting_for, &workflow);
    execution
        .request_approval(&step("check"))
        .expect("the approval step is ready");
    let bob = person("bob@corp.test");
    let deciding =
        StepApprover::assumed(managing(&bob), DataClassLevel::Restricted, Presence::Proven);
    execution
        .deny(&step("check"), &deciding)
        .expect("Bob may refuse the approval");
    (workflow, execution)
}
