//! The rights test people hold: full control, view only, one right, or
//! deciding a step.

use crate::domains::agents::oversight::approval::Presence;
use crate::domains::authorization::permission::{SystemPermission, WorkflowAction};
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::control::{StepApprover, WorkflowControl};
use crate::domains::workflows::design::workflow::{
    CodeReach, PublishFacts, Replaces, RunnableCode, Workflow,
};
use crate::domains::workflows::integration::events::ServiceEventSpec;
use crate::domains::workflows::integration::risk_override::TenantOperation;
use crate::domains::workflows::integration::{InputNeed, InputSpec};
use crate::domains::workflows::triggers::Trigger;
use crate::isolation::scope::ResolvedTenant;
use crate::test_support::authority::assumed_authority;
use crate::types::{EventVisibility, Human, TenantId};

/// Every workflow right there is.
const MANAGES: &[SystemPermission] = &[SystemPermission::Workflows(WorkflowAction::Manage)];

/// `by` with full control of workflows.
pub(crate) fn managing(by: &Human) -> WorkflowControl<'_> {
    WorkflowControl::new(assumed_authority(by, TenantId::new(), MANAGES, &[]))
}

/// `by`, with full control of workflows, publishes `workflow` as it stands
/// now. A service event it starts on is offered just as its trigger names
/// it, and every sandbox version its code steps name may run.
pub(crate) fn publish_as(
    workflow: &mut Workflow<ResolvedTenant>,
    by: &Human,
    offered: &[TenantOperation],
    sees: &impl EventVisibility,
) -> Result<(), crate::shared::errors::DomainError> {
    let reviewed = workflow.revision();
    let events = offered_as_named(workflow.trigger());
    let runnable: Vec<_> = workflow
        .graph()
        .code_steps()
        .map(|(_, step)| RunnableCode {
            version: step.version(),
            reach: CodeReach::Closed,
        })
        .collect();
    workflow.publish(
        &managing(by),
        reviewed,
        Replaces::Nothing,
        PublishFacts {
            offered,
            events: &events,
            sees,
            runnable: &runnable,
        },
    )
}

/// The service event `trigger` starts on, offered with exactly the filters
/// it gives, each required; none for any other trigger.
fn offered_as_named(trigger: &Trigger) -> Vec<ServiceEventSpec> {
    let Trigger::Service(on) = trigger else {
        return Vec::new();
    };
    let filters = on
        .filters()
        .iter()
        .map(|filter| InputSpec::new(filter.name().clone(), InputNeed::Required))
        .collect();
    vec![ServiceEventSpec::new(on.integration().clone(), on.event().clone(), filters).unwrap()]
}

/// `by` who may only view workflows.
pub(crate) fn viewing(by: &Human) -> WorkflowControl<'_> {
    WorkflowControl::new(assumed_authority(
        by,
        TenantId::new(),
        &[SystemPermission::Workflows(WorkflowAction::View)],
        &[],
    ))
}

/// `by` who holds the one workflow right for `action`.
pub(crate) fn holding_only(by: &Human, action: WorkflowAction) -> WorkflowControl<'_> {
    WorkflowControl::new(assumed_authority(
        by,
        TenantId::new(),
        &[SystemPermission::Workflows(action)],
        &[],
    ))
}

/// `by` deciding a step: allowed to approve, cleared for every class, and
/// present just now.
pub(crate) fn deciding(by: &Human) -> StepApprover<'_> {
    StepApprover::assumed(managing(by), DataClassLevel::Restricted, Presence::Proven)
}
