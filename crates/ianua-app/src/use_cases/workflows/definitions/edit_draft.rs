//! Edit draft: a person changes the name, description, steps, trigger, run
//! limit or failure alert of a workflow's draft, or moves its steps on the
//! canvas.
//!
//! Only a draft is edited, by someone who may update workflows. Each edit
//! makes a new revision, so a publisher who reviewed an earlier one looks
//! again before it goes into service. Moving steps is the one exception: it
//! changes nothing a run does, so it keeps the revision and records nothing.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::design::workflow::{
    CanvasLayout, FailureAlert, RunLimit, Workflow,
};
use ianua_domain::domains::workflows::triggers::Trigger;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, Text, WorkflowId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::WorkflowStore;
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::latest_version;

/// One change to a draft.
pub enum DraftEdit {
    /// Gives it this name.
    Rename(Label),
    /// Replaces its steps and edges with these.
    ReplaceSteps(WorkflowGraph),
    /// Starts it on this instead.
    ChangeTrigger(Trigger),
    /// Lets each execution run this long.
    ChangeRunLimit(RunLimit),
    /// Describes what it does, or takes the description away.
    Describe(Option<Text>),
    /// Tells these people when one of its runs fails.
    ChangeFailureAlert(FailureAlert),
    /// Moves its steps on the canvas.
    Arrange(CanvasLayout),
}

/// Which workflow's draft to change, and how.
pub struct EditDraftRequest {
    /// The workflow whose latest version is the draft.
    pub workflow_id: WorkflowId,
    /// The change.
    pub edit: DraftEdit,
}

/// The ports [`EditDraftUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EditDraftPorts {
    /// Keeps the versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes workflow drafts.
pub struct EditDraftUseCase {
    ports: EditDraftPorts,
}

impl EditDraftUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EditDraftPorts) -> Self {
        Self { ports }
    }
}

impl Command for EditDraftUseCase {
    type Caller = CallerContext;
    type Input = EditDraftRequest;
    type Output = Result<Workflow<ResolvedTenant>, AppError>;

    /// Applies `request.edit` to the latest version of the workflow, as the
    /// person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such workflow.
    /// - `AppError::Forbidden` when the caller may not update workflows.
    /// - `AppError::Conflict` when the latest version is not a draft.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: EditDraftRequest,
    ) -> Result<Workflow<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut workflow = latest_version(
            self.ports.workflows.as_ref(),
            &ctx.tenant(),
            &request.workflow_id,
        )
        .await?;
        apply_edit(
            &mut workflow,
            &WorkflowControl::new(&authority),
            request.edit,
        )
        .map_err(AppError::from_domain)?;
        self.ports
            .workflows
            .save(&ctx.tenant(), &workflow)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), workflow.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(workflow)
    }
}

/// Applies `edit` to `workflow` as `control`'s person.
fn apply_edit(
    workflow: &mut Workflow<ResolvedTenant>,
    control: &WorkflowControl<'_>,
    edit: DraftEdit,
) -> Result<(), DomainError> {
    match edit {
        DraftEdit::Rename(name) => workflow.rename(control, name),
        DraftEdit::ReplaceSteps(graph) => workflow.replace_graph(control, graph),
        DraftEdit::ChangeTrigger(trigger) => workflow.change_trigger(control, trigger),
        DraftEdit::ChangeRunLimit(limit) => workflow.change_run_limit(control, limit),
        DraftEdit::Describe(description) => workflow.describe(control, description),
        DraftEdit::ChangeFailureAlert(alert) => workflow.change_failure_alert(control, alert),
        DraftEdit::Arrange(layout) => workflow.arrange(control, layout),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::types::Lifetime;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{FakeWorkflowStore, draft_by, published_by, tidy_step};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A store holding `workflow`, and what an edit recorded.
    struct Editing {
        workflows: Arc<FakeWorkflowStore>,
        sink: Arc<FakeEventDispatcher>,
        id: WorkflowId,
    }

    impl Editing {
        fn of(workflow: &Workflow<ResolvedTenant>) -> Self {
            Self {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(workflow))),
                sink: Arc::new(FakeEventDispatcher::new()),
                id: *workflow.id(),
            }
        }

        fn edit(
            &self,
            authorities: FakeTenantAuthorities,
            edit: DraftEdit,
        ) -> Result<Workflow<ResolvedTenant>, AppError> {
            let use_case = EditDraftUseCase::new(EditDraftPorts {
                workflows: self.workflows.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            let request = EditDraftRequest {
                workflow_id: self.id,
                edit,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }

        fn name(&self) -> String {
            self.workflows
                .stored(&self.id, 1)
                .unwrap()
                .name()
                .as_str()
                .to_owned()
        }
    }

    fn draft() -> Workflow<ResolvedTenant> {
        draft_by(&caller_person(), vec![tidy_step("tidy")], Vec::new())
    }

    fn editor() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Update)])
    }

    fn renamed() -> DraftEdit {
        DraftEdit::Rename(Label::new("name", "Monthly report").unwrap())
    }

    /// Ann renames her draft. The new name is kept and the rename is
    /// recorded.
    #[test]
    fn a_renamed_draft_is_kept_and_recorded() {
        let editing = Editing::of(&draft());

        editing.edit(editor(), renamed()).unwrap();

        assert_eq!(editing.name(), "Monthly report");
        assert_eq!(editing.records(), ["workflows.draft_renamed"]);
    }

    /// Ann changes her draft's steps, trigger and run limit. Each change is
    /// recorded under its own name.
    #[test]
    fn each_kind_of_edit_is_recorded_under_its_name() {
        let editing = Editing::of(&draft());
        let limit = RunLimit::new(Lifetime::seconds(600).unwrap()).unwrap();
        let steps = WorkflowGraph::new(vec![tidy_step("other")], Vec::new()).unwrap();

        editing
            .edit(editor(), DraftEdit::ReplaceSteps(steps))
            .unwrap();
        editing
            .edit(editor(), DraftEdit::ChangeTrigger(Trigger::Webhook))
            .unwrap();
        editing
            .edit(editor(), DraftEdit::ChangeRunLimit(limit))
            .unwrap();

        assert_eq!(
            editing.records(),
            [
                "workflows.draft_steps_replaced",
                "workflows.draft_trigger_changed",
                "workflows.draft_run_limit_changed"
            ]
        );
    }

    /// Ann describes her draft and asks to hear of its failures. Each is
    /// recorded; then she moves its step on the canvas, which is kept and
    /// records nothing, since no run is changed by it.
    #[test]
    fn describing_alerting_and_arranging_are_kept() {
        let editing = Editing::of(&draft());
        let description = Text::new("description", "Tidies the weekly report").unwrap();
        let layout = CanvasLayout::new(vec![(
            ianua_domain::domains::workflows::design::node::NodeKey::new("tidy").unwrap(),
            ianua_domain::domains::workflows::design::workflow::StepPosition::new(40, 300).unwrap(),
        )])
        .unwrap();

        editing
            .edit(editor(), DraftEdit::Describe(Some(description)))
            .unwrap();
        editing
            .edit(
                editor(),
                DraftEdit::ChangeFailureAlert(FailureAlert::AlsoAuthors),
            )
            .unwrap();
        let arranged = editing
            .edit(editor(), DraftEdit::Arrange(layout.clone()))
            .unwrap();

        assert_eq!(arranged.layout(), &layout);
        assert_eq!(
            editing.records(),
            [
                "workflows.draft_described",
                "workflows.draft_failure_alert_changed"
            ]
        );
    }

    /// Renaming a published version returns a conflict, preserving its name and
    /// recording no audit event.
    #[test]
    fn a_published_version_is_not_edited() {
        let editing = Editing::of(&published_by(&caller_person(), draft()));

        let result = editing.edit(editor(), renamed());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(editing.name(), "Weekly report");
        assert!(editing.records().is_empty());
    }

    /// A workflow viewer cannot rename a draft; its saved name stays unchanged.
    #[test]
    fn a_caller_who_may_not_update_workflows_is_refused() {
        let editing = Editing::of(&draft());
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = editing.edit(sam, renamed());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(editing.name(), "Weekly report");
    }

    /// A signed-out session cannot rename a workflow draft.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let editing = Editing::of(&draft());

        let result = editing.edit(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            renamed(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
