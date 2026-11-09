//! The edits a person makes to a draft: its name, steps, trigger and run
//! limit, what it does in words, who is told when one of its runs fails,
//! and where its steps sit on the canvas.

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::workflow::{CanvasLayout, FailureAlert, RunLimit, Workflow};
use crate::domains::workflows::events::{
    WorkflowDraftDescribed, WorkflowDraftFailureAlertChanged, WorkflowDraftRenamed,
    WorkflowDraftRunLimitChanged, WorkflowDraftStepsReplaced, WorkflowDraftTriggerChanged,
};
use crate::domains::workflows::triggers::Trigger;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::{Label, Text};

impl<T: TenantScope> Workflow<T> {
    /// `by` renames a draft. Raises `workflows.draft_renamed`, naming the
    /// draft by its new name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Conflict`] unless it is a draft.
    pub fn rename(&mut self, by: &WorkflowControl<'_>, name: Label) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_draft()?;
        self.name = name;
        self.record_edit(by.by());
        self.raised.raise(WorkflowDraftRenamed {
            version: self.version_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// `by` replaces a draft's steps and edges. Steps that stay keep where
    /// they sat on the canvas. Raises `workflows.draft_steps_replaced`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Conflict`] unless it is a draft.
    pub fn replace_graph(
        &mut self,
        by: &WorkflowControl<'_>,
        graph: WorkflowGraph,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_draft()?;
        self.layout = self.layout.fitted_to(&graph);
        self.graph = graph;
        self.record_edit(by.by());
        self.raised.raise(WorkflowDraftStepsReplaced {
            version: self.version_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// `by` changes how long a draft's executions may run. Raises
    /// `workflows.draft_run_limit_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Conflict`] unless it is a draft.
    pub fn change_run_limit(
        &mut self,
        by: &WorkflowControl<'_>,
        run_limit: RunLimit,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_draft()?;
        self.run_limit = run_limit;
        self.record_edit(by.by());
        self.raised.raise(WorkflowDraftRunLimitChanged {
            version: self.version_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// `by` replaces what starts a draft. Raises
    /// `workflows.draft_trigger_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Conflict`] unless it is a draft.
    pub fn change_trigger(
        &mut self,
        by: &WorkflowControl<'_>,
        trigger: Trigger,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_draft()?;
        self.trigger = trigger;
        self.record_edit(by.by());
        self.raised.raise(WorkflowDraftTriggerChanged {
            version: self.version_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// `by` describes what a draft does, or takes its description away.
    /// Raises `workflows.draft_described`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Conflict`] unless it is a draft.
    pub fn describe(
        &mut self,
        by: &WorkflowControl<'_>,
        description: Option<Text>,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_draft()?;
        self.description = description;
        self.record_edit(by.by());
        self.raised.raise(WorkflowDraftDescribed {
            version: self.version_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// `by` moves a draft's steps on the canvas.
    ///
    /// Where steps sit changes nothing a run does, so the draft keeps its
    /// revision: a publisher who reviewed it need not look again because
    /// someone tidied the picture. Nothing is raised for the same reason;
    /// every step and edge a run follows is recorded when it changes.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Conflict`] unless it is a draft.
    /// - [`DomainError::Validation`] when `layout` places a step the draft
    ///   does not have.
    pub fn arrange(
        &mut self,
        by: &WorkflowControl<'_>,
        layout: CanvasLayout,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_draft()?;
        layout.ensure_fits(&self.graph)?;
        self.layout = layout;
        Ok(())
    }

    /// `by` chooses who is told when a run of a draft fails. Raises
    /// `workflows.draft_failure_alert_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Conflict`] unless it is a draft.
    pub fn change_failure_alert(
        &mut self,
        by: &WorkflowControl<'_>,
        alert: FailureAlert,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_draft()?;
        self.failure_alert = alert;
        self.record_edit(by.by());
        self.raised.raise(WorkflowDraftFailureAlertChanged {
            version: self.version_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }
}
