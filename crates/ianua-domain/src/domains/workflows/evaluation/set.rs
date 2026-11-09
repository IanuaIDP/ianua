//! A workflow's evaluation set: the sample cases its versions are tried
//! against, and whether publishing a draft needs its last evaluation to
//! pass.
//!
//! A workflow has one set, kept across its versions, so the cases written
//! for version 3 try version 4 too, and a change that does worse shows.
//! The gate is off unless the author turns it on: a set is first a tool
//! for the author, and a draft whose cases are still being written should
//! not be kept from service by them.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::design::workflow::Workflow;
use crate::domains::workflows::evaluation::case::EvaluationCase;
use crate::domains::workflows::evaluation::run::Evaluation;
use crate::domains::workflows::evaluation::view::SetView;
use crate::domains::workflows::events::EvaluationSetSaved;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{Human, WorkflowId};

/// The most cases one set may hold.
pub(crate) const MAX_CASES: usize = 50;

/// The most data one set's cases may carry together, in the bytes their
/// inputs and expected values count towards a workflow's data limit.
pub(crate) const MAX_SET_DATA: usize = 1024 * 1024;

/// Whether publishing a draft needs its last evaluation to pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PublishGate {
    /// A draft is published whatever its evaluations showed.
    #[default]
    Off,
    /// A draft is published only once its last evaluation, of the revision
    /// being published, passed every case.
    MustPass,
}

impl PublishGate {
    /// The gate's stored and audited name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::MustPass => "must_pass",
        }
    }
}

/// What an author saves as a workflow's set.
pub struct SetParams {
    /// The cases, each named once.
    pub cases: Vec<EvaluationCase>,
    /// Whether publishing needs the draft's last evaluation to pass.
    pub gate: PublishGate,
}

/// A set as stored.
pub struct EvaluationSetRow {
    /// The workflow whose versions it tries.
    pub workflow_id: WorkflowId,
    /// The sample cases, each run as its own test run, in the order given.
    pub cases: Vec<EvaluationCase>,
    /// Whether publishing needs the draft's last evaluation to pass.
    pub gate: PublishGate,
    /// The person who last saved it.
    pub edited_by: Human,
    /// When it was first saved.
    pub created_at: OffsetDateTime,
    /// When it was last saved.
    pub updated_at: OffsetDateTime,
}

/// A workflow's sample cases and its publishing gate.
#[derive(Debug, Clone)]
pub struct EvaluationSet<T: TenantScope> {
    workflow_id: WorkflowId,
    cases: Vec<EvaluationCase>,
    gate: PublishGate,
    edited_by: Human,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> EvaluationSet<T> {
    /// The first set of `workflow`, saved by `by`. Raises
    /// `workflows.evaluation_set_saved`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Validation`] when the cases break a rule of
    ///   [`replace`](Self::replace).
    pub fn create(
        workflow: &Workflow<T>,
        by: &WorkflowControl<'_>,
        params: SetParams,
    ) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        ensure_cases(&params.cases, params.gate)?;
        let now = crate::shared::clock::now();
        let mut set = Self {
            workflow_id: *workflow.id(),
            cases: params.cases,
            gate: params.gate,
            edited_by: by.by().clone(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        set.record_saved(workflow);
        Ok(set)
    }

    /// Replaces the cases and gate with `params`, as `by` saved them.
    /// Raises `workflows.evaluation_set_saved`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Validation`] for more than [`MAX_CASES`] cases, two
    ///   cases of one name, cases carrying more than [`MAX_SET_DATA`], or a
    ///   gate that must pass on a set with no case.
    /// - [`DomainError::Conflict`] when `workflow` is not the set's.
    pub fn replace(
        &mut self,
        workflow: &Workflow<T>,
        by: &WorkflowControl<'_>,
        params: SetParams,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_of(workflow)?;
        ensure_cases(&params.cases, params.gate)?;
        self.cases = params.cases;
        self.gate = params.gate;
        self.edited_by = by.by().clone();
        self.updated_at = crate::shared::clock::now();
        self.record_saved(workflow);
        Ok(())
    }

    /// Rebuilds a set from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it was saved before it was
    ///   made, or its cases break a rule saving them keeps.
    pub fn reconstitute(row: EvaluationSetRow) -> Result<Self, DomainError> {
        RowCheck::of("evaluation set")
            .in_order(row.created_at, row.updated_at, "saved before it was made")
            .holds(
                ensure_cases(&row.cases, row.gate).is_ok(),
                "cases that saving them refuses",
            )
            .finish()?;
        Ok(Self {
            workflow_id: row.workflow_id,
            cases: row.cases,
            gate: row.gate,
            edited_by: row.edited_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses to publish `draft` unless the gate is off, or `last`, the
    /// draft's last evaluation, tried this very revision of it and passed.
    ///
    /// Ann turns the gate on. Bob changes a step of her draft after its
    /// evaluation passed. Were the evaluation of the earlier revision
    /// counted, his change would go into service untried.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the gate must pass and `last` is
    ///   missing, still running, failed, or tried another revision.
    pub fn ensure_publishable(
        &self,
        draft: &Workflow<T>,
        last: Option<&Evaluation<T>>,
    ) -> Result<(), DomainError> {
        if self.gate == PublishGate::Off {
            return Ok(());
        }
        if last.is_some_and(|evaluation| evaluation.passed_for(draft)) {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "workflows-the-draft-must-pass-its-evaluation",
            "this workflow is published only once an evaluation of the draft as it stands passed every case"
        )))
    }

    /// The workflow whose versions it tries.
    #[must_use]
    pub fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// The sample cases an evaluation runs, in the order they were saved.
    #[must_use]
    pub fn cases(&self) -> &[EvaluationCase] {
        &self.cases
    }

    /// Whether publishing needs the draft's last evaluation to pass.
    #[must_use]
    pub fn gate(&self) -> PublishGate {
        self.gate
    }

    /// The person who last saved it.
    #[must_use]
    pub fn edited_by(&self) -> &Human {
        &self.edited_by
    }

    /// When it was first saved.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it was last saved.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Refuses `workflow` unless it is a version of the set's workflow.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when it is another workflow's.
    pub(super) fn ensure_of(&self, workflow: &Workflow<T>) -> Result<(), DomainError> {
        if workflow.id() == &self.workflow_id {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "workflows-the-cases-belong-to-another-workflow",
            "these sample cases belong to another workflow"
        )))
    }

    fn record_saved(&mut self, workflow: &Workflow<T>) {
        self.raised.raise(EvaluationSetSaved {
            version: workflow.version_ref(),
            cases: self.cases.len(),
            gate: self.gate,
            occurred_at: self.updated_at,
        });
    }
    /// This set as `viewer` may read it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `viewer` may not view workflows.
    pub fn viewed_by(self, viewer: WorkflowControl<'_>) -> Result<SetView<T>, DomainError> {
        viewer.ensure_may(WorkflowAction::View)?;
        Ok(SetView {
            clearance: viewer.authority().data_clearance(),
            set: self,
        })
    }

    /// This set as `author`, who just saved it, may read it back: what is
    /// above their clearance withheld. Saving already asked for a right
    /// beyond viewing, so viewing is not asked again.
    #[must_use]
    pub fn seen_by_author(self, author: WorkflowControl<'_>) -> SetView<T> {
        SetView {
            clearance: author.authority().data_clearance(),
            set: self,
        }
    }
}

impl<T: TenantScope> Raises for EvaluationSet<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses `cases` unless there are at most [`MAX_CASES`], each named once,
/// together within [`MAX_SET_DATA`], and at least one when `gate` must pass.
fn ensure_cases(cases: &[EvaluationCase], gate: PublishGate) -> Result<(), DomainError> {
    validate_count("cases", cases.len(), 0..=MAX_CASES)?;
    if let Some(name) = first_repeat(cases.iter().map(EvaluationCase::name)) {
        return Err(DomainError::invalid(message!(
            "workflows-two-cases-share-a-name",
            format!("two cases are named {name}; name each case once")
        )));
    }
    let size = cases
        .iter()
        .map(EvaluationCase::size)
        .fold(0, usize::saturating_add);
    if size > MAX_SET_DATA {
        return Err(DomainError::invalid(message!(
            "workflows-the-cases-carry-too-much-data",
            format!("the cases carry more than {MAX_SET_DATA} bytes of data together")
        )));
    }
    if gate == PublishGate::MustPass && cases.is_empty() {
        return Err(DomainError::invalid(message!(
            "workflows-a-gate-needs-a-case",
            "publishing can wait on an evaluation only once there is a case to try"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::evaluation::tests::{case_named, evaluator, set_of, workflow};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::TenantId;

    /// The tenant a test saves a set for.
    struct SavedIn(TenantId);

    impl SavedFor for SavedIn {
        fn saved_for(&self) -> TenantId {
            self.0
        }
    }

    fn params(cases: Vec<EvaluationCase>, gate: PublishGate) -> SetParams {
        SetParams { cases, gate }
    }

    /// Ann saves two cases for her draft. The set keeps them, names her,
    /// and records that it was saved, with the gate off unless she turns
    /// it on.
    #[test]
    fn an_author_saves_sample_cases() {
        let draft = workflow();

        let mut set = EvaluationSet::create(
            &draft,
            &evaluator(),
            params(
                vec![case_named("late"), case_named("lost")],
                PublishGate::default(),
            ),
        )
        .unwrap();

        assert_eq!(set.cases().len(), 2);
        assert_eq!(set.gate(), PublishGate::Off);
        assert_eq!(set.take_events(&SavedIn(TenantId::new())).len(), 1);
    }

    /// Two cases of one name, more than the limit, or a gate with nothing
    /// to try are refused.
    #[test]
    fn a_set_names_each_case_once_and_stays_bounded() {
        let draft = workflow();
        let twice = vec![case_named("late"), case_named("late")];
        let many = (0..=MAX_CASES)
            .map(|index| case_named(&format!("case {index}")))
            .collect();

        let repeated = EvaluationSet::create(&draft, &evaluator(), params(twice, PublishGate::Off));
        let too_many = EvaluationSet::create(&draft, &evaluator(), params(many, PublishGate::Off));
        let empty_gate = EvaluationSet::create(
            &draft,
            &evaluator(),
            params(Vec::new(), PublishGate::MustPass),
        );

        assert!(matches!(repeated, Err(DomainError::Validation(_))));
        assert!(matches!(too_many, Err(DomainError::Validation(_))));
        assert!(matches!(empty_gate, Err(DomainError::Validation(_))));
    }

    /// With the gate off, a draft never evaluated is published.
    #[test]
    fn an_open_gate_lets_any_draft_through() {
        let draft = workflow();
        let set = set_of(&draft, PublishGate::Off);

        assert!(set.ensure_publishable(&draft, None).is_ok());
    }

    /// With the gate on, a draft never evaluated is refused.
    #[test]
    fn a_closed_gate_needs_an_evaluation() {
        let draft = workflow();
        let set = set_of(&draft, PublishGate::MustPass);

        let refused = set.ensure_publishable(&draft, None);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// A stored set with two cases of one name is refused as corrupt.
    #[test]
    fn a_stored_set_breaking_its_rules_is_corrupt() {
        let draft = workflow();
        let set = set_of(&draft, PublishGate::Off);
        let row = EvaluationSetRow {
            workflow_id: *set.workflow_id(),
            cases: vec![case_named("late"), case_named("late")],
            gate: set.gate(),
            edited_by: set.edited_by().clone(),
            created_at: set.created_at(),
            updated_at: set.updated_at(),
        };

        assert!(refused_as_corrupt(
            &EvaluationSet::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
