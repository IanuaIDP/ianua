//! Sets and evaluations as their rows hold them: read back into the
//! aggregates, and written out from them.
//!
//! The cases and the outcomes are kept whole as JSON in the domain's
//! stored shape, so a case or an outcome read back passes the same rules
//! it was built under. The gate and where an evaluation stands are words.

use ianua_domain::domains::workflows::design::workflow::Revision;
use ianua_domain::domains::workflows::evaluation::outcome::Verdict;
use ianua_domain::domains::workflows::evaluation::run::{
    Evaluation, EvaluationRow, EvaluationState,
};
use ianua_domain::domains::workflows::evaluation::set::{
    EvaluationSet, EvaluationSetRow, PublishGate,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{EvaluationId, WorkflowId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _, stored_words};

const SET: Stored = Stored("evaluation set");

const EVALUATION: Stored = Stored("evaluation");

const SET_CASES: Kept = Kept {
    entity: SET.0,
    column: "cases",
    shape: 1,
};

const EDITED_BY: Kept = Kept {
    entity: SET.0,
    column: "edited_by",
    shape: 1,
};

const CASES: Kept = Kept {
    entity: EVALUATION.0,
    column: "cases",
    shape: 1,
};

const OUTCOMES: Kept = Kept {
    entity: EVALUATION.0,
    column: "outcomes",
    shape: 1,
};

const STARTED_BY: Kept = Kept {
    entity: EVALUATION.0,
    column: "started_by",
    shape: 1,
};

stored_words! {
    PublishGate as "publish gate" {
        Off => "off",
        MustPass => "must_pass",
    }
}

/// Which case of [`EvaluationState`] an evaluation stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateKind {
    Running,
    Passed,
    Failed,
}

stored_words! {
    StateKind as "evaluation state" {
        Running => "running",
        Passed => "passed",
        Failed => "failed",
    }
}

impl From<StateKind> for EvaluationState {
    fn from(kind: StateKind) -> Self {
        match kind {
            StateKind::Running => Self::Running,
            StateKind::Passed => Self::Ended(Verdict::Passed),
            StateKind::Failed => Self::Ended(Verdict::Failed),
        }
    }
}

/// The word `state` is stored as.
pub(super) fn state_word(state: EvaluationState) -> &'static str {
    let kind = match state {
        EvaluationState::Running => StateKind::Running,
        EvaluationState::Ended(Verdict::Passed) => StateKind::Passed,
        EvaluationState::Ended(Verdict::Failed) => StateKind::Failed,
    };
    kind.word()
}

/// A set's row, as read.
pub(super) struct SetRecord {
    pub(super) workflow_id: Uuid,
    pub(super) cases: Value,
    pub(super) publish_gate: String,
    pub(super) edited_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl SetRecord {
    /// The set the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer reads,
    /// the gate is unknown, or the cases break a rule of a set.
    pub(super) fn into_set(self) -> Result<EvaluationSet<ResolvedTenant>, DomainError> {
        EvaluationSet::reconstitute(EvaluationSetRow {
            workflow_id: WorkflowId::from_uuid(self.workflow_id),
            cases: SET_CASES.open(self.cases)?,
            gate: SET.choice(&self.publish_gate)?,
            edited_by: EDITED_BY.open(self.edited_by)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A set, as its columns write it.
pub(super) struct SetColumns {
    pub(super) workflow_id: Uuid,
    pub(super) cases: Value,
    pub(super) publish_gate: &'static str,
    pub(super) edited_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl SetColumns {
    /// The columns `set` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out.
    pub(super) fn of(set: &EvaluationSet<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            workflow_id: *set.workflow_id().as_uuid(),
            cases: SET_CASES.seal(set.cases())?,
            publish_gate: set.gate().word(),
            edited_by: EDITED_BY.seal(set.edited_by())?,
            created_at: set.created_at(),
            updated_at: set.updated_at(),
        })
    }
}

/// An evaluation's row, as read.
pub(super) struct EvaluationRecord {
    pub(super) id: Uuid,
    pub(super) workflow_id: Uuid,
    pub(super) version: i32,
    pub(super) revision: OffsetDateTime,
    pub(super) cases: Value,
    pub(super) outcomes: Value,
    pub(super) state: String,
    pub(super) started_by: Value,
    pub(super) deadline: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl EvaluationRecord {
    /// The evaluation the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer reads,
    /// a word is unknown, or the columns contradict each other.
    pub(super) fn into_evaluation(self) -> Result<Evaluation<ResolvedTenant>, DomainError> {
        let kind: StateKind = EVALUATION.choice(&self.state)?;
        Evaluation::reconstitute(EvaluationRow {
            id: EvaluationId::from_uuid(self.id),
            workflow_id: WorkflowId::from_uuid(self.workflow_id),
            version: u32::try_from(self.version)
                .map_err(|_| DomainError::corrupt_row(EVALUATION.0, "a version below one"))?,
            revision: Revision::reviewed(self.revision),
            cases: CASES.open(self.cases)?,
            outcomes: OUTCOMES.open(self.outcomes)?,
            started_by: STARTED_BY.open(self.started_by)?,
            state: EvaluationState::from(kind),
            deadline: self.deadline,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// An evaluation, as its columns write it.
pub(super) struct EvaluationColumns {
    pub(super) id: Uuid,
    pub(super) workflow_id: Uuid,
    pub(super) version: i32,
    pub(super) revision: OffsetDateTime,
    pub(super) cases: Value,
    pub(super) outcomes: Value,
    pub(super) state: &'static str,
    pub(super) started_by: Value,
    pub(super) deadline: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl EvaluationColumns {
    /// The columns `evaluation` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out, or the version does not fit its column.
    pub(super) fn of(evaluation: &Evaluation<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: *evaluation.id().as_uuid(),
            workflow_id: *evaluation.workflow_id().as_uuid(),
            version: i32::try_from(evaluation.version()).map_err(DomainError::infra)?,
            revision: evaluation.revision().changed_at(),
            cases: CASES.seal(evaluation.cases())?,
            outcomes: OUTCOMES.seal(evaluation.outcomes())?,
            state: state_word(evaluation.state()),
            started_by: STARTED_BY.seal(evaluation.started_by())?,
            deadline: evaluation.deadline(),
            created_at: evaluation.created_at(),
            updated_at: evaluation.updated_at(),
        })
    }
}

/// What a look or the sweep changed, as its columns write it.
pub(super) struct ProgressColumns {
    pub(super) outcomes: Value,
    pub(super) state: &'static str,
    pub(super) updated_at: OffsetDateTime,
}

impl ProgressColumns {
    /// The columns a change to `evaluation` writes.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the outcomes cannot be
    /// written out.
    pub(super) fn of(evaluation: &Evaluation<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            outcomes: OUTCOMES.seal(evaluation.outcomes())?,
            state: state_word(evaluation.state()),
            updated_at: evaluation.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowData};
    use ianua_domain::domains::workflows::evaluation::case::{
        CaseName, CaseParams, EvaluationCase,
    };
    use ianua_domain::domains::workflows::evaluation::check::{Expectation, ExpectedText};
    use ianua_domain::domains::workflows::evaluation::outcome::CaseOutcome;
    use ianua_domain::types::{Human, HumanAccount, PersonKey, UserId};
    use serde_json::json;

    use super::*;

    /// Ann, as the person who saved a set or started an evaluation.
    fn ann() -> Human {
        Human::new(
            HumanAccount::User(UserId::from_uuid(Uuid::nil())),
            PersonKey::new("ann@acme.example").unwrap(),
        )
    }

    /// Who saved a set and who started an evaluation are written as their
    /// account and address, and read back.
    #[test]
    fn the_people_are_stored_in_their_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000000"},
            "person": "ann@acme.example"
        }});

        assert_eq!(EDITED_BY.seal(&ann()).unwrap(), stored);
        assert_eq!(STARTED_BY.seal(&ann()).unwrap(), stored);
        assert_eq!(STARTED_BY.open::<Human>(stored).unwrap(), ann());
    }

    /// A set's cases, and the copy an evaluation runs, are written with
    /// their name, input, sensitivity and checks, and read back.
    #[test]
    fn the_cases_are_stored_in_their_pinned_shape() {
        let case = EvaluationCase::new(CaseParams {
            name: CaseName::new("Refund asked").unwrap(),
            input: FlowData::map(vec![(
                FieldName::new("order").unwrap(),
                FlowData::number(7.0).unwrap(),
            )])
            .unwrap(),
            exposure: DataClassLevel::Internal,
            checks: vec![Expectation::Contains {
                at: DataPath::parse("tidy.answer").unwrap(),
                text: ExpectedText::new("refund").unwrap(),
            }],
        })
        .unwrap();
        let stored = json!({"v": 1, "value": [{
            "name": "Refund asked",
            "input": {"map": [["order", 7.0]]},
            "exposure": "Internal",
            "checks": [{"kind": "contains", "at": "tidy.answer", "text": "refund"}]
        }]});

        assert_eq!(SET_CASES.seal(std::slice::from_ref(&case)).unwrap(), stored);
        assert_eq!(CASES.seal(std::slice::from_ref(&case)).unwrap(), stored);
        assert_eq!(
            SET_CASES.open::<Vec<EvaluationCase>>(stored).unwrap(),
            vec![case]
        );
    }

    /// Each case's outcome is written by its state with its test run, and
    /// read back.
    #[test]
    fn the_outcomes_are_stored_in_their_pinned_shape() {
        let stored = json!({"v": 1, "value": [
            {"state": "waiting"},
            {"state": "passed", "execution": "00000000-0000-0000-0000-000000000001"}
        ]});

        let outcomes: Vec<CaseOutcome> = OUTCOMES.open(stored.clone()).unwrap();

        assert_eq!(OUTCOMES.seal(&outcomes).unwrap(), stored);
    }

    /// Every state reads back as the word it is written as.
    #[test]
    fn every_state_reads_back_from_its_word() {
        for state in [
            EvaluationState::Running,
            EvaluationState::Ended(Verdict::Passed),
            EvaluationState::Ended(Verdict::Failed),
        ] {
            let kind: StateKind = EVALUATION.choice(state_word(state)).unwrap();

            assert_eq!(EvaluationState::from(kind), state);
        }
    }

    /// A word no state is written as is refused as a corrupt row.
    #[test]
    fn an_unknown_state_is_corrupt() {
        assert!(matches!(
            EVALUATION.choice::<StateKind>("paused"),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
