//! A trial as its row holds it: read back into the aggregate, and written
//! out from it.
//!
//! How far it got is kept as a word, with what the code gave back once it
//! succeeded, or the failure's word and the end of its error once it failed.

use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use ianua_domain::domains::workflows::sandbox::trial::{SandboxTrial, SandboxTrialRow, TrialState};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{SandboxId, SandboxTrialId, SandboxVersionId, UntrustedText};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _, stored_words};

const TRIAL: Stored = Stored("sandbox trial");

const INPUT: Kept = Kept {
    entity: TRIAL.0,
    column: "input",
    shape: 1,
};

const OUTPUT: Kept = Kept {
    entity: TRIAL.0,
    column: "output",
    shape: 1,
};

const STARTED_BY: Kept = Kept {
    entity: TRIAL.0,
    column: "started_by",
    shape: 1,
};

/// Which case of [`TrialState`] a trial stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateKind {
    Running,
    Succeeded,
    Failed,
}

stored_words! {
    StateKind as "trial state" {
        Running => "running",
        Succeeded => "succeeded",
        Failed => "failed",
    }
}

/// Which case of [`CodeFailure`] a failed trial stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    Raised,
    TimedOut,
    OutOfMemory,
    Unreadable,
    NotRun,
}

stored_words! {
    FailureKind as "trial failure" {
        Raised => "raised",
        TimedOut => "timed_out",
        OutOfMemory => "out_of_memory",
        Unreadable => "unreadable",
        NotRun => "not_run",
    }
}

/// A trial's row, as read.
pub(super) struct TrialRecord {
    pub(super) id: Uuid,
    pub(super) sandbox_id: Uuid,
    pub(super) version_id: Uuid,
    pub(super) input: Value,
    pub(super) state: String,
    pub(super) output: Option<Value>,
    pub(super) failure: Option<String>,
    pub(super) failure_detail: Option<String>,
    pub(super) started_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl TrialRecord {
    /// The trial the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer reads,
    /// a word is unknown, or the columns contradict each other.
    pub(super) fn into_trial(self) -> Result<SandboxTrial<ResolvedTenant>, DomainError> {
        let state = state_from(EndColumns {
            kind: TRIAL.choice(&self.state)?,
            output: self.output,
            failure: self.failure,
            detail: self.failure_detail,
        })?;
        SandboxTrial::reconstitute(SandboxTrialRow {
            id: SandboxTrialId::from_uuid(self.id),
            sandbox_id: SandboxId::from_uuid(self.sandbox_id),
            version_id: SandboxVersionId::from_uuid(self.version_id),
            input: INPUT.open(self.input)?,
            state,
            started_by: STARTED_BY.open(self.started_by)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// What the end columns of a row hold.
struct EndColumns {
    kind: StateKind,
    output: Option<Value>,
    failure: Option<String>,
    detail: Option<String>,
}

/// How far the trial a row's columns hold got.
fn state_from(read: EndColumns) -> Result<TrialState, DomainError> {
    match (read.kind, read.output, read.failure) {
        (StateKind::Running, None, None) => Ok(TrialState::Running),
        (StateKind::Succeeded, Some(output), None) => Ok(TrialState::Ended(
            CodeOutcome::Succeeded(OUTPUT.open::<FlowData>(output)?),
        )),
        (StateKind::Failed, None, Some(failure)) => {
            let failure = failure_from(TRIAL.choice(&failure)?, read.detail)?;
            Ok(TrialState::Ended(CodeOutcome::Failed(failure)))
        }
        (StateKind::Running | StateKind::Succeeded | StateKind::Failed, ..) => Err(
            DomainError::corrupt_row(TRIAL.0, "an end its columns contradict"),
        ),
    }
}

/// The failure a row names, with the detail it keeps.
fn failure_from(kind: FailureKind, detail: Option<String>) -> Result<CodeFailure, DomainError> {
    match (kind, detail) {
        (FailureKind::Raised, Some(detail)) => {
            Ok(CodeFailure::Raised(UntrustedText::record(&detail)))
        }
        (FailureKind::NotRun, Some(detail)) => {
            Ok(CodeFailure::NotRun(UntrustedText::record(&detail)))
        }
        (FailureKind::TimedOut, None) => Ok(CodeFailure::TimedOut),
        (FailureKind::OutOfMemory, None) => Ok(CodeFailure::OutOfMemory),
        (FailureKind::Unreadable, None) => Ok(CodeFailure::Unreadable),
        (
            FailureKind::Raised
            | FailureKind::NotRun
            | FailureKind::TimedOut
            | FailureKind::OutOfMemory
            | FailureKind::Unreadable,
            _,
        ) => Err(DomainError::corrupt_row(
            TRIAL.0,
            "a failure whose detail its kind contradicts",
        )),
    }
}

/// A trial's end, as its columns write it.
pub(super) struct EndWritten {
    pub(super) state: &'static str,
    pub(super) output: Option<Value>,
    pub(super) failure: Option<&'static str>,
    pub(super) failure_detail: Option<String>,
}

impl EndWritten {
    /// The columns `state` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the output cannot be
    /// written out.
    pub(super) fn of(state: &TrialState) -> Result<Self, DomainError> {
        let running = Self {
            state: StateKind::Running.word(),
            output: None,
            failure: None,
            failure_detail: None,
        };
        Ok(match state {
            TrialState::Running => running,
            TrialState::Ended(CodeOutcome::Succeeded(output)) => Self {
                state: StateKind::Succeeded.word(),
                output: Some(OUTPUT.seal(output)?),
                ..running
            },
            TrialState::Ended(CodeOutcome::Failed(failure)) => {
                let (kind, detail) = failure_columns(failure);
                Self {
                    state: StateKind::Failed.word(),
                    failure: Some(kind.word()),
                    failure_detail: detail,
                    ..running
                }
            }
        })
    }
}

/// The word and detail `failure` is written as.
fn failure_columns(failure: &CodeFailure) -> (FailureKind, Option<String>) {
    match failure {
        CodeFailure::Raised(detail) => (FailureKind::Raised, Some(detail.as_str().to_owned())),
        CodeFailure::NotRun(detail) => (FailureKind::NotRun, Some(detail.as_str().to_owned())),
        CodeFailure::TimedOut => (FailureKind::TimedOut, None),
        CodeFailure::OutOfMemory => (FailureKind::OutOfMemory, None),
        CodeFailure::Unreadable => (FailureKind::Unreadable, None),
    }
}

/// A trial's columns, as they are written when it starts.
pub(super) struct TrialColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) sandbox_id: &'a Uuid,
    pub(super) version_id: &'a Uuid,
    pub(super) input: Value,
    pub(super) end: EndWritten,
    pub(super) started_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> TrialColumns<'a> {
    /// The columns `trial` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out.
    pub(super) fn of(trial: &'a SandboxTrial<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: trial.id().as_uuid(),
            sandbox_id: trial.sandbox_id().as_uuid(),
            version_id: trial.version_id().as_uuid(),
            input: INPUT.seal(trial.input())?,
            end: EndWritten::of(trial.state())?,
            started_by: STARTED_BY.seal(trial.started_by())?,
            created_at: trial.created_at(),
            updated_at: trial.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::types::Human;
    use serde_json::json;

    use super::*;
    use crate::test_support::rows::workflows::{ann, trigger_data};

    /// The sample input a trial is given is written in the shape pinned
    /// here, and reads back.
    #[test]
    fn the_input_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {"map": [["ok", true]]}});

        assert_eq!(INPUT.seal(&trigger_data()).unwrap(), stored);
        assert_eq!(INPUT.open::<FlowData>(stored).unwrap(), trigger_data());
    }

    /// What the code gave back is written in the shape pinned here, and
    /// reads back.
    #[test]
    fn the_output_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {"map": [["ok", true]]}});

        assert_eq!(OUTPUT.seal(&trigger_data()).unwrap(), stored);
        assert_eq!(OUTPUT.open::<FlowData>(stored).unwrap(), trigger_data());
    }

    /// The person who started a trial is written as their account and
    /// address, and read back.
    #[test]
    fn the_starter_is_stored_in_their_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000a11"},
            "person": "ann@acme.example"
        }});

        assert_eq!(STARTED_BY.seal(&ann()).unwrap(), stored);
        assert_eq!(STARTED_BY.open::<Human>(stored).unwrap(), ann());
    }

    /// Each way a trial can end is written and read back as it was.
    #[test]
    fn every_end_reads_back() {
        let ends = [
            TrialState::Running,
            TrialState::Ended(CodeOutcome::Succeeded(FlowData::bool(true))),
            TrialState::Ended(CodeOutcome::Failed(CodeFailure::Raised(
                UntrustedText::record("ValueError: no title"),
            ))),
            TrialState::Ended(CodeOutcome::Failed(CodeFailure::NotRun(
                UntrustedText::record("no sandbox"),
            ))),
            TrialState::Ended(CodeOutcome::Failed(CodeFailure::TimedOut)),
            TrialState::Ended(CodeOutcome::Failed(CodeFailure::OutOfMemory)),
            TrialState::Ended(CodeOutcome::Failed(CodeFailure::Unreadable)),
        ];

        for end in ends {
            let written = EndWritten::of(&end).unwrap();
            let read = state_from(EndColumns {
                kind: TRIAL.choice(written.state).unwrap(),
                output: written.output,
                failure: written.failure.map(str::to_owned),
                detail: written.failure_detail,
            })
            .unwrap();
            assert_eq!(read, end);
        }
    }

    /// Reading a success without output or a timeout with failure detail
    /// returns an infrastructure error.
    #[test]
    fn contradicting_columns_are_refused() {
        let no_output = state_from(EndColumns {
            kind: StateKind::Succeeded,
            output: None,
            failure: None,
            detail: None,
        });
        let detailed = failure_from(FailureKind::TimedOut, Some("late".to_owned()));

        assert!(matches!(no_output, Err(DomainError::Infrastructure(_))));
        assert!(matches!(detailed, Err(DomainError::Infrastructure(_))));
    }
}
