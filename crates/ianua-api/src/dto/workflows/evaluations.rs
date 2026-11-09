//! Evaluations on the wire: the body that saves a workflow's sample cases,
//! the set as read, and an evaluation with what each case came to.

use ianua_app::use_cases::workflows::evaluations::{
    GetRequest, GetSetRequest, ListRequest, SaveSetRequest, StartRequest,
};
use ianua_domain::domains::workflows::data::DataPath;
use ianua_domain::domains::workflows::evaluation::case::{CaseName, CaseParams, EvaluationCase};
use ianua_domain::domains::workflows::evaluation::check::{Expectation, ExpectedText, TextPattern};
use ianua_domain::domains::workflows::evaluation::outcome::{CaseOutcome, Difference};
use ianua_domain::domains::workflows::evaluation::run::EvaluationState;
use ianua_domain::domains::workflows::evaluation::set::PublishGate;
use ianua_domain::domains::workflows::evaluation::view::{
    CaseView, EvaluationView, OutcomeView, SetView,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{EvaluationId, WorkflowExecutionId, WorkflowId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::workflows::data::{data_class, flow_data, json_of, person_label};
use crate::error::ApiError;

/// The read asked for: evaluation `evaluation_id` of workflow `workflow_id`.
#[must_use]
pub(crate) fn evaluation_reading(
    workflow_id: WorkflowId,
    evaluation_id: EvaluationId,
) -> GetRequest {
    GetRequest {
        workflow_id,
        evaluation_id,
    }
}

/// The read asked for: the set of workflow `workflow_id`.
#[must_use]
pub(crate) fn evaluation_set_reading(workflow_id: WorkflowId) -> GetSetRequest {
    GetSetRequest { workflow_id }
}

/// The listing asked for: the latest evaluations of workflow `workflow_id`.
#[must_use]
pub(crate) fn evaluation_listing(workflow_id: WorkflowId) -> ListRequest {
    ListRequest { workflow_id }
}

/// The start asked for: an evaluation of workflow `workflow_id`.
#[must_use]
pub(crate) fn evaluation_start(workflow_id: WorkflowId) -> StartRequest {
    StartRequest { workflow_id }
}

/// Request body for saving a workflow's sample cases.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SaveEvaluationSetBody {
    /// The cases, each named once, at most 50. An empty list keeps no case.
    pub cases: Vec<CaseBody>,
    /// `must_pass` holds publishing back until the draft's last evaluation
    /// passed every case; `off`, the default, never does.
    #[serde(default)]
    pub publish_gate: Option<String>,
}

/// One sample case.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CaseBody {
    /// What the author calls it, unique within the set.
    pub name: String,
    /// The trigger data its test run starts with: any JSON value.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub input: Value,
    /// The most sensitive data in the input, such as `internal`.
    pub exposure: String,
    /// The checks its results must pass, one to ten.
    pub checks: Vec<CheckBody>,
}

/// One check of a case's results.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct CheckBody {
    /// `equals`: the value at `at` is exactly `value`. `contains`: its text
    /// contains `text`. `matches`: its whole text matches `pattern`, where
    /// `*` is any run of characters and `?` any one.
    pub kind: String,
    /// Where in the results the value is read: `trigger` for the input,
    /// or a step's key and the fields under it, such as `summarise.answer`.
    pub at: String,
    /// The value expected, for `equals`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub value: Option<Value>,
    /// The text expected within, for `contains`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The pattern expected, for `matches`, at most 200 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

impl SaveEvaluationSetBody {
    /// Saving these cases as `workflow_id`'s set.
    ///
    /// # Errors
    ///
    /// - `422` when a case, a check or the gate is not valid.
    pub(crate) fn request(self, workflow_id: WorkflowId) -> Result<SaveSetRequest, ApiError> {
        let gate = publish_gate(self.publish_gate.as_deref())?;
        let cases = self
            .cases
            .into_iter()
            .map(CaseBody::case)
            .collect::<Result<_, _>>()?;
        Ok(SaveSetRequest {
            workflow_id,
            cases,
            gate,
        })
    }
}

impl CaseBody {
    /// The case this body describes.
    fn case(self) -> Result<EvaluationCase, ApiError> {
        let checks = self
            .checks
            .into_iter()
            .map(CheckBody::expectation)
            .collect::<Result<_, _>>()?;
        EvaluationCase::new(CaseParams {
            name: CaseName::new(self.name).map_err(ApiError::validation)?,
            input: flow_data(&self.input)?,
            exposure: data_class(&self.exposure)?,
            checks,
        })
        .map_err(ApiError::validation)
    }
}

impl CheckBody {
    /// The check this body describes.
    fn expectation(self) -> Result<Expectation, ApiError> {
        let at = DataPath::parse(&self.at).map_err(ApiError::validation)?;
        match (self.kind.as_str(), self.value, self.text, self.pattern) {
            ("equals", Some(value), None, None) => Ok(Expectation::Equals {
                at,
                value: flow_data(&value)?,
            }),
            ("contains", None, Some(text), None) => Ok(Expectation::Contains {
                at,
                text: ExpectedText::new(text).map_err(ApiError::validation)?,
            }),
            ("matches", None, None, Some(pattern)) => Ok(Expectation::Matches {
                at,
                pattern: TextPattern::new(pattern).map_err(ApiError::validation)?,
            }),
            _ => Err(ApiError::validation(message!(
                "api-a-check-names-its-kind-and-what-it-expects",
                "a check is `equals` with a value, `contains` with a text, or `matches` with a pattern"
            ))),
        }
    }

    /// `check` as the wire shows it.
    fn of(check: &Expectation) -> Self {
        let empty = Self {
            kind: String::new(),
            at: check.at().to_string(),
            value: None,
            text: None,
            pattern: None,
        };
        match check {
            Expectation::Equals { value, .. } => Self {
                kind: "equals".to_owned(),
                value: Some(json_of(value)),
                ..empty
            },
            Expectation::Contains { text, .. } => Self {
                kind: "contains".to_owned(),
                text: Some(text.as_str().to_owned()),
                ..empty
            },
            Expectation::Matches { pattern, .. } => Self {
                kind: "matches".to_owned(),
                pattern: Some(pattern.as_str().to_owned()),
                ..empty
            },
        }
    }
}

/// The gate named `value`; off when none is named.
fn publish_gate(value: Option<&str>) -> Result<PublishGate, ApiError> {
    match value {
        None => Ok(PublishGate::Off),
        Some(named) if named == PublishGate::Off.as_str() => Ok(PublishGate::Off),
        Some(named) if named == PublishGate::MustPass.as_str() => Ok(PublishGate::MustPass),
        Some(_) => Err(ApiError::validation(message!(
            "api-a-publish-gate-is-off-or-must-pass",
            "a publish gate is `off` or `must_pass`"
        ))),
    }
}

/// One case, as the caller may read it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CaseResponse {
    /// What the author calls it.
    pub name: String,
    /// The most sensitive data in its input.
    pub exposure: String,
    /// Whether its input is above the caller's clearance, so only its
    /// name and `exposure` are shown.
    pub withheld: bool,
    /// The trigger data its test run starts with, unless withheld.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub input: Option<Value>,
    /// The checks its results must pass, unless withheld.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<CheckBody>>,
}

impl From<CaseView<'_>> for CaseResponse {
    fn from(view: CaseView<'_>) -> Self {
        match view {
            CaseView::Shown(case) => Self {
                name: case.name().as_str().to_owned(),
                exposure: case.exposure().as_str().to_owned(),
                withheld: false,
                input: Some(json_of(case.input())),
                checks: Some(case.checks().iter().map(CheckBody::of).collect()),
            },
            CaseView::Withheld { name, exposure } => Self {
                name: name.as_str().to_owned(),
                exposure: exposure.as_str().to_owned(),
                withheld: true,
                input: None,
                checks: None,
            },
        }
    }
}

/// A workflow's sample cases and its publishing gate.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EvaluationSetResponse {
    /// The workflow whose versions the cases try.
    pub workflow_id: Uuid,
    /// `off` or `must_pass`.
    pub publish_gate: String,
    /// The sample cases, each with its input and checks, in the order saved.
    pub cases: Vec<CaseResponse>,
    /// The person who last saved it, as `<kind>:<uuid>`.
    pub edited_by: String,
    /// When it was last saved.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<SetView<ResolvedTenant>> for EvaluationSetResponse {
    fn from(set: SetView<ResolvedTenant>) -> Self {
        Self {
            workflow_id: *set.workflow_id().as_uuid(),
            publish_gate: set.gate().as_str().to_owned(),
            cases: set.cases().map(CaseResponse::from).collect(),
            edited_by: person_label(set.edited_by()),
            updated_at: set.updated_at(),
        }
    }
}

/// One thing that differed in a failed case.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DifferenceResponse {
    /// `run_ended`: the test run did not succeed. `check`: a check did not
    /// hold.
    pub kind: String,
    /// How the run ended, for `run_ended`: `failed`, `cancelled` or
    /// `timed_out`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_end: Option<String>,
    /// Which of the case's checks, counted from zero, for `check`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<usize>,
    /// What was found at the check's path, cut to 500 characters; left out
    /// when nothing was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<String>,
}

impl From<&Difference> for DifferenceResponse {
    fn from(difference: &Difference) -> Self {
        match difference {
            Difference::RunEnded { end } => Self {
                kind: "run_ended".to_owned(),
                run_end: Some(end.as_str().to_owned()),
                check: None,
                found: None,
            },
            Difference::Check { index, found } => Self {
                kind: "check".to_owned(),
                run_end: None,
                check: Some(*index),
                found: found.as_ref().map(|found| found.as_str().to_owned()),
            },
        }
    }
}

/// What one case of an evaluation came to.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CaseResultResponse {
    /// The sample case this result is for: its input and checks.
    pub case: CaseResponse,
    /// `waiting`, `running`, `passed`, `failed` or `not_run`.
    pub outcome: String,
    /// The case's test run, once it started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<Uuid>,
    /// Why it could not run, for `not_run`: `refused`,
    /// `evaluator_may_not_act`, `draft_changed` or `out_of_time`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What differed, for `failed`, unless the run held data above the
    /// caller's clearance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub differences: Option<Vec<DifferenceResponse>>,
    /// How sensitive the data its run held is, when `differences` is
    /// withheld for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withheld_exposure: Option<String>,
}

impl CaseResultResponse {
    /// `case` and what it came to, as the caller may read them.
    fn of(case: CaseView<'_>, outcome: OutcomeView<'_>) -> Self {
        let empty = Self {
            case: CaseResponse::from(case),
            outcome: String::new(),
            execution_id: None,
            reason: None,
            differences: None,
            withheld_exposure: None,
        };
        let OutcomeView::Shown(shown) = outcome else {
            return withheld(empty, outcome);
        };
        shown_outcome(empty, shown)
    }
}

/// `empty` with all of what `shown` came to.
fn shown_outcome(empty: CaseResultResponse, shown: &CaseOutcome) -> CaseResultResponse {
    match shown {
        CaseOutcome::Waiting => CaseResultResponse {
            outcome: "waiting".to_owned(),
            ..empty
        },
        CaseOutcome::Running { execution } => with_run(empty, "running", execution),
        CaseOutcome::Passed { execution } => with_run(empty, "passed", execution),
        CaseOutcome::Failed {
            execution,
            differences,
            ..
        } => CaseResultResponse {
            outcome: "failed".to_owned(),
            execution_id: Some(*execution.as_uuid()),
            differences: Some(differences.iter().map(DifferenceResponse::from).collect()),
            ..empty
        },
        CaseOutcome::NotRun { reason } => CaseResultResponse {
            outcome: "not_run".to_owned(),
            reason: Some(reason.as_str().to_owned()),
            ..empty
        },
    }
}

/// `empty` as `outcome`, under way or passed in the test run `execution`.
fn with_run(
    empty: CaseResultResponse,
    outcome: &str,
    execution: &WorkflowExecutionId,
) -> CaseResultResponse {
    CaseResultResponse {
        outcome: outcome.to_owned(),
        execution_id: Some(*execution.as_uuid()),
        ..empty
    }
}

/// `empty` as a failed case whose differences `outcome` withholds.
fn withheld(empty: CaseResultResponse, outcome: OutcomeView<'_>) -> CaseResultResponse {
    let OutcomeView::Withheld {
        execution,
        exposure,
    } = outcome
    else {
        return empty;
    };
    CaseResultResponse {
        outcome: "failed".to_owned(),
        execution_id: Some(*execution.as_uuid()),
        withheld_exposure: Some(exposure.as_str().to_owned()),
        ..empty
    }
}

/// One evaluation of a workflow version against its sample cases.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EvaluationResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The workflow it tries.
    pub workflow_id: Uuid,
    /// The version it tries.
    pub version: u32,
    /// The revision of that version it tries, as a publisher hands it back.
    #[serde(with = "time::serde::rfc3339")]
    pub revision: OffsetDateTime,
    /// `running` while cases wait or run, then `passed` when every case
    /// passed, or `failed`.
    pub status: String,
    /// What each case came to, in the set's order.
    pub cases: Vec<CaseResultResponse>,
    /// The person who started it, as `<kind>:<uuid>`.
    pub started_by: String,
    /// When every case still open could not run.
    #[serde(with = "time::serde::rfc3339")]
    pub deadline: OffsetDateTime,
    /// When it started.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<EvaluationView<ResolvedTenant>> for EvaluationResponse {
    fn from(evaluation: EvaluationView<ResolvedTenant>) -> Self {
        Self {
            id: *evaluation.id().as_uuid(),
            workflow_id: *evaluation.workflow_id().as_uuid(),
            version: evaluation.version(),
            revision: evaluation.revision().changed_at(),
            status: status_of(evaluation.state()).to_owned(),
            cases: evaluation
                .cases()
                .map(|(case, outcome)| CaseResultResponse::of(case, outcome))
                .collect(),
            started_by: person_label(evaluation.started_by()),
            deadline: evaluation.deadline(),
            created_at: evaluation.created_at(),
            updated_at: evaluation.updated_at(),
        }
    }
}

/// The wire's name for where an evaluation stands.
fn status_of(state: EvaluationState) -> &'static str {
    match state {
        EvaluationState::Running => "running",
        EvaluationState::Ended(verdict) => verdict.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::evaluation::outcome::Verdict;
    use serde_json::json;

    use super::*;

    /// The expectation the check body `body` makes, as a request would.
    fn check(body: Value) -> Result<Expectation, ApiError> {
        serde_json::from_value::<CheckBody>(body)
            .unwrap()
            .expectation()
    }

    /// Each kind of check reads with what it expects; a kind with the
    /// wrong field, or none, is refused.
    #[test]
    fn a_check_reads_by_its_kind() {
        let equals = check(json!({"kind": "equals", "at": "tidy.seen", "value": true}));
        let contains = check(json!({"kind": "contains", "at": "tidy.answer", "text": "refund"}));
        let matches = check(json!({"kind": "matches", "at": "tidy.answer", "pattern": "INC-*"}));
        let mixed = check(json!({"kind": "contains", "at": "tidy.answer", "value": "refund"}));

        assert!(matches!(equals, Ok(Expectation::Equals { .. })));
        assert!(matches!(contains, Ok(Expectation::Contains { .. })));
        assert!(matches!(matches, Ok(Expectation::Matches { .. })));
        assert!(mixed.is_err());
    }

    /// The gate is off unless the body says `must_pass`; any other word is
    /// refused.
    #[test]
    fn the_gate_is_off_by_default() {
        assert_eq!(publish_gate(None).ok(), Some(PublishGate::Off));
        assert_eq!(
            publish_gate(Some("must_pass")).ok(),
            Some(PublishGate::MustPass)
        );
        assert!(publish_gate(Some("always")).is_err());
    }

    /// A check reads back on the wire in the shape it was sent.
    #[test]
    fn a_check_reads_back_as_sent() {
        let sent = json!({"kind": "contains", "at": "tidy.answer", "text": "refund"});

        let shown = CheckBody::of(&check(sent.clone()).ok().unwrap());

        assert_eq!(serde_json::to_value(shown).unwrap(), sent);
    }

    /// An ended evaluation's status is its verdict.
    #[test]
    fn an_ended_status_is_its_verdict() {
        assert_eq!(status_of(EvaluationState::Running), "running");
        assert_eq!(status_of(EvaluationState::Ended(Verdict::Passed)), "passed");
    }
}
