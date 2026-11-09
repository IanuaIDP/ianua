//! A run and its steps as their rows hold them: read back into the
//! aggregate, and written out from it.

use ianua_app::ports::agents::RunSummary;
use ianua_domain::domains::agents::authority::delegation::ActingUnder;
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::{
    AgentRun, AgentRunRow, CheckTries, MAX_RUN_STEPS, PendingCall, RunCheck, RunGoal, RunState,
    RunStep, SpendCheck,
};
use ianua_domain::domains::agents::execution::tool::ToolName;
use ianua_domain::domains::agents::execution::usage::{ModelTokens, Spend};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    ActionClass, AgentId, AgentRunId, DelegationId, Initiator, ModelProviderId, SandboxVersionId,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::agents::run::chains::{depth_of, origin_from};
use crate::postgres::agents::run::initiators::{InitiatorColumns, initiator_from};
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const RUN: Stored = Stored("agent run");

const PENDING_CALL: Kept = Kept {
    entity: RUN.0,
    column: "pending_call",
    shape: 1,
};

const STEP: Kept = Kept {
    entity: RUN.0,
    column: "step",
    shape: 1,
};

/// A run's stored header and, for detail reads, its steps from the same
/// SQL snapshot. Summary reads supply an empty array without reading steps.
pub(super) struct RunRecord {
    pub(super) id: Uuid,
    pub(super) agent_id: Uuid,
    pub(super) provider_id: Uuid,
    pub(super) goal: String,
    pub(super) purpose: Vec<String>,
    pub(super) granted_tools: Vec<String>,
    pub(super) approval_classes: Vec<String>,
    pub(super) approval: String,
    pub(super) delegation_id: Option<Uuid>,
    pub(super) max_steps: i32,
    pub(super) spend_limit_micros: Option<i64>,
    pub(super) input_tokens: i64,
    pub(super) output_tokens: i64,
    pub(super) spent_micros: i64,
    pub(super) started_by_kind: String,
    pub(super) started_by_id: Uuid,
    pub(super) started_by_person: Option<String>,
    pub(super) exposure: String,
    pub(super) chain_depth: Option<i16>,
    pub(super) status: String,
    pub(super) pending_call: Option<Value>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
    pub(super) spend_check: Option<String>,
    pub(super) spend_check_micros: Option<i64>,
    pub(super) check_version_id: Option<Uuid>,
    pub(super) check_tries: Option<i16>,
    pub(super) steps: Vec<Value>,
}

impl RunRecord {
    /// Reads only the listing fields, checking their values without creating
    /// a run aggregate whose step history would be incomplete.
    pub(super) fn into_summary(mut self) -> Result<RunSummary, DomainError> {
        let state = self.state()?;
        let started_by = self.starter()?;
        let (max_steps, spend_limit, usage, spent) = self.budget()?;
        let spend_check = self.spend_check()?;
        self.ensure_summary_consistent(&state, spent, spend_limit)?;
        Ok(RunSummary {
            id: AgentRunId::from_uuid(self.id),
            agent_id: AgentId::from_uuid(self.agent_id),
            provider_id: ModelProviderId::from_uuid(self.provider_id),
            goal: RUN.value("goal", RunGoal::new(self.goal))?,
            purpose: IntentEnvelope::new(classes_from(&self.purpose)?),
            approval_classes: classes_from(&self.approval_classes)?,
            delegation_id: ActingUnder::from_stored(
                self.delegation_id.map(DelegationId::from_uuid),
            ),
            max_steps,
            spend_limit,
            spend_check,
            usage,
            spent,
            started_by,
            exposure: DataClassLevel::from_stored(&self.exposure)?,
            state,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// Refuses cross-field corruption visible without reading the trace.
    fn ensure_summary_consistent(
        &self,
        state: &RunState,
        spent: Spend,
        limit: Restriction<Spend>,
    ) -> Result<(), DomainError> {
        if !(1..=i64::from(MAX_RUN_STEPS)).contains(&i64::from(self.max_steps)) {
            return Err(DomainError::corrupt_row(RUN.0, "step limit out of range"));
        }
        self.ensure_summary_times(state)?;
        if !state.status().is_terminal() && limit.limit().is_some_and(|max| spent > *max) {
            return Err(DomainError::corrupt_row(
                RUN.0,
                "spent past its limit yet still going",
            ));
        }
        Ok(())
    }

    /// Refuses a summary whose update or approval predates its run.
    fn ensure_summary_times(&self, state: &RunState) -> Result<(), DomainError> {
        if self.created_at > self.updated_at {
            return Err(DomainError::corrupt_row(
                RUN.0,
                "changed before it was started",
            ));
        }
        if state
            .pending()
            .and_then(PendingCall::approved_at)
            .is_some_and(|at| at < self.created_at || at > self.updated_at)
        {
            return Err(DomainError::corrupt_row(
                RUN.0,
                "call approved outside run lifetime",
            ));
        }
        Ok(())
    }

    /// The run the record holds with its steps in order, rebuilt
    /// through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, a step or the held call does not read,
    /// or the run breaks a rule it keeps.
    pub(super) fn into_run(mut self) -> Result<AgentRun<ResolvedTenant>, DomainError> {
        let state = self.state()?;
        let started_by = self.starter()?;
        let (max_steps, spend_limit, usage, spent) = self.budget()?;
        let spend_check = self.spend_check()?;
        let check = self.check()?;
        let delegation = self.delegation_id.map(DelegationId::from_uuid);
        AgentRun::reconstitute(AgentRunRow {
            id: AgentRunId::from_uuid(self.id),
            agent_id: AgentId::from_uuid(self.agent_id),
            provider_id: ModelProviderId::from_uuid(self.provider_id),
            goal: RUN.value("goal", RunGoal::new(self.goal))?,
            purpose: IntentEnvelope::new(classes_from(&self.purpose)?),
            granted_tools: tools_from(self.granted_tools)?,
            approval_classes: classes_from(&self.approval_classes)?,
            approval: RUN.choice(&self.approval)?,
            delegation_id: ActingUnder::from_stored(delegation),
            max_steps,
            spend_limit,
            spend_check,
            usage,
            spent,
            started_by,
            exposure: DataClassLevel::from_stored(&self.exposure)?,
            origin: origin_from(RUN, self.chain_depth)?,
            steps: steps_from(self.steps)?,
            state,
            check,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// Where the run stands, with the call it holds, which this takes from
    /// the record.
    fn state(&mut self) -> Result<RunState, DomainError> {
        let held = self
            .pending_call
            .take()
            .map(|value| PENDING_CALL.open::<PendingCall>(value))
            .transpose()?;
        RunState::from_stored(RUN.choice(&self.status)?, held)
    }

    /// Where the run waits for a person before spending more.
    fn spend_check(&self) -> Result<SpendCheck, DomainError> {
        let mark = self.spend_check_micros.map(count_from).transpose()?;
        match (self.spend_check.as_deref(), mark) {
            (None, None) => Ok(SpendCheck::Off),
            (Some("ask_at"), Some(mark)) => Ok(SpendCheck::AskAt(Spend::from_micros(mark))),
            (Some("due"), Some(mark)) => Ok(SpendCheck::Due(Spend::from_micros(mark))),
            (Some("asked"), Some(mark)) => Ok(SpendCheck::Asked(Spend::from_micros(mark))),
            _ => Err(DomainError::corrupt_row(RUN.0, "an unknown spend check")),
        }
    }

    /// What the run's answers are held to: nothing, or a sandbox version's
    /// check with its tries.
    fn check(&self) -> Result<RunCheck, DomainError> {
        match (self.check_version_id, self.check_tries) {
            (None, None) => Ok(RunCheck::Unchecked),
            (Some(version), Some(tries)) => Ok(RunCheck::Sandbox {
                version: SandboxVersionId::from_uuid(version),
                tries: CheckTries::from_stored(u8::try_from(tries).map_err(|_| below_nothing())?)?,
            }),
            _ => Err(DomainError::corrupt_row(
                RUN.0,
                "a check without its version or tries",
            )),
        }
    }

    /// Who started the run, whose person this takes from the record.
    fn starter(&mut self) -> Result<Initiator, DomainError> {
        let person = self.started_by_person.take();
        initiator_from(RUN, &self.started_by_kind, self.started_by_id, person)
    }

    /// The run's step limit, its spend limit, the tokens it used and what
    /// they cost.
    fn budget(&self) -> Result<(u32, Restriction<Spend>, ModelTokens, Spend), DomainError> {
        let max_steps = u32::try_from(self.max_steps).map_err(|_| below_nothing())?;
        let usage = ModelTokens::new(
            count_from(self.input_tokens)?,
            count_from(self.output_tokens)?,
        );
        let spent = Spend::from_micros(count_from(self.spent_micros)?);
        Ok((
            max_steps,
            spend_limit_from(self.spend_limit_micros)?,
            usage,
            spent,
        ))
    }
}

/// The steps `steps` hold, each read through the domain's checks.
fn steps_from(steps: Vec<Value>) -> Result<Vec<RunStep>, DomainError> {
    steps.into_iter().map(|step| STEP.open(step)).collect()
}

/// The action classes a stored list of words names.
fn classes_from(words: &[String]) -> Result<Vec<ActionClass>, DomainError> {
    words
        .iter()
        .map(|word| ActionClass::from_stored(word))
        .collect()
}

/// The tools a stored list of names names.
fn tools_from(names: Vec<String>) -> Result<Vec<ToolName>, DomainError> {
    names
        .into_iter()
        .map(|name| RUN.value("granted tool", ToolName::new(name)))
        .collect()
}

/// The spend limit a stored column holds, or no limit when it is empty.
fn spend_limit_from(micros: Option<i64>) -> Result<Restriction<Spend>, DomainError> {
    let Some(micros) = micros else {
        return Ok(Restriction::Unrestricted);
    };
    Ok(Restriction::To(Spend::from_micros(count_from(micros)?)))
}

/// A count or an amount a stored column holds.
fn count_from(stored: i64) -> Result<u64, DomainError> {
    u64::try_from(stored).map_err(|_| below_nothing())
}

fn below_nothing() -> DomainError {
    DomainError::corrupt_row(RUN.0, "a count below nothing")
}

/// A run's columns, as they are written.
pub(super) struct RunColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) agent_id: &'a Uuid,
    pub(super) provider_id: &'a Uuid,
    pub(super) goal: &'a str,
    pub(super) purpose: Vec<String>,
    pub(super) granted_tools: Vec<String>,
    pub(super) approval_classes: Vec<String>,
    pub(super) approval: &'static str,
    pub(super) delegation_id: Option<Uuid>,
    pub(super) max_steps: i32,
    pub(super) spend_limit_micros: Option<i64>,
    pub(super) input_tokens: i64,
    pub(super) output_tokens: i64,
    pub(super) spent_micros: i64,
    pub(super) started_by: InitiatorColumns<'a>,
    pub(super) exposure: &'static str,
    pub(super) chain_depth: Option<i16>,
    pub(super) status: &'static str,
    pub(super) pending_call: Option<Value>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
    pub(super) spend_check: Option<&'static str>,
    pub(super) spend_check_micros: Option<i64>,
    pub(super) check_version_id: Option<Uuid>,
    pub(super) check_tries: Option<i16>,
}

impl<'a> RunColumns<'a> {
    /// The columns `run` is written to, its held call sealed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a count is past what a
    /// column holds, or the held call cannot be written out.
    pub(super) fn of(run: &'a AgentRun<ResolvedTenant>) -> Result<Self, DomainError> {
        let (spend_check, spend_check_micros) = spend_check_columns(run.spend_check())?;
        let (check_version_id, check_tries) = check_columns(run.check());
        Ok(Self {
            id: run.id().as_uuid(),
            agent_id: run.agent_id().as_uuid(),
            provider_id: run.provider_id().as_uuid(),
            goal: run.goal().as_str(),
            purpose: class_words(run.purpose().allowed()),
            granted_tools: tool_names(run.granted_tools()),
            approval_classes: class_words(run.approval_classes()),
            approval: run.approval().word(),
            delegation_id: run.delegation_id().delegation().map(|id| *id.as_uuid()),
            max_steps: i32::try_from(run.max_steps()).map_err(DomainError::infra)?,
            spend_limit_micros: limit_column(run.spend_limit())?,
            input_tokens: column_of(run.usage().input())?,
            output_tokens: column_of(run.usage().output())?,
            spent_micros: column_of(run.spent().micros())?,
            started_by: InitiatorColumns::of(run.started_by()),
            exposure: run.exposure().as_str(),
            chain_depth: depth_of(run.origin()),
            status: run.status().word(),
            pending_call: held_column(run.pending())?,
            created_at: run.created_at(),
            updated_at: run.updated_at(),
            spend_check,
            spend_check_micros,
            check_version_id,
            check_tries,
        })
    }
}

/// The version and tries a run's check is written to, both empty when its
/// answers are held to none.
fn check_columns(check: RunCheck) -> (Option<Uuid>, Option<i16>) {
    match check {
        RunCheck::Unchecked => (None, None),
        RunCheck::Sandbox { version, tries } => {
            (Some(*version.as_uuid()), Some(i16::from(tries.get())))
        }
    }
}

/// The word and the amount a spend check is written to, both empty when
/// the run never waits over spend.
fn spend_check_columns(
    check: SpendCheck,
) -> Result<(Option<&'static str>, Option<i64>), DomainError> {
    let word = match check {
        SpendCheck::Off => return Ok((None, None)),
        SpendCheck::AskAt(_) => "ask_at",
        SpendCheck::Due(_) => "due",
        SpendCheck::Asked(_) => "asked",
    };
    let micros = check
        .mark()
        .map(|mark| column_of(mark.micros()))
        .transpose()?;
    Ok((Some(word), micros))
}

/// The words `classes` are stored as.
fn class_words(classes: &[ActionClass]) -> Vec<String> {
    classes
        .iter()
        .map(|class| class.as_str().to_owned())
        .collect()
}

/// The names `tools` are stored as.
fn tool_names(tools: &[ToolName]) -> Vec<String> {
    tools.iter().map(|tool| tool.as_str().to_owned()).collect()
}

/// The column a count or an amount is written to.
fn column_of(count: u64) -> Result<i64, DomainError> {
    i64::try_from(count).map_err(DomainError::infra)
}

/// The column a spend limit is written to, empty for no limit.
fn limit_column(limit: Restriction<Spend>) -> Result<Option<i64>, DomainError> {
    limit
        .limit()
        .map(|spend| column_of(spend.micros()))
        .transpose()
}

/// The column the call a run holds is written to, sealed.
fn held_column(held: Option<&PendingCall>) -> Result<Option<Value>, DomainError> {
    held.map(|call| PENDING_CALL.seal(call)).transpose()
}

/// The steps of a run past `latest`, the last one already stored, as one
/// statement writes them: their numbers, and each step sealed.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a step cannot be written out.
pub(super) fn steps_after(
    run: &AgentRun<ResolvedTenant>,
    latest: i32,
) -> Result<(Vec<i32>, Vec<Value>), DomainError> {
    let mut numbers = Vec::new();
    let mut sealed = Vec::new();
    for step in run.steps() {
        let seq = i32::try_from(step.seq()).map_err(DomainError::infra)?;
        if seq <= latest {
            continue;
        }
        numbers.push(seq);
        sealed.push(STEP.seal(step)?);
    }
    Ok((numbers, sealed))
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use serde_json::json;

    use super::*;

    /// A call held for approval is written in the shape pinned here, and a
    /// row in that shape reads back the same.
    #[test]
    fn a_held_call_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "tool": "delete_order",
            "arguments": "{\"id\":1}",
            "class": "Delete",
            "at_step": 3,
            "approved": "Awaiting",
        }});

        let read: PendingCall = PENDING_CALL.open(stored.clone()).unwrap();

        assert_eq!(read.tool(), "delete_order");
        assert_eq!(read.at_step(), 3);
        assert!(!read.is_approved());
        assert_eq!(PENDING_CALL.seal(&read).unwrap(), stored);
    }

    /// An approved call keeps the time the run took the approval, in the
    /// shape pinned here.
    #[test]
    fn an_approved_call_is_stored_with_its_time() {
        let stored = json!({"v": 1, "value": {
            "tool": "delete_order",
            "arguments": "{}",
            "class": "Delete",
            "at_step": 1,
            "approved": {"Approved": "2027-01-15 08:00:00.0 +00:00:00"},
        }});

        let read: PendingCall = PENDING_CALL.open(stored.clone()).unwrap();

        assert_eq!(
            read.approved_at(),
            Some(crate::test_support::rows::pinned(0))
        );
        assert_eq!(PENDING_CALL.seal(&read).unwrap(), stored);
    }

    /// A step is written in the shape pinned here, a tool call with its
    /// tool and arguments apart and a model answer with neither, and a row
    /// in that shape reads back the same.
    #[test]
    fn a_step_is_stored_in_its_pinned_shape() {
        let called = json!({"v": 1, "value": {
            "seq": 1,
            "tool": "get_order",
            "arguments": "{\"id\":1}",
            "outcome": {"Allowed": "{\"total\":1}"},
            "read": "Internal",
            "at": "2027-01-15 08:00:01.0 +00:00:00",
        }});
        let answered = json!({"v": 1, "value": {
            "seq": 2,
            "tool": null,
            "arguments": null,
            "outcome": {"Answered": "done"},
            "read": "Public",
            "at": "2027-01-15 08:00:02.0 +00:00:00",
        }});

        let call: RunStep = STEP.open(called.clone()).unwrap();
        let answer: RunStep = STEP.open(answered.clone()).unwrap();

        assert_eq!(call.tool(), Some("get_order"));
        assert_eq!(answer.tool(), None);
        assert_eq!(STEP.seal(&call).unwrap(), called);
        assert_eq!(STEP.seal(&answer).unwrap(), answered);
    }
}
