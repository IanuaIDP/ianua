//! Checking a run's answer: the program of the sandbox version the run is
//! held to runs on the answer, in a locked-down sandbox as any version's
//! code does, and what it said is recorded on the run.
//!
//! A broken rule goes back to the model with what the check said, fenced
//! as data, and the model answers again within the run's tries. A version
//! that is gone or not ready, an answer too large to hand over, or no
//! sandbox to run in, is a check that did not run: the run fails, so no
//! answer leaves unchecked, and nothing waits or loops on a sandbox that
//! may never come.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::chat::ChatMessage;
use ianua_domain::domains::agents::execution::run::{AgentRun, CheckVerdict, RunStatus};
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::sandbox::agent::{check_input, verdict_of};
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{CodeRunId, UntrustedText};

use crate::error::AppError;
use crate::ports::workflows::{CodeRan, CodeRequest, CodeRunner, SandboxVersionStore};
use crate::services::ready_versions::ready_version;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::runs::driving::conversation::check_failed_message;
use crate::use_cases::agents::runs::driving::drive::Driving;
use crate::use_cases::agents::runs::driving::keeping::keep;
use crate::use_cases::agents::runs::driving::step::{Progress, Step, Turn};
use crate::use_cases::workflows::sandboxes::images::pulls::{ImagePulls, Pull};

/// What checks a run's answers: the sandbox versions whose programs check
/// them, and the sandbox they run in.
#[derive(Clone, ianua_macros::Fakes)]
pub struct AnswerChecks {
    /// The sandbox versions runs are held to.
    pub versions: Arc<dyn SandboxVersionStore>,
    /// Runs a check in a sandbox of its own, as code steps run.
    pub runner: Arc<dyn CodeRunner>,
    /// How a check's image is pulled, and whether it still may be.
    pub pulls: ImagePulls,
}

/// Runs the check on the answer the run holds and records what it said:
/// the run completes, fails, or goes on with what the check found shown to
/// its model.
///
/// # Errors
///
/// - `AppError::Domain` when no answer waits for its check.
/// - `AppError::Conflict` when the run was removed while it was driven.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::runs) async fn check_answer(
    turn: &Turn<'_>,
    progress: &mut Progress,
) -> Result<Step, AppError> {
    let verdict = verdict_on(turn.driving, &progress.run).await?;
    let feedback = match &verdict {
        CheckVerdict::Broken(said) | CheckVerdict::NotRun(said) => {
            check_failed_message(said.as_str())
        }
        CheckVerdict::Passed => String::new(),
    };
    progress
        .run
        .record_check(verdict)
        .map_err(AppError::from_domain)?;
    if progress.run.status() != RunStatus::Running {
        return Ok(Step::Settled);
    }
    progress.messages.push(ChatMessage::user(feedback));
    keep(turn, progress).await?;
    Ok(Step::Continue)
}

/// What the check `run` is held to says of the answer waiting for it.
async fn verdict_on(
    driving: &Driving<'_>,
    run: &AgentRun<ResolvedTenant>,
) -> Result<CheckVerdict, AppError> {
    let Some(due) = run.due_check() else {
        return Err(AppError::internal_msg(
            "no answer of the run waits for its check",
        ));
    };
    let checks = &driving.ports.checks;
    let Some(version) =
        ready_version(checks.versions.as_ref(), driving.tenant, &due.version).await?
    else {
        return Ok(not_run(
            "the check's sandbox version is gone or not ready to run",
        ));
    };
    let Ok(input) = check_input(&due) else {
        return Ok(not_run("the answer is larger than a check may be handed"));
    };
    run_check(checks, driving.tenant, &version, &input).await
}

/// What `version`'s check says of `input`, run in a sandbox of its own;
/// not run when its image may no longer be pulled or no sandbox takes it.
async fn run_check(
    checks: &AnswerChecks,
    tenant: &ScopedTenant,
    version: &SandboxVersion<ResolvedTenant>,
    input: &FlowData,
) -> Result<CheckVerdict, AppError> {
    let login = match checks.pulls.for_version(tenant, version).await? {
        Pull::Allowed(login) => login,
        Pull::Refused(refusal) => return Ok(not_run(refusal.reason())),
    };
    let request = CodeRequest {
        run_id: CodeRunId::new(),
        version,
        input,
        login: &login,
    };
    Ok(match checks.runner.run(tenant, request).await {
        CodeRan::Ran(outcome) => verdict_of(outcome),
        CodeRan::Unavailable(why) => CheckVerdict::NotRun(why),
    })
}

/// A check that did not run, for `why`.
fn not_run(why: &str) -> CheckVerdict {
    CheckVerdict::NotRun(UntrustedText::record(why))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::run::{
        CheckTries, RunCheck, RunStep, StartRunParams, StepOutcome,
    };
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::execution::step::CodeOutcome;
    use ianua_domain::domains::workflows::sandbox::agent::{BROKEN_FIELD, PASS_FIELD};
    use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
    use ianua_domain::test_support::builders::held_to;
    use ianua_domain::types::{ActionClass, AgentRunId};

    use super::*;
    use crate::test_support::Fake;
    use crate::test_support::workflows::{
        FakeCodeRunner, FakeSandboxVersionStore, built_version_of, python_sandbox,
    };
    use crate::use_cases::agents::runs::DrivePorts;
    use crate::use_cases::agents::runs::driving::harness::{
        Delegated, Harness, ScriptedModel, harness,
    };

    /// A built check version, and a run of Ann's held to it with `tries`.
    fn held_run(h: &Harness, tries: u8) -> (AgentRunId, SandboxVersion<ResolvedTenant>) {
        let version = built_version_of(&mut python_sandbox());
        let params = StartRunParams {
            granted_tools: Vec::new(),
            ..h.plan(&[ActionClass::Read], 10)
        };
        let started = h.start(params, Delegated::No);
        let check = RunCheck::Sandbox {
            version: *version.id(),
            tries: CheckTries::new(tries).unwrap(),
        };
        h.save_run(&held_to(h.stored_run(&started.run), check));
        (started.run, version)
    }

    /// The ports driving with `model`, checking against `versions` with a
    /// check answering `verdict`.
    fn checking(
        h: &Harness,
        model: ScriptedModel,
        versions: FakeSandboxVersionStore,
        verdict: CodeRan,
    ) -> DrivePorts {
        DrivePorts {
            checks: AnswerChecks {
                versions: Arc::new(versions),
                runner: Arc::new(FakeCodeRunner::answering(verdict)),
                pulls: ImagePulls::fake(),
            },
            ..h.ports(model)
        }
    }

    fn verdict(pass: bool) -> CodeRan {
        let fields = vec![
            (FieldName::new(PASS_FIELD).unwrap(), FlowData::bool(pass)),
            (
                FieldName::new(BROKEN_FIELD).unwrap(),
                FlowData::text("no promises of refunds").unwrap(),
            ),
        ];
        CodeRan::Ran(CodeOutcome::Succeeded(FlowData::map(fields).unwrap()))
    }

    /// The drafted reply passes the company's check. The run completes
    /// with it.
    #[test]
    fn an_answer_that_passes_its_check_completes_the_run() {
        let h = harness("{}");
        let (run, version) = held_run(&h, 3);
        let model = ScriptedModel::new(&["Dear Pat, we are looking into it."]);
        let versions = FakeSandboxVersionStore::holding(&version);

        h.drive_with(checking(&h, model, versions, verdict(true)), &run)
            .unwrap();

        let stored = h.stored_run(&run);
        assert_eq!(stored.status(), RunStatus::Completed);
        assert_eq!(stored.answer(), Some("Dear Pat, we are looking into it."));
    }

    /// The drafter promises a refund twice and gets two tries. The second
    /// conversation shows the model what the check found, and the run
    /// fails once the second answer breaks the rule too.
    #[test]
    fn an_agent_that_keeps_breaking_a_rule_fails_after_its_tries() {
        let h = harness("{}");
        let (run, version) = held_run(&h, 2);
        let model = ScriptedModel::new(&["Refund approved.", "Refund approved, really."]);
        let transcript = model.transcript();
        let versions = FakeSandboxVersionStore::holding(&version);

        h.drive_with(checking(&h, model, versions, verdict(false)), &run)
            .unwrap();

        let stored = h.stored_run(&run);
        assert_eq!(stored.status(), RunStatus::Failed);
        assert_eq!(stored.failed_checks(), 2);
        let second = transcript.lock().unwrap()[1].clone();
        let shown = second.last().map(|message| message.content().to_owned());
        assert!(shown.is_some_and(|said| said.contains("no promises of refunds")));
    }

    /// The check's version is gone. The answer is not let through: the run
    /// fails on its first try.
    #[test]
    fn an_answer_whose_check_cannot_run_fails_the_run() {
        let h = harness("{}");
        let (run, _) = held_run(&h, 3);
        let model = ScriptedModel::new(&["Refund approved."]);

        h.drive_with(
            checking(&h, model, FakeSandboxVersionStore::empty(), verdict(true)),
            &run,
        )
        .unwrap();

        let stored = h.stored_run(&run);
        assert_eq!(stored.status(), RunStatus::Failed);
        assert_eq!(stored.answer(), None);
        assert!(matches!(
            stored.steps().last().map(RunStep::outcome),
            Some(StepOutcome::CheckFailed(_))
        ));
    }
}
