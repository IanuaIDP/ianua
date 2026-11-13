//! The steps a worker drives a run through.
//!
//! Each step either makes the call a person approved, or asks the model and
//! acts on its answer. The model is untrusted: whatever it asks for goes
//! through the run's own call check, and a refusal is recorded and fed back
//! so it can change course. Between steps the worker checks the kill switch,
//! whether a person paused the run, the agent's standing and its own lease.
//! Every model call's usage is counted on the run, which stops once it
//! spent its limit.

use ianua_domain::domains::agents::execution::chat::{ChatMessage, Completion, CompletionRequest};
use ianua_domain::domains::agents::execution::model_provider::ModelProvider;
use ianua_domain::domains::agents::execution::run::{
    Admission, AgentRun, CallRefusal, CancelOrder, ResolvedCall, RunStatus, ToolArguments, ToolCall,
};
use ianua_domain::domains::agents::execution::tool::{AgentTool, PathValue, PathValues};
use ianua_domain::domains::agents::execution::usage::ModelUsage;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::oversight::approval::ApprovalAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ActorRef;

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{
    ModelCharge, ModelFailure, ModelTarget, RunVersion, ToolInvocationContext,
};
use crate::use_cases::agents::runs::control::stopping::{Withdrawal, withdrawn_approvals};
use crate::use_cases::agents::runs::driving::checking::check_answer;
use crate::use_cases::agents::runs::driving::conversation::{parse_tool_call, tool_result_message};
use crate::use_cases::agents::runs::driving::drive::Driving;
use crate::use_cases::agents::runs::driving::keeping::{keep, moved_on};
use crate::use_cases::agents::runs::driving::toolbox::Toolbox;

/// The most tokens a model step may answer with. A model that thinks
/// first is given room for its thinking on top by its adapter, or no cap
/// at all on a self-hosted server.
const MAX_STEP_TOKENS: u32 = 512;

/// What a run is driven with: the worker's ports, the tools it may reach
/// for and the model it reasons with.
pub(in crate::use_cases::agents::runs) struct Turn<'a> {
    /// The ports and tenant.
    pub(in crate::use_cases::agents::runs) driving: &'a Driving<'a>,
    /// What the run may reach for.
    pub(in crate::use_cases::agents::runs) toolbox: &'a Toolbox,
    /// The run's model provider, checked before every model step.
    pub(in crate::use_cases::agents::runs) provider: &'a ModelProvider<ResolvedTenant>,
    /// Where the model is called.
    pub(in crate::use_cases::agents::runs) target: &'a ModelTarget,
}

/// A run as the worker drives it: the run, its agent as last loaded, the
/// conversation so far, and the action it paused on, if it did.
pub(in crate::use_cases::agents::runs) struct Progress {
    /// The mutable execution state accumulated during this drive.
    pub(in crate::use_cases::agents::runs) run: AgentRun<ResolvedTenant>,
    /// The run's agent, loaded again before every step.
    pub(in crate::use_cases::agents::runs) agent: AgentIdentity<ResolvedTenant>,
    /// What the model has been shown.
    pub(in crate::use_cases::agents::runs) messages: Vec<ChatMessage>,
    /// Why the run paused itself, when it did.
    pub(in crate::use_cases::agents::runs) paused: Option<Pause>,
    /// The approvals withdrawn when the run was stopped on an order.
    pub(in crate::use_cases::agents::runs) withdrawal: Option<Withdrawal>,
    /// The version of the run the worker last read or wrote.
    pub(in crate::use_cases::agents::runs) version: RunVersion,
}

/// Why a run paused itself, for what is kept with the pause.
#[derive(Debug, Clone)]
pub(in crate::use_cases::agents::runs) enum Pause {
    /// On a call, with the action the approval request it raises names.
    ForApproval(ApprovalAction),
    /// Before spending more, until a person lets it go on.
    AtSpend,
}

/// Where one step left the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::agents::runs) enum Step {
    /// The run may take another step.
    Continue,
    /// The run answered, failed, or paused for approval.
    Settled,
}

/// Whether a call is the one a person approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// The model asked for it just now.
    ByModel,
    /// A person approved it while the run was paused.
    Approved,
}

/// Takes steps until the run answers, fails, pauses for approval or over
/// what it spent, is stopped, or runs out of steps.
///
/// # Errors
///
/// - `AppError::Conflict` when another driver took the run over.
/// - `AppError::Internal` on lease or persistence failure.
pub(in crate::use_cases::agents::runs) async fn step_until_settled(
    turn: &Turn<'_>,
    progress: &mut Progress,
) -> Result<(), AppError> {
    while progress.run.can_step() {
        if !may_continue(turn, progress).await? {
            break;
        }
        if take_step(turn, progress).await? == Step::Settled {
            break;
        }
    }
    Ok(())
}

/// Checks the kill switch, the stored run and the agent between steps, and
/// renews the lease when the run may go on.
///
/// A person who paused the run since the last step stops it here. A lease
/// this driver no longer holds is an error, not a stop: another driver
/// took the run, and anything written here now would overwrite its
/// progress.
async fn may_continue(turn: &Turn<'_>, progress: &mut Progress) -> Result<bool, AppError> {
    let driving = turn.driving;
    if stop_requested(driving, progress).await? {
        return Ok(false);
    }
    if moved_on(turn, progress).await? && !progress.run.can_step() {
        return Ok(false);
    }
    let Some(agent) = acting_agent(driving, &progress.run).await? else {
        progress.run.halt();
        return Ok(false);
    };
    progress.agent = agent;
    match driving.ports.run_lease.renew(progress.run.id()).await {
        Ok(true) => Ok(true),
        Ok(false) => Err(AppError::Conflict(message!(
            "agents-another-driver-took-over-the-run",
            "another driver took over the run"
        ))),
        Err(e) => Err(AppError::internal(e)),
    }
}

/// Whether someone asked the run to stop, stopping it if so.
///
/// A person's order settles the run: the stored run as their own request
/// ended it, or cancelled here on the order. An order the run cannot be
/// cancelled on, or a kill switch it cannot read, halts the run: neither
/// may read as "keep going".
async fn stop_requested(driving: &Driving<'_>, progress: &mut Progress) -> Result<bool, AppError> {
    match driving
        .ports
        .run_cancellation
        .order_for(driving.tenant, progress.run.id())
        .await
    {
        Ok(None) => Ok(false),
        Ok(Some(order)) => {
            settle_on_stop(driving, progress, &order).await?;
            Ok(true)
        }
        Err(e) => {
            tracing::error!(error = %e, "kill switch unreadable; halting the run");
            progress.run.halt();
            Ok(true)
        }
    }
}

/// Ends the run on `order`: as the stored run ended when the person's own
/// request already settled it, cancelled on the order otherwise, with the
/// approvals it waited on withdrawn.
async fn settle_on_stop(
    driving: &Driving<'_>,
    progress: &mut Progress,
    order: &CancelOrder,
) -> Result<(), AppError> {
    let stored = driving
        .ports
        .stores
        .run_store
        .find_by_id(driving.tenant, progress.run.id())
        .await
        .or_internal()?;
    if let Some(stored) = stored.filter(|stored| stored.status().is_terminal()) {
        progress.version = RunVersion::of(&stored);
        progress.run = stored;
        return Ok(());
    }
    let Some(cancelled) = progress.run.cancel(order).map_err(AppError::from_domain)? else {
        progress.run.halt();
        return Ok(());
    };
    let approvals = withdrawn_approvals(
        driving.ports.stores.approval_store.as_ref(),
        driving.tenant,
        &progress.run,
        &cancelled,
    )
    .await?;
    progress.withdrawal = Some(Withdrawal {
        by: ActorRef::from(order.by().account()),
        approvals,
    });
    Ok(())
}

/// The run's agent, as stored now, while it may act.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::runs) async fn acting_agent(
    driving: &Driving<'_>,
    run: &AgentRun<ResolvedTenant>,
) -> Result<Option<AgentIdentity<ResolvedTenant>>, AppError> {
    Ok(driving
        .ports
        .stores
        .agent_store
        .find_by_id(driving.tenant, run.agent_id())
        .await
        .or_internal()?
        .filter(|agent| agent.may_act_at(clock::now())))
}

/// Takes one step: checks the answer waiting for its check, makes the call
/// a person approved, or asks the model and acts on its answer. A run that
/// spent what it may spend unasked pauses here instead, before it spends
/// more.
async fn take_step(turn: &Turn<'_>, progress: &mut Progress) -> Result<Step, AppError> {
    if progress.run.due_check().is_some() {
        return check_answer(turn, progress).await;
    }
    if let Some(approved) = progress.run.approved_call().cloned() {
        return attempt(turn, progress, approved, Asked::Approved).await;
    }
    if progress.run.pause_at_spend_check(&progress.agent) {
        progress.paused = Some(Pause::AtSpend);
        return Ok(Step::Settled);
    }
    if let Err(refused) = progress.run.ensure_may_ask(turn.provider) {
        tracing::warn!(reason = %refused, "the run may not ask its model; failing it");
        progress.run.fail();
        return Ok(Step::Settled);
    }
    let Some(content) = model_turn(turn, progress).await? else {
        return Ok(Step::Settled);
    };
    act_on_reply(turn, progress, content).await
}

/// The model's finished reply to the conversation so far, once what the
/// call cost is counted on the run.
///
/// `None` when the run spent its limit and stopped, or when there is no
/// finished reply to use, which fails the run: the call failed, the model
/// declined, or its answer was cut off. A call the provider billed is
/// counted however it ended, so a model that keeps declining or running
/// past its cap still spends against the run's limit.
async fn model_turn(turn: &Turn<'_>, progress: &mut Progress) -> Result<Option<String>, AppError> {
    let outcome = next_completion(turn, &progress.messages).await;
    if let Some(usage) = billed(&outcome) {
        progress
            .run
            .record_model_usage(&progress.agent, turn.provider, usage)
            .map_err(AppError::from_domain)?;
    }
    let Some(reply) = finished_reply(outcome) else {
        progress.run.fail();
        return Ok(None);
    };
    if progress.run.status() != RunStatus::Running {
        return Ok(None);
    }
    Ok(Some(reply))
}

/// What the provider billed for the call `outcome` ended in, or `None`
/// when it billed nothing.
fn billed(outcome: &Result<Completion, ModelFailure>) -> Option<ModelUsage> {
    match outcome {
        Ok(completion) => Some(completion.usage),
        Err(ModelFailure {
            charge: ModelCharge::Billed(usage),
            ..
        }) => Some(*usage),
        Err(ModelFailure {
            charge: ModelCharge::Unbilled,
            ..
        }) => None,
    }
}

/// The reply in `outcome` when the model finished one, saying why there is
/// none otherwise.
fn finished_reply(outcome: Result<Completion, ModelFailure>) -> Option<String> {
    let completion = match outcome {
        Ok(completion) => completion,
        Err(failure) => {
            tracing::warn!(error = %failure.error, "the model gave no answer; failing the run");
            return None;
        }
    };
    let reply = completion.finished();
    if reply.is_none() {
        tracing::warn!("the model's answer was cut off before it finished; failing the run");
    }
    reply
}

/// Acts on the model's `content`: records an answer, and puts a tool call
/// through the run's check.
async fn act_on_reply(
    turn: &Turn<'_>,
    progress: &mut Progress,
    content: String,
) -> Result<Step, AppError> {
    let Some((name, args)) = parse_tool_call(&content) else {
        return take_answer(turn, progress, content).await;
    };
    progress.messages.push(ChatMessage::assistant(&content));
    let Ok(call) = ToolCall::new(&name, &args) else {
        progress.run.fail();
        return Ok(Step::Settled);
    };
    attempt(turn, progress, call, Asked::ByModel).await
}

/// Records the model's final answer `content`. A run held to no check
/// completes on it. A run held to a check keeps the answer, shown to the
/// model as its own in case the check turns it back, and goes on to the
/// check.
async fn take_answer(
    turn: &Turn<'_>,
    progress: &mut Progress,
    content: String,
) -> Result<Step, AppError> {
    progress.messages.push(ChatMessage::assistant(&content));
    progress
        .run
        .record_answer(content)
        .map_err(AppError::from_domain)?;
    if progress.run.due_check().is_none() {
        return Ok(Step::Settled);
    }
    keep(turn, progress).await?;
    Ok(Step::Continue)
}

/// The model's reply to the conversation so far, or why there is none.
async fn next_completion(
    turn: &Turn<'_>,
    messages: &[ChatMessage],
) -> Result<Completion, ModelFailure> {
    let request = CompletionRequest {
        messages: messages.to_vec(),
        max_tokens: Some(MAX_STEP_TOKENS),
    };
    turn.driving
        .ports
        .calls
        .model_client
        .complete(turn.target, &request)
        .await
}

/// Puts `call` through the run's check: refused, paused for a person, or
/// made.
///
/// An approved call goes through the check too. Approval says a person is
/// content for it to run, not that the run's authority or exposure still
/// allow it, and either can have changed while it waited.
async fn attempt(
    turn: &Turn<'_>,
    progress: &mut Progress,
    call: ToolCall,
    asked: Asked,
) -> Result<Step, AppError> {
    let resolved = match resolved_call(turn.toolbox, call.clone()) {
        Ok(resolved) => resolved,
        Err(refusal) => return refuse(turn, progress, call, refusal.reason()).await,
    };
    match (progress.run.admit(&resolved), asked) {
        (Err(refusal), _) => refuse(turn, progress, call, refusal.reason()).await,
        (Ok(Admission::NeedsApproval), Asked::ByModel) => pause(progress, resolved),
        (Ok(_), Asked::Approved) if approval_lapsed(&progress.run) => {
            refuse(turn, progress, call, LAPSED.to_owned()).await
        }
        (Ok(_), _) => make_call(turn, progress, resolved).await,
    }
}

/// Why an approved call that waited too long is not made.
const LAPSED: &str = "the approval for this call lapsed before the call was made";

/// Whether the approved call the run holds waited past its window.
fn approval_lapsed(run: &AgentRun<ResolvedTenant>) -> bool {
    run.pending()
        .is_some_and(|held| held.approval_lapsed_at(clock::now()))
}

/// `call` to the offered tool it names, at the path its arguments fill.
fn resolved_call<'a>(
    toolbox: &'a Toolbox,
    call: ToolCall,
) -> Result<ResolvedCall<'a, ResolvedTenant>, CallRefusal> {
    if toolbox.token().is_none() {
        return Err(CallRefusal::NoAuthority);
    }
    let tool = toolbox.tool(call.tool()).ok_or(CallRefusal::UnknownTool)?;
    let values = path_values(tool, call.arguments()).ok_or(CallRefusal::UnfilledPath)?;
    ResolvedCall::resolve(call, tool, &values)
}

/// The values `arguments` puts into `tool`'s path, one for each part the
/// path names, or `None` when one is missing or not a single plain segment.
pub(in crate::use_cases::agents::runs) fn path_values(
    tool: &AgentTool<ResolvedTenant>,
    arguments: &str,
) -> Option<PathValues> {
    let placeholders = tool.path().placeholders();
    if placeholders.is_empty() {
        return Some(PathValues::new());
    }
    let parsed: serde_json::Value = serde_json::from_str(arguments).ok()?;
    let given = parsed.as_object()?;
    placeholders
        .into_iter()
        .try_fold(PathValues::new(), |values, name| {
            let value = segment_of(given.get(name)?)?;
            Some(values.with(name, PathValue::new(value).ok()?))
        })
}

/// A JSON string or number as the path segment it fills.
fn segment_of(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Records `call` as refused for `reason`, and tells the model.
async fn refuse(
    turn: &Turn<'_>,
    progress: &mut Progress,
    call: ToolCall,
    reason: String,
) -> Result<Step, AppError> {
    let feedback = format!(
        "DENIED: `{}` was refused: {reason}. Use a listed tool or give a final answer.",
        call.tool()
    );
    progress
        .run
        .record_denied(call, reason)
        .map_err(AppError::from_domain)?;
    progress.messages.push(ChatMessage::user(feedback));
    keep(turn, progress).await?;
    Ok(Step::Continue)
}

/// Pauses the run on `resolved` until a person decides, remembering the
/// action the approval request is raised for.
fn pause(
    progress: &mut Progress,
    resolved: ResolvedCall<'_, ResolvedTenant>,
) -> Result<Step, AppError> {
    let action =
        ApprovalAction::for_call(resolved.tool().method().into(), resolved.target().as_str())
            .map_err(AppError::from_domain)?;
    progress
        .run
        .await_approval(resolved, &progress.agent)
        .map_err(AppError::from_domain)?;
    progress.paused = Some(Pause::ForApproval(action));
    Ok(Step::Settled)
}

/// Makes an admitted call through the proxy, records it, and feeds its
/// result back fenced as untrusted data.
async fn make_call(
    turn: &Turn<'_>,
    progress: &mut Progress,
    resolved: ResolvedCall<'_, ResolvedTenant>,
) -> Result<Step, AppError> {
    let invocation = invocation_for(turn, &progress.run)?;
    let arguments = ToolArguments::new(resolved.call().arguments())
        .map_err(|e| AppError::from_domain(DomainError::from(e)))?;
    let tool = resolved.tool();
    let text = turn
        .driving
        .ports
        .calls
        .tool_invoker
        .invoke(tool, &arguments, &invocation)
        .await
        .unwrap_or_else(|e| format!("tool error: {e}"));
    let message = tool_result_message(tool.name().as_str(), &text);
    progress
        .run
        .record_allowed(resolved, &progress.agent, text)
        .map_err(AppError::from_domain)?;
    progress.messages.push(ChatMessage::user(message));
    keep(turn, progress).await?;
    Ok(Step::Continue)
}

/// What the run's next tool call carries: the run, its step and the
/// delegation it acts under; refused when it acts under none.
fn invocation_for(
    turn: &Turn<'_>,
    run: &AgentRun<ResolvedTenant>,
) -> Result<ToolInvocationContext, AppError> {
    let token = turn.toolbox.token().ok_or_else(|| {
        AppError::Forbidden(message!(
            "agents-the-run-acts-under-no-delegation-2",
            "the run acts under no delegation"
        ))
    })?;
    Ok(ToolInvocationContext {
        run_id: *run.id(),
        step: next_step(run),
        authorization: token.clone(),
    })
}

/// The 1-based position the run's next step takes.
fn next_step(run: &AgentRun<ResolvedTenant>) -> u32 {
    u32::try_from(run.steps().len()).map_or(u32::MAX, |taken| taken.saturating_add(1))
}
