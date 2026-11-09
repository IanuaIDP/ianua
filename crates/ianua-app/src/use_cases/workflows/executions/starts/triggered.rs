//! Starting a published version for its publisher when its schedule comes
//! round, its webhook is called with its secret, its event happens or its
//! service sends the event it starts on.
//!
//! Nobody signs in for these. What the publisher holds is worked out from
//! their account as it stands, and a start they may not have is refused
//! out loud with `workflows.start_refused`, so nobody wonders why payroll
//! stopped running after Ann left.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::workflow::{
    Hold, MissingAccount, Publication, Workflow,
};
use ianua_domain::domains::workflows::execution::record::ExecutionRecord;
use ianua_domain::domains::workflows::execution::{
    ActingAuthority, Cause, ServiceStartParams, StartExecutionParams, StartRefusal,
    WebhookStartParams, WorkflowExecution,
};
use ianua_domain::domains::workflows::triggers::secret::WebhookCall;
use ianua_domain::domains::workflows::triggers::subscription::ServiceDelivery;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::services::holds::{AccountReads, missing_account, publisher_now};
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::executions::{TriggerStartPorts, TriggeredStart};

/// How a firing reaches the domain.
pub(in crate::use_cases::workflows::executions) enum Admission {
    /// A schedule came round or an event happened.
    Trigger,
    /// The webhook was called with its secret, which admitted this call.
    Webhook(WebhookCall),
    /// A service sent the event, which its live registration admitted.
    Service(ServiceDelivery),
}

/// What a trigger hands a version: what fired, how it was admitted, its
/// data, and how sensitive that data is, as the adapter that received it
/// classed it.
pub(in crate::use_cases::workflows::executions) struct Firing {
    /// What fired.
    pub(in crate::use_cases::workflows::executions) cause: Cause,
    /// How it was admitted.
    pub(in crate::use_cases::workflows::executions) admission: Admission,
    /// The trigger's data.
    pub(in crate::use_cases::workflows::executions) input: FlowData,
    /// The most sensitive data in it.
    pub(in crate::use_cases::workflows::executions) exposure: DataClassLevel,
}

/// The version a trigger fired, published by someone it would act for, and
/// what fired it.
struct Fired<'a> {
    workflow: &'a Workflow<ResolvedTenant>,
    cause: Cause,
}

/// A start the publisher may have: what it starts with and how it was
/// admitted.
struct Start {
    params: StartExecutionParams,
    admission: Admission,
}

impl Start {
    /// The start `firing` asks for, acting for `acting_for`.
    fn of(acting_for: ActingAuthority, firing: Firing) -> Self {
        Self {
            params: StartExecutionParams {
                acting_for,
                cause: firing.cause,
                input: firing.input,
                exposure: firing.exposure,
            },
            admission: firing.admission,
        }
    }
}

/// Starts `workflow` on `firing` for the person who published it, or
/// records why it may not start.
///
/// # Errors
///
/// - `AppError::Conflict` when `workflow` was never published.
/// - `AppError::Domain` when `workflow` does not start on what fired.
/// - `AppError::Forbidden` when a webhook call was admitted for another
///   version.
/// - `AppError::Internal` when the publisher's records name a role that is
///   not there, or the start or its record cannot be kept.
pub(in crate::use_cases::workflows::executions) async fn started_for_publisher(
    ports: &TriggerStartPorts,
    tenant: &ScopedTenant,
    auditor: &RequestAuditor,
    workflow: &Workflow<ResolvedTenant>,
    firing: Firing,
) -> Result<TriggeredStart, AppError> {
    let Some(fired) = fired(workflow, firing.cause)? else {
        return Ok(TriggeredStart::ChainTooLong);
    };
    let Some(acting_for) = publisher_now(&ports.accounts_now, tenant, workflow).await? else {
        return refused(
            ports,
            auditor,
            tenant,
            &fired,
            StartRefusal::PersonMayNotRun,
        )
        .await;
    };
    if let Some(missing) = newly_missing(ports, tenant, workflow, &acting_for).await? {
        return held(ports, auditor, tenant, &fired, missing).await;
    }
    let start = Start::of(acting_for, firing);
    match StartRefusal::of(workflow, &start.params) {
        Some(why) => refused(ports, auditor, tenant, &fired, why).await,
        None => started(ports, tenant, auditor, workflow, start).await,
    }
}

/// `workflow` as `cause` fires it, or `None` when `cause` came from a chain
/// of executions already as long as any may be.
///
/// # Errors
///
/// - `AppError::Conflict` when `workflow` was never published.
fn fired(workflow: &Workflow<ResolvedTenant>, cause: Cause) -> Result<Option<Fired<'_>>, AppError> {
    if cause.chain_depth().is_err() {
        return Ok(None);
    }
    let Publication::PublishedBy(_) = workflow.publication() else {
        return Err(AppError::Conflict(message!(
            "workflows-the-workflow-was-never-published",
            "the workflow was never published"
        )));
    };
    Ok(Some(Fired { workflow, cause }))
}

/// Starts `workflow` as `start` says and keeps the execution with its
/// record.
async fn started(
    ports: &TriggerStartPorts,
    tenant: &ScopedTenant,
    auditor: &RequestAuditor,
    workflow: &Workflow<ResolvedTenant>,
    start: Start,
) -> Result<TriggeredStart, AppError> {
    let (execution, records) = execution_of(workflow, start).map_err(AppError::from_domain)?;
    let keeping = Keeping {
        executions: ports.executions.as_ref(),
        wakeups: &ports.wakeups,
        runs: &ports.run_stops,
    };
    kept_together(
        ports.unit_of_work.as_ref(),
        keeping.keep(tenant, auditor, Kept::Started(&execution), records),
    )
    .await?;
    Ok(TriggeredStart::Started(*execution.id()))
}

/// The execution `start` makes of `workflow`: through the trigger's start,
/// or a webhook's, which needs the call its secret admitted.
fn execution_of(
    workflow: &Workflow<ResolvedTenant>,
    start: Start,
) -> Result<(WorkflowExecution<ResolvedTenant>, Vec<ExecutionRecord>), DomainError> {
    let Start { params, admission } = start;
    match admission {
        Admission::Trigger => WorkflowExecution::start_on_trigger(workflow, params),
        Admission::Webhook(call) => WorkflowExecution::start_on_webhook(
            workflow,
            call,
            WebhookStartParams {
                acting_for: params.acting_for,
                input: params.input,
                exposure: params.exposure,
            },
        ),
        Admission::Service(delivery) => WorkflowExecution::start_on_service_event(
            workflow,
            delivery,
            ServiceStartParams {
                acting_for: params.acting_for,
                input: params.input,
                exposure: params.exposure,
            },
        ),
    }
}

/// The account `workflow`, not yet held, can no longer use for
/// `acting_for`, or none when it is held already or every account still
/// serves it.
///
/// # Errors
///
/// `AppError::Internal` when an account or its owner's records cannot be
/// read.
async fn newly_missing(
    ports: &TriggerStartPorts,
    tenant: &ScopedTenant,
    workflow: &Workflow<ResolvedTenant>,
    acting_for: &ActingAuthority,
) -> Result<Option<MissingAccount>, AppError> {
    if workflow.hold() != &Hold::Clear {
        return Ok(None);
    }
    let reads = AccountReads {
        accounts: ports.accounts.as_ref(),
        people: &ports.accounts_now,
    };
    missing_account(reads, tenant, workflow, acting_for).await
}

/// Holds the version `fired` names for want of `missing`, records the hold
/// and that this start was refused for it, all together.
async fn held(
    ports: &TriggerStartPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    fired: &Fired<'_>,
    missing: MissingAccount,
) -> Result<TriggeredStart, AppError> {
    let why = StartRefusal::NeedsAccount;
    let refusal = why
        .recorded(tenant, fired.workflow, fired.cause)
        .map_err(AppError::from_domain)?;
    let mut version = fired.workflow.clone();
    version.hold_for(missing).map_err(AppError::from_domain)?;
    kept_together(ports.unit_of_work.as_ref(), async {
        ports.workflows.save(tenant, &version).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, version.take_events(tenant))
            .await
            .or_internal()?;
        auditor.dispatch(&[refusal]).await.or_internal()
    })
    .await?;
    Ok(TriggeredStart::Refused(why))
}

/// Records that the version `fired` names did not start, for `why`, marked
/// at the depth the start would have run at.
async fn refused(
    ports: &TriggerStartPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    fired: &Fired<'_>,
    why: StartRefusal,
) -> Result<TriggeredStart, AppError> {
    let event = why
        .recorded(tenant, fired.workflow, fired.cause)
        .map_err(AppError::from_domain)?;
    kept_together(ports.unit_of_work.as_ref(), async {
        auditor.dispatch(&[event]).await.or_internal()
    })
    .await?;
    Ok(TriggeredStart::Refused(why))
}
