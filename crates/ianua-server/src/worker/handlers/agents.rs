//! The handlers of agent runs: their drives.
//!
//! One drive job takes a run through its governed loop to an end or a
//! pause, each turn a model call and at most one tool call. A run is
//! driven by one worker at a time, held by a lease in the database that
//! outlasts the longest drive the settings allow, so a drive that stopped
//! with its worker is taken over only once its lease lapsed.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::workflows::CodeRunner;
use ianua_app::services::limits::enforcer::PlanLimitEnforcer;
use ianua_app::services::limits::plan::StoredPlanLimits;
use ianua_app::use_cases::agents::runs::{
    AnswerChecks, DrivePorts, DriveRunHandler, DriveUseCase, RunCalls, RunPeople, RunStores,
};
use ianua_app::use_cases::scheduling::JobHandler;
use ianua_domain::domains::agents::execution::run::MAX_CHECK_TRIES;
use ianua_domain::domains::workflows::sandbox::recipe::MAX_RUN_SECONDS;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::Lifetime;
use ianua_infra::crypto::Pkcs8TaskTokenIssuer;
use ianua_infra::http::{HttpModelClient, HttpToolInvoker};
use ianua_infra::postgres::agents::{
    PgAgentCredentialStore, PgAgentStore, PgApprovalStore, PgDelegationStore, PgModelProviderStore,
    PgRunCancellation, PgRunLease, PgRunStore, PgToolStore,
};
use ianua_infra::postgres::identity::PgUserStore;
use ianua_infra::postgres::limits::{PgOrgResourceCounter, PgResourceCounter};
use ianua_infra::postgres::organization::PgOrgUserStore;
use ianua_infra::postgres::routing::PgServiceStore;
use ianua_infra::postgres::shared::PgAuditLabelResolver;
use ianua_infra::postgres::workflows::PgSandboxVersionStore;

use crate::config::serving::AgentsConfig;
use crate::error::{PlatformError, ServerError};
use crate::worker::parts::Parts;

/// What a drive takes beyond its model and tool calls: the reads, writes
/// and records of every turn, and the settling of how it left off.
const DRIVE_MARGIN: Duration = Duration::from_secs(60);

/// The handlers of agent runs, the checks of their answers running through
/// `runner`.
///
/// # Errors
///
/// [`ServerError`] when one cannot be built.
pub(super) fn handlers(
    parts: &Parts<'_>,
    runner: Arc<dyn CodeRunner>,
) -> Result<Vec<Arc<dyn JobHandler>>, ServerError> {
    Ok(vec![drive_run(parts, runner)?])
}

/// The longest one drive of a run may take as the settings allow: every
/// step the longest run may take, each a model call and a tool call at
/// their time limits, every check a run held to one may run at its longest,
/// and a margin. A drive job must be given this long, and the run's lease
/// lasts this long.
pub(in crate::worker) fn longest_drive(agents: &AgentsConfig) -> Duration {
    let turn = agents.model_timeout.saturating_add(agents.tool_timeout);
    let checks =
        Duration::from_secs(u64::from(MAX_RUN_SECONDS)).saturating_mul(u32::from(MAX_CHECK_TRIES));
    turn.saturating_mul(agents.run_max_steps)
        .saturating_add(checks)
        .saturating_add(DRIVE_MARGIN)
}

/// The issuer of the task tokens a run's tool calls carry, a rotated key
/// still checking for as long as the JWKS publishes it.
fn task_tokens(parts: &Parts<'_>) -> Result<Pkcs8TaskTokenIssuer, ServerError> {
    let databases = &parts.platform.databases;
    Ok(Pkcs8TaskTokenIssuer::new(
        parts.signing_keys(),
        key_grace(parts)?,
        Arc::new(PgServiceStore::new(Arc::clone(databases))),
        Arc::new(PgAgentCredentialStore::new(Arc::clone(databases))),
    ))
}

/// How long a rotated signing key still checks the tokens it signed: as
/// long as the JWKS publishes it.
pub(in crate::worker) fn key_grace(parts: &Parts<'_>) -> Result<Lifetime, ServerError> {
    let grace = time::Duration::try_from(parts.config.sign_in.tokens.jwks_grace)
        .map_err(PlatformError::of("the signing keys' rotation grace"))?;
    Ok(Lifetime::new(grace).map_err(PlatformError::of("the signing keys' rotation grace"))?)
}

/// The handler driving a started run through its governed loop, checking
/// the answers of a run held to a check through `runner`.
fn drive_run(
    parts: &Parts<'_>,
    runner: Arc<dyn CodeRunner>,
) -> Result<Arc<dyn JobHandler>, ServerError> {
    let clients = RunClients::new(parts)?;
    let approval_ttl = time::Duration::try_from(parts.config.agents.lifetimes.run_approval)
        .map_err(PlatformError::of("the run approvals' lifetime"))?;
    let checks = AnswerChecks {
        versions: Arc::new(PgSandboxVersionStore::new(Arc::clone(
            &parts.platform.databases,
        ))),
        runner,
        pulls: super::workflows::image_pulls(parts),
    };
    let drive = DriveUseCase::new(drive_ports(parts, clients, checks)?, approval_ttl);
    let handler = DriveRunHandler::new(Arc::new(drive))
        .map_err(PlatformError::of("the agent run drive handler"))?;
    Ok(Arc::new(handler))
}

/// The screened clients used for one run's model and tool calls.
struct RunClients {
    model: HttpModelClient,
    tool: HttpToolInvoker,
}

impl RunClients {
    /// Builds both outbound clients before validating the drive's remaining settings.
    fn new(parts: &Parts<'_>) -> Result<Self, PlatformError> {
        let platform = parts.platform;
        let agents = &parts.config.agents;
        let model_client = HttpModelClient::new(
            platform.outbound.model_networks.clone(),
            agents.model_timeout,
        )
        .map_err(PlatformError::of("the model client"))?;
        let tool_invoker = HttpToolInvoker::new(
            agents.proxy_base_url.clone(),
            platform.outbound.upstream_networks.clone(),
            agents.tool_timeout,
        )
        .map_err(PlatformError::of("the tool invoker"))?;
        Ok(Self {
            model: model_client,
            tool: tool_invoker,
        })
    }
}

/// Supplies the governed drive with its stores, authority, calls, the
/// checks of its answers and accounting.
fn drive_ports(
    parts: &Parts<'_>,
    clients: RunClients,
    checks: AnswerChecks,
) -> Result<DrivePorts, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Ok(DrivePorts {
        stores: run_stores(parts),
        people: run_people(parts),
        calls: run_calls(parts, clients)?,
        checks,
        run_cancellation: Arc::new(PgRunCancellation::new(Arc::clone(databases))),
        run_lease: Arc::new(PgRunLease::new(
            Arc::clone(databases),
            longest_drive(&parts.config.agents),
        )),
        audit_label_resolver: Arc::new(PgAuditLabelResolver::new(Arc::clone(databases))),
        unit_of_work: Arc::clone(&platform.unit_of_work),
        plan_limits: Arc::new(StoredPlanLimits::new(
            Arc::clone(&parts.tenants),
            Arc::clone(&parts.organizations),
        )),
        limit_enforcer: Arc::new(PlanLimitEnforcer::new(
            Arc::new(PgResourceCounter::new(Arc::clone(databases))),
            Arc::new(PgOrgResourceCounter::new(Arc::clone(databases))),
        )),
    })
}

/// Holds the state a drive reads and changes while advancing one agent run.
fn run_stores(parts: &Parts<'_>) -> RunStores {
    let databases = &parts.platform.databases;
    RunStores {
        run_store: Arc::new(PgRunStore::new(Arc::clone(databases))),
        agent_store: Arc::new(PgAgentStore::new(Arc::clone(databases))),
        delegation_store: Arc::new(PgDelegationStore::new(Arc::clone(databases))),
        tool_store: Arc::new(PgToolStore::new(Arc::clone(databases))),
        provider_store: Arc::new(PgModelProviderStore::new(Arc::clone(databases))),
        approval_store: Arc::new(PgApprovalStore::new(Arc::clone(databases))),
    }
}

/// Resolves the current standing of the accounts represented by a run.
fn run_people(parts: &Parts<'_>) -> RunPeople {
    let databases = &parts.platform.databases;
    RunPeople {
        accounts_now: Arc::clone(&parts.accounts_now),
        user_store: Arc::new(PgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        org_user_store: Arc::new(PgOrgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
    }
}

/// Signs each tool call and resolves its tenant issuer using the screened clients.
fn run_calls(parts: &Parts<'_>, clients: RunClients) -> Result<RunCalls, ServerError> {
    let platform = parts.platform;
    Ok(RunCalls {
        model_client: Arc::new(clients.model),
        tool_invoker: Arc::new(clients.tool),
        encryptor: platform.secrets.encryptor.clone(),
        task_token_issuer: Arc::new(task_tokens(parts)?),
        issuers: parts.issuers(),
    })
}
