//! The handlers of workflows: drives, the passes of loops taken in and
//! stopped, starts on an event or a schedule, checks of the versions an
//! account that changed still serves, the builds of sandbox versions'
//! package bundles, the runs of code steps' code, and the looks that move
//! evaluations on.
//!
//! An execution is driven by one worker at a time, held by a lease in the
//! database. The lease outlasts the longest a drive job may run, so a
//! drive stopped at its timeout lets the lease lapse before the job's
//! retry, and a drive never runs on two workers at once.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::workflows::{CodeRunner, ImageScanner};
use ianua_app::services::account_now::AccountsNow;
use ianua_app::services::limits::enforcer::PlanLimitEnforcer;
use ianua_app::services::limits::plan::StoredPlanLimits;
use ianua_app::services::registrations::RegistrationPorts;
use ianua_app::use_cases::agents::runs::{RunDrives, StopPorts};
use ianua_app::use_cases::scheduling::JobHandler;
use ianua_app::use_cases::workflows::evaluations::{
    EvaluationHandler, Evaluations, RunPorts, RunUseCase,
};
use ianua_app::use_cases::workflows::executions::{
    ActionPorts, AgentStepPorts, AskInSlackHandler, AskInSlackPorts, AskInSlackUseCase,
    CompanyPorts, CompanyStepRunner, DriveHandler, DrivePorts, DriveUseCase, GuardrailPorts,
    MemoryPorts, RunCodeHandler, RunCodePorts, RunCodeUseCase, SettlePassHandler, SettlePassPorts,
    SettlePassUseCase, StartOnEventHandler, StartOnEventPorts, StartOnEventUseCase,
    StartOnTriggerUseCase, StartScheduledHandler, StopPassHandler, StopPassPorts, StopPassUseCase,
    TriggerStartPorts, Wakeups,
};
use ianua_app::use_cases::workflows::published::holds::{
    CheckAccountHandler, CheckAccountPorts, CheckAccountUseCase,
};
use ianua_app::use_cases::workflows::sandboxes::images::ImagePulls;
use ianua_app::use_cases::workflows::sandboxes::trying::{
    RunTrialPorts, RunTrialUseCase, TrialHandler,
};
use ianua_app::use_cases::workflows::sandboxes::{
    BuildHandler, BuildVersionPorts, BuildVersionUseCase,
};
use ianua_infra::crypto::{HmacRedactionDigest, OsSecureTokenGenerator, Pkcs8RunPasses};
use ianua_infra::integrations::{
    DataLink, EventAddresses, InstalledActionRunner, InstalledIntegrationCatalog,
    InstalledServiceChannelSetup, InstalledServiceRegistrar,
};
use ianua_infra::packages::RegistryPackageBundler;
use ianua_infra::postgres::agents::{
    PgAgentStore, PgApprovalStore, PgDelegationStore, PgModelProviderStore, PgRunCancellation,
    PgRunStore,
};
use ianua_infra::postgres::data_classification::PgClassificationStore;
use ianua_infra::postgres::limits::{PgOrgResourceCounter, PgResourceCounter};
use ianua_infra::postgres::routing::{PgStreamRouteLogins, PgStreamRouteStore};
use ianua_infra::postgres::shared::PgAuditLabelResolver;
use ianua_infra::postgres::workflows::{
    PgAccountChannelStore, PgEvaluationStore, PgExecutionLease, PgImageRegistryStore,
    PgIntegrationAccountStore, PgOperationRiskOverrideStore, PgSandboxStore, PgSandboxTrialStore,
    PgSandboxVersionStore, PgServiceSubscriptionStore, PgWorkflowExecutionStore, PgWorkflowStore,
};
use ianua_infra::runtime::LocalWorkingCalendar;
use ianua_infra::sandbox::{
    ClusterCodeRunner, CommandImageScanner, ContainerCodeRunner, GateCodeRunner, NoCodeRunner,
    NoImageScanner,
};

use crate::config::serving::CodeRunning;
use crate::error::{PlatformError, ServerError};
use crate::worker::handlers::agents::key_grace;
use crate::worker::parts::Parts;

/// How much longer than a drive job may run its execution's lease lasts,
/// so the lease of a drive stopped at its timeout lapses before anything
/// else could take the execution, and not long after.
const LEASE_MARGIN: Duration = Duration::from_secs(60);

/// The handlers of workflows, running code through `runner`, the one the
/// checks of agents' answers run through too.
///
/// # Errors
///
/// [`ServerError`] when one cannot be built.
pub(super) fn handlers(
    parts: &Parts<'_>,
    runner: Arc<dyn CodeRunner>,
) -> Result<Vec<Arc<dyn JobHandler>>, ServerError> {
    let accounts_now = Arc::clone(&parts.accounts_now);
    Ok(vec![
        drive(parts, &accounts_now)?,
        settle_pass(parts)?,
        stop_pass(parts)?,
        start_on_event(parts, &accounts_now)?,
        start_scheduled(parts, &accounts_now)?,
        check_account(parts, &accounts_now)?,
        build_sandbox(parts)?,
        run_code(parts, Arc::clone(&runner))?,
        try_sandbox(parts, runner)?,
        ask_in_slack(parts)?,
        evaluate(parts, &accounts_now)?,
    ])
}

/// The handler taking each look at an evaluation: its ended test runs
/// taken in, and the cases whose turn came started as test runs, acting
/// for whoever started it as they hold rights now.
fn evaluate(
    parts: &Parts<'_>,
    accounts_now: &Arc<AccountsNow>,
) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let run = RunUseCase::new(RunPorts {
        evaluations: Arc::new(PgEvaluationStore::new(Arc::clone(databases))),
        workflows: Arc::new(PgWorkflowStore::new(Arc::clone(databases))),
        executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(databases))),
        sandboxes: Arc::new(PgSandboxStore::new(Arc::clone(databases))),
        sandbox_versions: Arc::new(PgSandboxVersionStore::new(Arc::clone(databases))),
        accounts_now: Arc::clone(accounts_now),
        looks: Evaluations::new(Arc::clone(&parts.jobs)),
        wakeups: Wakeups::new(Arc::clone(&parts.jobs)),
        run_stops: run_stops(parts),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let handler = EvaluationHandler::new(Arc::new(run))
        .map_err(PlatformError::of("the workflow evaluation handler"))?;
    Ok(Arc::new(handler))
}

/// The handler posting an open approval's question to the Slack channel its
/// step names, its buttons opening the approval in the dashboard.
fn ask_in_slack(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let databases = &parts.platform.databases;
    let ask = AskInSlackUseCase::new(
        AskInSlackPorts {
            executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(databases))),
            accounts: Arc::new(PgIntegrationAccountStore::new(Arc::clone(databases))),
            action_runner: Arc::new(action_runner(parts)?),
            tenants: Arc::clone(&parts.tenants),
            organizations: Arc::clone(&parts.organizations),
        },
        parts.config.deployment.app_base_url.clone(),
    );
    let handler = AskInSlackHandler::new(Arc::new(ask))
        .map_err(PlatformError::of("the ask-in-Slack handler"))?;
    Ok(Arc::new(handler))
}

/// The handler running each code step's code in a sandbox through
/// `runner`, and settling what came of it.
fn run_code(
    parts: &Parts<'_>,
    runner: Arc<dyn CodeRunner>,
) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let run = RunCodeUseCase::new(RunCodePorts {
        executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(
            &platform.databases,
        ))),
        versions: Arc::new(PgSandboxVersionStore::new(Arc::clone(&platform.databases))),
        runner,
        pulls: image_pulls(parts),
        lease: execution_lease(parts),
        wakeups: Wakeups::new(Arc::clone(&parts.jobs)),
        run_stops: run_stops(parts),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let handler = RunCodeHandler::new(Arc::new(run))
        .map_err(PlatformError::of("the workflow code run handler"))?;
    Ok(Arc::new(handler))
}

/// What runs code: containers on this server, containers the sandbox gate
/// starts, pods on a cluster, or nothing, as the deployment says.
pub(super) fn code_runner(parts: &Parts<'_>) -> Arc<dyn CodeRunner> {
    let files = || Arc::clone(&parts.platform.files);
    let network = || parts.config.sandboxes.network.clone();
    match &parts.config.sandboxes.running {
        CodeRunning::Containers(settings) => Arc::new(ContainerCodeRunner::new(
            files(),
            settings.clone(),
            network(),
        )),
        CodeRunning::Cluster(settings) => {
            Arc::new(ClusterCodeRunner::new(files(), settings.clone(), network()))
        }
        CodeRunning::Gate(settings) => {
            Arc::new(GateCodeRunner::new(files(), settings.clone(), network()))
        }
        CodeRunning::Nowhere => Arc::new(NoCodeRunner),
    }
}

/// The handler running each started trial through `runner`, the one code
/// steps run through, and keeping how it went.
fn try_sandbox(
    parts: &Parts<'_>,
    runner: Arc<dyn CodeRunner>,
) -> Result<Arc<dyn JobHandler>, ServerError> {
    let databases = &parts.platform.databases;
    let run = RunTrialUseCase::new(RunTrialPorts {
        trials: Arc::new(PgSandboxTrialStore::new(Arc::clone(databases))),
        versions: Arc::new(PgSandboxVersionStore::new(Arc::clone(databases))),
        runner,
        pulls: image_pulls(parts),
    });
    let handler =
        TrialHandler::new(Arc::new(run)).map_err(PlatformError::of("the sandbox trial handler"))?;
    Ok(Arc::new(handler))
}

/// The logins companies' images are pulled with, for the registries each
/// tenant allowed, while the deployment lets tenants run their own images.
pub(super) fn image_pulls(parts: &Parts<'_>) -> ImagePulls {
    ImagePulls::new(
        Arc::new(PgImageRegistryStore::new(Arc::clone(
            &parts.platform.databases,
        ))),
        parts.platform.secrets.encryptor.clone(),
        parts.config.sandboxes.own_images,
    )
}

/// What scans companies' images: the operator's scanner command, or with
/// none, nothing, so no company image is cleared to run.
fn image_scanner(parts: &Parts<'_>) -> Arc<dyn ImageScanner> {
    match &parts.config.sandboxes.scanner {
        Some(settings) => Arc::new(CommandImageScanner::new(settings.clone())),
        None => Arc::new(NoImageScanner),
    }
}

/// The handler building each saved sandbox version's package bundle, or
/// scanning its company's image.
fn build_sandbox(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let bundler = RegistryPackageBundler::new(
        parts.config.sandboxes.registries.clone(),
        Arc::clone(&platform.files),
    )
    .map_err(PlatformError::of("the sandbox package bundler"))?;
    let build = BuildVersionUseCase::new(BuildVersionPorts {
        versions: Arc::new(PgSandboxVersionStore::new(Arc::clone(&platform.databases))),
        bundler: Arc::new(bundler),
        pulls: image_pulls(parts),
        scanner: image_scanner(parts),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let handler = BuildHandler::new(Arc::new(build))
        .map_err(PlatformError::of("the sandbox build handler"))?;
    Ok(Arc::new(handler))
}

/// The handler having a loop take in each of its passes that ended.
fn settle_pass(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let settle = SettlePassUseCase::new(SettlePassPorts {
        executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(
            &platform.databases,
        ))),
        lease: execution_lease(parts),
        wakeups: Wakeups::new(Arc::clone(&parts.jobs)),
        run_stops: run_stops(parts),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let handler = SettlePassHandler::new(Arc::new(settle))
        .map_err(PlatformError::of("the workflow pass settle handler"))?;
    Ok(Arc::new(handler))
}

/// The handler stopping the passes a loop that failed or ended left
/// running.
fn stop_pass(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let stop = StopPassUseCase::new(StopPassPorts {
        executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(
            &platform.databases,
        ))),
        lease: execution_lease(parts),
        wakeups: Wakeups::new(Arc::clone(&parts.jobs)),
        run_stops: run_stops(parts),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let handler = StopPassHandler::new(Arc::new(stop))
        .map_err(PlatformError::of("the workflow pass stop handler"))?;
    Ok(Arc::new(handler))
}

/// The handler holding the versions an account that just changed no longer
/// serves.
fn check_account(
    parts: &Parts<'_>,
    accounts_now: &Arc<AccountsNow>,
) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let check = CheckAccountUseCase::new(CheckAccountPorts {
        workflows: Arc::new(PgWorkflowStore::new(Arc::clone(databases))),
        accounts: Arc::new(PgIntegrationAccountStore::new(Arc::clone(databases))),
        accounts_now: Arc::clone(accounts_now),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let handler = CheckAccountHandler::new(Arc::new(check))
        .map_err(PlatformError::of("the workflow account check handler"))?;
    Ok(Arc::new(handler))
}

/// What registering a workflow at its trigger's service, renewing it and
/// removing it needs, in the worker.
pub(in crate::worker) fn registrations(parts: &Parts<'_>) -> RegistrationPorts {
    let platform = parts.platform;
    let databases = &platform.databases;
    let registrar = Arc::new(InstalledServiceRegistrar::new(
        Arc::clone(&platform.integrations),
        platform.secrets.encryptor.clone(),
        EventAddresses::new(&parts.config.deployment.app_base_url),
        parts.config.integrations.timeout,
    ));
    RegistrationPorts {
        accounts: Arc::new(PgIntegrationAccountStore::new(Arc::clone(databases))),
        accounts_now: Arc::clone(&parts.accounts_now),
        subscriptions: Arc::new(PgServiceSubscriptionStore::new(Arc::clone(databases))),
        channels: Arc::new(PgAccountChannelStore::new(Arc::clone(databases))),
        channel_setup: Arc::new(InstalledServiceChannelSetup::new(Arc::clone(&registrar))),
        registrar,
        grants: Arc::clone(&parts.grants),
        encryptor: platform.secrets.encryptor.clone(),
        tokens: Arc::new(OsSecureTokenGenerator),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    }
}

/// The lease that keeps an execution to one worker at a time, lasting the
/// longest a drive job may run and a margin.
pub(in crate::worker) fn execution_lease(parts: &Parts<'_>) -> Arc<PgExecutionLease> {
    let lasting = parts
        .config
        .worker
        .jobs
        .timeout
        .saturating_add(LEASE_MARGIN);
    Arc::new(PgExecutionLease::new(
        Arc::clone(&parts.platform.databases),
        lasting,
    ))
}

/// The stopping of the agent runs an execution gives up when it ends.
pub(in crate::worker) fn run_stops(parts: &Parts<'_>) -> StopPorts {
    let databases = &parts.platform.databases;
    StopPorts {
        run_cancellation: Arc::new(PgRunCancellation::new(Arc::clone(databases))),
        run_store: Arc::new(PgRunStore::new(Arc::clone(databases))),
        approval_store: Arc::new(PgApprovalStore::new(Arc::clone(databases))),
        audit_label_resolver: Arc::new(PgAuditLabelResolver::new(Arc::clone(databases))),
    }
}

/// The ports a start on an event or a schedule goes through.
fn trigger_starts(parts: &Parts<'_>, accounts_now: &Arc<AccountsNow>) -> TriggerStartPorts {
    let platform = parts.platform;
    let databases = &platform.databases;
    TriggerStartPorts {
        workflows: Arc::new(PgWorkflowStore::new(Arc::clone(databases))),
        executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(databases))),
        wakeups: Wakeups::new(Arc::clone(&parts.jobs)),
        run_stops: run_stops(parts),
        accounts_now: Arc::clone(accounts_now),
        accounts: Arc::new(PgIntegrationAccountStore::new(Arc::clone(databases))),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    }
}

/// The handler driving an execution as far as it goes now.
fn drive(
    parts: &Parts<'_>,
    accounts_now: &Arc<AccountsNow>,
) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let drive = DriveUseCase::new(DrivePorts {
        executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(databases))),
        memory: workflow_memory(parts),
        guardrail: guardrail(parts),
        company: CompanyPorts {
            steps: Arc::new(CompanyStepRunner::new(Arc::clone(&parts.company))),
            tenants: Arc::clone(&parts.tenants),
        },
        agent_steps: agent_steps(parts),
        actions: actions(parts)?,
        lease: execution_lease(parts),
        wakeups: Wakeups::new(Arc::clone(&parts.jobs)),
        run_stops: run_stops(parts),
        accounts_now: Arc::clone(accounts_now),
        plan_limits: Arc::new(StoredPlanLimits::new(
            Arc::clone(&parts.tenants),
            Arc::clone(&parts.organizations),
        )),
        unit_of_work: Arc::clone(&platform.unit_of_work),
        calendar: Arc::new(LocalWorkingCalendar),
    });
    let handler = DriveHandler::new(Arc::new(drive))
        .map_err(PlatformError::of("the workflow drive handler"))?;
    Ok(Arc::new(handler))
}

/// What guardrail steps read the tenant's classification rules through,
/// and the gateway's keyed digest a classified field its rule hashes is
/// replaced with.
fn guardrail(parts: &Parts<'_>) -> GuardrailPorts {
    let platform = parts.platform;
    GuardrailPorts {
        classification: Arc::new(PgClassificationStore::new(Arc::clone(&platform.databases))),
        digest: Arc::new(HmacRedactionDigest::new(&platform.keys.shared_root)),
    }
}

/// Supplies memory steps with stored text, embeddings and sealed model credentials.
fn workflow_memory(parts: &Parts<'_>) -> MemoryPorts {
    let platform = parts.platform;
    MemoryPorts {
        memories: Arc::clone(&platform.memory.store),
        entries: Arc::clone(&platform.memory.entries),
        embedder: Arc::clone(&platform.memory.embedder),
        providers: Arc::new(PgModelProviderStore::new(Arc::clone(&platform.databases))),
        encryptor: platform.secrets.encryptor.clone(),
    }
}

/// What agent run steps start their runs through.
fn agent_steps(parts: &Parts<'_>) -> AgentStepPorts {
    let databases = &parts.platform.databases;
    AgentStepPorts {
        agents: Arc::new(PgAgentStore::new(Arc::clone(databases))),
        delegations: Arc::new(PgDelegationStore::new(Arc::clone(databases))),
        runs: Arc::new(PgRunStore::new(Arc::clone(databases))),
        run_drives: RunDrives {
            queue: Arc::clone(&parts.jobs),
            attempts: parts.attempts,
        },
        limit_enforcer: Arc::new(PlanLimitEnforcer::new(
            Arc::new(PgResourceCounter::new(Arc::clone(databases))),
            Arc::new(PgOrgResourceCounter::new(Arc::clone(databases))),
        )),
        audit_label_resolver: Arc::new(PgAuditLabelResolver::new(Arc::clone(databases))),
        sandbox_versions: Arc::new(PgSandboxVersionStore::new(Arc::clone(databases))),
    }
}

/// What action steps make their calls through.
///
/// # Errors
///
/// [`ServerError`] when the action runner or the pass signer cannot be
/// built.
fn actions(parts: &Parts<'_>) -> Result<ActionPorts, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    Ok(ActionPorts {
        catalog: Arc::new(InstalledIntegrationCatalog::new(Arc::clone(
            &platform.integrations,
        ))),
        risks: Arc::new(PgOperationRiskOverrideStore::new(Arc::clone(databases))),
        accounts: Arc::new(PgIntegrationAccountStore::new(Arc::clone(databases))),
        action_runner: Arc::new(action_runner(parts)?),
        grants: Arc::clone(&parts.grants),
        run_passes: Arc::new(Pkcs8RunPasses::new(parts.signing_keys(), key_grace(parts)?)),
        stream_routes: Arc::new(PgStreamRouteStore::new(Arc::clone(databases))),
        stream_route_logins: Arc::new(PgStreamRouteLogins::new(Arc::clone(databases))),
        issuers: parts.issuers(),
    })
}

/// The runner making action steps' calls through the installed
/// integrations, opening Protected data connections at the gateway's
/// workflow listener when `GATEWAY_WORKFLOW_URL` is set.
///
/// # Errors
///
/// [`PlatformError`] when the internal authority or the worker's
/// certificate does not read.
fn action_runner(parts: &Parts<'_>) -> Result<InstalledActionRunner, PlatformError> {
    let platform = parts.platform;
    let timeout = parts.config.http.workflow_requests.timeout;
    let runner = InstalledActionRunner::new(
        Arc::clone(&platform.integrations),
        platform.secrets.encryptor.clone(),
        timeout,
    );
    let Some(link) = &parts.config.gateway_link else {
        return Ok(runner);
    };
    let data = DataLink::new(link.url.clone(), &link.link, timeout)
        .map_err(PlatformError::of("the Protected data link"))?;
    Ok(runner.with_data(data))
}

/// The handler starting a published version on an event it listens for.
fn start_on_event(
    parts: &Parts<'_>,
    accounts_now: &Arc<AccountsNow>,
) -> Result<Arc<dyn JobHandler>, ServerError> {
    let start = StartOnEventUseCase::new(StartOnEventPorts {
        starts: trigger_starts(parts, accounts_now),
        records: Arc::clone(&parts.recorded_events),
    });
    let handler = StartOnEventHandler::new(Arc::new(start))
        .map_err(PlatformError::of("the workflow event start handler"))?;
    Ok(Arc::new(handler))
}

/// The handler starting a published version its schedule fired.
fn start_scheduled(
    parts: &Parts<'_>,
    accounts_now: &Arc<AccountsNow>,
) -> Result<Arc<dyn JobHandler>, ServerError> {
    let start = StartOnTriggerUseCase::new(trigger_starts(parts, accounts_now));
    let handler = StartScheduledHandler::new(Arc::new(start))
        .map_err(PlatformError::of("the workflow schedule start handler"))?;
    Ok(Arc::new(handler))
}
