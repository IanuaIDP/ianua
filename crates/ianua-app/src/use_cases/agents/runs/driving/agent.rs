//! Run agent: a person starts a governed run of an agent.
//!
//! Starting a run checks that the person may use its model provider, that
//! the delegation it acts under is theirs and they still hold what it hands
//! over, stores the run, queues the job that drives it on a worker (see
//! [`drive_run`](crate::use_cases::agents::runs::driving::drive)) and
//! announces it.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::ResourceCapability;
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::agents::execution::run::{
    AgentRun, MAX_RUN_STEPS, RunStarter, StartRunParams,
};
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{
    AgentStore, DelegationStore, ModelProviderStore, RelationshipResolver, RunAgentRequest,
    RunStore, ToolStore,
};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::shared::AuditLabelResolver;
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::resources::usage::UseCheck;
use crate::use_cases::agents::lookup::existing_model_provider;
use crate::use_cases::agents::runs::driving::RunDrives;
use crate::use_cases::agents::runs::driving::backing::{
    BackingSources, backing_delegation, ensure_still_held,
};
use crate::use_cases::agents::runs::reading::names::run_names;

/// The ports starting a run needs. Driving it is the worker's, through
/// [`DrivePorts`](crate::use_cases::agents::runs::DrivePorts),
/// which re-checks what starting checked first and holds the model, the
/// tools, the lease and the kill switch.
#[derive(Clone, ianua_macros::Fakes)]
pub struct AgentPorts {
    /// Keeps the runs.
    pub run_store: Arc<dyn RunStore>,
    /// The tenant's tool registry.
    pub tool_store: Arc<dyn ToolStore>,
    /// The agents, to check the acting one may act.
    pub agent_store: Arc<dyn AgentStore>,
    /// The delegations a run acts under.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// What the person starting a run holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The resource graph: what a person may use and hold.
    pub relationship_resolver: Arc<dyn RelationshipResolver>,
    /// The model providers.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// The tenant's cap on runs in flight.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Names the agent and provider in the audit trail.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Where the job driving the run is queued.
    pub run_drives: RunDrives,
}

/// How many model steps a run gets.
#[derive(Debug, Clone, Copy)]
pub struct StepLimits {
    /// What a run that asks for none gets.
    pub default: u32,
    /// The most a run may ask for.
    pub max: u32,
}

impl StepLimits {
    /// The steps a run that asked for `asked` gets: the default when it
    /// asked for none, never more than the maximum or the domain's
    /// [`MAX_RUN_STEPS`].
    #[must_use]
    pub fn resolve(self, asked: u32) -> u32 {
        let wanted = match asked {
            0 => self.default,
            asked => asked.min(self.max),
        };
        wanted.min(MAX_RUN_STEPS)
    }
}

/// Starts governed runs: stores each and hands it to a worker to drive.
pub struct AgentUseCase {
    ports: AgentPorts,
    steps: StepLimits,
}

impl AgentUseCase {
    /// A use case working through `ports`, giving runs as many steps as
    /// `steps` allows.
    #[must_use]
    pub fn new(ports: AgentPorts, steps: StepLimits) -> Self {
        Self { ports, steps }
    }
}

impl Command for AgentUseCase {
    type Caller = CallerContext;
    type Input = RunAgentRequest;
    type Output = Result<AgentRun<ResolvedTenant>, AppError>;

    /// Starts and stores a run of `request.agent_id` for the caller, queues
    /// the job that drives it with the save, then announces it. The caller
    /// returns at once.
    ///
    /// The tenant's limit is on runs in flight: a run keeps calling the
    /// model after the request returns, so a per-request limit would not
    /// bound what runs spend together.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the agent, the model provider or the
    ///   named delegation does not exist, or the delegation is another
    ///   agent's.
    /// - `AppError::Forbidden` when the tenant's limit on runs in flight is
    ///   reached, the caller may not use the provider, the delegation is
    ///   not theirs, is revoked, expired or sender-constrained, grants more
    ///   than they hold now, or the agent may not act.
    /// - `AppError::Domain` when the run asks for tools with no delegation
    ///   behind it.
    /// - `AppError::Internal` on persistence or dispatch failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RunAgentRequest,
    ) -> Result<AgentRun<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ensure_below_limit(&self.ports, ctx).await?;
        let control = AgentControl::new(&authority);
        ensure_usable_provider(&self.ports, &tenant, &control, &request).await?;
        let agent =
            existing_agent(self.ports.agent_store.as_ref(), &tenant, &request.agent_id).await?;
        let delegation = checked_delegation(&self.ports, &tenant, &control, &request).await?;
        let start = RunStart {
            authority: &authority,
            agent: &agent,
            delegation: delegation.as_ref(),
        };
        let mut run = started_run(&start, run_params(self.steps, request))?;
        let names = run_names(self.ports.audit_label_resolver.as_ref(), &tenant, &run).await;
        run.announce_start(names);
        self.ports
            .run_store
            .save(&tenant, &run)
            .await
            .or_internal()?;
        self.ports.run_drives.hand_over(&tenant, &run).await?;
        auditor
            .dispatch(&run.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(run)
    }
}

/// Who starts a run, of which agent, under which delegation, if any.
struct RunStart<'a> {
    /// The person starting it.
    authority: &'a TenantAuthority,
    /// The agent it runs.
    agent: &'a AgentIdentity<ResolvedTenant>,
    /// The delegation it acts under, or none.
    delegation: Option<&'a Delegation<ResolvedTenant>>,
}

/// Refuses a run once the tenant has as many in flight as its plan allows.
async fn ensure_below_limit(ports: &AgentPorts, ctx: &CallerContext) -> Result<(), AppError> {
    ports
        .limit_enforcer
        .check_tenant_limit(
            ctx.plan_limits(),
            &ctx.tenant(),
            ResourceKind::ActiveAgentRuns,
        )
        .await
        .map_err(AppError::from_domain)
}

/// Refuses a run on a provider that the person `control` names was not
/// given use of, or that does not exist. The use is checked first, so a
/// provider id tells someone not given it nothing about which exist.
async fn ensure_usable_provider(
    ports: &AgentPorts,
    tenant: &ScopedTenant,
    control: &AgentControl<'_>,
    request: &RunAgentRequest,
) -> Result<(), AppError> {
    let provider_id = &request.provider_id;
    let check = UseCheck {
        resolver: ports.relationship_resolver.as_ref(),
        tenant,
    };
    check
        .require(control, ResourceCapability::use_of_provider(provider_id))
        .await?;
    existing_model_provider(ports.provider_store.as_ref(), tenant, provider_id).await?;
    Ok(())
}

/// The delegation the run acts under, once the person `control` names
/// still holds what it hands over.
async fn checked_delegation(
    ports: &AgentPorts,
    tenant: &ScopedTenant,
    control: &AgentControl<'_>,
    request: &RunAgentRequest,
) -> Result<Option<Delegation<ResolvedTenant>>, AppError> {
    let starter = control.by().principal();
    let delegation = backing_delegation(
        ports.delegation_store.as_ref(),
        tenant,
        &starter,
        &request.agent_id,
        request.delegation_id,
    )
    .await?;
    let Some(delegation) = delegation else {
        return Ok(None);
    };
    let sources = BackingSources {
        resolver: ports.relationship_resolver.as_ref(),
        tools: ports.tool_store.as_ref(),
    };
    ensure_still_held(&sources, tenant, control, &delegation).await?;
    Ok(Some(delegation))
}

/// What a person's run starts with: what they asked for, at public, from
/// outside any workflow.
fn run_params(steps: StepLimits, request: RunAgentRequest) -> StartRunParams {
    StartRunParams {
        provider_id: request.provider_id,
        goal: request.goal,
        purpose: request.purpose,
        granted_tools: request.tool_names,
        approval_classes: request.approval_classes,
        max_steps: steps.resolve(request.max_steps),
        spend_limit: request.spend_limit,
        ask_past: request.ask_past,
        exposure: DataClassLevel::Public,
        origin: EventOrigin::Outside,
    }
}

/// The run `start` describes, started by the person, under its delegation
/// or, with none, without tools.
fn started_run(
    start: &RunStart<'_>,
    params: StartRunParams,
) -> Result<AgentRun<ResolvedTenant>, AppError> {
    let starter = RunStarter::person(start.authority);
    let started = match start.delegation {
        Some(delegation) => AgentRun::start(starter, params, delegation, start.agent),
        None => AgentRun::start_without_tools(starter, params, start.agent),
    };
    started.map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::agents::authority::delegation::{
        ActingUnder, DelegationRow, DelegationStatus,
    };
    use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
    use ianua_domain::domains::agents::execution::run::RunGoal;
    use ianua_domain::domains::agents::execution::tool::ToolName;
    use ianua_domain::domains::agents::execution::usage::Spend;
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{
        AgentAction, RoutingAction, SystemPermission,
    };
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::types::{ActionClass, AgentId, DelegationId, ModelProviderId, Seconds};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeDelegationStore, FakeModelProviderStore, FakeRelationshipResolver, FakeRunStore,
        caller_person, callers_agent, delegation_row, provider_cleared_for, someone, step_limits,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::agents::runs::DRIVE_RUN_JOB;

    /// The caller's agent and a provider they may use, with nothing granted
    /// yet.
    struct World {
        agent: AgentId,
        provider: ModelProviderId,
        agents: Arc<crate::test_support::agents::FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        providers: Arc<FakeModelProviderStore>,
        runs: Arc<FakeRunStore>,
        sink: Arc<FakeEventDispatcher>,
        queue: Arc<FakeJobQueue>,
    }

    fn world() -> World {
        let agent = AgentId::new();
        let provider = provider_cleared_for(DataClassLevel::Internal);
        let providers = Arc::new(FakeModelProviderStore::empty());
        block_on(providers.save(&test_ctx().tenant(), &provider)).unwrap();
        World {
            agent,
            provider: *provider.id(),
            agents: Arc::new(callers_agent(agent)),
            delegations: Arc::new(FakeDelegationStore::empty()),
            providers,
            runs: Arc::new(FakeRunStore::empty()),
            sink: Arc::new(FakeEventDispatcher::new()),
            queue: Arc::new(FakeJobQueue::new()),
        }
    }

    impl World {
        fn ports(&self) -> AgentPorts {
            AgentPorts {
                run_store: self.runs.clone(),
                agent_store: self.agents.clone(),
                delegation_store: self.delegations.clone(),
                provider_store: self.providers.clone(),
                run_drives: RunDrives {
                    queue: self.queue.clone(),
                    attempts: NonZeroU32::MIN,
                },
                ..AgentPorts::fakes()
            }
        }

        fn drive_jobs(&self) -> usize {
            self.queue.jobs_of(DRIVE_RUN_JOB).len()
        }

        /// Stores the delegation `row` describes, changed by `change`.
        fn granted(&self, change: impl FnOnce(&mut DelegationRow)) -> DelegationId {
            let mut row = delegation_row(self.agent, caller_person().principal());
            change(&mut row);
            let delegation = Delegation::reconstitute(row).unwrap();
            block_on(self.delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
            *delegation.id()
        }

        fn request(&self, delegation_id: Option<DelegationId>) -> RunAgentRequest {
            RunAgentRequest {
                agent_id: self.agent,
                provider_id: self.provider,
                goal: RunGoal::new("summarise the orders").unwrap(),
                purpose: IntentEnvelope::new([ActionClass::Read]),
                tool_names: Vec::new(),
                approval_classes: Vec::new(),
                delegation_id,
                max_steps: 5,
                spend_limit: Restriction::Unrestricted,
                ask_past: Restriction::Unrestricted,
            }
        }

        fn start_with(
            &self,
            ports: AgentPorts,
            request: RunAgentRequest,
        ) -> Result<AgentRun<ResolvedTenant>, AppError> {
            block_on(AgentUseCase::new(ports, step_limits()).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                request,
            ))
        }

        fn start(&self, request: RunAgentRequest) -> Result<AgentRun<ResolvedTenant>, AppError> {
            self.start_with(self.ports(), request)
        }
    }

    fn expiring_in(seconds: u32) -> impl FnOnce(&mut DelegationRow) {
        move |row| row.expires_at = row.issued_at + Seconds::new(seconds).duration()
    }

    /// Ann starts a run of her agent, which holds a delegation from her. The
    /// run acts under it, is stored, and is announced naming the agent and
    /// the provider.
    #[test]
    fn a_run_under_the_callers_delegation_is_stored_and_announced() {
        let w = world();
        let delegation = w.granted(|_| {});

        let run = w.start(w.request(None)).unwrap();

        assert_eq!(run.delegation_id(), &ActingUnder::Delegation(delegation));
        assert_eq!(w.runs.count(), 1);
        assert_eq!(
            w.sink.label_of("agents.run_started", "agent"),
            Some("test agent".to_owned())
        );
        assert_eq!(
            w.sink.label_of("agents.run_started", "provider"),
            Some("test provider".to_owned())
        );
    }

    /// Ann starts a run. With the run, the job that drives it is queued,
    /// so a worker takes it up even if the announcement never arrives.
    #[test]
    fn a_started_run_is_queued_to_be_driven() {
        let w = world();

        w.start(w.request(None)).unwrap();

        let jobs = w.queue.jobs_of(DRIVE_RUN_JOB);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].tenant_id(), Some(&test_ctx().tenant_id()));
        assert_eq!(w.runs.count(), 1);
    }

    /// A plan-limit refusal fails the start without queueing a drive job.
    #[test]
    fn a_refused_run_queues_no_drive_job() {
        let w = world();
        let ports = AgentPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..w.ports()
        };

        let result = w.start_with(ports, w.request(None));

        assert!(result.is_err());
        assert_eq!(w.drive_jobs(), 0);
    }

    /// Ann caps her run at five currency units. The run is stored with that
    /// limit, having spent nothing yet.
    #[test]
    fn a_run_keeps_the_spend_limit_it_was_started_with() {
        let w = world();
        let limit = Restriction::To(Spend::from_micros(5_000_000));
        let request = RunAgentRequest {
            spend_limit: limit,
            ..w.request(None)
        };

        let run = w.start(request).unwrap();

        assert_eq!(run.spend_limit(), limit);
        assert_eq!(run.spent(), Spend::default());
    }

    /// Ann's agent holds two delegations from her and the run names none.
    /// It acts under the one that ends first, whatever order the store
    /// keeps them in.
    #[test]
    fn of_two_delegations_the_soonest_to_end_backs_the_run() {
        let w = world();
        w.granted(expiring_in(500));
        let shorter = w.granted(expiring_in(300));

        let run = w.start(w.request(None)).unwrap();

        assert_eq!(run.delegation_id(), &ActingUnder::Delegation(shorter));
    }

    /// Ann names her own live delegation to her agent. The run acts under
    /// it.
    #[test]
    fn a_run_may_name_the_callers_live_delegation() {
        let w = world();
        let delegation = w.granted(|_| {});

        let run = w.start(w.request(Some(delegation))).unwrap();

        assert_eq!(run.delegation_id(), &ActingUnder::Delegation(delegation));
    }

    /// Naming another agent's delegation returns not found and saves no run.
    #[test]
    fn a_run_cannot_name_another_agents_delegation() {
        let w = world();
        let other = w.granted(|row| row.delegate = AgentId::new());

        let result = w.start(w.request(Some(other)));

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
    }

    /// A revoked delegation cannot back a new run; the refusal leaves none saved.
    #[test]
    fn a_run_cannot_name_a_revoked_delegation() {
        let w = world();
        let revoked = w.granted(|row| row.status = DelegationStatus::Revoked);

        let result = w.start(w.request(Some(revoked)));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
    }

    /// Explicitly naming a sender-constrained delegation is forbidden for a run.
    #[test]
    fn a_run_cannot_name_a_sender_constrained_delegation() {
        let w = world();
        let bound = w.granted(|row| row.constraints = row.constraints.clone().sender_constrained());

        let result = w.start(w.request(Some(bound)));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
    }

    /// The agent's only delegation from Ann is sender-constrained, and the
    /// run names none. It is not chosen: the run acts under no delegation.
    #[test]
    fn a_sender_constrained_delegation_is_never_chosen() {
        let w = world();
        w.granted(|row| row.constraints = row.constraints.clone().sender_constrained());

        let run = w.start(w.request(None)).unwrap();

        assert_eq!(run.delegation_id(), &ActingUnder::NoDelegation);
    }

    /// Another person's delegation cannot back the caller's run; the refusal
    /// leaves no run saved.
    #[test]
    fn a_run_cannot_act_under_someone_elses_delegation() {
        let w = world();
        let bobs = w.granted(|row| row.delegator = someone("bob@example.test").principal());

        let result = w.start(w.request(Some(bobs)));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
    }

    /// Requesting tools without a backing delegation fails validation and saves
    /// no run.
    #[test]
    fn a_run_with_tools_but_no_delegation_is_refused() {
        let w = world();
        let mut request = w.request(None);
        request.tool_names = vec![ToolName::new("delete_order").unwrap()];

        let result = w.start(request);

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
    }

    /// A caller lacking the routing rights granted by a delegation cannot start
    /// a run under it; no run is saved.
    #[test]
    fn a_run_under_authority_the_caller_no_longer_holds_is_refused() {
        let w = world();
        let delegation = w.granted(|row| {
            row.granted =
                CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![]);
        });
        let ports = AgentPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Delegate),
            ])),
            relationship_resolver: Arc::new(FakeRelationshipResolver::HoldsEverything),
            ..w.ports()
        };

        let result = w.start_with(ports, w.request(Some(delegation)));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
    }

    /// Delegation rights without permission to use the provider do not permit
    /// starting a run; none is saved.
    #[test]
    fn a_run_on_a_provider_the_caller_was_not_given_is_refused() {
        let w = world();
        let ports = AgentPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Delegate),
            ])),
            ..w.ports()
        };

        let result = w.start_with(ports, w.request(None));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
    }

    /// Ann asks for a run on a provider the tenant does not have. It is not
    /// found.
    #[test]
    fn a_run_on_an_unknown_provider_is_not_found() {
        let w = world();
        let mut request = w.request(None);
        request.provider_id = ModelProviderId::new();

        let result = w.start(request);

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
    }

    /// An unknown agent returns not found without saving a run or queueing a
    /// drive job.
    #[test]
    fn a_run_of_an_unknown_agent_is_not_found() {
        let w = world();
        let mut request = w.request(None);
        request.agent_id = AgentId::new();

        let result = w.start(request);

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
        assert_eq!(w.drive_jobs(), 0);
    }

    /// A suspended agent cannot start a delegated run; no run is saved.
    #[test]
    fn a_run_of_a_suspended_agent_is_refused() {
        let w = world();
        w.agents.add_with_status(w.agent, AgentStatus::Suspended);
        let delegation = w.granted(|_| {});

        let result = w.start(w.request(Some(delegation)));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
    }

    /// A revoked agent cannot start a run without delegation; the refusal saves
    /// no run and queues no drive job.
    #[test]
    fn a_run_of_a_revoked_agent_is_refused() {
        let w = world();
        w.agents
            .add_owned(w.agent, caller_person(), AgentStatus::Revoked);

        let result = w.start(w.request(None));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
        assert_eq!(w.drive_jobs(), 0);
    }

    /// A plan-limit refusal prevents starting a run and leaves the run store empty.
    #[test]
    fn a_run_past_the_plans_limit_is_refused() {
        let w = world();
        let ports = AgentPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..w.ports()
        };

        let result = w.start_with(ports, w.request(None));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(w.runs.count(), 0);
    }

    /// A signed-out session cannot start a run; none is saved and no audit event
    /// is recorded.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let w = world();
        let ports = AgentPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..w.ports()
        };

        let result = w.start_with(ports, w.request(None));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(w.runs.count(), 0);
        assert!(w.sink.records.lock().unwrap().is_empty());
    }

    /// A run that asks for no steps gets the default.
    #[test]
    fn a_run_that_asks_for_no_steps_gets_the_default() {
        let steps = StepLimits {
            default: 8,
            max: 20,
        };

        assert_eq!(steps.resolve(0), 8);
    }

    /// A run never gets more steps than the maximum, and gets what it asks
    /// for below it.
    #[test]
    fn a_run_cannot_ask_for_more_steps_than_the_maximum() {
        let steps = StepLimits {
            default: 8,
            max: 20,
        };

        assert_eq!(steps.resolve(50), 20);
        assert_eq!(steps.resolve(12), 12);
    }

    /// A deployment set to allow more steps than the domain does still
    /// gives a run no more than the domain's limit.
    #[test]
    fn no_run_gets_more_steps_than_the_domain_allows() {
        let steps = StepLimits {
            default: 8,
            max: MAX_RUN_STEPS * 2,
        };

        assert_eq!(steps.resolve(MAX_RUN_STEPS + 1), MAX_RUN_STEPS);
    }
}
