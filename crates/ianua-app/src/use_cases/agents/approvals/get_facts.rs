//! Approval facts: what ianua knows about an action, before what the agent
//! says about it.
//!
//! An approver judges by what they are shown. A summary the model wrote can
//! say whatever gets the action through. So the approval view leads with what
//! ianua itself computed: the exact call, the registered tool's method, path,
//! action class and data class, the most sensitive data the agent has touched,
//! whom it acts for, how often it was refused, drifted or met another agent
//! lately, and the channels data could have reached it through. The agent's own
//! words come last, labelled as its claim, with every invisible character
//! stripped.
//!
//! The facts quote the call, so a reader must be cleared for what the
//! request shows, as an approver must.

use std::sync::Arc;

use ianua_domain::domains::agents::channels::channel::AgentChannel;
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::oversight::approval::{Approval, ApprovalRequest};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::validation::invisible::{is_invisible, strip_invisible};
use ianua_domain::types::{AgentId, ApprovalId, PrincipalRef};
use time::{Duration, OffsetDateTime};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{
    AgentActivityStore, AgentExposureGate, AgentStore, ApprovalStore, DelegationStore, ToolStore,
};
use crate::ports::audit::AuditLogFilter;
use crate::ports::messaging::AgentChannelStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::agents::delegation::granting::lineage::principal_chain;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent, owned_approval};

/// Which approval request to read the facts for, addressed under the agent it
/// was raised for.
pub struct GetFactsRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The request being decided.
    pub approval_id: ApprovalId,
}

/// The exact call a run is holding.
#[derive(Debug, Clone)]
pub struct HeldCall {
    /// The tool the model asked for.
    pub tool: String,
    /// Its arguments, verbatim: exactly what will run.
    pub arguments: String,
    /// Whether the arguments carry invisible characters. They are shown, not
    /// hidden, because stripping them would misstate what runs.
    pub arguments_hide_characters: bool,
    /// The tool as registered, when it still is.
    pub registered: Option<AgentTool<ResolvedTenant>>,
}

/// How the agent has behaved lately, from its own audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecentRecord {
    /// Requests and messages ianua refused it.
    pub refusals: u64,
    /// Times it drifted from its declared intent.
    pub drifts: u64,
    /// Times it met another agent at one path.
    pub meetings: u64,
}

/// Everything ianua computed about a paused action, and the agent's claim.
pub struct Facts {
    /// The request being decided.
    pub approval: ApprovalRequest<ResolvedTenant>,
    /// The call a run is holding, when a run raised the request.
    pub call: Option<HeldCall>,
    /// The most sensitive data the agent has touched.
    pub exposure: DataClassLevel,
    /// Whom the agent acts for, nearest first. Empty when the request names
    /// no delegation.
    pub on_behalf_of: Vec<PrincipalRef>,
    /// Its record over the recent window.
    pub recent: RecentRecord,
    /// Open channels other agents' data could have reached it through.
    pub channels_in: Vec<AgentChannel<ResolvedTenant>>,
    /// How many different people must approve.
    pub approvers_needed: u8,
    /// The first of two approvals, if given.
    pub first_approval: Option<Approval>,
    /// The agent's own summary, invisible characters stripped. A claim, not a
    /// fact.
    pub agent_claim: String,
}

/// The ports [`GetFactsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetFactsPorts {
    /// The request.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// The agent, whose owner may read the facts.
    pub agent_store: Arc<dyn AgentStore>,
    /// The delegation chain.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// The registered tool.
    pub tool_store: Arc<dyn ToolStore>,
    /// The agent's data mark.
    pub exposure: Arc<dyn AgentExposureGate>,
    /// The agent's audit record.
    pub activity_store: Arc<dyn AgentActivityStore>,
    /// Channels into the agent.
    pub channel_store: Arc<dyn AgentChannelStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the facts for one approval.
pub struct GetFactsUseCase {
    recent: Duration,
    ports: GetFactsPorts,
}

impl GetFactsUseCase {
    /// A use case reading through `ports`. `recent` is how far back the
    /// agent's record of refusals, drift and meetings reaches.
    #[must_use]
    pub fn new(recent: Duration, ports: GetFactsPorts) -> Self {
        Self { recent, ports }
    }
}

impl Query for GetFactsUseCase {
    type Caller = CallerContext;
    type Input = GetFactsRequest;
    type Output = Result<Facts, AppError>;

    /// The facts for the approval request, which must belong to the agent
    /// the address named.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when there is no such agent or request, the
    ///   request is not this agent's, or the caller neither owns the agent
    ///   nor may view agents, so that an agent of someone else's answers as
    ///   one that does not exist.
    /// - `AppError::Forbidden` when the caller is not cleared for what the
    ///   request shows.
    /// - `AppError::Internal` when any fact cannot be read. Facts are not
    ///   optional: a partial view is how an approver is misled.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: GetFactsRequest,
    ) -> Result<Facts, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let approval = readable_approval(&self.ports, &tenant, &authority, &request).await?;
        let agent_id = approval.agent_id();
        Ok(Facts {
            call: held_call(&self.ports, &tenant, &approval).await?,
            exposure: self
                .ports
                .exposure
                .current(&tenant, agent_id)
                .await
                .or_internal()?,
            on_behalf_of: on_behalf_of(&self.ports, &tenant, &approval).await?,
            recent: recent(&self.ports, &tenant, agent_id, clock::now() - self.recent).await?,
            channels_in: channels_in(&self.ports, &tenant, agent_id).await?,
            approvers_needed: approval.approvers_needed(),
            first_approval: approval.first_approval().cloned(),
            agent_claim: strip_invisible(approval.action().as_str()),
            approval,
        })
    }
}

/// Refuses a reader cleared below what `approval` shows.
fn ensure_cleared(
    authority: &TenantAuthority,
    approval: &ApprovalRequest<ResolvedTenant>,
) -> Result<(), AppError> {
    if approval.readable_by(authority) {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "agents-the-reader-is-not-cleared-for",
        "the reader is not cleared for the data the request shows"
    )))
}

/// The request `request` names, once `authority`'s person owns its agent or
/// may view agents, and is cleared for what it shows.
async fn readable_approval(
    ports: &GetFactsPorts,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    request: &GetFactsRequest,
) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
    let control = AgentControl::new(authority);
    let reach = AgentReach::Acting(AgentAction::View);
    let agents = ports.agent_store.as_ref();
    let agent = owned_agent(agents, tenant, &request.agent_id, &control, reach).await?;
    let approval = owned_approval(
        ports.approval_store.as_ref(),
        tenant,
        agent.id(),
        &request.approval_id,
    )
    .await?;
    ensure_cleared(authority, &approval)?;
    Ok(approval)
}

/// The call the run behind `approval` holds, with the tool as registered.
async fn held_call(
    ports: &GetFactsPorts,
    tenant: &ScopedTenant,
    approval: &ApprovalRequest<ResolvedTenant>,
) -> Result<Option<HeldCall>, AppError> {
    let Some(call) = approval.pending_call() else {
        return Ok(None);
    };
    let registered = ports
        .tool_store
        .list(tenant)
        .await
        .or_internal()?
        .into_iter()
        .find(|tool| tool.name().as_str() == call.tool());
    Ok(Some(HeldCall {
        tool: call.tool().to_owned(),
        arguments: call.arguments().to_owned(),
        arguments_hide_characters: call.arguments().chars().any(is_invisible),
        registered,
    }))
}

/// The principals the delegation `approval` uses descends from, nearest
/// first.
async fn on_behalf_of(
    ports: &GetFactsPorts,
    tenant: &ScopedTenant,
    approval: &ApprovalRequest<ResolvedTenant>,
) -> Result<Vec<PrincipalRef>, AppError> {
    let Some(delegation_id) = approval.delegation_id().delegation() else {
        return Ok(Vec::new());
    };
    let store = ports.delegation_store.as_ref();
    let Some(delegation) = store
        .find_by_id(tenant, delegation_id)
        .await
        .or_internal()?
    else {
        return Ok(Vec::new());
    };
    principal_chain(store, tenant, &delegation).await
}

/// The agent's refusals, drift and meetings since `since`.
async fn recent(
    ports: &GetFactsPorts,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    since: OffsetDateTime,
) -> Result<RecentRecord, AppError> {
    let count = |event_type: &'static str| count_since(ports, tenant, agent_id, event_type, since);
    Ok(RecentRecord {
        refusals: count("agents.action_denied").await? + count("agents.message_denied").await?,
        drifts: count("agents.intent_drift").await?,
        meetings: count("agents.converged").await?,
    })
}

/// How many `event_type` records the agent produced since `since`.
async fn count_since(
    ports: &GetFactsPorts,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    event_type: &str,
    since: OffsetDateTime,
) -> Result<u64, AppError> {
    let filter = AuditLogFilter {
        event_type: Some(event_type.to_owned()),
        after: Some(since),
        ..AuditLogFilter::default()
    };
    ports
        .activity_store
        .count(tenant, agent_id, &filter)
        .await
        .or_internal()
}

/// The channels into the agent that are open now.
async fn channels_in(
    ports: &GetFactsPorts,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
) -> Result<Vec<AgentChannel<ResolvedTenant>>, AppError> {
    let now = clock::now();
    let channels = ports
        .channel_store
        .unclosed_into(tenant, agent_id)
        .await
        .or_internal()?;
    Ok(channels
        .into_iter()
        .filter(|channel| channel.is_open(now))
        .collect())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::delegation::{ActingUnder, Delegation};
    use ianua_domain::domains::agents::execution::run::{ResolvedCall, ToolCall};
    use ianua_domain::domains::agents::execution::tool::{PathValue, PathValues, ToolMethod};
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::agents::oversight::approval::{
        ActionParties, ApprovalAction, ApprovalOrigin, RequestApprovalParams,
    };
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{ActionClass, DeclaredAction, Human, Initiator, Seconds};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentActivityStore, FakeAgentStore, FakeApprovalStore, FakeDelegationStore,
        FakeExposureGate, FakeToolStore, agent_owned_by, delegation_row, order_tool,
        raised_approval, run_started_by, someone,
    };
    use crate::test_support::messaging::{FakeAgentChannelStore, open_channel};
    use crate::test_support::{block_on, test_ctx};

    /// Ann's agent, the stores the facts are read from, and the use case
    /// over them.
    struct Fixture {
        use_case: GetFactsUseCase,
        agent: AgentIdentity<ResolvedTenant>,
        ann: Human,
        approvals: Arc<FakeApprovalStore>,
        delegations: Arc<FakeDelegationStore>,
        tools: Arc<FakeToolStore>,
        channels: Arc<FakeAgentChannelStore>,
    }

    fn fixture(recent_total: u64) -> Fixture {
        fixture_for(
            recent_total,
            Arc::new(FakeTenantAuthorities::holding_everything()),
        )
    }

    fn fixture_for(recent_total: u64, authorities: Arc<dyn TenantAuthorities>) -> Fixture {
        let tenant = test_ctx().tenant();
        let agent = agent_owned_by(AgentId::new(), someone("owner@corp.test"));
        let agents = stored_agent(&agent);
        let exposure = Arc::new(FakeExposureGate::default());
        exposure.set(&tenant, *agent.id(), DataClassLevel::Confidential);
        let (approvals, delegations, tools, channels) = (
            Arc::new(FakeApprovalStore::empty()),
            Arc::new(FakeDelegationStore::empty()),
            Arc::new(FakeToolStore::empty()),
            Arc::new(FakeAgentChannelStore::empty()),
        );
        let ports = GetFactsPorts {
            approval_store: approvals.clone(),
            agent_store: agents,
            delegation_store: delegations.clone(),
            tool_store: tools.clone(),
            exposure,
            activity_store: Arc::new(FakeAgentActivityStore::with_total(recent_total)),
            channel_store: channels.clone(),
            tenant_authorities: authorities,
        };
        Fixture {
            use_case: GetFactsUseCase::new(Duration::hours(24), ports),
            agent,
            ann: someone("ann@corp.test"),
            approvals,
            delegations,
            tools,
            channels,
        }
    }

    /// Makes the fixture's agent available through the same store the use case reads.
    fn stored_agent(agent: &AgentIdentity<ResolvedTenant>) -> Arc<FakeAgentStore> {
        let agents = Arc::new(FakeAgentStore::empty());
        block_on(agents.save(&test_ctx().tenant(), agent)).unwrap();
        agents
    }

    impl Fixture {
        fn agent_id(&self) -> AgentId {
            *self.agent.id()
        }

        fn delegation(&self) -> Delegation<ResolvedTenant> {
            let delegation =
                Delegation::reconstitute(delegation_row(self.agent_id(), self.ann.principal()))
                    .unwrap();
            block_on(self.delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
            delegation
        }

        /// A request raised by Ann's run, paused on deleting order 1 with
        /// `arguments`.
        fn raised(&self, arguments: &str) -> ApprovalId {
            let delegation = self.delegation();
            let mut run = run_started_by(&self.ann, &self.agent, &delegation);
            let tool = order_tool("delete_order");
            let values = PathValues::new().with("id", PathValue::new("1").unwrap());
            let call = ToolCall::new("delete_order", arguments).unwrap();
            run.await_approval(
                ResolvedCall::resolve(call, &tool, &values).unwrap(),
                &self.agent,
            )
            .unwrap();
            self.saved(&raised_approval(&run, &self.agent, &self.ann, &tool))
        }

        /// A request Olga opened by hand, with `action` as its summary,
        /// under the delegation when one is given.
        fn opened(&self, action: &str, under: Option<&Delegation<ResolvedTenant>>) -> ApprovalId {
            let (delegation_id, delegators) = match under {
                Some(delegation) => (
                    ActingUnder::Delegation(*delegation.id()),
                    vec![self.ann.clone()],
                ),
                None => (ActingUnder::NoDelegation, Vec::new()),
            };
            let approval = ApprovalRequest::request(RequestApprovalParams {
                agent_id: self.agent_id(),
                delegation_id,
                origin: ApprovalOrigin::Opened(Initiator::Human(someone("olga@corp.test"))),
                parties: ActionParties::from_stored(self.agent.owner().clone(), delegators),
                action_class: DeclaredAction::Declared(ActionClass::Write),
                action: ApprovalAction::new(action).unwrap(),
                ttl_seconds: Seconds::new(900),
            })
            .unwrap();
            self.saved(&approval)
        }

        fn saved(&self, approval: &ApprovalRequest<ResolvedTenant>) -> ApprovalId {
            block_on(self.approvals.save(&test_ctx().tenant(), approval)).unwrap();
            *approval.id()
        }

        fn read(&self, approval_id: ApprovalId) -> Result<Facts, AppError> {
            block_on(self.use_case.execute(
                &test_ctx(),
                GetFactsRequest {
                    agent_id: self.agent_id(),
                    approval_id,
                },
            ))
        }
    }

    /// Bob reads the facts of the delete Ann's run paused on. He sees the
    /// exact arguments, the tool as registered, the agent's data mark and
    /// that two people must approve.
    #[test]
    fn the_held_call_comes_with_the_tool_as_registered() {
        let f = fixture(0);
        block_on(
            f.tools
                .save(&test_ctx().tenant(), &order_tool("delete_order")),
        )
        .unwrap();
        let id = f.raised(r#"{"id":1}"#);

        let facts = f.read(id).unwrap();

        let call = facts.call.unwrap();
        assert_eq!(call.arguments, r#"{"id":1}"#);
        assert_eq!(call.registered.unwrap().method(), ToolMethod::Delete);
        assert_eq!(facts.exposure, DataClassLevel::Confidential);
        assert_eq!(facts.approvers_needed, 2);
    }

    /// Arguments are shown as they will run; hidden characters in them are
    /// flagged rather than silently removed.
    #[test]
    fn hidden_characters_in_the_arguments_are_flagged_not_hidden() {
        let f = fixture(0);
        let id = f.raised("{\"id\":1}\u{202E}");

        let call = f.read(id).unwrap().call.unwrap();

        assert!(call.arguments_hide_characters);
        assert!(call.arguments.contains('\u{202E}'));
    }

    /// The summary on a request opened by hand comes last, as a claim, and
    /// there is no held call.
    #[test]
    fn the_agents_claim_comes_last_and_clean() {
        let f = fixture(0);
        let id = f.opened("just a routine cleanup", None);

        let facts = f.read(id).unwrap();

        assert_eq!(facts.agent_claim, "just a routine cleanup");
        assert!(facts.call.is_none());
    }

    /// The agent's recent record counts refusals, drift and meetings.
    #[test]
    fn the_record_counts_refusals_drift_and_meetings() {
        let f = fixture(2);
        let id = f.opened("x", None);

        let recent = f.read(id).unwrap().recent;

        assert_eq!(
            recent,
            RecentRecord {
                refusals: 4,
                drifts: 2,
                meetings: 2
            }
        );
    }

    /// The facts name Ann, whose delegation the agent acts under.
    #[test]
    fn the_chain_names_whom_the_agent_acts_for() {
        let f = fixture(0);
        let delegation = f.delegation();
        let id = f.opened("x", Some(&delegation));

        let facts = f.read(id).unwrap();

        assert_eq!(facts.on_behalf_of, [f.ann.principal()]);
    }

    /// An open channel into the agent is listed as a way data could have
    /// reached it.
    #[test]
    fn open_channels_into_the_agent_are_listed() {
        let f = fixture(0);
        let channel = open_channel(AgentId::new(), f.agent_id(), &someone("sam@corp.test"));
        block_on(f.channels.save(&test_ctx().tenant(), &channel)).unwrap();
        let id = f.opened("x", None);

        assert_eq!(f.read(id).unwrap().channels_in.len(), 1);
    }

    /// Reading approval facts through another agent's address reports the
    /// request as missing.
    #[test]
    fn another_agents_approval_is_not_found() {
        let f = fixture(0);
        let other = fixture(0);
        let id = other.opened("x", None);
        let request = other.approvals.all().remove(0);
        f.saved(&request);

        let result = f.read(id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An internal-cleared viewer cannot read facts from an agent-opened
    /// request whose data exceeds that clearance.
    #[test]
    fn a_reader_cleared_below_the_request_is_refused() {
        let f = fixture_for(
            0,
            Arc::new(FakeTenantAuthorities::holding(&[SystemPermission::Agents(
                AgentAction::View,
            )])),
        );
        let approval = ApprovalRequest::request(RequestApprovalParams {
            agent_id: f.agent_id(),
            delegation_id: ActingUnder::NoDelegation,
            origin: ApprovalOrigin::Opened(Initiator::Agent(f.agent_id())),
            parties: ActionParties::from_stored(f.agent.owner().clone(), Vec::new()),
            action_class: DeclaredAction::Declared(ActionClass::Write),
            action: ApprovalAction::new("pay the usual vendor").unwrap(),
            ttl_seconds: Seconds::new(900),
        })
        .unwrap();
        let id = f.saved(&approval);

        let result = f.read(id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading another owner's approval facts without agent-view permission
    /// reports the agent as missing.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let f = fixture_for(0, Arc::new(FakeTenantAuthorities::holding(&[])));
        let id = f.opened("x", None);

        let result = f.read(id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot read approval facts.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_for(
            0,
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        );
        let id = f.opened("x", None);

        let result = f.read(id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
