//! Grant delegation: a person hands an agent part of what they hold.
//!
//! The domain works out what the person may grant from (`held_by`), and
//! refuses an agent that is reviewing another or may not act now. A bound
//! intent narrows the grant, and a task template caps it.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{
    AppAccess, CapabilitySet, DelegationConstraints,
};
use ianua_domain::domains::agents::authority::delegation::{
    Delegate, Delegation, GrantDelegationParams,
};
use ianua_domain::domains::agents::authority::intent::{DriftPolicy, IntentStatement};
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, Label, PrincipalRef, TaskTemplateId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{
    AgentStore, DelegationStore, IntentCompiler, RelationshipResolver, ReviewAssignmentStore,
    TaskTemplateStore, TaskTokenIssuer, ToolStore,
};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::messaging::AgentChannelStore;
use crate::ports::routing::ServiceStore;
use crate::services::issuers::TenantIssuers;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::granting::authority::{AuthoritySources, held_by};
use crate::use_cases::agents::delegation::granting::grant_shape::{
    AskedGrant, ShapeSources, Shaped, shaped_grant,
};
use crate::use_cases::agents::delegation::resources::sharing::{
    SharingAgent, SharingStores, refuse_unchanneled_sharing,
};
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};
use crate::use_cases::agents::reviews::reviewing::review_duty;

/// A granted delegation together with the task token minted for it.
pub struct GrantedDelegation {
    /// The persisted delegation.
    pub delegation: Delegation<ResolvedTenant>,
    /// The signed task token the agent presents to the proxy.
    pub task_token: String,
    /// The principals the authority descends from, nearest first: one entry
    /// for a root delegation, and the whole line back to the person at the
    /// root for a sub-delegation.
    pub chain: Vec<PrincipalRef>,
}

/// An intent to bind to the delegation for drift monitoring.
pub struct IntentGrant {
    /// What the person said the agent is for.
    pub statement: IntentStatement,
    /// How drift from the intent is handled.
    pub drift_policy: DriftPolicy,
}

/// Request to grant a delegation to an agent.
pub struct GrantDelegationRequest {
    /// The agent receiving authority.
    pub delegate: AgentId,
    /// The capabilities to grant, held to what the caller holds.
    pub granted: CapabilitySet,
    /// Lifetime, depth, task, budget, resource scope, approval gate and
    /// sender constraint.
    pub constraints: DelegationConstraints,
    /// An intent to bind for drift monitoring, if any.
    pub intent: Option<IntentGrant>,
    /// A title people see, such as "Q1 reconciliation delegation".
    pub name: Option<Label>,
    /// The approved task template the delegation must fit inside, if any.
    pub template: Option<TaskTemplateId>,
}

/// The ports [`GrantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GrantPorts {
    /// What a grant is checked against and kept in: the agent, its delegations, the tenant's resource types, relations, tools, services and task templates.
    pub records: GrantRecordPorts,
    /// What mints the task token a delegation hands its agent.
    pub tokens: TaskTokenPorts,
    /// What follows a delegation: the agent's channel and the reviews it asks for.
    pub follow_up: FollowUpPorts,
    /// Compiles a bound intent into its scope and digest.
    pub intent_compiler: Arc<dyn IntentCompiler>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// What a grant is checked against and kept in: the agent, its delegations, the tenant's resource types, relations, tools, services and task templates.
#[derive(ianua_macros::Fakes)]
pub struct GrantRecordPorts {
    /// Loads the agent receiving the delegation.
    pub agent_store: Arc<dyn AgentStore>,
    /// Saves delegations, and says who holds a resource.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// The tenant's resource types, for how sensitive a shared object is.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// The relationship graph: what the caller holds.
    pub relationship_resolver: Arc<dyn RelationshipResolver>,
    /// The tenant's tool registry, the bound on any tool grant.
    pub tool_store: Arc<dyn ToolStore>,
    /// The tenant's services; every app a delegation names must be one.
    pub service_store: Arc<dyn ServiceStore>,
    /// The task templates a delegation may be granted under.
    pub template_store: Arc<dyn TaskTemplateStore>,
}

/// What mints the task token a delegation hands its agent.
#[derive(ianua_macros::Fakes)]
pub struct TaskTokenPorts {
    /// Mints the task token.
    pub token_issuer: Arc<dyn TaskTokenIssuer>,
    /// Works out the tenant's own issuer the task token names.
    pub issuers: TenantIssuers,
}

/// What follows a delegation: the agent's channel and the reviews it asks for.
#[derive(ianua_macros::Fakes)]
pub struct FollowUpPorts {
    /// The channels people opened between agents; a shared resource needs
    /// one.
    pub channel_store: Arc<dyn AgentChannelStore>,
    /// Who reviews whom; an agent that reviews is given nothing.
    pub review_store: Arc<dyn ReviewAssignmentStore>,
}

/// Grants delegations from people to agents.
pub struct GrantUseCase {
    ports: GrantPorts,
}

impl GrantUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: GrantPorts) -> Self {
        Self { ports }
    }
}

impl Command for GrantUseCase {
    type Caller = CallerContext;
    type Input = GrantDelegationRequest;
    type Output = Result<GrantedDelegation, AppError>;

    /// Grants the caller's delegation to `request.delegate`, shaped by its
    /// intent and template, saves it and mints its task token.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing/inaccessible agent or missing template.
    /// - `AppError::Forbidden` for exceeded caller, intent or template rights, an unapproved template, a closed shared-resource channel, or an agent unable to act or reviewing another.
    /// - `AppError::Conflict` when the agent lacks the bound credential.
    /// - `AppError::Domain` when a named app is outside the tenant's services; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: GrantDelegationRequest,
    ) -> Result<GrantedDelegation, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let agent = receiving_agent(&self.ports, &tenant, &control, &request.delegate).await?;
        let grant = Grant {
            tenant: &tenant,
            control: &control,
            agent: &agent,
        };
        let (mut delegation, task_token) = issued_grant(&self.ports, &grant, request).await?;
        let store = self.ports.records.delegation_store.as_ref();
        store.save(&tenant, &delegation).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), delegation.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(GrantedDelegation {
            chain: vec![*delegation.delegator()],
            delegation,
            task_token,
        })
    }
}

/// Who grants to which agent, in which tenant.
struct Grant<'a> {
    /// The scope containing both the grant and its recipient.
    tenant: &'a ScopedTenant,
    /// The person granting, with what they hold.
    control: &'a AgentControl<'a>,
    /// The agent receiving it.
    agent: &'a AgentIdentity<ResolvedTenant>,
}

/// Refuses a grant naming an app the tenant does not serve, or sharing a
/// resource with the agent over no open channel.
async fn ensure_shareable(
    ports: &GrantPorts,
    tenant: &ScopedTenant,
    agent: &AgentId,
    shaped: &Shaped,
) -> Result<(), AppError> {
    ensure_known_apps(
        ports.records.service_store.as_ref(),
        tenant,
        shaped.constraints.apps(),
    )
    .await?;
    refuse_unchanneled_sharing(
        SharingStores {
            delegations: ports.records.delegation_store.as_ref(),
            channels: ports.follow_up.channel_store.as_ref(),
            resource_types: ports.records.resource_type_store.as_ref(),
        },
        SharingAgent {
            tenant_id: tenant,
            agent,
        },
        shaped.granted.resources(),
    )
    .await
}

/// Refuses a delegation naming an app that is not one of this tenant's
/// services: its token would name no audience for it, and the grant would
/// promise access it cannot give.
///
/// # Errors
///
/// - `AppError::Domain` when an app named is not one of the tenant's
///   services.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::delegation) async fn ensure_known_apps(
    services: &dyn ServiceStore,
    tenant: &ScopedTenant,
    apps: &AppAccess,
) -> Result<(), AppError> {
    let AppAccess::Listed(apps) = apps else {
        return Ok(());
    };
    let found = services
        .find_by_ids(tenant, apps.services())
        .await
        .or_internal()?;
    if found.len() == apps.services().len() {
        return Ok(());
    }
    Err(AppError::from_domain(DomainError::invalid(message!(
        "agents-a-delegation-names-an-app-that",
        "a delegation names an app that is not one of this tenant's services"
    ))))
}

/// The agent `agent_id` names, once the person `control` names owns it or
/// may delegate to agents. Any other agent reads as missing.
async fn receiving_agent(
    ports: &GrantPorts,
    tenant: &ScopedTenant,
    control: &AgentControl<'_>,
    agent_id: &AgentId,
) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
    let reach = AgentReach::Acting(AgentAction::Delegate);
    owned_agent(
        ports.records.agent_store.as_ref(),
        tenant,
        agent_id,
        control,
        reach,
    )
    .await
}

/// What the request asks the delegation to be.
fn asked(request: &GrantDelegationRequest) -> AskedGrant<'_> {
    AskedGrant {
        granted: &request.granted,
        constraints: &request.constraints,
        intent: request.intent.as_ref(),
        template: request.template.as_ref(),
    }
}

fn shape_sources(ports: &GrantPorts) -> ShapeSources<'_> {
    ShapeSources {
        compiler: ports.intent_compiler.as_ref(),
        templates: ports.records.template_store.as_ref(),
    }
}

/// The delegation `request` asks for, shaped, held to what the caller holds
/// and shareable with the agent, with the task token minted for it.
async fn issued_grant(
    ports: &GrantPorts,
    grant: &Grant<'_>,
    request: GrantDelegationRequest,
) -> Result<(Delegation<ResolvedTenant>, String), AppError> {
    let shaped = shaped_grant(shape_sources(ports), grant.tenant, asked(&request)).await?;
    ensure_shareable(ports, grant.tenant, grant.agent.id(), &shaped).await?;
    let delegation = granted(ports, grant, shaped, request.name).await?;
    let minting = TaskTokenMinting {
        tokens: ports.tokens.token_issuer.as_ref(),
        issuers: &ports.tokens.issuers,
    };
    let task_token = issued_task_token(minting, grant.tenant, &delegation).await?;
    Ok((delegation, task_token))
}

/// The delegation the domain grants for `shaped`, held to what the caller
/// holds and refused to an agent that reviews another.
async fn granted(
    ports: &GrantPorts,
    grant: &Grant<'_>,
    shaped: Shaped,
    name: Option<Label>,
) -> Result<Delegation<ResolvedTenant>, AppError> {
    let sources = AuthoritySources {
        resolver: ports.records.relationship_resolver.as_ref(),
        tools: ports.records.tool_store.as_ref(),
    };
    let held = held_by(sources, grant.tenant, grant.control, &shaped.granted).await?;
    let duty = review_duty(
        ports.follow_up.review_store.as_ref(),
        grant.tenant,
        grant.agent.id(),
    )
    .await?;
    Delegation::grant(
        GrantDelegationParams {
            granted: shaped.granted,
            constraints: shaped.constraints,
            name,
        },
        &held,
        &Delegate {
            agent: grant.agent,
            duty,
        },
    )
    .map_err(AppError::from_domain)
}

/// The signed task token `minting` mints for `delegation`, revealed for
/// handing to the agent.
///
/// # Errors
///
/// - `AppError::Conflict` when the token is bound to a credential the agent
///   does not have.
/// - `AppError::NotFound` when the tenant or its organization is not on
///   record.
/// - `AppError::Internal` when no signing key is available, signing fails,
///   or the tenant cannot be read.
pub(in crate::use_cases::agents) async fn issued_task_token(
    minting: TaskTokenMinting<'_>,
    tenant: &ScopedTenant,
    delegation: &Delegation<ResolvedTenant>,
) -> Result<String, AppError> {
    let issuer = minting.issuers.of(tenant).await?;
    Ok(minting
        .tokens
        .issue(tenant, &issuer, delegation)
        .await
        .map_err(AppError::from_domain)?
        .reveal()
        .to_owned())
}

/// What a task token is minted through: the signer, and the tenant's own
/// issuer the token names.
#[derive(Clone, Copy)]
pub(in crate::use_cases::agents) struct TaskTokenMinting<'a> {
    /// Signs the token.
    pub(in crate::use_cases::agents) tokens: &'a dyn TaskTokenIssuer,
    /// Works out the issuer the token names.
    pub(in crate::use_cases::agents) issuers: &'a TenantIssuers,
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::{ActionApproval, AppReach};
    use ianua_domain::domains::agents::authority::intent::{
        DriftThreshold, IntentDigest, IntentEnvelope,
    };
    use ianua_domain::domains::agents::authority::task_template::{
        TaskTemplate, TaskTemplateRow, TemplateLimits, TemplateState,
    };
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::agents::oversight::review::{ReviewAssignment, ReviewAssignmentRow};
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::routing::backend::upstream::{
        HostHeader, Upstream, UpstreamTimeout,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::types::{
        ActionClass, Ending, HttpUrl, Human, HumanAccount, PersonKey, ReviewAssignmentId, Seconds,
        ServiceId, UserId,
    };

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        ConflictingTaskTokenIssuer, FakeAgentStore, FakeDelegationStore, FakeReviewStore,
        FakeTaskTemplateStore, WideningIntentCompiler, callers_agent,
    };
    use crate::test_support::routing::FakeServiceStore;
    use crate::test_support::{
        FakeEventDispatcher, block_on, reference_label, test_auditor, test_ctx,
    };

    fn caps(action: RoutingAction) -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(action)], vec![])
    }

    fn limits() -> DelegationConstraints {
        DelegationConstraints::new(Seconds::new(600), 1).unwrap()
    }

    /// The test caller's own agent, kept in a store with a fresh delegation
    /// store beside it.
    struct Bench {
        agent: AgentId,
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
    }

    fn bench() -> Bench {
        let agent = AgentId::new();
        Bench {
            agent,
            agents: Arc::new(callers_agent(agent)),
            delegations: Arc::new(FakeDelegationStore::empty()),
        }
    }

    impl Bench {
        fn ports(&self) -> GrantPorts {
            GrantPorts {
                records: GrantRecordPorts {
                    agent_store: self.agents.clone(),
                    delegation_store: self.delegations.clone(),
                    ..GrantRecordPorts::fakes()
                },
                ..GrantPorts::fakes()
            }
        }

        fn request(&self, granted: CapabilitySet) -> GrantDelegationRequest {
            GrantDelegationRequest {
                delegate: self.agent,
                granted,
                constraints: limits(),
                intent: None,
                name: None,
                template: None,
            }
        }
    }

    fn grant(
        ports: GrantPorts,
        sink: &Arc<FakeEventDispatcher>,
        request: GrantDelegationRequest,
    ) -> Result<GrantedDelegation, AppError> {
        block_on(GrantUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn quietly(
        ports: GrantPorts,
        request: GrantDelegationRequest,
    ) -> Result<GrantedDelegation, AppError> {
        grant(ports, &Arc::new(FakeEventDispatcher::new()), request)
    }

    fn holding(system: &[SystemPermission]) -> Arc<FakeTenantAuthorities> {
        Arc::new(FakeTenantAuthorities::holding(system))
    }

    /// Ann, who may manage routes, gives her agent "view routes". The
    /// delegation is saved, named as hers, and its grant and token are
    /// recorded.
    #[test]
    fn a_grant_within_what_the_caller_holds_is_saved_and_recorded() {
        let b = bench();
        let sink = Arc::new(FakeEventDispatcher::new());

        let granted = grant(b.ports(), &sink, b.request(caps(RoutingAction::View))).unwrap();

        assert_eq!(b.delegations.count(), 1);
        assert_eq!(granted.chain, vec![*granted.delegation.delegator()]);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.delegation_granted", "agents.token_issued"]
        );
    }

    /// The grant names the agent by its name and the delegation by its id
    /// when it has no title.
    #[test]
    fn the_records_name_the_agent_and_fall_back_to_the_delegation_id() {
        let b = bench();
        let sink = Arc::new(FakeEventDispatcher::new());

        let granted = grant(b.ports(), &sink, b.request(caps(RoutingAction::View))).unwrap();

        let payloads = sink.all_payloads();
        let id = granted.delegation.id().to_string();
        assert_eq!(
            reference_label(&payloads[0], "delegate"),
            Some("fake-agent")
        );
        assert_eq!(
            reference_label(&payloads[0], "delegation"),
            Some(id.as_str())
        );
        assert_eq!(
            reference_label(&payloads[1], "delegate"),
            Some("fake-agent")
        );
    }

    /// Ann titles the delegation "Q1 reconciliation delegation". Both
    /// records name it so.
    #[test]
    fn the_records_prefer_the_delegations_title() {
        let b = bench();
        let sink = Arc::new(FakeEventDispatcher::new());
        let mut request = b.request(caps(RoutingAction::View));
        request.name = Some(Label::new("name", "Q1 reconciliation delegation").unwrap());

        grant(b.ports(), &sink, request).unwrap();

        let payloads = sink.all_payloads();
        for payload in &payloads {
            assert_eq!(
                reference_label(payload, "delegation"),
                Some("Q1 reconciliation delegation")
            );
        }
    }

    /// A caller holding only route-view permission cannot grant route
    /// management, and no delegation is saved.
    #[test]
    fn a_grant_beyond_what_the_caller_holds_is_refused() {
        let b = bench();
        let ports = GrantPorts {
            tenant_authorities: holding(&[SystemPermission::Routing(RoutingAction::View)]),
            ..b.ports()
        };

        let result = quietly(ports, b.request(caps(RoutingAction::Manage)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(b.delegations.count(), 0);
    }

    /// An intent compiler adding route management to a route-view request
    /// causes rejection without saving a delegation.
    #[test]
    fn an_intent_compiled_wider_than_the_grant_is_refused() {
        let b = bench();
        let ports = GrantPorts {
            intent_compiler: Arc::new(WideningIntentCompiler {
                extra: caps(RoutingAction::Manage),
            }),
            ..b.ports()
        };
        let mut request = b.request(caps(RoutingAction::View));
        request.intent = Some(IntentGrant {
            statement: IntentStatement::new("read the route table").unwrap(),
            drift_policy: DriftPolicy::Off,
        });

        let result = quietly(ports, request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(b.delegations.count(), 0);
    }

    /// A route manager without authority over another owner's agent sees it
    /// as missing when granting, and no delegation is saved.
    #[test]
    fn a_caller_with_no_say_over_the_agent_is_refused() {
        let agent = AgentId::new();
        let b = Bench {
            agent,
            agents: Arc::new(FakeAgentStore::with_active(agent)),
            delegations: Arc::new(FakeDelegationStore::empty()),
        };
        let ports = GrantPorts {
            tenant_authorities: holding(&[SystemPermission::Routing(RoutingAction::Manage)]),
            ..b.ports()
        };

        let result = quietly(ports, b.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(b.delegations.count(), 0);
    }

    /// A signed-out caller cannot grant authority; no delegation is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let b = bench();
        let ports = GrantPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..b.ports()
        };

        let result = quietly(ports, b.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(b.delegations.count(), 0);
    }

    /// Ann gives a delegation to an agent the tenant does not have. It is
    /// not found.
    #[test]
    fn a_grant_to_an_unknown_agent_is_not_found() {
        let b = bench();
        let mut request = b.request(caps(RoutingAction::View));
        request.delegate = AgentId::new();

        let result = quietly(b.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Granting authority to a suspended agent is refused without saving a
    /// delegation.
    #[test]
    fn a_suspended_agent_is_given_nothing() {
        let agent = AgentId::new();
        let agents = FakeAgentStore::empty();
        agents.add_with_status(agent, AgentStatus::Suspended);
        let b = Bench {
            agent,
            agents: Arc::new(agents),
            delegations: Arc::new(FakeDelegationStore::empty()),
        };

        let result = quietly(b.ports(), b.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(b.delegations.count(), 0);
    }

    /// An agent reviewing another cannot receive route-view authority, and
    /// no delegation is saved.
    #[test]
    fn an_agent_reviewing_another_is_given_nothing() {
        let b = bench();
        let ports = {
            let base = b.ports();
            GrantPorts {
                follow_up: FollowUpPorts {
                    review_store: Arc::new(reviewing(b.agent)),
                    ..base.follow_up
                },
                ..base
            }
        };

        let result = quietly(ports, b.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(b.delegations.count(), 0);
    }

    /// A reviewer cannot receive an app-scoped delegation even with empty
    /// capabilities; no delegation is saved.
    #[test]
    fn an_agent_reviewing_another_is_given_no_app_either() {
        let b = bench();
        let (ports, billing) = with_service(&b);
        let ports = GrantPorts {
            follow_up: FollowUpPorts {
                review_store: Arc::new(reviewing(b.agent)),
                ..ports.follow_up
            },
            ..ports
        };
        let mut request = b.request(CapabilitySet::empty());
        request.constraints = limits().with_apps(AppReach::new([billing]).unwrap());

        let result = quietly(ports, request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(b.delegations.count(), 0);
    }

    /// A review store in which `reviewer` reviews another agent now.
    fn reviewing(reviewer: AgentId) -> FakeReviewStore {
        let reviews = FakeReviewStore::default();
        let assignment = ReviewAssignment::reconstitute(ReviewAssignmentRow {
            id: ReviewAssignmentId::new(),
            reviewer,
            reviewed: AgentId::new(),
            assigned_by: PrincipalRef::User(UserId::new()),
            assigned_at: clock::now(),
            ending: Ending::from_stored(None),
        })
        .unwrap();
        block_on(reviews.save(&test_ctx().tenant(), &assignment)).unwrap();
        reviews
    }

    /// Asking for a token bound to a credential the agent does not have is
    /// for the caller to fix by enrolling one, not a server failure. It is a
    /// conflict, and nothing is saved.
    #[test]
    fn a_token_bound_to_a_missing_credential_is_a_conflict() {
        let b = bench();
        let ports = {
            let base = b.ports();
            GrantPorts {
                tokens: TaskTokenPorts {
                    token_issuer: Arc::new(ConflictingTaskTokenIssuer),
                    ..base.tokens
                },
                ..base
            }
        };
        let mut request = b.request(caps(RoutingAction::View));
        request.constraints = limits().sender_constrained();

        let result = quietly(ports, request);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(b.delegations.count(), 0);
    }

    fn with_service(b: &Bench) -> (GrantPorts, ServiceId) {
        let upstream = Upstream::new(
            HttpUrl::new("https://backend:8080").unwrap(),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );
        let (services, id) = FakeServiceStore::with_one(test_ctx().tenant_id(), upstream);
        let ports = {
            let base = b.ports();
            GrantPorts {
                records: GrantRecordPorts {
                    service_store: services,
                    ..base.records
                },
                ..base
            }
        };
        (ports, id)
    }

    /// Ann lets her agent call the tenant's backend app. The delegation
    /// keeps the app.
    #[test]
    fn a_grant_naming_one_of_the_tenants_apps_keeps_it() {
        let b = bench();
        let (ports, service) = with_service(&b);
        let mut request = b.request(caps(RoutingAction::View));
        request.constraints = limits().with_apps(AppReach::new([service]).unwrap());

        let granted = quietly(ports, request).unwrap();

        let AppAccess::Listed(apps) = granted.delegation.constraints().apps() else {
            panic!("the delegation keeps its apps");
        };
        assert_eq!(apps.services(), [service]);
    }

    /// Ann names the backend app and one the tenant does not have. She is
    /// refused and nothing is saved.
    #[test]
    fn a_grant_naming_an_app_the_tenant_does_not_have_is_refused() {
        let b = bench();
        let (ports, service) = with_service(&b);
        let mut request = b.request(caps(RoutingAction::View));
        request.constraints =
            limits().with_apps(AppReach::new([service, ServiceId::new()]).unwrap());

        let result = quietly(ports, request);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(b.delegations.count(), 0);
    }

    fn template(state: TemplateState) -> TaskTemplate<ResolvedTenant> {
        let proposer = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("sam@example.test").unwrap(),
        );
        TaskTemplate::reconstitute(TaskTemplateRow {
            id: TaskTemplateId::new(),
            name: Label::new("name", "reports").unwrap(),
            purpose: IntentStatement::new("read the reports").unwrap(),
            digest: IntentDigest::new([3; 32]),
            ceiling: caps(RoutingAction::View),
            classes: IntentEnvelope::new([ActionClass::Read]),
            limits: TemplateLimits {
                max_ttl_seconds: Seconds::new(600),
                max_depth: 1,
                max_data_class: DataClassLevel::Internal,
                resource_scope: Restriction::Unrestricted,
                budget: Restriction::Unrestricted,
                approval: ActionApproval::NotRequired,
            },
            proposed_by: proposer,
            proposed_at: clock::now() - time::Duration::minutes(1),
            state,
        })
        .unwrap()
    }

    fn approved() -> TemplateState {
        let approver = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("bob@example.test").unwrap(),
        );
        TemplateState::from_stored(Some(approver), Some(clock::now()), None).unwrap()
    }

    fn under_template(
        state: Option<TemplateState>,
        intent: Option<IntentGrant>,
    ) -> Result<GrantedDelegation, AppError> {
        let b = bench();
        let templates = FakeTaskTemplateStore::default();
        let id = state.map_or_else(TaskTemplateId::new, |state| {
            let template = template(state);
            block_on(templates.save(&test_ctx().tenant(), &template)).unwrap();
            *template.id()
        });
        let ports = {
            let base = b.ports();
            GrantPorts {
                records: GrantRecordPorts {
                    template_store: Arc::new(templates),
                    ..base.records
                },
                ..base
            }
        };
        let mut request = b.request(CapabilitySet::new(
            vec![
                SystemPermission::Routing(RoutingAction::View),
                SystemPermission::Routing(RoutingAction::Manage),
            ],
            vec![],
        ));
        request.template = Some(id);
        request.intent = intent;
        quietly(ports, request)
    }

    /// Ann grants under the approved "reports" template. The grant is what
    /// both she and the template allow, under its purpose and data ceiling.
    #[test]
    fn a_grant_under_a_template_is_capped_by_it() {
        let granted = under_template(Some(approved()), None).unwrap();

        let delegation = granted.delegation;
        assert_eq!(delegation.granted(), &caps(RoutingAction::View));
        let bounds = delegation.constraints();
        assert!(bounds.template().limit().is_some());
        assert_eq!(
            bounds.max_data_class().limit(),
            Some(&DataClassLevel::Internal)
        );
        assert_eq!(
            bounds.intent().limit().unwrap().envelope(),
            &IntentEnvelope::new([ActionClass::Read])
        );
    }

    /// A proposed task template cannot authorize a grant before approval.
    #[test]
    fn a_template_not_yet_approved_grants_nothing() {
        let result = under_template(Some(TemplateState::Proposed), None);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A warning-only intent cannot broaden an approved template's read
    /// envelope.
    #[test]
    fn an_intent_that_only_warns_cannot_lift_the_templates_classes() {
        let result = under_template(
            Some(approved()),
            Some(IntentGrant {
                statement: IntentStatement::new("read the reports").unwrap(),
                drift_policy: DriftPolicy::Warn(DriftThreshold::DEFAULT),
            }),
        );

        assert!(result.is_err());
    }

    /// Ann names a template the tenant does not have. It is not found.
    #[test]
    fn an_unknown_template_is_not_found() {
        let result = under_template(None, None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
