//! Grant delegation resource: add one resource capability to a delegation
//! without granting the whole thing again.
//!
//! The domain decides how far the delegation may grow. A root grows only
//! within what its delegator holds: the delegator adds what they hold
//! themselves, and an agent administrator adds what both they and the
//! delegator hold now. A sub-delegation grows only within its parent, and
//! only by the agent holding the parent or a person with a say over it. A
//! token an agent minted for itself never grows. The app adds the rest:
//! the task template the delegation was granted under, a channel for an
//! object another agent holds, and an agent that reviews holding nothing.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, ResourceCapability};
use ianua_domain::domains::agents::authority::delegation::{
    Delegation, HeldBy, HeldNow, Lineage, ResourceCeiling,
};
use ianua_domain::domains::agents::authority::task_template::TemplateStatus;
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, DelegationId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{
    AgentStore, DelegationStore, RelationshipResolver, ReviewAssignmentStore, TaskTemplateStore,
    ToolStore,
};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::messaging::AgentChannelStore;
use crate::services::account_now::AccountsNow;
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::granting::authority::{
    AuthoritySources, Speaker, asked_about, speaker_for,
};
use crate::use_cases::agents::delegation::resources::sharing::{
    SharingAgent, SharingStores, refuse_unchanneled_sharing,
};
use crate::use_cases::agents::delegation::resources::usage::held_resources;
use crate::use_cases::agents::lookup::{existing_delegation, owned_delegation};
use crate::use_cases::agents::reviews::reviewing::refuse_capabilities_for_reviewer;

/// Request to grant a single resource capability onto an existing delegation.
pub struct GrantResourceRequest {
    /// The agent the route named. The delegation must be one of its own.
    pub agent_id: AgentId,
    /// The delegation receiving the capability.
    pub delegation_id: DelegationId,
    /// The relation and object to grant.
    pub capability: ResourceCapability,
}

/// The ports [`GrantResourceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GrantResourcePorts {
    /// The tenant's resource types, for how sensitive a shared object is.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// Loads and saves the delegation, and its parent.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// The agent holding a sub-delegation's parent.
    pub agent_store: Arc<dyn AgentStore>,
    /// The tenant's tool registry, which bounds tool grants.
    pub tool_store: Arc<dyn ToolStore>,
    /// What people hold in the relationship graph.
    pub relationship_resolver: Arc<dyn RelationshipResolver>,
    /// The person who granted a delegation, as their account stands now,
    /// for what they hold now.
    pub accounts_now: Arc<AccountsNow>,
    /// The channels people opened between agents. A shared object needs one.
    pub channel_store: Arc<dyn AgentChannelStore>,
    /// Who reviews whom. An agent that reviews holds no capabilities.
    pub review_store: Arc<dyn ReviewAssignmentStore>,
    /// The task templates delegations are granted under.
    pub template_store: Arc<dyn TaskTemplateStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Grants a single resource capability onto an existing delegation.
pub struct GrantResourceUseCase {
    ports: GrantResourcePorts,
}

impl GrantResourceUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: GrantResourcePorts) -> Self {
        Self { ports }
    }
}

impl Command for GrantResourceUseCase {
    type Caller = CallerContext;
    type Input = GrantResourceRequest;
    type Output = Result<Delegation<ResolvedTenant>, AppError>;

    /// Adds `req.capability` to the delegation, in place.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the delegation, its parent or the agent
    ///   holding the parent does not exist, or the delegation is not the
    ///   named agent's.
    /// - `AppError::Forbidden` when the domain refuses to widen it: the
    ///   caller is neither its delegator nor an agent administrator, or has
    ///   no say over the parent's agent, the resource reaches past what the
    ///   delegator or the parent holds, or the agent minted it for itself.
    ///   Also when its task template does not allow the resource, a shared
    ///   object has no channel, or the agent reviews another.
    /// - `AppError::Domain` when the delegation is revoked.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: GrantResourceRequest,
    ) -> Result<Delegation<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.delegation_store.as_ref();
        let mut delegation =
            owned_delegation(store, &tenant, &req.agent_id, &req.delegation_id).await?;
        ensure_grantable(&self.ports, &tenant, &delegation, &req).await?;
        let widened = widened(&delegation, &req.capability);
        let source = ceiling_source(&self.ports, &tenant, &control, &delegation, &widened).await?;
        delegation
            .grant_resource(&req.capability, &source.ceiling(control))
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &delegation).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), delegation.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(delegation)
    }
}

/// What the ceiling on a delegation's growth is made from, loaded for
/// where the delegation sits in its chain.
enum CeilingSource {
    /// The caller granted the root: what they hold.
    Delegator(HeldBy),
    /// Someone else granted the root: what the caller and the delegator
    /// hold.
    Administrator {
        /// What the caller holds.
        admin: HeldBy,
        /// What the delegator holds now.
        delegator: HeldNow,
    },
    /// A sub-delegation: its parent and the agent holding the parent.
    Parent {
        /// The parent delegation.
        parent: Box<Delegation<ResolvedTenant>>,
        /// The agent holding it.
        holder: Box<AgentIdentity<ResolvedTenant>>,
        /// How the caller speaks for that agent.
        speaker: Speaker,
    },
}

impl CeilingSource {
    /// The ceiling, with the caller `control` widening a sub-delegation for
    /// the agent holding its parent.
    fn ceiling<'a>(&'a self, control: AgentControl<'a>) -> ResourceCeiling<'a, ResolvedTenant> {
        match self {
            Self::Delegator(held) => ResourceCeiling::Delegator(held.clone()),
            Self::Administrator { admin, delegator } => ResourceCeiling::Administrator {
                admin: admin.clone(),
                delegator: delegator.clone(),
            },
            Self::Parent {
                parent,
                holder,
                speaker,
            } => ResourceCeiling::Parent {
                parent: parent.as_ref(),
                by: speaker.attenuator(control, holder.as_ref()),
            },
        }
    }
}

/// A delegation about to grow, the caller growing it and what it would
/// grant afterwards.
struct Widening<'a> {
    /// The tenant it lives in.
    tenant: &'a ScopedTenant,
    /// The caller.
    control: &'a AgentControl<'a>,
    /// What it would grant afterwards.
    widened: &'a CapabilitySet,
    /// The tenant's tool registry.
    registry: &'a [AgentTool<ResolvedTenant>],
}

/// Refuses a resource the delegation's task template does not allow, an
/// object shared with another agent over no channel, or any resource for
/// an agent that reviews.
async fn ensure_grantable(
    ports: &GrantResourcePorts,
    tenant: &ScopedTenant,
    delegation: &Delegation<ResolvedTenant>,
    req: &GrantResourceRequest,
) -> Result<(), AppError> {
    ensure_within_template(
        ports.template_store.as_ref(),
        tenant,
        delegation,
        &req.capability,
    )
    .await?;
    refuse_unchanneled_sharing(
        SharingStores {
            delegations: ports.delegation_store.as_ref(),
            channels: ports.channel_store.as_ref(),
            resource_types: ports.resource_type_store.as_ref(),
        },
        SharingAgent {
            tenant_id: tenant,
            agent: &req.agent_id,
        },
        std::slice::from_ref(&req.capability),
    )
    .await?;
    refuse_capabilities_for_reviewer(
        ports.review_store.as_ref(),
        tenant,
        &req.agent_id,
        &CapabilitySet::empty().with_resources(vec![req.capability.clone()]),
    )
    .await
}

/// Refuses a resource the task template the delegation was granted under
/// does not allow. A template retired or gone since allows nothing more.
async fn ensure_within_template(
    templates: &dyn TaskTemplateStore,
    tenant: &ScopedTenant,
    delegation: &Delegation<ResolvedTenant>,
    capability: &ResourceCapability,
) -> Result<(), AppError> {
    let Some(template_id) = delegation.constraints().template().limit() else {
        return Ok(());
    };
    let template = templates
        .find_by_id(tenant, template_id)
        .await
        .or_internal()?;
    let allowed = template.is_some_and(|template| {
        template.status() == TemplateStatus::Approved
            && template
                .ceiling()
                .resources()
                .iter()
                .any(|held| held.covers(capability))
    });
    if allowed {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "agents-the-task-template-this-delegation-was",
        "the task template this delegation was granted under does not allow that resource"
    )))
}

/// What `delegation` would grant with `capability` added.
fn widened(
    delegation: &Delegation<ResolvedTenant>,
    capability: &ResourceCapability,
) -> CapabilitySet {
    let mut resources = delegation.granted().resources().to_vec();
    resources.push(capability.clone());
    delegation.granted().clone().with_resources(resources)
}

/// The ceiling's makings for where `delegation` sits: its parent for a
/// sub-delegation, the caller's holdings when they granted it or the agent
/// minted it, and the caller's beside the delegator's otherwise.
async fn ceiling_source(
    ports: &GrantResourcePorts,
    tenant: &ScopedTenant,
    control: &AgentControl<'_>,
    delegation: &Delegation<ResolvedTenant>,
    widened: &CapabilitySet,
) -> Result<CeilingSource, AppError> {
    if let Lineage::Under(parent_id) = delegation.lineage() {
        return parent_source(ports, tenant, parent_id, control, widened).await;
    }
    let registry = ports.tool_store.list(tenant).await.or_internal()?;
    let widening = Widening {
        tenant,
        control,
        widened,
        registry: &registry,
    };
    let admin = held_by_caller(ports, &widening).await?;
    if delegation.is_self_rooted() || *delegation.delegator() == control.by().principal() {
        return Ok(CeilingSource::Delegator(admin));
    }
    let delegator = held_by_delegator(ports, &widening, delegation).await?;
    Ok(CeilingSource::Administrator { admin, delegator })
}

/// The parent `parent_id` names, the agent holding it, and how the caller
/// speaks for that agent when widening to `widened`.
async fn parent_source(
    ports: &GrantResourcePorts,
    tenant: &ScopedTenant,
    parent_id: &DelegationId,
    control: &AgentControl<'_>,
    widened: &CapabilitySet,
) -> Result<CeilingSource, AppError> {
    let parent = existing_delegation(ports.delegation_store.as_ref(), tenant, parent_id).await?;
    let holder = existing_agent(ports.agent_store.as_ref(), tenant, parent.delegate()).await?;
    let sources = AuthoritySources {
        resolver: ports.relationship_resolver.as_ref(),
        tools: ports.tool_store.as_ref(),
    };
    let speaker = speaker_for(sources, tenant, control, &holder, widened).await?;
    Ok(CeilingSource::Parent {
        parent: Box::new(parent),
        holder: Box::new(holder),
        speaker,
    })
}

/// What the caller may grant from, for the widened delegation.
async fn held_by_caller(
    ports: &GrantResourcePorts,
    widening: &Widening<'_>,
) -> Result<HeldBy, AppError> {
    let held = held_resources(
        ports.relationship_resolver.as_ref(),
        widening.tenant,
        widening.control.by().principal(),
        widening.widened,
        widening.registry,
    )
    .await?;
    HeldBy::worked_out(widening.control, widening.widened, &held, widening.registry)
        .map_err(AppError::from_domain)
}

/// What the person who granted `delegation` holds now, for the widened
/// delegation, from their account as it stands.
///
/// # Errors
///
/// - `AppError::Forbidden` when no person granted it, or their account is
///   gone or may not act in the tenant now: they hold nothing to widen it
///   with.
/// - `AppError::Internal` when the records cannot be read, or name a role
///   or group that is not there.
async fn held_by_delegator(
    ports: &GrantResourcePorts,
    widening: &Widening<'_>,
    delegation: &Delegation<ResolvedTenant>,
) -> Result<HeldNow, AppError> {
    let holds_nothing = || {
        AppError::Forbidden(message!(
            "agents-the-delegation-s-delegator-holds-nothing",
            "the delegation's delegator holds nothing now"
        ))
    };
    let account = delegation
        .delegator()
        .human_account()
        .ok_or_else(holds_nothing)?;
    let asked = asked_about(widening.widened, widening.registry);
    let person = ports
        .accounts_now
        .holder_of(widening.tenant, account, &asked)
        .await?
        .ok_or_else(holds_nothing)?;
    person
        .authority(|account, access, held| {
            HeldNow::worked_out(access, account, widening.widened, held, widening.registry)
        })?
        .ok_or_else(holds_nothing)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::DelegationConstraints;
    use ianua_domain::domains::agents::authority::delegation::{DelegationStatus, Lineage};
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::{PrincipalRef, Seconds, TaskTemplateId, UserId};

    use super::*;
    use crate::services::account_now::AccountsNowPorts;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, FakeResourceGraph, StoredGrant, caller_person,
        callers_agent, resource_cap, stored_delegation,
    };
    use crate::test_support::authorization::FakeAccessRecordStore;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn me() -> PrincipalRef {
        caller_person().principal()
    }

    fn constraints() -> DelegationConstraints {
        DelegationConstraints::new(Seconds::new(600), 1).unwrap()
    }

    fn grant(delegator: PrincipalRef, delegate: AgentId, lineage: Lineage) -> StoredGrant {
        StoredGrant {
            delegator,
            delegate,
            granted: CapabilitySet::empty(),
            constraints: constraints(),
            lineage,
            status: DelegationStatus::Active,
        }
    }

    /// A tenant with its delegations, the graph of who holds what and its
    /// agents.
    struct Tenant {
        delegations: Arc<FakeDelegationStore>,
        graph: Arc<FakeResourceGraph>,
        agents: Arc<FakeAgentStore>,
        users: Arc<FakeUserStore>,
        records: Arc<FakeAccessRecordStore>,
    }

    impl Tenant {
        fn new() -> Self {
            Self {
                delegations: Arc::new(FakeDelegationStore::empty()),
                graph: Arc::new(FakeResourceGraph::empty()),
                agents: Arc::new(FakeAgentStore::empty()),
                users: Arc::new(FakeUserStore::empty()),
                records: Arc::new(FakeAccessRecordStore::empty()),
            }
        }

        /// Someone with an active account of the tenant.
        fn person(&self) -> PrincipalRef {
            let id = UserId::new();
            self.users.add_active_user(id, "ann@example.test");
            PrincipalRef::User(id)
        }

        fn with_agents(agents: FakeAgentStore) -> Self {
            Self {
                agents: Arc::new(agents),
                ..Self::new()
            }
        }

        fn stored(&self, grant: StoredGrant) -> Delegation<ResolvedTenant> {
            let delegation = stored_delegation(grant);
            block_on(self.delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
            delegation
        }

        fn holding(&self, holder: PrincipalRef, capability: ResourceCapability) {
            self.graph.insert(&test_ctx().tenant(), holder, capability);
        }

        fn ports(&self) -> GrantResourcePorts {
            let accounts = AccountsNow::new(AccountsNowPorts {
                access_records: self.records.clone(),
                users: self.users.clone(),
                relationships: self.graph.clone(),
                ..AccountsNowPorts::fakes()
            });
            GrantResourcePorts {
                delegation_store: self.delegations.clone(),
                agent_store: self.agents.clone(),
                relationship_resolver: self.graph.clone(),
                accounts_now: Arc::new(accounts),
                ..GrantResourcePorts::fakes()
            }
        }

        fn grants(&self, id: &DelegationId) -> Vec<ResourceCapability> {
            block_on(self.delegations.find_by_id(&test_ctx().tenant(), id))
                .unwrap()
                .unwrap()
                .granted()
                .resources()
                .to_vec()
        }
    }

    fn add(
        ports: GrantResourcePorts,
        sink: &Arc<FakeEventDispatcher>,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<Delegation<ResolvedTenant>, AppError> {
        block_on(GrantResourceUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            GrantResourceRequest {
                agent_id: *delegation.delegate(),
                delegation_id: *delegation.id(),
                capability: resource_cap("reader", "ledger:2026-q1"),
            },
        ))
    }

    fn quietly(
        ports: GrantResourcePorts,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<Delegation<ResolvedTenant>, AppError> {
        add(ports, &Arc::new(FakeEventDispatcher::new()), delegation)
    }

    /// Ann reads the Q1 ledger and adds it to the delegation she gave her
    /// agent. The delegation grants it, and the change is recorded.
    #[test]
    fn a_delegator_adds_a_resource_they_hold() {
        let tenant = Tenant::new();
        let delegation = tenant.stored(grant(me(), AgentId::new(), Lineage::Root));
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));
        let sink = Arc::new(FakeEventDispatcher::new());

        add(tenant.ports(), &sink, &delegation).unwrap();

        assert_eq!(
            tenant.grants(delegation.id()),
            vec![resource_cap("reader", "ledger:2026-q1")]
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.delegation_resource_granted"]
        );
    }

    /// A delegator without the ledger relation cannot add it; no resource
    /// capability or audit event is saved.
    #[test]
    fn a_resource_the_delegator_does_not_hold_is_refused() {
        let tenant = Tenant::new();
        let delegation = tenant.stored(grant(me(), AgentId::new(), Lineage::Root));
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = add(tenant.ports(), &sink, &delegation);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.grants(delegation.id()).is_empty());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Bob manages agents. He adds the ledger to the delegation Ann gave her
    /// agent, and both of them read it. The delegation grants it.
    #[test]
    fn an_agent_administrator_adds_what_both_hold() {
        let tenant = Tenant::new();
        let ann = tenant.person();
        let delegation = tenant.stored(grant(ann, AgentId::new(), Lineage::Root));
        tenant.holding(ann, resource_cap("reader", "ledger:2026-q1"));
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));
        let bob = GrantResourcePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Manage),
            ])),
            ..tenant.ports()
        };

        quietly(bob, &delegation).unwrap();

        assert_eq!(
            tenant.grants(delegation.id()),
            vec![resource_cap("reader", "ledger:2026-q1")]
        );
    }

    /// An administrator cannot widen a delegation whose delegator account
    /// is missing, even when the graph still grants both people the resource.
    #[test]
    fn widening_the_delegation_of_someone_who_left_is_refused() {
        let tenant = Tenant::new();
        let ann = PrincipalRef::User(UserId::new());
        let delegation = tenant.stored(grant(ann, AgentId::new(), Lineage::Root));
        tenant.holding(ann, resource_cap("reader", "ledger:2026-q1"));
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));
        let bob = GrantResourcePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Manage),
            ])),
            ..tenant.ports()
        };

        let result = quietly(bob, &delegation);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.grants(delegation.id()).is_empty());
    }

    /// Bob, who manages agents, widens the delegation Ann gave her agent.
    /// What Ann holds now is read from her own records alone; the rest of
    /// the tenant's are not read.
    #[test]
    fn widening_reads_only_the_delegators_records() {
        let tenant = Tenant::new();
        let ann = tenant.person();
        let delegation = tenant.stored(grant(ann, AgentId::new(), Lineage::Root));
        tenant.holding(ann, resource_cap("reader", "ledger:2026-q1"));
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));
        let bob = GrantResourcePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Manage),
            ])),
            ..tenant.ports()
        };

        quietly(bob, &delegation).unwrap();

        assert_eq!(tenant.records.whole_reads(), 0);
    }

    /// Delegation permission cannot widen someone else's grant, even when
    /// both people hold the resource; its capabilities stay empty.
    #[test]
    fn widening_someone_elses_delegation_without_managing_agents_is_refused() {
        let tenant = Tenant::new();
        let ann = tenant.person();
        let delegation = tenant.stored(grant(ann, AgentId::new(), Lineage::Root));
        tenant.holding(ann, resource_cap("reader", "ledger:2026-q1"));
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));
        let sam = GrantResourcePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Delegate),
            ])),
            ..tenant.ports()
        };

        let result = quietly(sam, &delegation);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.grants(delegation.id()).is_empty());
    }

    /// Adding a resource through another agent's address reports the
    /// delegation as missing.
    #[test]
    fn a_delegation_named_through_another_agent_is_not_found() {
        let tenant = Tenant::new();
        let delegation = tenant.stored(grant(me(), AgentId::new(), Lineage::Root));
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));

        let result = block_on(GrantResourceUseCase::new(tenant.ports()).execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            GrantResourceRequest {
                agent_id: AgentId::new(),
                delegation_id: *delegation.id(),
                capability: resource_cap("reader", "ledger:2026-q1"),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A parent's owner cannot add a resource outside the parent delegation,
    /// even when the owner holds that resource personally.
    #[test]
    fn a_sub_delegation_is_capped_by_its_parent() {
        let parent_agent = AgentId::new();
        let tenant = Tenant::with_agents(callers_agent(parent_agent));
        let parent = tenant.stored(grant(me(), parent_agent, Lineage::Root));
        let child = tenant.stored(grant(
            PrincipalRef::Agent(parent_agent),
            AgentId::new(),
            Lineage::Under(*parent.id()),
        ));
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));

        let result = quietly(tenant.ports(), &child);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann's agent's delegation grants the ledger, and it passed part of the
    /// delegation on. Ann, its owner, adds the ledger to the part passed on.
    #[test]
    fn a_sub_delegation_grows_within_its_parent() {
        let parent_agent = AgentId::new();
        let tenant = Tenant::with_agents(callers_agent(parent_agent));
        let parent = tenant.stored(StoredGrant {
            granted: CapabilitySet::empty()
                .with_resources(vec![resource_cap("reader", "ledger:2026-q1")]),
            ..grant(me(), parent_agent, Lineage::Root)
        });
        let child = tenant.stored(grant(
            PrincipalRef::Agent(parent_agent),
            AgentId::new(),
            Lineage::Under(*parent.id()),
        ));

        quietly(tenant.ports(), &child).unwrap();

        assert_eq!(
            tenant.grants(child.id()),
            vec![resource_cap("reader", "ledger:2026-q1")]
        );
    }

    /// A viewer without authority over the parent's agent cannot widen its
    /// child delegation, even within the parent's capabilities.
    #[test]
    fn a_person_without_a_say_over_the_parents_agent_is_refused() {
        let parent_agent = AgentId::new();
        let tenant = Tenant::with_agents(FakeAgentStore::with_active(parent_agent));
        let parent = tenant.stored(StoredGrant {
            granted: CapabilitySet::empty()
                .with_resources(vec![resource_cap("reader", "ledger:2026-q1")]),
            ..grant(
                PrincipalRef::User(UserId::new()),
                parent_agent,
                Lineage::Root,
            )
        });
        let child = tenant.stored(grant(
            PrincipalRef::Agent(parent_agent),
            AgentId::new(),
            Lineage::Under(*parent.id()),
        ));
        let mallory = GrantResourcePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..tenant.ports()
        };

        let result = quietly(mallory, &child);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Adding a resource to a delegation rooted in the agent itself is refused.
    #[test]
    fn a_resource_cannot_be_added_to_an_agents_own_token() {
        let tenant = Tenant::new();
        let agent = AgentId::new();
        let own = tenant.stored(grant(PrincipalRef::Agent(agent), agent, Lineage::Root));
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));

        let result = quietly(tenant.ports(), &own);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A delegation bound to an unavailable task template cannot gain a resource.
    #[test]
    fn a_resource_the_template_does_not_allow_is_refused() {
        let tenant = Tenant::new();
        let delegation = tenant.stored(StoredGrant {
            constraints: constraints().under_template(TaskTemplateId::new()),
            ..grant(me(), AgentId::new(), Lineage::Root)
        });
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));

        let result = quietly(tenant.ports(), &delegation);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A revoked delegation refuses a resource addition and keeps its
    /// resource capabilities empty.
    #[test]
    fn a_revoked_delegation_takes_no_resource() {
        let tenant = Tenant::new();
        let delegation = tenant.stored(StoredGrant {
            status: DelegationStatus::Revoked,
            ..grant(me(), AgentId::new(), Lineage::Root)
        });
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));

        let result = quietly(tenant.ports(), &delegation);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(tenant.grants(delegation.id()).is_empty());
    }

    /// A signed-out caller cannot add a resource; the delegation's resource
    /// capabilities stay empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::new();
        let delegation = tenant.stored(grant(me(), AgentId::new(), Lineage::Root));
        tenant.holding(me(), resource_cap("reader", "ledger:2026-q1"));
        let ports = GrantResourcePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = quietly(ports, &delegation);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(tenant.grants(delegation.id()).is_empty());
    }
}
