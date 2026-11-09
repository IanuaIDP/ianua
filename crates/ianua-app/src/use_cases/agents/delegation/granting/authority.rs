//! What a person may hand to an agent, worked out by the domain from what
//! the records say they hold.
//!
//! The domain decides the ceiling ([`HeldBy::worked_out`]). The app only
//! fetches what it reads: the tenant's tool registry, and the relationship
//! graph's answer for the resources a grant wants and the use of each
//! registered tool. The ceiling is never built from the request, or the
//! check would compare the request against itself.

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, ResourceCapability};
use ianua_domain::domains::agents::authority::delegation::{Attenuator, HeldBy, HeldResources};
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::PrincipalRef;

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{RelationshipResolver, ToolStore};
use crate::tenancy::ScopedTenant;

/// Where what someone holds is read from.
#[derive(Clone, Copy)]
pub(in crate::use_cases::agents) struct AuthoritySources<'a> {
    /// The relationship graph.
    pub(in crate::use_cases::agents) resolver: &'a dyn RelationshipResolver,
    /// The tenant's tool registry.
    pub(in crate::use_cases::agents) tools: &'a dyn ToolStore,
}

/// What the domain needs read to work out what one principal holds: the
/// graph's answer about them, and the tool registry it was asked against.
pub(in crate::use_cases::agents) struct Holdings {
    /// The resources and tool uses the graph says they hold.
    pub(in crate::use_cases::agents) held: HeldResources,
    /// The tenant's registered tools.
    pub(in crate::use_cases::agents) registry: Vec<AgentTool<ResolvedTenant>>,
}

/// What the person `control` names may grant from, for a grant asking for
/// `wanted`.
///
/// # Errors
///
/// - `AppError::Internal` when the registry or the graph cannot be read.
pub(in crate::use_cases::agents) async fn held_by(
    sources: AuthoritySources<'_>,
    tenant: &ScopedTenant,
    control: &AgentControl<'_>,
    wanted: &CapabilitySet,
) -> Result<HeldBy, AppError> {
    let holdings = holdings_of(sources, tenant, control.by().principal(), wanted).await?;
    HeldBy::worked_out(control, wanted, &holdings.held, &holdings.registry)
        .map_err(AppError::from_domain)
}

/// How a person speaks for the agent holding a delegation they pass on or
/// widen: as its owner, or as a steward who passes on only what they hold.
pub(in crate::use_cases::agents) enum Speaker {
    /// They own the agent.
    Owner,
    /// They may delegate to agents and hold this, worked out for what they
    /// pass on.
    Steward(HeldBy),
}

impl Speaker {
    /// The domain's attenuator for this speaker, `control`, over `holder`.
    pub(in crate::use_cases::agents) fn attenuator<'a>(
        &'a self,
        control: AgentControl<'a>,
        holder: &'a AgentIdentity<ResolvedTenant>,
    ) -> Attenuator<'a, ResolvedTenant> {
        match self {
            Self::Owner => Attenuator::Owner { control, holder },
            Self::Steward(held) => Attenuator::Steward {
                control,
                holder,
                held,
            },
        }
    }
}

/// How the person `control` names speaks for `holder` when passing on
/// `passed`: as its owner, or as a steward with what they hold of it.
///
/// # Errors
///
/// - `AppError::Internal` when the registry or the graph cannot be read.
pub(in crate::use_cases::agents) async fn speaker_for(
    sources: AuthoritySources<'_>,
    tenant: &ScopedTenant,
    control: &AgentControl<'_>,
    holder: &AgentIdentity<ResolvedTenant>,
    passed: &CapabilitySet,
) -> Result<Speaker, AppError> {
    if control.by().is_same_person_as(holder.owner()) {
        return Ok(Speaker::Owner);
    }
    held_by(sources, tenant, control, passed)
        .await
        .map(Speaker::Steward)
}

/// What the graph says `subject` holds of what `wanted` asks about, and of
/// the use of each registered tool, with the registry it was asked against.
///
/// # Errors
///
/// - `AppError::Internal` when the registry or the graph cannot be read.
pub(in crate::use_cases::agents) async fn holdings_of(
    sources: AuthoritySources<'_>,
    tenant: &ScopedTenant,
    subject: PrincipalRef,
    wanted: &CapabilitySet,
) -> Result<Holdings, AppError> {
    let registry = sources.tools.list(tenant).await.or_internal()?;
    let asked = asked_about(wanted, &registry);
    let held = sources
        .resolver
        .held_subset(tenant, &subject, &asked)
        .await
        .or_internal()?;
    Ok(Holdings {
        held: HeldResources::answered(subject, held),
        registry,
    })
}

/// The resources `wanted` names and the use of every registered tool, each
/// once: what the graph is asked about to work out what someone may grant
/// or still holds of it.
pub(in crate::use_cases::agents) fn asked_about(
    wanted: &CapabilitySet,
    registry: &[AgentTool<ResolvedTenant>],
) -> Vec<ResourceCapability> {
    let tool_uses = registry
        .iter()
        .map(|tool| ResourceCapability::use_of_tool(tool.id()));
    let mut asked: Vec<ResourceCapability> = Vec::new();
    for capability in wanted.resources().iter().cloned().chain(tool_uses) {
        if !asked.contains(&capability) {
            asked.push(capability);
        }
    }
    asked
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::{
        McpGrant, McpTool, McpToolPattern, Relation, ResourceRef,
    };
    use ianua_domain::domains::agents::execution::tool::{
        AgentToolRow, ToolDescription, ToolMethod, ToolName, ToolPath, ToolSchema, ToolStatus,
    };
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ActionClass, AgentToolId, DeclaredAction, RouteId};

    use super::*;
    use crate::acting::TenantAuthorities;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::agents::{FakeResourceGraph, FakeToolStore, caller_person};
    use crate::test_support::{block_on, test_ctx};

    fn tool_named(name: &str) -> AgentTool<ResolvedTenant> {
        let now = clock::now();
        let path = "/things/{id}";
        let declared = DeclaredAction::Declared(ActionClass::Read);
        AgentTool::reconstitute(AgentToolRow {
            id: AgentToolId::new(),
            name: ToolName::new(name).unwrap(),
            description: ToolDescription::new("A registered tool").unwrap(),
            schema: ToolSchema::new(r#"{"type":"object"}"#).unwrap(),
            method: ToolMethod::Get,
            path: ToolPath::new(path).unwrap(),
            route_id: RouteId::new(),
            declared_action: declared,
            action_class: ActionClass::for_route(ToolMethod::Get.into(), path, declared),
            classification: DataClassLevel::Internal,
            status: ToolStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .unwrap()
    }

    fn registry(tools: &[&AgentTool<ResolvedTenant>]) -> FakeToolStore {
        let store = FakeToolStore::empty();
        for tool in tools {
            block_on(store.save(&test_ctx().tenant(), tool)).unwrap();
        }
        store
    }

    fn wanting_tools(patterns: &[&str]) -> CapabilitySet {
        let tools = patterns
            .iter()
            .map(|p| McpTool::new(McpToolPattern::new(*p).unwrap(), ActionClass::Read))
            .collect();
        CapabilitySet::empty().with_mcp(McpGrant::new(tools, Vec::new(), Vec::new()))
    }

    fn patterns(held: &HeldBy) -> Vec<String> {
        held.caps()
            .mcp()
            .tools()
            .iter()
            .map(|tool| tool.pattern().as_str().to_owned())
            .collect()
    }

    fn held_for(
        holding: &[SystemPermission],
        tools: &FakeToolStore,
        graph: &FakeResourceGraph,
        wanted: &CapabilitySet,
    ) -> HeldBy {
        let authority =
            block_on(FakeTenantAuthorities::holding(holding).authority(&test_ctx())).unwrap();
        let control = AgentControl::new(&authority);
        let sources = AuthoritySources {
            resolver: graph,
            tools,
        };
        block_on(held_by(sources, &test_ctx().tenant(), &control, wanted)).unwrap()
    }

    /// Bob manages agents and asks to hand on `stripe_*` and `github_*`. Only
    /// a Stripe tool is registered, so he holds `stripe_*` and not
    /// `github_*`.
    #[test]
    fn an_administrator_holds_only_the_patterns_a_registered_tool_backs() {
        let tools = registry(&[&tool_named("stripe_charge")]);

        let held = held_for(
            &[SystemPermission::Agents(AgentAction::Manage)],
            &tools,
            &FakeResourceGraph::empty(),
            &wanting_tools(&["stripe_*", "github_*"]),
        );

        assert_eq!(patterns(&held), ["stripe_*"]);
    }

    /// Ann was given use of `stripe_charge` only and asks for every Stripe
    /// tool. She holds `stripe_charge`, by name, and not `stripe_refund`.
    #[test]
    fn a_delegator_holds_only_the_tools_they_were_given_by_name() {
        let charge = tool_named("stripe_charge");
        let tools = registry(&[&charge, &tool_named("stripe_refund")]);
        let graph = FakeResourceGraph::empty();
        graph.insert(
            &test_ctx().tenant(),
            caller_person().principal(),
            ResourceCapability::use_of_tool(charge.id()),
        );

        let held = held_for(
            &[SystemPermission::Agents(AgentAction::Delegate)],
            &tools,
            &graph,
            &wanting_tools(&["stripe_*"]),
        );

        assert_eq!(patterns(&held), ["stripe_charge"]);
    }

    /// Ann was given no tool and asks for `stripe_refund`. She holds none.
    #[test]
    fn a_delegator_given_no_tools_holds_none() {
        let tools = registry(&[&tool_named("stripe_refund")]);

        let held = held_for(
            &[SystemPermission::Agents(AgentAction::Delegate)],
            &tools,
            &FakeResourceGraph::empty(),
            &wanting_tools(&["stripe_refund"]),
        );

        assert!(held.caps().mcp().tools().is_empty());
    }

    /// Ann asks to hand on reading two ledgers and the graph says she reads
    /// one. She holds that one only.
    #[test]
    fn only_the_resources_the_graph_answers_are_held() {
        let q1 = ResourceCapability::new(
            Relation::new("reader").unwrap(),
            ResourceRef::new("ledger:2026-q1").unwrap(),
        );
        let q2 = ResourceCapability::new(
            Relation::new("reader").unwrap(),
            ResourceRef::new("ledger:2026-q2").unwrap(),
        );
        let graph = FakeResourceGraph::empty();
        graph.insert(
            &test_ctx().tenant(),
            caller_person().principal(),
            q1.clone(),
        );
        let wanted = CapabilitySet::empty().with_resources(vec![q1.clone(), q2]);

        let held = held_for(&[], &FakeToolStore::empty(), &graph, &wanted);

        assert_eq!(held.caps().resources(), [q1]);
    }

    /// The graph is asked about the use of every registered tool, each once,
    /// beside the resources a grant wants.
    #[test]
    fn the_graph_is_asked_about_every_registered_tool_once() {
        let charge = tool_named("stripe_charge");
        let tool_use = ResourceCapability::use_of_tool(charge.id());
        let wanted = CapabilitySet::empty().with_resources(vec![tool_use.clone()]);

        let asked = asked_about(&wanted, &[charge]);

        assert_eq!(asked, [tool_use]);
    }
}
