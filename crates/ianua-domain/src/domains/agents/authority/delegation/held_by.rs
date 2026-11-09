//! What a person granting a root delegation holds, worked out here from
//! their standing rights, the relationship graph's answer and the tenant's
//! tool registry.
//!
//! The ceiling is never the caller's word. Sam may delegate to agents and
//! holds nothing else. If the app wrote his ceiling, one slip would let him
//! hand his agent every topic, Ann's ledger and every tool the tenant has.

use crate::domains::agents::authority::capability::{
    CapabilitySet, McpGrant, McpTool, McpToolPattern, PubSub, ResourceCapability, TopicCapability,
    TopicPattern,
};
use crate::domains::agents::execution::tool::{AgentTool, ToolName};
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::permission::SystemPermission;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::PrincipalRef;

/// The topic pattern every topic name matches.
const EVERY_TOPIC: &str = ">";

/// Which of the resources asked about one person holds, as the relationship
/// graph answered for them.
///
/// The graph lives outside the domain, so this is the adapter's word, the
/// same as a stored row. It names who it was answered for, so an answer
/// about Ann cannot stand as Sam's. The resources asked about are the ones
/// a grant wants, plus use of each registered tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldResources {
    subject: PrincipalRef,
    held: Vec<ResourceCapability>,
}

impl HeldResources {
    /// The graph's answer for `subject`: the part of what was asked about
    /// that they hold, `held`.
    #[must_use]
    pub fn answered(subject: PrincipalRef, held: Vec<ResourceCapability>) -> Self {
        Self { subject, held }
    }

    /// Who the answer is for.
    pub(crate) fn subject(&self) -> &PrincipalRef {
        &self.subject
    }

    /// The resources the answer says they hold.
    pub(crate) fn resources(&self) -> &[ResourceCapability] {
        &self.held
    }
}

/// What the person granting holds, named together with them.
///
/// A delegation's delegator is the holder, so the rights it is checked
/// against can only be that party's own. Without this, the app could pass
/// Ann's rights while naming Sam as the delegator, and Sam would hand out
/// what only Ann holds.
///
/// Its fields are private. Only [`HeldBy::worked_out`] makes one, from a
/// person's [`AgentControl`]. So the holder is always the person acting,
/// never an agent, and every part of the ceiling follows a rule kept here.
#[derive(Debug, Clone)]
pub struct HeldBy {
    holder: PrincipalRef,
    caps: CapabilitySet,
}

impl HeldBy {
    /// What the acting person may delegate from standing rights, excluding break-glass.
    /// Messaging rights cover every tenant topic; resources are intersected with `wanted`.
    /// Agent admins keep wanted tool patterns matching the registry. Others get only
    /// named registered tools they hold and a wanted pattern matches. With no wanted tools,
    /// the MCP grant stays unchanged; MCP resources and prompts otherwise pass through.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] when `held` was answered for another person.
    pub fn worked_out<T: TenantScope>(
        control: &AgentControl<'_>,
        wanted: &CapabilitySet,
        held: &HeldResources,
        registry: &[AgentTool<T>],
    ) -> Result<Self, DomainError> {
        let holder = control.by().principal();
        ensure_answered_for(held, &holder)?;
        Ok(Self {
            holder,
            caps: ceiling_from(control.holds(), wanted, held, registry),
        })
    }

    /// Who holds them: the person acting.
    #[must_use]
    pub fn holder(&self) -> PrincipalRef {
        self.holder
    }

    /// What they hold.
    #[must_use]
    pub fn caps(&self) -> &CapabilitySet {
        &self.caps
    }

    /// Whether they may manage every agent, through their standing rights.
    pub(super) fn manages_agents(&self) -> bool {
        self.caps
            .http()
            .iter()
            .any(|right| right.implies(&SystemPermission::ManageAgents))
    }
}

/// Refuses an answer from the relationship graph made for someone other
/// than `holder`.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `held` was answered for someone else.
pub(super) fn ensure_answered_for(
    held: &HeldResources,
    holder: &PrincipalRef,
) -> Result<(), DomainError> {
    if held.subject == *holder {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-the-resources-answered-are-another-person",
        "the resources answered are another person's"
    )))
}

/// What someone holding `standing` may grant from, for a grant asking for
/// `wanted`. See [`HeldBy::worked_out`] for each part.
pub(super) fn ceiling_from<T: TenantScope>(
    standing: HeldByGranter<'_>,
    wanted: &CapabilitySet,
    held: &HeldResources,
    registry: &[AgentTool<T>],
) -> CapabilitySet {
    let system = standing.system();
    CapabilitySet::new(system.to_vec(), topics_for(system))
        .with_resources(resources_held(wanted.resources(), held))
        .with_mcp(mcp_ceiling(standing, wanted.mcp(), held, registry))
}

/// Every topic, both ways, when `standing` holds a messaging permission.
fn topics_for(standing: &[SystemPermission]) -> Vec<TopicCapability> {
    if !standing
        .iter()
        .any(|right| matches!(right, SystemPermission::Messaging(_)))
    {
        return Vec::new();
    }
    TopicPattern::new(EVERY_TOPIC)
        .map(|every| vec![TopicCapability::new(every, PubSub::Both)])
        .unwrap_or_default()
}

/// The resources in `wanted` that `held` says the person holds.
fn resources_held(wanted: &[ResourceCapability], held: &HeldResources) -> Vec<ResourceCapability> {
    wanted
        .iter()
        .filter(|resource| held.resources().contains(resource))
        .cloned()
        .collect()
}

/// The MCP part of the ceiling, for a grant asking for `wanted`.
///
/// A grant naming no tools keeps `wanted` as it is. Otherwise the tools are
/// narrowed by [`tools_ceiling`], and resources and prompts pass through.
fn mcp_ceiling<T: TenantScope>(
    standing: HeldByGranter<'_>,
    wanted: &McpGrant,
    held: &HeldResources,
    registry: &[AgentTool<T>],
) -> McpGrant {
    if wanted.tools().is_empty() {
        return wanted.clone();
    }
    McpGrant::new(
        tools_ceiling(standing, wanted.tools(), held, registry),
        wanted.resources().to_vec(),
        wanted.prompts().to_vec(),
    )
}

/// The tools the person may hand on, of those `wanted` names.
///
/// An agent administrator keeps each wanted pattern that matches a
/// registered tool, so a prefix still reaches tools registered later under
/// it: the registry is theirs to control. Anyone else hands on only the
/// registered tools they were given use of, each by name. Sam was given
/// `stripe_charge` and asks for `stripe_*`. He hands on `stripe_charge`,
/// never `stripe_refund` or a tool registered tomorrow.
fn tools_ceiling<T: TenantScope>(
    standing: HeldByGranter<'_>,
    wanted: &[McpTool],
    held: &HeldResources,
    registry: &[AgentTool<T>],
) -> Vec<McpTool> {
    if standing.holds(SystemPermission::ManageAgents) {
        return registered_patterns(wanted, registry);
    }
    registry
        .iter()
        .filter(|tool| {
            held.resources()
                .contains(&ResourceCapability::use_of_tool(tool.id()))
        })
        .flat_map(|tool| by_name(tool.name(), wanted))
        .collect()
}

/// The patterns in `wanted` that match some tool in `registry`.
fn registered_patterns<T: TenantScope>(
    wanted: &[McpTool],
    registry: &[AgentTool<T>],
) -> Vec<McpTool> {
    wanted
        .iter()
        .filter(|tool| {
            registry
                .iter()
                .any(|registered| tool.pattern().matches(registered.name()))
        })
        .cloned()
        .collect()
}

/// The tool `name`, named exactly, once for each wanted pattern matching it
/// and with that pattern's class. None when no wanted pattern matches it.
fn by_name(name: &ToolName, wanted: &[McpTool]) -> Vec<McpTool> {
    let Ok(exact) = McpToolPattern::new(name.as_str()) else {
        return Vec::new();
    };
    wanted
        .iter()
        .filter(|tool| tool.pattern().matches(name))
        .map(|tool| McpTool::new(exact.clone(), tool.class()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::{
        DelegationConstraints, Relation, ResourceRef,
    };
    use crate::domains::agents::authority::delegation::{
        Delegate, Delegation, GrantDelegationParams, ReviewDuty,
    };
    use crate::domains::agents::execution::tool::ToolMethod;
    use crate::domains::agents::execution::tool::tests::fixtures::{MANAGE, holding, registered};
    use crate::domains::agents::identity::agent::tests::fixtures::{agent_of, ann, sam};
    use crate::domains::authorization::permission::{AgentAction, MessagingAction, RoutingAction};
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{ActionClass, DeclaredAction, Human, Seconds};

    const DELEGATE: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::Delegate)];

    /// What `by`, holding `system`, may grant from for `wanted`, with no
    /// resources held and no tools registered.
    fn ceiling_of(by: &Human, system: &[SystemPermission], wanted: &CapabilitySet) -> HeldBy {
        HeldBy::worked_out::<ResolvedTenant>(
            &holding(by, system),
            wanted,
            &answered_for(by, Vec::new()),
            &[],
        )
        .unwrap()
    }

    fn tool(name: &str) -> AgentTool<ResolvedTenant> {
        registered(
            name,
            ToolMethod::Get,
            "/orders/{id}",
            DeclaredAction::Undeclared,
            DataClassLevel::Internal,
        )
    }

    fn ledger(relation: &str) -> ResourceCapability {
        ResourceCapability::new(
            Relation::new(relation).unwrap(),
            ResourceRef::new("ledger:2026-q1").unwrap(),
        )
    }

    /// The tools `pattern` matches, as writes.
    fn writing(pattern: &str) -> McpTool {
        McpTool::new(McpToolPattern::new(pattern).unwrap(), ActionClass::Write)
    }

    fn wanting_tools(patterns: &[&str]) -> CapabilitySet {
        let tools = patterns.iter().copied().map(writing).collect();
        CapabilitySet::empty().with_mcp(McpGrant::new(tools, Vec::new(), Vec::new()))
    }

    fn answered_for(person: &Human, held: Vec<ResourceCapability>) -> HeldResources {
        HeldResources::answered(person.principal(), held)
    }

    fn tool_names(held: &HeldBy) -> Vec<&str> {
        held.caps()
            .mcp()
            .tools()
            .iter()
            .map(|tool| tool.pattern().as_str())
            .collect()
    }

    /// Route-viewing rights contribute no messaging topics to a caller's
    /// ceiling, while a messaging permission contributes one topic grant.
    #[test]
    fn a_person_without_a_messaging_permission_gets_no_topics() {
        let sam = sam();
        let views = [SystemPermission::Routing(RoutingAction::View)];
        let publishes = [SystemPermission::Messaging(MessagingAction::Publish)];

        let viewer = ceiling_of(&sam, &views, &CapabilitySet::empty());
        let publisher = ceiling_of(&sam, &publishes, &CapabilitySet::empty());

        assert!(viewer.caps().messaging().is_empty());
        assert_eq!(publisher.caps().messaging().len(), 1);
    }

    /// When the graph confirms only ledger reading, the caller's ceiling
    /// excludes writing. A requested delegation granting both is forbidden.
    #[test]
    fn a_resource_the_graph_does_not_say_they_hold_is_left_out() {
        let ann = ann();
        let wanted =
            CapabilitySet::empty().with_resources(vec![ledger("reader"), ledger("writer")]);
        let held = HeldBy::worked_out::<ResolvedTenant>(
            &holding(&ann, &DELEGATE),
            &wanted,
            &answered_for(&ann, vec![ledger("reader")]),
            &[],
        )
        .unwrap();

        let granted = Delegation::<ResolvedTenant>::grant(
            GrantDelegationParams {
                granted: wanted,
                constraints: DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
                name: None,
            },
            &held,
            &Delegate {
                agent: &agent_of(&ann),
                duty: ReviewDuty::NotReviewing,
            },
        );

        assert_eq!(held.caps().resources(), &[ledger("reader")]);
        assert!(matches!(granted, Err(DomainError::Forbidden(_))));
    }

    /// A non-administrator asking for a Stripe wildcard receives only the
    /// exact registered charge-tool name they may use, excluding the refund tool.
    #[test]
    fn a_non_admin_hands_on_only_registered_tools_they_may_use_by_name() {
        let sam = sam();
        let charge = tool("stripe_charge");
        let registry = [charge.clone(), tool("stripe_refund")];
        let uses_charge = answered_for(&sam, vec![ResourceCapability::use_of_tool(charge.id())]);

        let held = HeldBy::worked_out(
            &holding(&sam, &DELEGATE),
            &wanting_tools(&["stripe_*"]),
            &uses_charge,
            &registry,
        )
        .unwrap();

        assert_eq!(tool_names(&held), ["stripe_charge"]);
    }

    /// An agent administrator asks for `stripe_*` and `github_*` in a
    /// tenant with only Stripe tools. They keep `stripe_*`, and `github_*`,
    /// which matches nothing registered, is left out.
    #[test]
    fn an_agent_administrator_keeps_the_patterns_a_registered_tool_backs() {
        let ann = ann();
        let registry = [tool("stripe_charge")];

        let held = HeldBy::worked_out(
            &holding(&ann, &MANAGE),
            &wanting_tools(&["stripe_*", "github_*"]),
            &answered_for(&ann, Vec::new()),
            &registry,
        )
        .unwrap();

        assert_eq!(tool_names(&held), ["stripe_*"]);
    }

    /// A graph answer confirming another person's ledger rights cannot
    /// establish the granting caller's holdings.
    #[test]
    fn an_answer_for_another_person_is_refused() {
        let wanted = CapabilitySet::empty().with_resources(vec![ledger("reader")]);

        let result = HeldBy::worked_out::<ResolvedTenant>(
            &holding(&sam(), &DELEGATE),
            &wanted,
            &answered_for(&ann(), vec![ledger("reader")]),
            &[],
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
