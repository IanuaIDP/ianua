//! What a delegation lets an agent do, and the limits on how it may do it.
//!
//! A [`CapabilitySet`] is what a delegation grants. It holds HTTP
//! permissions, messaging topics, relations on named resources, and what the
//! agent may reach on an MCP server.
//!
//! A delegated set must fit inside what the delegator holds. That is
//! [`CapabilitySet::subset_of`]. HTTP permissions use
//! [`SystemPermission::can_delegate`]. A topic pattern counts as covered only
//! when the held pattern surely matches every topic it matches.
//!
//! Beside the set sit the limits on using it. [`DelegationConstraints`] holds
//! the lifetime, task and approval rule. [`AgentBudget`] caps requests per
//! window. [`ResourceScope`] and [`AppReach`] say which paths and apps the
//! agent may reach.

use crate::domains::agents::execution::tool::ToolName;
use crate::domains::authorization::permission::SystemPermission;
mod budget;
mod constraints;
mod mcp;
mod mcp_grant;
mod reach;
mod resource;
mod topic;

pub use budget::*;
pub use constraints::*;
pub use mcp::*;
pub use mcp_grant::*;
pub use reach::*;
pub use resource::*;
pub use topic::*;

/// What a delegation grants an agent.
///
/// It has four parts: HTTP permissions, messaging topics, relations on named
/// resources, and an MCP grant. Each part grants nothing when empty.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CapabilitySet {
    http: Vec<SystemPermission>,
    messaging: Vec<TopicCapability>,
    #[cfg_attr(feature = "serde", serde(default))]
    resources: Vec<ResourceCapability>,
    /// What this set reaches on an MCP server.
    ///
    /// An empty grant reaches nothing. A stored set with no MCP part reads
    /// back as empty, so it calls no tool.
    #[cfg_attr(feature = "serde", serde(default))]
    mcp: McpGrant,
}

impl CapabilitySet {
    /// Creates a set from HTTP permissions and topics, with no resources and
    /// no MCP grant.
    #[must_use]
    pub fn new(http: Vec<SystemPermission>, messaging: Vec<TopicCapability>) -> Self {
        Self {
            http,
            messaging,
            resources: Vec::new(),
            mcp: McpGrant::default(),
        }
    }

    /// Sets the relations this set grants on named resources, replacing any
    /// it had.
    #[must_use]
    pub fn with_resources(mut self, resources: Vec<ResourceCapability>) -> Self {
        self.resources = resources;
        self
    }

    /// Sets what this set reaches on an MCP server, replacing any grant it had.
    #[must_use]
    pub fn with_mcp(mut self, mcp: McpGrant) -> Self {
        self.mcp = mcp;
        self
    }

    /// A set that grants nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The HTTP permissions.
    #[must_use]
    pub fn http(&self) -> &[SystemPermission] {
        &self.http
    }

    /// The messaging topics.
    #[must_use]
    pub fn messaging(&self) -> &[TopicCapability] {
        &self.messaging
    }

    /// The relations on named resources.
    #[must_use]
    pub fn resources(&self) -> &[ResourceCapability] {
        &self.resources
    }

    /// What this set reaches on an MCP server.
    #[must_use]
    pub fn mcp(&self) -> &McpGrant {
        &self.mcp
    }

    /// Whether this set grants nothing in any of its four parts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.http.is_empty()
            && self.messaging.is_empty()
            && self.resources.is_empty()
            && self.mcp.is_empty()
    }

    /// Whether `other` covers everything in this set.
    ///
    /// This is the check a delegation must pass: it may hand on only what the
    /// delegator holds. HTTP permissions use [`SystemPermission::can_delegate`].
    /// Each topic and each resource relation must be covered by one held in
    /// `other`. The MCP grant must fit inside `other`'s.
    #[must_use]
    pub fn subset_of(&self, other: &Self) -> bool {
        SystemPermission::can_delegate(&other.http, &self.http)
            && self
                .messaging
                .iter()
                .all(|needed| other.messaging.iter().any(|held| held.covers(needed)))
            && self
                .resources
                .iter()
                .all(|needed| other.resources.iter().any(|held| held.covers(needed)))
            && self.mcp.subset_of(&other.mcp)
    }

    /// Everything either set grants, with duplicates removed.
    ///
    /// This gives an agent's combined rights across several delegations.
    /// HTTP permissions are normalized, so a `View` that a held `Manage`
    /// implies is dropped. Topics and resource relations drop exact repeats.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut http = self.http.clone();
        http.extend(other.http.iter().copied());
        let http = SystemPermission::normalize(&http);

        let mut messaging = self.messaging.clone();
        for capability in &other.messaging {
            if !messaging.contains(capability) {
                messaging.push(capability.clone());
            }
        }

        let mut resources = self.resources.clone();
        for capability in &other.resources {
            if !resources.contains(capability) {
                resources.push(capability.clone());
            }
        }

        Self {
            http,
            messaging,
            resources,
            mcp: self.mcp.union(&other.mcp),
        }
    }

    /// Keeps only the parts of this set that `ceiling` grants.
    ///
    /// This trims a request down to what the caller holds. Sam holds "view
    /// routes" and asks for "manage routes" too. Sam gets "view routes" only.
    ///
    /// The result fits inside both sets. With an empty `ceiling` it grants
    /// nothing.
    #[must_use]
    pub fn intersect(&self, ceiling: &Self) -> Self {
        Self {
            http: SystemPermission::normalize(
                &self
                    .http
                    .iter()
                    .filter(|wanted| ceiling.permits(wanted))
                    .copied()
                    .collect::<Vec<_>>(),
            ),
            messaging: self
                .messaging
                .iter()
                .filter(|wanted| ceiling.permits_topic(wanted))
                .cloned()
                .collect(),
            resources: self
                .resources
                .iter()
                .filter(|wanted| ceiling.permits_resource(wanted))
                .cloned()
                .collect(),
            mcp: self.mcp.intersect(&ceiling.mcp),
        }
    }

    /// Whether some HTTP permission in this set implies `permission`.
    #[must_use]
    pub fn permits(&self, permission: &SystemPermission) -> bool {
        self.http.iter().any(|held| held.implies(permission))
    }

    /// Whether some topic in this set covers `capability`.
    #[must_use]
    pub fn permits_topic(&self, capability: &TopicCapability) -> bool {
        self.messaging.iter().any(|held| held.covers(capability))
    }

    /// Whether this set holds exactly `capability`.
    ///
    /// The relation and the resource must both match. No relation implies
    /// another: holding owner does not hold reader.
    #[must_use]
    pub fn permits_resource(&self, capability: &ResourceCapability) -> bool {
        self.resources.iter().any(|held| held.covers(capability))
    }

    /// Whether this set permits calling the MCP tool named `name`.
    ///
    /// A set that names no tools permits no tool. This checks the name only.
    /// The classes the call takes come from [`McpGrant::tool_classes`].
    #[must_use]
    pub fn permits_tool(&self, name: &ToolName) -> bool {
        self.mcp.permits_tool(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::{McpTool, McpToolPattern};
    use crate::domains::authorization::permission::{RoutingAction, SystemPermission};
    use crate::types::ActionClass;

    fn topic(pattern: &str, rights: PubSub) -> TopicCapability {
        TopicCapability::new(TopicPattern::new(pattern).unwrap(), rights)
    }

    fn named(value: &str) -> ToolName {
        ToolName::new(value).unwrap()
    }

    /// Viewing routes and publishing on one topic fits within route
    /// management and both rights on the wider topic pattern. The broader
    /// set does not fit within the narrow one.
    #[test]
    fn subset_of_uses_permission_delegation() {
        let broad = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::Manage)],
            vec![topic("ianua.msg.t1.>", PubSub::Both)],
        );
        let narrow = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::View)],
            vec![topic("ianua.msg.t1.agents.a2", PubSub::Publish)],
        );
        assert!(narrow.subset_of(&broad));
        assert!(!broad.subset_of(&narrow));
    }

    /// A person who holds only "view routes" delegates nothing. The empty set
    /// fits, so a delegation that grants nothing is always allowed.
    #[test]
    fn empty_set_is_subset_of_anything() {
        let any = CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![]);
        assert!(CapabilitySet::empty().subset_of(&any));
    }

    /// One delegation gives "view routes", another "manage routes", and both
    /// give the same topic. The union keeps one HTTP permission that still
    /// allows viewing, and one copy of the topic.
    #[test]
    fn union_merges_and_dedups() {
        let a = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::View)],
            vec![topic("ianua.msg.t1.a", PubSub::Publish)],
        );
        let b = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::Manage)],
            vec![topic("ianua.msg.t1.a", PubSub::Publish)],
        );
        let union = a.union(&b);
        assert_eq!(union.http().len(), 1);
        assert!(union.permits(&SystemPermission::Routing(RoutingAction::View)));
        assert_eq!(union.messaging().len(), 1);
    }

    /// Intersecting requested route and topic rights with a ceiling keeps
    /// route viewing and the covered topic, removing route management and
    /// the topic outside that ceiling.
    #[test]
    fn intersect_keeps_only_what_the_ceiling_grants() {
        let wanted = CapabilitySet::new(
            vec![
                SystemPermission::Routing(RoutingAction::View),
                SystemPermission::Routing(RoutingAction::Manage),
            ],
            vec![
                topic("ianua.msg.t1.a", PubSub::Publish),
                topic("ianua.msg.t2.a", PubSub::Publish),
            ],
        );
        let ceiling = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::View)],
            vec![topic("ianua.msg.t1.>", PubSub::Both)],
        );

        let capped = wanted.intersect(&ceiling);

        assert!(capped.permits(&SystemPermission::Routing(RoutingAction::View)));
        assert!(
            !capped.permits(&SystemPermission::Routing(RoutingAction::Manage)),
            "asking for more than is held must not grant it"
        );
        assert_eq!(capped.messaging().len(), 1);
        assert!(capped.permits_topic(&topic("ianua.msg.t1.a", PubSub::Publish)));
    }

    /// A request for "manage routes" is trimmed by a set holding "view
    /// routes". The result fits inside both the request and the held set, so
    /// a token exchange never hands out more than either.
    #[test]
    fn intersect_is_always_a_subset_of_both_sides() {
        let wanted = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::Manage)],
            vec![topic("ianua.msg.t1.a", PubSub::Both)],
        );
        let ceiling = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::View)],
            vec![topic("ianua.msg.t1.a", PubSub::Both)],
        );

        let capped = wanted.intersect(&ceiling);

        assert!(capped.subset_of(&wanted));
        assert!(capped.subset_of(&ceiling));
    }

    /// Intersecting route, topic and calendar-ownership capabilities with
    /// an empty ceiling produces an empty capability set.
    #[test]
    fn intersecting_with_an_empty_ceiling_grants_nothing() {
        let wanted = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::Manage)],
            vec![topic("ianua.msg.t1.a", PubSub::Both)],
        )
        .with_resources(vec![resource("owner", "cal:a")]);

        assert!(wanted.intersect(&CapabilitySet::empty()).is_empty());
    }

    /// A caller asks to publish on one topic and holds both rights on every
    /// topic under `t1`. The request is kept as asked, since the held set
    /// covers it, and the matching resource relation is kept too.
    #[test]
    fn intersect_keeps_a_capability_the_ceiling_covers_more_broadly() {
        let wanted = CapabilitySet::new(vec![], vec![topic("ianua.msg.t1.a", PubSub::Publish)])
            .with_resources(vec![resource("reader", "cal:a")]);
        let ceiling = CapabilitySet::new(vec![], vec![topic("ianua.msg.t1.>", PubSub::Both)])
            .with_resources(vec![resource("reader", "cal:a")]);

        let capped = wanted.intersect(&ceiling);

        assert_eq!(capped.messaging().len(), 1);
        assert_eq!(capped.resources().len(), 1);
    }

    /// A set holds "view routes" and every topic under `t1`. It allows
    /// viewing but not managing routes, and publishing on any topic under `t1`.
    #[test]
    fn permits_uses_implication_and_coverage() {
        let caps = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::View)],
            vec![topic("ianua.msg.t1.>", PubSub::Both)],
        );
        assert!(caps.permits(&SystemPermission::Routing(RoutingAction::View)));
        assert!(!caps.permits(&SystemPermission::Routing(RoutingAction::Manage)));
        assert!(caps.permits_topic(&topic("ianua.msg.t1.agents.x", PubSub::Publish)));
    }

    fn resource(relation: &str, resource_ref: &str) -> ResourceCapability {
        ResourceCapability::new(
            Relation::new(relation).unwrap(),
            ResourceRef::new(resource_ref).unwrap(),
        )
    }

    /// A resource capability covers the same relation on the same object,
    /// but refuses a different object or a different relation on that object.
    #[test]
    fn resource_subset_is_exact_match_only() {
        let held = CapabilitySet::new(vec![], vec![])
            .with_resources(vec![resource("reader", "calendar:a")]);
        let same = CapabilitySet::new(vec![], vec![])
            .with_resources(vec![resource("reader", "calendar:a")]);
        let other_object = CapabilitySet::new(vec![], vec![])
            .with_resources(vec![resource("reader", "calendar:b")]);
        let other_relation = CapabilitySet::new(vec![], vec![])
            .with_resources(vec![resource("writer", "calendar:a")]);

        assert!(same.subset_of(&held));
        assert!(
            !other_object.subset_of(&held),
            "different object is not covered"
        );
        assert!(
            !other_relation.subset_of(&held),
            "different relation is not covered (hierarchy resolved at enforcement)"
        );
    }

    /// Two delegations both give reader on calendar `a`, and one adds owner
    /// on `b`. The union holds two relations, with the repeat dropped.
    #[test]
    fn union_merges_and_dedups_resources() {
        let a =
            CapabilitySet::new(vec![], vec![]).with_resources(vec![resource("reader", "cal:a")]);
        let b = CapabilitySet::new(vec![], vec![]).with_resources(vec![
            resource("reader", "cal:a"),
            resource("owner", "cal:b"),
        ]);
        let union = a.union(&b);
        assert_eq!(union.resources().len(), 2);
        assert!(union.permits_resource(&resource("owner", "cal:b")));
    }

    /// A set with no HTTP permissions or topics but one resource relation is
    /// not empty. A delegation granting only that relation still grants
    /// something.
    #[test]
    fn empty_set_accounts_for_resources() {
        let with_resource =
            CapabilitySet::new(vec![], vec![]).with_resources(vec![resource("reader", "cal:a")]);
        assert!(!with_resource.is_empty());
        assert!(CapabilitySet::empty().is_empty());
    }

    /// A topic pattern, relation, resource reference and task are each built
    /// from text. Each gives back that same text, since requests are matched
    /// against it.
    #[test]
    fn each_capability_string_reports_the_text_it_was_built_from() {
        assert_eq!(
            TopicPattern::new("ianua.msg.orders.*").unwrap().as_str(),
            "ianua.msg.orders.*"
        );
        assert_eq!(Relation::new("reader").unwrap().as_str(), "reader");
        assert_eq!(
            ResourceRef::new("ledger:2026-q1").unwrap().as_str(),
            "ledger:2026-q1"
        );
        assert_eq!(
            TaskBinding::new("close the Q1 books").unwrap().as_str(),
            "close the Q1 books"
        );
    }

    /// The empty set has no HTTP permission, topic, resource relation or MCP
    /// grant. It refuses a call to `github_create_issue` as well.
    #[test]
    fn an_empty_capability_set_grants_nothing_in_any_dimension() {
        let empty = CapabilitySet::empty();

        assert!(empty.is_empty());
        assert!(empty.http().is_empty());
        assert!(empty.messaging().is_empty());
        assert!(empty.resources().is_empty());
        assert!(empty.mcp().is_empty());
        assert!(!empty.permits_tool(&named("github_create_issue")));
    }

    /// A set is given the MCP tools `github_*`. It may call
    /// `github_create_issue` but not `shell_exec`, and it counts as not empty.
    #[test]
    fn a_set_with_mcp_tools_permits_those_tools_and_no_others() {
        let grant = McpGrant::new(
            vec![McpTool::new(
                McpToolPattern::new("github_*").unwrap(),
                ActionClass::Write,
            )],
            Vec::new(),
            Vec::new(),
        );

        let caps = CapabilitySet::empty().with_mcp(grant.clone());

        assert_eq!(caps.mcp(), &grant);
        assert!(!caps.is_empty(), "a tool grant is a capability");
        assert!(caps.permits_tool(&named("github_create_issue")));
        assert!(!caps.permits_tool(&named("shell_exec")));
    }
}
