//! The tools, resources and prompts one delegation reaches on an MCP server.
//!
//! Each tool pattern carries the [`ActionClass`] its tools take. Every MCP
//! call is the same JSON-RPC `POST`, so the request alone says nothing about
//! what a tool does. The class on the pattern does. The purpose check reads
//! it the way it reads a registered tool's class.
//!
//! A name may match more than one pattern. Then every class those patterns
//! carry counts, and the purpose must allow each one. Ann grants `github_*`
//! as a write and `github_delete_repo` as a delete. A call to
//! `github_delete_repo` is a write and a delete, so a purpose that only
//! writes refuses it.

use crate::domains::agents::authority::capability::{
    McpResourcePattern, McpResourceUri, McpToolPattern,
};
use crate::domains::agents::execution::tool::ToolName;
use crate::types::ActionClass;

/// An MCP tool pattern and the class of action the tools it matches take.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct McpTool {
    pattern: McpToolPattern,
    class: ActionClass,
}

impl McpTool {
    /// Labels the tools `pattern` matches with `class`.
    #[must_use]
    pub fn new(pattern: McpToolPattern, class: ActionClass) -> Self {
        Self { pattern, class }
    }

    /// The names this entry matches.
    #[must_use]
    pub fn pattern(&self) -> &McpToolPattern {
        &self.pattern
    }

    /// The class of action the matched tools take.
    #[must_use]
    pub fn class(&self) -> ActionClass {
        self.class
    }
}

/// What a delegation reaches on an MCP server: tools, resources and prompts.
///
/// They are three separate rights. A tool call acts. A resource read fetches
/// content. A prompt fetch returns a template the agent will follow. Each
/// list narrows on its own and starts empty. An empty list reaches nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct McpGrant {
    /// Tools this grant may call, each with its class.
    ///
    /// A grant stored before tools carried a class keeps its patterns under
    /// `tools`. That key is not read. Such a grant loads with no tools and
    /// calls none until it is granted again, so no tool runs unclassed.
    #[cfg_attr(feature = "serde", serde(default, rename = "classed_tools"))]
    tools: Vec<McpTool>,
    /// Resources this grant may read.
    #[cfg_attr(feature = "serde", serde(default))]
    resources: Vec<McpResourcePattern>,
    /// Prompts this grant may fetch.
    #[cfg_attr(feature = "serde", serde(default))]
    prompts: Vec<McpToolPattern>,
}

impl McpGrant {
    /// Creates a grant over the given tools, resources, and prompts.
    #[must_use]
    pub fn new(
        tools: Vec<McpTool>,
        resources: Vec<McpResourcePattern>,
        prompts: Vec<McpToolPattern>,
    ) -> Self {
        Self {
            tools,
            resources,
            prompts,
        }
    }

    /// The tools this grant may call, each with its class.
    #[must_use]
    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }

    /// The resources this grant may read.
    #[must_use]
    pub fn resources(&self) -> &[McpResourcePattern] {
        &self.resources
    }

    /// The prompts this grant may fetch.
    #[must_use]
    pub fn prompts(&self) -> &[McpToolPattern] {
        &self.prompts
    }

    /// Whether this grant reaches nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty() && self.resources.is_empty() && self.prompts.is_empty()
    }

    /// Whether this grant permits calling the tool named `name`.
    ///
    /// This is only the name check. The purpose check reads
    /// [`tool_classes`](Self::tool_classes) as well.
    #[must_use]
    pub fn permits_tool(&self, name: &ToolName) -> bool {
        self.tools.iter().any(|held| held.pattern.matches(name))
    }

    /// Every class the patterns matching `name` carry, sorted, each once.
    ///
    /// A call to the tool takes all of them, so the purpose must allow each.
    /// It is empty when no pattern matches, and the call is then refused.
    #[must_use]
    pub fn tool_classes(&self, name: &ToolName) -> Vec<ActionClass> {
        let mut classes: Vec<ActionClass> = self
            .tools
            .iter()
            .filter(|held| held.pattern.matches(name))
            .map(McpTool::class)
            .collect();
        classes.sort_unstable();
        classes.dedup();
        classes
    }

    /// Whether this grant permits reading the resource at `uri`.
    #[must_use]
    pub fn permits_resource(&self, uri: &McpResourceUri) -> bool {
        self.resources.iter().any(|held| held.matches(uri))
    }

    /// Whether this grant permits fetching the prompt named `name`.
    #[must_use]
    pub fn permits_prompt(&self, name: &str) -> bool {
        self.prompts.iter().any(|held| held.matches_name(name))
    }

    /// Whether `other` covers every tool, resource and prompt pattern here.
    ///
    /// Each list is checked against the same list in `other`. Going beyond
    /// `other` in any one list fails the whole check. A tool must also keep
    /// every class `other` puts on its names. Sam's agent holds
    /// `delete_repo` as a delete. It may not hand it on labelled a read, or
    /// a read-only purpose would let the delete through.
    #[must_use]
    pub fn subset_of(&self, other: &Self) -> bool {
        tools_within(&self.tools, &other.tools)
            && covered(&self.resources, &other.resources)
            && covered(&self.prompts, &other.prompts)
    }

    /// Every entry in either grant, each list without exact repeats.
    ///
    /// A tool both grants name keeps the classes of both.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self {
            tools: merged(&self.tools, &other.tools),
            resources: merged(&self.resources, &other.resources),
            prompts: merged(&self.prompts, &other.prompts),
        }
    }

    /// The entries here that `ceiling` covers. The rest are dropped.
    ///
    /// A kept tool also takes every class `ceiling` puts on its names. So
    /// asking for `delete_repo` as a read, under a ceiling that holds it as
    /// a delete, still gives a delete.
    #[must_use]
    pub fn intersect(&self, ceiling: &Self) -> Self {
        Self {
            tools: capped_tools(&self.tools, &ceiling.tools),
            resources: within(&self.resources, &ceiling.resources),
            prompts: within(&self.prompts, &ceiling.prompts),
        }
    }

    /// This grant with only the tools whose class `fits`. Resources and
    /// prompts are kept as they are.
    ///
    /// A tool that does not fit is still kept when its names overlap a kept
    /// tool. Dropping it would drop a class from those names. Ann's purpose
    /// writes. She holds `github_*` as a write and `github_delete_repo` as a
    /// delete. The delete entry stays, so `github_delete_repo` is still
    /// refused.
    #[must_use]
    pub fn narrowed_to_classes(&self, fits: impl Fn(ActionClass) -> bool) -> Self {
        let mut kept: Vec<&McpTool> = self.tools.iter().filter(|tool| fits(tool.class)).collect();
        while let Some(next) = self
            .tools
            .iter()
            .find(|tool| !kept.contains(tool) && overlaps_any(tool, &kept))
        {
            kept.push(next);
        }
        Self {
            tools: self
                .tools
                .iter()
                .filter(|tool| kept.contains(tool))
                .cloned()
                .collect(),
            resources: self.resources.clone(),
            prompts: self.prompts.clone(),
        }
    }
}

/// The part two patterns share, when they share any name.
///
/// Two patterns share a name only when one covers the other. The narrower
/// one is then the shared part.
fn overlap<'p>(a: &'p McpToolPattern, b: &'p McpToolPattern) -> Option<&'p McpToolPattern> {
    if b.covers(a) {
        return Some(a);
    }
    a.covers(b).then_some(b)
}

/// Whether `tool` shares a name with any of `others`.
fn overlaps_any(tool: &McpTool, others: &[&McpTool]) -> bool {
    others
        .iter()
        .any(|other| overlap(&tool.pattern, &other.pattern).is_some())
}

/// Whether every tool in `child` is covered by `parent` and keeps the
/// classes `parent` puts on its names.
fn tools_within(child: &[McpTool], parent: &[McpTool]) -> bool {
    child.iter().all(|tool| {
        parent.iter().any(|held| held.pattern.covers(&tool.pattern))
            && keeps_classes_of(tool, child, parent)
    })
}

/// Whether, for each `parent` entry sharing names with `tool`, `child`
/// carries that entry's class on the shared names.
fn keeps_classes_of(tool: &McpTool, child: &[McpTool], parent: &[McpTool]) -> bool {
    parent
        .iter()
        .all(|held| match overlap(&tool.pattern, &held.pattern) {
            None => true,
            Some(shared) => carries(child, shared, held.class),
        })
}

/// Whether some entry in `tools` covers `pattern` with `class`.
fn carries(tools: &[McpTool], pattern: &McpToolPattern, class: ActionClass) -> bool {
    tools
        .iter()
        .any(|tool| tool.class == class && tool.pattern.covers(pattern))
}

/// The tools in `wanted` that `ceiling` covers, each joined by the classes
/// `ceiling` puts on its names.
fn capped_tools(wanted: &[McpTool], ceiling: &[McpTool]) -> Vec<McpTool> {
    let entries: Vec<McpTool> = wanted
        .iter()
        .filter(|tool| {
            ceiling
                .iter()
                .any(|held| held.pattern.covers(&tool.pattern))
        })
        .flat_map(|tool| {
            std::iter::once(tool.clone()).chain(ceiling.iter().filter_map(|held| {
                overlap(&tool.pattern, &held.pattern)
                    .map(|shared| McpTool::new(shared.clone(), held.class))
            }))
        })
        .collect();
    merged(&[], &entries)
}

/// Whether every pattern in `needed` is covered by one in `held`.
fn covered<P: Coverable>(needed: &[P], held: &[P]) -> bool {
    needed
        .iter()
        .all(|want| held.iter().any(|have| have.covers(want)))
}

/// Every entry in either list, without exact repeats.
fn merged<P: Clone + PartialEq>(left: &[P], right: &[P]) -> Vec<P> {
    let mut out = left.to_vec();
    for entry in right {
        if !out.contains(entry) {
            out.push(entry.clone());
        }
    }
    out
}

/// The patterns in `wanted` that `ceiling` already covers.
fn within<P: Coverable + Clone>(wanted: &[P], ceiling: &[P]) -> Vec<P> {
    wanted
        .iter()
        .filter(|want| ceiling.iter().any(|have| have.covers(want)))
        .cloned()
        .collect()
}

/// A pattern that can say whether it covers another of its kind.
///
/// Resources and prompts share one set of list functions through it. One
/// copy means neither list can quietly stop narrowing while the other still
/// does.
pub(crate) trait Coverable {
    /// Whether this pattern covers everything `other` matches.
    fn covers(&self, other: &Self) -> bool;
}

impl Coverable for McpToolPattern {
    fn covers(&self, other: &Self) -> bool {
        Self::covers(self, other)
    }
}

impl Coverable for McpResourcePattern {
    fn covers(&self, other: &Self) -> bool {
        Self::covers(self, other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(value: &str) -> McpToolPattern {
        McpToolPattern::new(value).unwrap()
    }

    fn tool(value: &str, class: ActionClass) -> McpTool {
        McpTool::new(pattern(value), class)
    }

    fn write(value: &str) -> McpTool {
        tool(value, ActionClass::Write)
    }

    fn uri(value: &str) -> McpResourceUri {
        McpResourceUri::new(value).unwrap()
    }

    fn resource(value: &str) -> McpResourcePattern {
        McpResourcePattern::new(value).unwrap()
    }

    fn tools_only(tools: Vec<McpTool>) -> McpGrant {
        McpGrant::new(tools, Vec::new(), Vec::new())
    }

    fn named(value: &str) -> ToolName {
        ToolName::new(value).unwrap()
    }

    /// A grant built with `github_*` tools, a project folder and the
    /// `summarise` prompt gives back each list as it was given.
    #[test]
    fn a_grant_holds_the_three_dimensions_it_was_built_with() {
        let grant = McpGrant::new(
            vec![write("github_*")],
            vec![resource("file:///project/*")],
            vec![pattern("summarise")],
        );

        assert_eq!(grant.tools(), [write("github_*")]);
        assert_eq!(grant.resources(), [resource("file:///project/*")]);
        assert_eq!(grant.prompts(), [pattern("summarise")]);
    }

    /// A default grant is empty. A grant naming only one tool, one resource
    /// or one prompt is not, so a check for "grants nothing" never passes it.
    #[test]
    fn a_grant_is_empty_only_when_all_three_dimensions_are() {
        assert!(McpGrant::default().is_empty());

        assert!(
            !tools_only(vec![write("github_*")]).is_empty(),
            "a tool grant is not empty"
        );
        assert!(
            !McpGrant::new(Vec::new(), vec![resource("file:///project/*")], Vec::new()).is_empty(),
            "a resource grant is not empty"
        );
        assert!(
            !McpGrant::new(Vec::new(), Vec::new(), vec![pattern("summarise")]).is_empty(),
            "a prompt grant is not empty"
        );
    }

    /// Tool, resource and prompt permissions each match only their own
    /// list. A prompt name grants no tool call, and a tool name grants no prompt.
    #[test]
    fn each_dimension_permits_only_its_own_kind() {
        let grant = McpGrant::new(
            vec![write("github_*")],
            vec![resource("file:///project/*")],
            vec![pattern("summarise")],
        );

        assert!(grant.permits_tool(&named("github_create_issue")));
        assert!(!grant.permits_tool(&named("shell_exec")));
        assert!(
            !grant.permits_tool(&named("summarise")),
            "a prompt is not a tool"
        );

        assert!(grant.permits_resource(&uri("file:///project/README.md")));
        assert!(!grant.permits_resource(&uri("file:///etc/hosts")));

        assert!(grant.permits_prompt("summarise"));
        assert!(!grant.permits_prompt("github_create_issue"));
    }

    /// A grant names only `github_*` tools. It reads no resource and fetches
    /// no prompt.
    #[test]
    fn a_grant_with_nothing_in_a_dimension_permits_nothing_in_it() {
        let grant = tools_only(vec![write("github_*")]);

        assert!(!grant.permits_resource(&uri("file:///project/README.md")));
        assert!(!grant.permits_prompt("summarise"));
    }

    /// Ann grants `github_*` as a write and `github_delete_repo` as a
    /// delete. A call to `github_delete_repo` takes both classes, another
    /// github tool only the write, and `shell_exec` none.
    #[test]
    fn a_tool_takes_every_class_its_matching_patterns_carry() {
        let grant = tools_only(vec![
            write("github_*"),
            tool("github_delete_repo", ActionClass::Delete),
        ]);

        assert_eq!(
            grant.tool_classes(&named("github_delete_repo")),
            [ActionClass::Write, ActionClass::Delete]
        );
        assert_eq!(
            grant.tool_classes(&named("github_create_issue")),
            [ActionClass::Write]
        );
        assert!(grant.tool_classes(&named("shell_exec")).is_empty());
    }

    /// A narrower or empty MCP grant fits its parent, but widening tools,
    /// resources or prompts independently fails. A nonempty parent does not
    /// fit within an empty grant.
    #[test]
    fn a_subset_must_be_within_the_parent_in_every_dimension() {
        let parent = McpGrant::new(
            vec![write("github_*")],
            vec![resource("file:///project/*")],
            vec![pattern("summarise")],
        );

        let narrower = McpGrant::new(
            vec![write("github_create_issue")],
            vec![resource("file:///project/src/*")],
            Vec::new(),
        );
        assert!(narrower.subset_of(&parent));
        assert!(McpGrant::default().subset_of(&parent));

        let wider_tools = tools_only(vec![write("*")]);
        let wider_resources = McpGrant::new(Vec::new(), vec![resource("file:///*")], Vec::new());
        let wider_prompts = McpGrant::new(Vec::new(), Vec::new(), vec![pattern("*")]);

        assert!(!wider_tools.subset_of(&parent), "tools escaped the ceiling");
        assert!(
            !wider_resources.subset_of(&parent),
            "resources escaped the ceiling"
        );
        assert!(
            !wider_prompts.subset_of(&parent),
            "prompts escaped the ceiling"
        );
        assert!(!parent.subset_of(&McpGrant::default()));
    }

    /// A child grant cannot relabel a delete tool as a read. Retaining the
    /// parent's delete class makes the child fit.
    #[test]
    fn a_child_may_not_relabel_a_tool_to_another_class() {
        let parent = tools_only(vec![tool("delete_repo", ActionClass::Delete)]);

        let relabelled = tools_only(vec![tool("delete_repo", ActionClass::Read)]);
        let kept = tools_only(vec![tool("delete_repo", ActionClass::Delete)]);

        assert!(!relabelled.subset_of(&parent));
        assert!(kept.subset_of(&parent));
    }

    /// A child keeping a broad write pattern must also keep the delete
    /// class attached to a tool beneath it. Dropping that entry fails the
    /// subset check; retaining it passes.
    #[test]
    fn a_child_may_not_drop_a_class_a_narrower_parent_entry_adds() {
        let parent = tools_only(vec![
            write("github_*"),
            tool("github_delete_repo", ActionClass::Delete),
        ]);

        let dropped = tools_only(vec![write("github_*")]);
        let kept = tools_only(vec![
            write("github_*"),
            tool("github_delete_repo", ActionClass::Delete),
        ]);

        assert!(!dropped.subset_of(&parent));
        assert!(kept.subset_of(&parent));
    }

    /// Two grants both name `github_*`, and each adds other tools, resources
    /// or prompts. The union keeps everything in order and lists `github_*`
    /// once.
    #[test]
    fn a_union_keeps_both_sides_and_repeats_nothing() {
        let left = McpGrant::new(
            vec![write("github_*")],
            vec![resource("file:///project/*")],
            vec![pattern("summarise")],
        );
        let right = McpGrant::new(
            vec![write("github_*"), write("shell_exec")],
            Vec::new(),
            vec![pattern("translate")],
        );

        let both = left.union(&right);

        assert_eq!(both.tools(), [write("github_*"), write("shell_exec")]);
        assert_eq!(both.resources(), [resource("file:///project/*")]);
        assert_eq!(both.prompts(), [pattern("summarise"), pattern("translate")]);
    }

    /// Intersection keeps the covered GitHub tool and project file while
    /// removing an uncovered shell tool, file and prompt. The result fits
    /// within its ceiling.
    #[test]
    fn an_intersection_keeps_only_what_the_ceiling_already_covers() {
        let wanted = McpGrant::new(
            vec![write("github_create_issue"), write("shell_exec")],
            vec![
                resource("file:///project/README.md"),
                resource("file:///etc/hosts"),
            ],
            vec![pattern("summarise")],
        );
        let ceiling = McpGrant::new(
            vec![write("github_*")],
            vec![resource("file:///project/*")],
            Vec::new(),
        );

        let capped = wanted.intersect(&ceiling);

        assert_eq!(capped.tools(), [write("github_create_issue")]);
        assert_eq!(capped.resources(), [resource("file:///project/README.md")]);
        assert!(
            capped.prompts().is_empty(),
            "a ceiling that grants no prompts caps prompts to none"
        );
        assert!(capped.subset_of(&ceiling));
    }

    /// Intersecting a tool requested as a read with a delete-class ceiling
    /// retains the delete class and produces a grant within that ceiling.
    #[test]
    fn an_intersection_keeps_the_ceilings_class_on_a_relabelled_tool() {
        let wanted = tools_only(vec![tool("github_delete_repo", ActionClass::Read)]);
        let ceiling = tools_only(vec![tool("github_delete_repo", ActionClass::Delete)]);

        let capped = wanted.intersect(&ceiling);

        assert!(
            capped
                .tool_classes(&named("github_delete_repo"))
                .contains(&ActionClass::Delete)
        );
        assert!(capped.subset_of(&ceiling));
    }

    /// A caller with no MCP grant asks for tools, resources and a prompt.
    /// Trimmed by the empty grant, the request reaches nothing.
    #[test]
    fn an_intersection_with_an_empty_ceiling_reaches_nothing() {
        let wanted = McpGrant::new(
            vec![write("github_*")],
            vec![resource("file:///project/*")],
            vec![pattern("summarise")],
        );

        assert!(wanted.intersect(&McpGrant::default()).is_empty());
    }

    /// A grant of `github_get_*` as a read and `shell_exec` as admin is
    /// narrowed to reads. The read tools stay. `shell_exec` shares no name
    /// with them and goes.
    #[test]
    fn narrowing_keeps_only_tools_whose_class_fits() {
        let grant = tools_only(vec![
            tool("github_get_*", ActionClass::Read),
            tool("shell_exec", ActionClass::Admin),
        ]);

        let narrowed = grant.narrowed_to_classes(|class| class == ActionClass::Read);

        assert_eq!(narrowed.tools(), [tool("github_get_*", ActionClass::Read)]);
        assert!(narrowed.subset_of(&grant));
    }

    /// Narrowing to writes retains a delete class on names covered by a
    /// kept write pattern. The narrowed grant remains within the original.
    #[test]
    fn narrowing_keeps_a_class_that_still_marks_a_kept_tool() {
        let grant = tools_only(vec![
            write("github_*"),
            tool("github_delete_repo", ActionClass::Delete),
        ]);

        let narrowed = grant.narrowed_to_classes(|class| class == ActionClass::Write);

        assert!(
            narrowed
                .tool_classes(&named("github_delete_repo"))
                .contains(&ActionClass::Delete)
        );
        assert!(narrowed.subset_of(&grant));
    }

    /// A delegation stored before tools carried a class lists `github_*`
    /// under `tools`. That list is not read, so the grant calls no tool
    /// unclassed. The resources it names still load.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_grant_with_unclassed_tools_calls_no_tool() {
        let stored = r#"{"tools":["github_*"],"resources":["file:///project/*"]}"#;

        let grant: McpGrant = serde_json::from_str(stored).unwrap();

        assert!(!grant.permits_tool(&named("github_delete_repo")));
        assert_eq!(grant.resources(), [resource("file:///project/*")]);
    }

    /// A grant with a delete-classed tool is written out and read back. It
    /// comes back with the same pattern and class.
    #[cfg(feature = "serde")]
    #[test]
    fn a_grant_reads_back_its_tool_classes() {
        let grant = tools_only(vec![tool("github_delete_repo", ActionClass::Delete)]);

        let json = serde_json::to_string(&grant).unwrap();

        assert_eq!(serde_json::from_str::<McpGrant>(&json).unwrap(), grant);
    }
}
