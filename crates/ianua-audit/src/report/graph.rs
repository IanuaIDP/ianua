//! One context drawn from the domain out: aggregates, what they offer and
//! the events they raise, the use cases that call them, the ports those
//! use cases need, and the adapters that implement the ports and drive the
//! use cases. Unreached nodes are marked.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::model::Model;
use crate::model::app::UseCase;
use crate::model::domain::{Behaviour, BehaviourKind, Event};
use crate::model::raising::RaiseKind;
use crate::report::{Paint, Style};
use crate::source::usage::Usage;
use crate::source::{Layer, Place, Workspace};

/// One context, from the domain to the adapters.
#[derive(Debug, Serialize)]
pub(crate) struct ContextGraph {
    /// The context's name.
    pub(crate) context: String,
    /// Its aggregates.
    pub(crate) aggregates: Vec<AggregateNode>,
    /// Its events.
    pub(crate) events: Vec<EventNode>,
    /// Its use cases, and those elsewhere that call its aggregates.
    pub(crate) use_cases: Vec<UseCaseNode>,
}

/// An aggregate and what it offers.
#[derive(Debug, Serialize)]
pub(crate) struct AggregateNode {
    /// Its name.
    pub(crate) name: String,
    /// Where it is declared.
    pub(crate) place: Place,
    /// Its public creators and changes.
    pub(crate) behaviours: Vec<BehaviourNode>,
}

/// A creator or change, and the use cases that call it.
#[derive(Debug, Serialize)]
pub(crate) struct BehaviourNode {
    /// Its name.
    pub(crate) name: String,
    /// `create` or `change`.
    pub(crate) kind: &'static str,
    /// Where it is declared.
    pub(crate) place: Place,
    /// The use cases that call it.
    pub(crate) use_cases: Vec<String>,
}

/// An event and what raises it.
#[derive(Debug, Serialize)]
pub(crate) struct EventNode {
    /// The struct's name.
    pub(crate) name: String,
    /// The dotted string it is recorded under, when known.
    pub(crate) event_type: Option<String>,
    /// Where it is declared.
    pub(crate) place: Place,
    /// The types whose changes raise it, and the observations that build it.
    pub(crate) raised_by: Vec<String>,
}

/// A use case, its ports and the adapters that name it.
#[derive(Debug, Serialize)]
pub(crate) struct UseCaseNode {
    /// Its name.
    pub(crate) name: String,
    /// `command` or `query`.
    pub(crate) kind: &'static str,
    /// Where it is implemented.
    pub(crate) place: Place,
    /// The ports its `Ports` struct holds.
    pub(crate) ports: Vec<PortNode>,
    /// The adapter files that name it.
    pub(crate) adapters: Vec<String>,
}

/// A port and the types that implement it.
#[derive(Debug, Serialize)]
pub(crate) struct PortNode {
    /// Its name.
    pub(crate) name: String,
    /// `Type (crate)` for each implementation outside the domain.
    pub(crate) implementations: Vec<String>,
}

/// Every context that has aggregates or use cases.
pub(crate) fn contexts(model: &Model) -> Vec<String> {
    let found: BTreeSet<String> = model
        .domain
        .aggregates
        .iter()
        .map(|aggregate| aggregate.context.clone())
        .chain(
            model
                .app
                .use_cases
                .iter()
                .map(|use_case| use_case.context.clone()),
        )
        .collect();
    found.into_iter().collect()
}

/// The graph of `context`, or `None` when it has no aggregates and no use
/// cases.
pub(crate) fn build(workspace: &Workspace, model: &Model, context: &str) -> Option<ContextGraph> {
    let aggregates = aggregate_nodes(workspace, model, context);
    let mut wanted: BTreeSet<String> = (aggregates.iter())
        .flat_map(|aggregate| aggregate.behaviours.iter())
        .flat_map(|behaviour| behaviour.use_cases.iter().cloned())
        .collect();
    let own = (model.app.use_cases.iter()).filter(|use_case| use_case.context == context);
    wanted.extend(own.map(|use_case| use_case.name.clone()));
    if aggregates.is_empty() && wanted.is_empty() {
        return None;
    }
    Some(ContextGraph {
        context: context.to_owned(),
        events: (model.domain.events.iter())
            .filter(|event| event.context == context)
            .map(|event| event_node(model, event))
            .collect(),
        use_cases: (model.app.use_cases.iter())
            .filter(|use_case| wanted.contains(&use_case.name))
            .map(|use_case| use_case_node(workspace, model, use_case))
            .collect(),
        aggregates,
    })
}

/// The aggregates of `context`, each with its behaviours.
fn aggregate_nodes(workspace: &Workspace, model: &Model, context: &str) -> Vec<AggregateNode> {
    (model.domain.aggregates.iter())
        .filter(|aggregate| aggregate.context == context)
        .map(|aggregate| AggregateNode {
            name: aggregate.name.clone(),
            place: aggregate.place.clone(),
            behaviours: (model.domain.behaviours.iter())
                .filter(|behaviour| behaviour.owner == aggregate.name)
                .map(|behaviour| behaviour_node(workspace, model, behaviour))
                .collect(),
        })
        .collect()
}

fn calls(usage: &Usage, behaviour: &Behaviour) -> bool {
    match behaviour.kind {
        BehaviourKind::Change => usage
            .method_calls
            .iter()
            .any(|call| call.name == behaviour.name),
        BehaviourKind::Create => usage
            .pairs
            .iter()
            .any(|pair| pair.owner == behaviour.owner && pair.name == behaviour.name),
    }
}

/// The use cases whose files call `behaviour`; those that also name its
/// aggregate when there are any, since another aggregate may have a
/// method of the same name.
fn behaviour_node(workspace: &Workspace, model: &Model, behaviour: &Behaviour) -> BehaviourNode {
    let callers: Vec<&UseCase> = model
        .app
        .use_cases
        .iter()
        .filter(|use_case| calls(workspace.files[use_case.file_index].usage(), behaviour))
        .collect();
    let naming_owner: Vec<&UseCase> = callers
        .iter()
        .copied()
        .filter(|use_case| {
            workspace.files[use_case.file_index]
                .usage()
                .idents
                .contains_key(&behaviour.owner)
        })
        .collect();
    let chosen = if naming_owner.is_empty() {
        callers
    } else {
        naming_owner
    };
    BehaviourNode {
        name: behaviour.name.clone(),
        kind: behaviour.kind.as_str(),
        place: behaviour.place.clone(),
        use_cases: chosen
            .iter()
            .map(|use_case| use_case.name.clone())
            .collect(),
    }
}

/// The event with what raises it: the type a change belongs to, or the
/// observation that builds it.
fn event_node(model: &Model, event: &Event) -> EventNode {
    let mut raised_by: Vec<String> = model
        .domain
        .raising
        .raisers_of(&event.name)
        .iter()
        .map(|raiser| match (raiser.kind, &raiser.owner) {
            (RaiseKind::Change, Some(owner)) => owner.clone(),
            (RaiseKind::Change, None) | (RaiseKind::Observation, _) => raiser.subject(),
        })
        .collect();
    raised_by.sort();
    raised_by.dedup();
    EventNode {
        name: event.name.clone(),
        event_type: event.event_type.as_ref().and_then(|(enum_name, variant)| {
            model
                .domain
                .event_types
                .iter()
                .find(|listed| listed.enum_name == *enum_name && listed.variant == *variant)
                .map(|listed| listed.text.clone())
        }),
        place: event.place.clone(),
        raised_by,
    }
}

fn use_case_node(workspace: &Workspace, model: &Model, use_case: &UseCase) -> UseCaseNode {
    UseCaseNode {
        name: use_case.name.clone(),
        kind: use_case.kind.as_str(),
        place: use_case.place.clone(),
        ports: model
            .app
            .ports_of(use_case)
            .into_iter()
            .map(|port| PortNode {
                name: port.name.clone(),
                implementations: model
                    .impls
                    .iter()
                    .filter(|block| block.implements(&port.item))
                    .map(|block| format!("{} ({})", block.self_type, block.crate_name))
                    .collect(),
            })
            .collect(),
        adapters: workspace
            .layer(Layer::Adapter)
            .filter(|file| file.usage().idents.contains_key(&use_case.name))
            .map(crate::source::SourceFile::display_path)
            .collect(),
    }
}

/// A labelled node with children, drawn as an indented tree.
struct Tree {
    label: String,
    children: Vec<Tree>,
}

impl Tree {
    fn leaf(label: String) -> Self {
        Self {
            label,
            children: Vec::new(),
        }
    }

    fn draw(&self, out: &mut String) {
        out.push_str(&self.label);
        out.push('\n');
        self.draw_children("", out);
    }

    fn draw_children(&self, prefix: &str, out: &mut String) {
        let count = self.children.len();
        for (index, child) in self.children.iter().enumerate() {
            let last = index + 1 == count;
            let (branch, carry) = if last {
                ("`-- ", "    ")
            } else {
                ("+-- ", "|   ")
            };
            out.push_str(prefix);
            out.push_str(branch);
            out.push_str(&child.label);
            out.push('\n');
            child.draw_children(&format!("{prefix}{carry}"), out);
        }
    }
}

/// `behaviour` with the use cases that reach it, marked when none does.
fn behaviour_tree(behaviour: &BehaviourNode, style: Style) -> Tree {
    let unreached = match behaviour.use_cases.is_empty() {
        true => format!("  {}", style.paint("[unreached]", Paint::Missing)),
        false => String::new(),
    };
    Tree {
        label: format!("{} ({}){unreached}", behaviour.name, behaviour.kind),
        children: (behaviour.use_cases.iter())
            .map(|name| Tree::leaf(format!("-> {}", style.paint(name, Paint::Present))))
            .collect(),
    }
}

/// The graph as an ASCII tree for a terminal.
pub(crate) fn render_ascii(graph: &ContextGraph, style: Style) -> String {
    let dim = |text: &str| style.paint(text, Paint::Dim);
    let mut out = format!(
        "{}  {}\n\n",
        style.paint(&graph.context, Paint::Heading),
        dim("aggregate -> behaviour -> use case -> port -> adapter")
    );
    for aggregate in &graph.aggregates {
        let tree = Tree {
            label: format!(
                "{}  {}",
                style.paint(&aggregate.name, Paint::Heading),
                dim(&location(&aggregate.place))
            ),
            children: (aggregate.behaviours.iter())
                .map(|behaviour| behaviour_tree(behaviour, style))
                .collect(),
        };
        tree.draw(&mut out);
        out.push('\n');
    }
    events_tree(graph, style).draw(&mut out);
    out.push('\n');
    use_cases_tree(graph, style).draw(&mut out);
    out
}

fn events_tree(graph: &ContextGraph, style: Style) -> Tree {
    Tree {
        label: style.paint("events", Paint::Heading),
        children: graph
            .events
            .iter()
            .map(|event| {
                let kind = event
                    .event_type
                    .as_deref()
                    .map(|text| format!("  {}", style.paint(text, Paint::Dim)))
                    .unwrap_or_default();
                let raised = match event.raised_by.is_empty() {
                    true => format!("  {}", style.paint("[never raised]", Paint::Missing)),
                    false => format!("  raised by {}", event.raised_by.join(", ")),
                };
                Tree::leaf(format!("{}{kind}{raised}", event.name))
            })
            .collect(),
    }
}

fn use_cases_tree(graph: &ContextGraph, style: Style) -> Tree {
    Tree {
        label: style.paint("use cases", Paint::Heading),
        children: (graph.use_cases.iter())
            .map(|use_case| use_case_tree(use_case, style))
            .collect(),
    }
}

/// `use_case` with its ports and their adapters, and the adapters that
/// name it, marked when none does.
fn use_case_tree(use_case: &UseCaseNode, style: Style) -> Tree {
    let unwired = match use_case.adapters.is_empty() {
        true => format!("  {}", style.paint("[unwired]", Paint::Missing)),
        false => String::new(),
    };
    let mut children: Vec<Tree> = (use_case.ports.iter())
        .map(|port| {
            let implementations = match port.implementations.is_empty() {
                true => style.paint("[no adapter]", Paint::Missing),
                false => port.implementations.join(", "),
            };
            Tree::leaf(format!("port {} -> {implementations}", port.name))
        })
        .collect();
    let named_in =
        |file: &String| Tree::leaf(format!("named in {}", style.paint(file, Paint::Dim)));
    children.extend(use_case.adapters.iter().map(named_in));
    Tree {
        label: format!(
            "{} ({}){unwired}  {}",
            use_case.name,
            use_case.kind,
            style.paint(&location(&use_case.place), Paint::Dim)
        ),
        children,
    }
}

fn location(place: &Place) -> String {
    format!("{}:{}", place.file, place.line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{adapter, app, domain, workspace};

    const TOPIC: &str = r"
        pub struct Topic;
        impl Topic {
            pub fn reconstitute(row: TopicRow) -> Result<Self, DomainError> { make() }
            pub fn archive(&mut self, by: &MessagingControl<'_>) { self.raised.raise(TopicArchived { at: now() }); }
            pub fn pause(&mut self, by: &MessagingControl<'_>) {}
        }
        tenant_event! { TopicArchived => MessagingEvent::TopicArchived }
        tenant_event! { TopicPaused => MessagingEvent::TopicPaused }
    ";

    const USE_CASE: &str = r"
        pub struct ArchivePorts { pub topic_store: Arc<dyn TopicStore> }
        impl Command for ArchiveUseCase {
            async fn execute(&self) { let topic: Topic = load(); topic.archive(&control); }
        }
    ";

    fn graph() -> ContextGraph {
        let ws = workspace(vec![
            domain("domains/messaging/topic.rs", TOPIC),
            app("use_cases/messaging/archive_topic.rs", USE_CASE),
            app(
                "ports/messaging.rs",
                "pub trait TopicStore { fn find(&self); }",
            ),
            adapter(
                "ianua-infra",
                "pg.rs",
                "impl TopicStore for PgTopicStore { fn find(&self) {} }",
            ),
            adapter(
                "ianua-server",
                "bootstrap.rs",
                "fn wire() { ArchiveUseCase::new(ports); }",
            ),
        ]);
        let model = Model::build(&ws, &DomainLists::default());
        build(&ws, &model, "messaging").unwrap()
    }

    #[test]
    fn a_behaviour_links_to_the_use_cases_that_call_it() {
        let found = graph();

        let behaviours = &found.aggregates[0].behaviours;

        assert_eq!(behaviours[0].use_cases, ["ArchiveUseCase"]);
        assert!(behaviours[1].use_cases.is_empty());
    }

    #[test]
    fn a_use_case_lists_its_ports_with_their_implementations_and_adapters() {
        let found = graph();

        let use_case = &found.use_cases[0];

        assert_eq!(
            use_case.ports[0].implementations,
            ["PgTopicStore (ianua-infra)"]
        );
        assert_eq!(use_case.adapters, ["crates/ianua-server/src/bootstrap.rs"]);
    }

    #[test]
    fn the_ascii_graph_marks_unreached_and_never_raised_nodes() {
        let text = render_ascii(&graph(), Style::new(false));

        assert!(text.contains("+-- archive (change)\n|   `-- -> ArchiveUseCase"));
        assert!(text.contains("`-- pause (change)  [unreached]"));
        assert!(text.contains("TopicPaused  [never raised]"));
        assert!(text.contains("TopicArchived  raised by Topic"));
    }

    #[test]
    fn an_unknown_context_has_no_graph() {
        let ws = workspace(vec![domain("domains/messaging/topic.rs", TOPIC)]);
        let model = Model::build(&ws, &DomainLists::default());

        assert!(build(&ws, &model, "nowhere").is_none());
    }
}
