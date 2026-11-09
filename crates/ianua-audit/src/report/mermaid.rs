//! Mermaid flowcharts in the docs' house style: classes set stroke widths
//! only, `ok` for what holds, `step` for what passes through, `ask` for
//! what is asked of, and `deny` for what nothing reaches.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::finding::{Area, Check};
use crate::report::Report;
use crate::report::graph::{AggregateNode, ContextGraph, EventNode, UseCaseNode};

const CLASSES: &str = concat!(
    "    classDef ok stroke-width:1.5px\n",
    "    classDef ask stroke-width:1.5px\n",
    "    classDef step stroke-width:1.25px\n",
    "    classDef deny stroke-width:1.25px\n",
);

/// The class a node gets.
#[derive(Clone, Copy)]
enum Class {
    Ok,
    Ask,
    Step,
    Deny,
}

impl Class {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Ask => "ask",
            Self::Step => "step",
            Self::Deny => "deny",
        }
    }
}

/// Nodes with stable ids, written once each, and the edges between them.
#[derive(Default)]
struct Chart {
    ids: BTreeMap<String, String>,
    nodes: String,
    edges: String,
}

impl Chart {
    /// The id of the node keyed `key`, writing it the first time.
    fn node(&mut self, key: &str, label: &str, class: Class) -> String {
        if let Some(id) = self.ids.get(key) {
            return id.clone();
        }
        let id = format!("n{}", self.ids.len());
        let _ = writeln!(
            self.nodes,
            "    {id}[\"{}\"]:::{}",
            label.replace('"', "'"),
            class.as_str()
        );
        self.ids.insert(key.to_owned(), id.clone());
        id
    }

    fn edge(&mut self, from: &str, to: &str, label: Option<&str>) {
        let _ = match label {
            Some(label) => writeln!(self.edges, "    {from} -- {label} --> {to}"),
            None => writeln!(self.edges, "    {from} --> {to}"),
        };
    }

    fn finish(self) -> String {
        format!("flowchart LR\n{}{}\n{CLASSES}", self.nodes, self.edges)
    }
}

/// One context as a flowchart.
pub(crate) fn render_graph(graph: &ContextGraph) -> String {
    let mut chart = Chart::default();
    chart_aggregates(&mut chart, &graph.aggregates);
    chart_events(&mut chart, &graph.events);
    chart_use_cases(&mut chart, &graph.use_cases);
    chart.finish()
}

/// Draws each aggregate, its behaviours and the use cases reaching them.
fn chart_aggregates(chart: &mut Chart, aggregates: &[AggregateNode]) {
    for aggregate in aggregates {
        let owner = chart.node(
            &format!("aggregate:{}", aggregate.name),
            &aggregate.name,
            Class::Ok,
        );
        for behaviour in &aggregate.behaviours {
            let (label, class) = match behaviour.use_cases.is_empty() {
                true => (format!("{}<br/>unreached", behaviour.name), Class::Deny),
                false => (behaviour.name.clone(), Class::Step),
            };
            let key = format!("behaviour:{}::{}", aggregate.name, behaviour.name);
            let node = chart.node(&key, &label, class);
            chart.edge(&owner, &node, None);
            for use_case in &behaviour.use_cases {
                let target = chart.node(&format!("use_case:{use_case}"), use_case, Class::Ask);
                chart.edge(&node, &target, None);
            }
        }
    }
}

/// Draws each event and the aggregates that raise it.
fn chart_events(chart: &mut Chart, events: &[EventNode]) {
    for event in events {
        let class = if event.raised_by.is_empty() {
            Class::Deny
        } else {
            Class::Step
        };
        let node = chart.node(&format!("event:{}", event.name), &event.name, class);
        for raiser in &event.raised_by {
            let from = chart.node(&format!("aggregate:{raiser}"), raiser, Class::Ok);
            chart.edge(&from, &node, Some("raises"));
        }
    }
}

/// Draws each use case, its ports and their adapters, and the crates that
/// drive it.
fn chart_use_cases(chart: &mut Chart, use_cases: &[UseCaseNode]) {
    for use_case in use_cases {
        let class = if use_case.adapters.is_empty() {
            Class::Deny
        } else {
            Class::Ask
        };
        let node = chart.node(
            &format!("use_case:{}", use_case.name),
            &use_case.name,
            class,
        );
        for port in &use_case.ports {
            let port_class = if port.implementations.is_empty() {
                Class::Deny
            } else {
                Class::Step
            };
            let port_node = chart.node(&format!("port:{}", port.name), &port.name, port_class);
            chart.edge(&node, &port_node, None);
            for implementation in &port.implementations {
                let target =
                    chart.node(&format!("impl:{implementation}"), implementation, Class::Ok);
                chart.edge(&port_node, &target, None);
            }
        }
        for crate_name in adapter_crates(&use_case.adapters) {
            let driver = chart.node(&format!("crate:{crate_name}"), &crate_name, Class::Ok);
            chart.edge(&driver, &node, Some("drives"));
        }
    }
}

/// The crate folder names of adapter file paths, each once.
fn adapter_crates(files: &[String]) -> Vec<String> {
    let mut crates: Vec<String> = files
        .iter()
        .filter_map(|file| file.strip_prefix("crates/")?.split('/').next())
        .map(str::to_owned)
        .collect();
    crates.sort();
    crates.dedup();
    crates
}

/// The whole report as one flowchart: the layers in a row, each with how
/// many findings its area has.
pub(crate) fn render_report(report: &Report) -> String {
    let counts = report.by_check();
    let in_area = |area: Area| -> usize {
        counts
            .iter()
            .filter(|(check, _)| check.area() == area)
            .map(|(_, tally)| tally.total())
            .sum()
    };
    let count_of = |check: Check| counts.get(&check).map_or(0, super::Tally::total);
    let unreached = count_of(Check::UnreachedBehaviour);
    let mut chart = Chart::default();
    let domain_label = format!("Domain<br/>{unreached} unreached behaviours");
    let domain = chart.node("domain", &domain_label, Class::Ok);
    let app = chart.node("app", "App", Class::Ask);
    let adapters_label = format!("Adapters<br/>{} wiring findings", in_area(Area::Adapters));
    let adapters = chart.node("adapters", &adapters_label, Class::Step);
    let flows = in_area(Area::Flow);
    let flow_label = format!("Listeners and rights<br/>{flows} flow findings");
    let flow = chart.node("flow", &flow_label, Class::Step);
    let reach = format!("{} reach findings", in_area(Area::Reach));
    chart.edge(&domain, &app, Some(&reach));
    let unwired = format!("{} unwired use cases", count_of(Check::UnwiredUseCase));
    chart.edge(&app, &adapters, Some(&unwired));
    let logic = in_area(Area::Logic);
    let logic_label = format!("Places that should agree<br/>{logic} logic conflicts");
    let logic = chart.node("logic", &logic_label, Class::Deny);
    chart.edge(&domain, &flow, Some("events"));
    chart.edge(&app, &logic, Some("limits, statuses, rights"));
    chart.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::graph::BehaviourNode;
    use crate::source::Place;

    fn place() -> Place {
        Place {
            file: "a.rs".to_owned(),
            line: 1,
        }
    }

    /// The change `name`, reached by `use_cases`.
    fn change(name: &str, use_cases: &[&str]) -> BehaviourNode {
        BehaviourNode {
            name: name.to_owned(),
            kind: "change",
            place: place(),
            use_cases: use_cases
                .iter()
                .map(|&use_case| use_case.to_owned())
                .collect(),
        }
    }

    fn graph() -> ContextGraph {
        ContextGraph {
            context: "messaging".to_owned(),
            aggregates: vec![AggregateNode {
                name: "Topic".to_owned(),
                place: place(),
                behaviours: vec![change("archive", &["ArchiveUseCase"]), change("pause", &[])],
            }],
            events: vec![EventNode {
                name: "TopicArchived".to_owned(),
                event_type: None,
                place: place(),
                raised_by: vec!["Topic".to_owned()],
            }],
            use_cases: vec![UseCaseNode {
                name: "ArchiveUseCase".to_owned(),
                kind: "command",
                place: place(),
                ports: Vec::new(),
                adapters: vec!["crates/ianua-api/src/handlers/topics.rs".to_owned()],
            }],
        }
    }

    #[test]
    fn the_graph_is_a_flowchart_in_the_house_style() {
        let text = render_graph(&graph());

        assert!(text.starts_with("flowchart LR\n"));
        assert!(text.contains("n0[\"Topic\"]:::ok"));
        assert!(text.contains("[\"pause<br/>unreached\"]:::deny"));
        assert!(text.ends_with("\n    classDef ok stroke-width:1.5px\n    classDef ask stroke-width:1.5px\n    classDef step stroke-width:1.25px\n    classDef deny stroke-width:1.25px\n"));
    }

    #[test]
    fn each_node_is_written_once_and_edges_reuse_it() {
        let text = render_graph(&graph());

        assert_eq!(text.matches("[\"ArchiveUseCase\"]").count(), 1);
        assert!(text.contains("n0 -- raises --> "));
        assert!(text.contains(" -- drives --> "));
    }
}
