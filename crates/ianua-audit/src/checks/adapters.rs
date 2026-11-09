//! App to adapters: what the app needs from outside that nothing provides.
//!
//! - A port trait with methods that no adapter (and no app service)
//!   implements.
//! - An adapter impl of a port that lacks a required method, or has one the
//!   port no longer declares.
//! - A use case no adapter names: nothing constructs or calls it.
//! - A `*Ports` struct written out in an adapter without one of its fields,
//!   or with a field it no longer has.
//!
//! A trait an `impl` names is the port its path leads to through the
//! file's imports (see [`crate::model::paths`]), since two contexts may
//! declare ports of one name; a name the reader cannot follow stands for
//! the only port of that name. An adapter crate's own trait of a port's
//! name is not the port. An `impl` whose trait is one of several ports of
//! that name, and the reader cannot tell which, is checked against none,
//! and no port of that name is called unimplemented on its account. A
//! `*Ports` struct is found the same way, since many contexts declare one
//! of the same name.

use std::collections::BTreeSet;

use crate::finding::{Check, Finding, Found, Severity, Unsaid};
use crate::model::app::{PortLookup, PortTrait, PortsStruct, UseCase};
use crate::model::paths::Modules;
use crate::model::{Model, TraitImpl};
use crate::source::usage::StructLiteral;
use crate::source::{Layer, Place, SourceFile, Workspace};

/// Every adapter finding; `parked` names the crates waiting for a rebuild.
pub(crate) fn run(workspace: &Workspace, model: &Model, parked: &BTreeSet<String>) -> Found {
    let mut found = unimplemented_ports(model);
    found.findings.extend(mismatched_methods(model));
    found
        .findings
        .extend(unwired_use_cases(workspace, model, parked));
    found.findings.extend(ports_literals(workspace, model));
    found
}

fn unimplemented_ports(model: &Model) -> Found {
    let mut found = Found::default();
    for port in model
        .app
        .ports
        .iter()
        .filter(|port| !port.methods.is_empty())
    {
        if model.impls.iter().any(|block| block.implements(&port.item)) {
            continue;
        }
        let unplaced = model
            .impls
            .iter()
            .any(|block| block.port == PortLookup::Unplaced(port.name.clone()));
        if unplaced {
            found.leave_unsaid(unplaced_port(port));
            continue;
        }
        found.findings.push(unimplemented_port(port));
    }
    found
}

/// What is left unsaid of `port` when an adapter implements a port of its
/// name the reader cannot tell apart from it.
fn unplaced_port(port: &PortTrait) -> Unsaid {
    Unsaid::new(
        Check::UnimplementedPort,
        port.item.path(),
        port.place.clone(),
        format!(
            "an adapter implements a `{}` the reader cannot tell apart from another port of that name",
            port.name
        ),
    )
}

/// The finding that no adapter implements `port`.
fn unimplemented_port(port: &PortTrait) -> Finding {
    Finding::new(
        Check::UnimplementedPort,
        port.place.clone(),
        port.item.path(),
        format!(
            "no adapter implements `{}`: a use case needing it cannot be wired",
            port.item.path()
        ),
    )
}

fn mismatched_methods(model: &Model) -> Vec<Finding> {
    let mut found = Vec::new();
    for block in model
        .impls
        .iter()
        .filter(|block| block.layer == Layer::Adapter)
    {
        let Some(port) = block.port.found().and_then(|item| model.app.port_at(item)) else {
            continue;
        };
        found.extend(missing_methods(block, port));
        found.extend(stale_methods(block, port));
    }
    found
}

/// The methods `port` requires that `block`, an adapter's implementation
/// of it, lacks.
fn missing_methods(block: &TraitImpl, port: &PortTrait) -> Vec<Finding> {
    let subject = format!("{} for {}", port.name, block.self_type);
    (port.methods.iter())
        .filter(|method| method.required && !block.methods.contains(&method.name))
        .map(|method| {
            Finding::new(
                Check::MissingPortMethod,
                block.place.clone(),
                format!("{subject}::{}", method.name),
                format!(
                    "`impl {subject}` lacks `{}`, which the port requires",
                    method.name
                ),
            )
        })
        .collect()
}

/// The methods `block`, an adapter's implementation of `port`, has that
/// the port no longer declares.
fn stale_methods(block: &TraitImpl, port: &PortTrait) -> Vec<Finding> {
    let subject = format!("{} for {}", port.name, block.self_type);
    (block.methods.iter())
        .filter(|name| !port.methods.iter().any(|method| method.name == **name))
        .map(|name| {
            Finding::new(
                Check::StalePortMethod,
                block.place.clone(),
                format!("{subject}::{name}"),
                format!("`impl {subject}` has `{name}`, which the port no longer declares"),
            )
        })
        .collect()
}

/// Whether `subject`, of an unwired use case, says only the parked crate
/// `crate_name` wires it.
pub(crate) fn wired_in_parked(subject: &str, crate_name: &str) -> bool {
    subject.ends_with(&format!("(wired in parked {crate_name})"))
}

/// The use cases no live adapter names. One that a parked crate names is
/// wired there, waiting for that crate's rebuild: it is reported for the
/// record, at info, naming the crate.
fn unwired_use_cases(
    workspace: &Workspace,
    model: &Model,
    parked: &BTreeSet<String>,
) -> Vec<Finding> {
    let naming = |name: &str, live: bool| {
        workspace
            .layer(Layer::Adapter)
            .filter(move |file| parked.contains(&file.crate_name) != live)
            .find(|file| file.usage().idents.contains_key(name))
            .map(|file| file.crate_name.clone())
    };
    model
        .app
        .use_cases
        .iter()
        .filter(|use_case| naming(&use_case.name, true).is_none())
        .map(|use_case| match naming(&use_case.name, false) {
            Some(crate_name) => wired_while_parked(use_case, &crate_name),
            None => Finding::new(
                Check::UnwiredUseCase,
                use_case.place.clone(),
                use_case.name.clone(),
                format!(
                    "no adapter names `{}`: no handler, worker or wiring constructs or calls it",
                    use_case.name
                ),
            ),
        })
        .collect()
}

/// The finding, at info, that only the parked crate `crate_name` wires
/// `use_case`.
fn wired_while_parked(use_case: &UseCase, crate_name: &str) -> Finding {
    let mut finding = Finding::new(
        Check::UnwiredUseCase,
        use_case.place.clone(),
        format!("{} (wired in parked {crate_name})", use_case.name),
        format!(
            "no live adapter names `{}`: only `{crate_name}`, which is parked, wires it",
            use_case.name
        ),
    );
    finding.severity = Severity::Info;
    finding
}

/// Each `*Ports` struct an adapter writes out, checked against the struct
/// its path names: the one its imports lead to, or the only one of its
/// name. One the reader cannot place among several of that name is left
/// alone.
fn ports_literals(workspace: &Workspace, model: &Model) -> Vec<Finding> {
    let modules = Modules::of(workspace);
    let mut found = Vec::new();
    for file in workspace.layer(Layer::Adapter) {
        for literal in &file.usage().struct_literals {
            let Some(ports) = model
                .app
                .ports_struct_written(&modules, file, &literal.path)
            else {
                continue;
            };
            found.extend(literal_mismatches(file, literal, ports));
        }
    }
    found
}

fn literal_mismatches(
    file: &SourceFile,
    literal: &StructLiteral,
    ports: &PortsStruct,
) -> Vec<Finding> {
    let place = Place::at(file, literal.line);
    let struct_name = &ports.item.name;
    let unset = ports
        .fields
        .iter()
        .filter(|_| !literal.has_rest)
        .filter(|field| !literal.fields.contains(&field.name))
        .map(|field| {
            Finding::new(
                Check::UnsetPortsField,
                place.clone(),
                format!("{struct_name}.{}", field.name),
                format!("`{struct_name}` is written out without `{}`", field.name),
            )
        });
    let unknown = literal
        .fields
        .iter()
        .filter(|name| !ports.fields.iter().any(|field| field.name == **name))
        .map(|name| {
            Finding::new(
                Check::UnknownPortsField,
                place.clone(),
                format!("{struct_name}.{name}"),
                format!("`{struct_name}` has no field `{name}` any more"),
            )
        });
    unset.chain(unknown).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{adapter, app, workspace};

    const PORTS: &str = r"
        pub trait TopicStore: Send + Sync {
            async fn find(&self, id: &TopicId) -> Option<Topic>;
            async fn save(&self, topic: &Topic);
            fn label(&self) -> &str { name() }
        }
        pub trait AuditSink: Send + Sync {
            async fn write(&self, record: &Record);
        }
        pub trait Marker {}
    ";

    const USE_CASES: &str = r"
        pub struct ArchivePorts {
            pub topic_store: Arc<dyn TopicStore>,
            pub authorities: Arc<dyn TenantAuthorities>,
        }
        impl Command for ArchiveUseCase {}
        impl Query for ListUseCase {}
    ";

    const INFRA: &str = r"
        impl TopicStore for PgTopicStore {
            async fn find(&self, id: &TopicId) -> Option<Topic> { none() }
            async fn find_all(&self) {}
        }
    ";

    const SERVER: &str = r"
        fn wire() {
            let archive = ArchiveUseCase::new(ArchivePorts {
                topic_store: store,
                old_field: x,
            });
        }
    ";

    fn findings() -> Vec<Finding> {
        let ws = workspace(vec![
            app("ports/messaging.rs", PORTS),
            app("use_cases/messaging/topics.rs", USE_CASES),
            adapter("ianua-infra", "postgres/topics.rs", INFRA),
            adapter("ianua-server", "bootstrap.rs", SERVER),
        ]);
        run(
            &ws,
            &Model::build(&ws, &DomainLists::default()),
            &BTreeSet::new(),
        )
        .findings
    }

    fn subjects(found: &[Finding], check: Check) -> Vec<String> {
        found
            .iter()
            .filter(|finding| finding.check == check)
            .map(|finding| finding.subject.clone())
            .collect()
    }

    #[test]
    fn a_port_no_adapter_implements_is_flagged_and_a_marker_is_not() {
        let found = findings();

        assert_eq!(
            subjects(&found, Check::UnimplementedPort),
            ["ports::messaging::AuditSink"]
        );
    }

    /// The oauth and agents contexts each declare a `ReplayGuard`, with
    /// different methods. Storage implements the oauth one, through its
    /// import. That `impl` is checked against the oauth port only, and the
    /// agents port, which nothing implements, is reported.
    fn shared_name(adapter_text: &str) -> Found {
        let ws = workspace(vec![
            app(
                "ports/oauth.rs",
                "pub trait ReplayGuard { async fn first_use(&self) -> bool; }",
            ),
            app(
                "ports/agents.rs",
                "pub trait ReplayGuard { async fn consume(&self) -> bool; }",
            ),
            adapter("ianua-infra", "postgres/oauth.rs", adapter_text),
        ]);
        run(
            &ws,
            &Model::build(&ws, &DomainLists::default()),
            &BTreeSet::new(),
        )
    }

    #[test]
    fn two_ports_of_one_name_are_told_apart_by_the_import_of_the_impl() {
        let found = shared_name(
            "use ianua_app::ports::oauth::ReplayGuard;
             impl ReplayGuard for PgReplayGuard { async fn first_use(&self) -> bool { true } }",
        );

        assert_eq!(
            subjects(&found.findings, Check::UnimplementedPort),
            ["ports::agents::ReplayGuard"]
        );
        assert!(subjects(&found.findings, Check::MissingPortMethod).is_empty());
        assert!(subjects(&found.findings, Check::StalePortMethod).is_empty());
    }

    /// The `impl` names the shared trait without an import the reader can
    /// follow. It could be either port, so neither is called unimplemented
    /// nor checked against it, and the silence is counted.
    #[test]
    fn an_impl_of_a_shared_name_the_reader_cannot_place_keeps_both_quiet() {
        let found = shared_name(
            "use ianua_app::ports::*;
             impl ReplayGuard for PgReplayGuard { async fn first_use(&self) -> bool { true } }",
        );

        assert!(subjects(&found.findings, Check::UnimplementedPort).is_empty());
        assert!(subjects(&found.findings, Check::StalePortMethod).is_empty());
        assert_eq!(found.silenced.get(&Check::UnimplementedPort), Some(&2));
    }

    #[test]
    fn an_impl_missing_a_required_method_is_flagged_but_not_a_default_one() {
        let found = findings();

        assert_eq!(
            subjects(&found, Check::MissingPortMethod),
            ["TopicStore for PgTopicStore::save"]
        );
    }

    #[test]
    fn an_impl_method_the_port_does_not_declare_is_stale() {
        let found = findings();

        assert_eq!(
            subjects(&found, Check::StalePortMethod),
            ["TopicStore for PgTopicStore::find_all"]
        );
    }

    #[test]
    fn a_use_case_no_adapter_names_is_unwired() {
        let found = findings();

        assert_eq!(subjects(&found, Check::UnwiredUseCase), ["ListUseCase"]);
    }

    /// Only the parked server wires the archive use case: it is reported
    /// for the record, at info, naming the crate. The list use case no
    /// adapter names stays at its own severity.
    #[test]
    fn a_use_case_only_a_parked_crate_wires_is_reported_at_info() {
        let ws = workspace(vec![
            app("ports/messaging.rs", PORTS),
            app("use_cases/messaging/topics.rs", USE_CASES),
            adapter("ianua-server", "bootstrap.rs", SERVER),
        ]);
        let parked = BTreeSet::from(["ianua-server".to_owned()]);

        let found = run(&ws, &Model::build(&ws, &DomainLists::default()), &parked).findings;

        let unwired: Vec<(String, Severity)> = found
            .iter()
            .filter(|finding| finding.check == Check::UnwiredUseCase)
            .map(|finding| (finding.subject.clone(), finding.severity))
            .collect();
        assert_eq!(
            unwired,
            [
                (
                    "ArchiveUseCase (wired in parked ianua-server)".to_owned(),
                    Severity::Info
                ),
                ("ListUseCase".to_owned(), Severity::Medium),
            ]
        );
    }

    #[test]
    fn a_ports_literal_reports_unset_and_unknown_fields() {
        let found = findings();

        assert_eq!(
            subjects(&found, Check::UnsetPortsField),
            ["ArchivePorts.authorities"]
        );
        assert_eq!(
            subjects(&found, Check::UnknownPortsField),
            ["ArchivePorts.old_field"]
        );
    }

    /// Two contexts each declare a `CreatePorts`, with different fields.
    /// The wiring imports the groups one through its module's re-export and
    /// writes it out whole: nothing is unset or unknown. A literal of the
    /// shared name the reader cannot place is not checked against either.
    #[test]
    fn a_ports_literal_is_checked_against_the_struct_its_import_names() {
        let ws = two_create_ports();

        let found = run(
            &ws,
            &Model::build(&ws, &DomainLists::default()),
            &BTreeSet::new(),
        )
        .findings;

        assert!(subjects(&found, Check::UnsetPortsField).is_empty());
        assert!(subjects(&found, Check::UnknownPortsField).is_empty());
    }

    /// Two contexts' `CreatePorts`, one wiring that imports the groups one
    /// and fills it, and one that cannot place the name it writes.
    fn two_create_ports() -> Workspace {
        workspace(vec![
            app(
                "use_cases/groups/mod.rs",
                "pub mod create;\npub use create::{CreatePorts, CreateUseCase};",
            ),
            app(
                "use_cases/groups/create.rs",
                "pub struct CreatePorts { pub groups: Arc<dyn GroupStore> }",
            ),
            app(
                "use_cases/topics/create.rs",
                "pub struct CreatePorts { pub topics: Arc<dyn TopicStore> }",
            ),
            adapter(
                "ianua-server",
                "bootstrap.rs",
                "use ianua_app::use_cases::groups::{CreatePorts, CreateUseCase};
                 fn wire() { CreateUseCase::new(CreatePorts { groups: store }); }",
            ),
            adapter(
                "ianua-api",
                "state.rs",
                "use ianua_app::use_cases::*;
                 fn wire() { CreatePorts { other: store }; }",
            ),
        ])
    }

    #[test]
    fn an_adapter_implementing_its_own_trait_of_the_same_name_is_left_alone() {
        let ws = workspace(vec![
            app("ports/messaging.rs", PORTS),
            adapter(
                "ianua-zero",
                "store.rs",
                "pub trait TopicStore { fn other(&self); }
                 impl TopicStore for ZeroStore { fn other(&self) {} }",
            ),
        ]);

        let found = run(
            &ws,
            &Model::build(&ws, &DomainLists::default()),
            &BTreeSet::new(),
        )
        .findings;

        assert!(subjects(&found, Check::MissingPortMethod).is_empty());
    }
}
