//! The app's parts the checks look at: use cases, the port traits they
//! work through, and the `Ports` structs that hand the ports in.

use std::collections::BTreeSet;

use syn::{Item, TraitItem};

use crate::model::context_of;
use crate::model::domain::{listed, pairs};
use crate::model::paths::{AppItem, Modules, Origin, WrittenIn};
use crate::source::syntax::{
    implemented_trait, is_public, items_of, names_in_type, returned_core, returned_items,
    type_name, type_path, type_paths, type_text,
};
use crate::source::{Layer, Place, SourceFile, Workspace};

/// Whether a use case changes state or only reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UseCaseKind {
    /// It implements `Command` and receives an auditor.
    Command,
    /// It implements `Query`.
    Query,
}

impl UseCaseKind {
    /// The name reports use.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Query => "query",
        }
    }

    fn of_trait(name: &str) -> Option<Self> {
        match name {
            "Command" => Some(Self::Command),
            "Query" => Some(Self::Query),
            _ => None,
        }
    }
}

/// A type that implements `Command` or `Query`.
#[derive(Clone, Debug)]
pub(crate) struct UseCase {
    /// Its name.
    pub(crate) name: String,
    /// Whether it changes state.
    pub(crate) kind: UseCaseKind,
    /// The context folder it is in.
    pub(crate) context: String,
    /// Where it is implemented.
    pub(crate) place: Place,
    /// Its file's index in the workspace.
    pub(crate) file_index: usize,
    /// The `*Ports` struct it holds in a field, or else the first one
    /// declared beside it, if any.
    pub(crate) ports_struct: Option<AppItem>,
}

/// One method of a port trait.
#[derive(Clone, Debug)]
pub(crate) struct PortMethod {
    /// Its name.
    pub(crate) name: String,
    /// Whether an implementation must write it: it has no default body.
    pub(crate) required: bool,
    /// The type it hands back once its `Result` or `Option` is taken off,
    /// by its last name, when one is written.
    pub(crate) returns: Option<String>,
    /// The type of the items it hands back, when it hands back a
    /// collection, such as `User` for `Result<Vec<User>, DomainError>`.
    pub(crate) items: Option<String>,
    /// Every name its parameters' types mention, such as `ResourceKind`.
    pub(crate) param_types: Vec<String>,
    /// Where it is declared.
    pub(crate) place: Place,
}

/// A trait the app declares for the outside to implement. Two contexts may
/// declare one of the same name, so each is known by its module too.
#[derive(Clone, Debug)]
pub(crate) struct PortTrait {
    /// Its module and name.
    pub(crate) item: AppItem,
    /// Its name.
    pub(crate) name: String,
    /// Its methods.
    pub(crate) methods: Vec<PortMethod>,
    /// Where it is declared.
    pub(crate) place: Place,
}

/// What a name written for a trait stands for among the ports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PortLookup {
    /// This port.
    Found(AppItem),
    /// One of several ports of this name, and the reader cannot tell which.
    Unplaced(String),
    /// No port.
    NotAPort,
}

impl PortLookup {
    /// The port, when the reader knows which.
    pub(crate) fn found(&self) -> Option<&AppItem> {
        match self {
            Self::Found(item) => Some(item),
            Self::Unplaced(_) | Self::NotAPort => None,
        }
    }

    /// The port's name, when the name is a port's, placed or not.
    pub(crate) fn name(&self) -> Option<&str> {
        match self {
            Self::Found(item) => Some(&item.name),
            Self::Unplaced(name) => Some(name),
            Self::NotAPort => None,
        }
    }
}

/// A field of a `*Ports` struct.
#[derive(Clone, Debug)]
pub(crate) struct PortsField {
    /// Its name.
    pub(crate) name: String,
    /// Every name its type mentions, such as `Arc` and `TopicStore`.
    pub(crate) type_names: Vec<String>,
    /// Its type as written, such as `Arc<dyn TopicStore>`.
    pub(crate) written: Option<String>,
    /// The port its type names, read through the imports of the struct's
    /// file.
    pub(crate) port: PortLookup,
}

/// A struct whose name ends in `Ports`: what a use case is handed. Many
/// share a name, so each is known by its module too.
#[derive(Clone, Debug)]
pub(crate) struct PortsStruct {
    /// Its module and name.
    pub(crate) item: AppItem,
    /// Its named fields.
    pub(crate) fields: Vec<PortsField>,
}

/// The app's parts.
#[derive(Debug, Default)]
pub(crate) struct AppModel {
    /// Use cases.
    pub(crate) use_cases: Vec<UseCase>,
    /// Port traits.
    pub(crate) ports: Vec<PortTrait>,
    /// `*Ports` structs.
    pub(crate) ports_structs: Vec<PortsStruct>,
    /// The commands the app's conventions let save or take the auditor
    /// without recording, as `(file below src/, use case)`.
    pub(crate) silent_commands: BTreeSet<(String, String)>,
}

/// Where the app's conventions list the commands that record nothing on
/// purpose.
pub(crate) const APP_LISTS: &str = "crates/ianua-audit/src/conventions/app/security.rs";

/// The commands `SILENT_COMMANDS_ALLOWED` and `UNRECORDED_SAVES_ALLOWED`
/// in the app conventions' text `lists_text` name, as `(file below src/,
/// use case)`; none when it does not parse.
pub(crate) fn silent_commands(lists_text: &str) -> BTreeSet<(String, String)> {
    let Ok(parsed) = syn::parse_file(lists_text) else {
        return BTreeSet::new();
    };
    pairs(listed(
        &parsed,
        &["SILENT_COMMANDS_ALLOWED", "UNRECORDED_SAVES_ALLOWED"],
    ))
    .into_iter()
    .map(|(file, name)| {
        let use_case = name.split("::").next().unwrap_or(&name).to_owned();
        (file, use_case)
    })
    .collect()
}

impl AppModel {
    /// Reads the app files of `workspace`.
    pub(crate) fn build(workspace: &Workspace) -> Self {
        let modules = Modules::of(workspace);
        let app_files: Vec<(usize, &SourceFile)> = workspace
            .files
            .iter()
            .enumerate()
            .filter(|(_, file)| file.layer == Layer::App)
            .collect();
        let mut model = Self {
            ports: app_files
                .iter()
                .filter(|(_, file)| {
                    file.path.starts_with("ports/") || file.path.starts_with("acting/")
                })
                .flat_map(|(_, file)| port_traits(file))
                .collect(),
            ports_structs: Vec::new(),
            use_cases: Vec::new(),
            silent_commands: BTreeSet::new(),
        };
        model.ports_structs = app_files
            .iter()
            .flat_map(|(_, file)| model.ports_structs_in(file, &modules))
            .collect();
        model.use_cases = app_files
            .iter()
            .filter(|(_, file)| file.path.starts_with("use_cases/"))
            .flat_map(|(index, file)| model.use_cases_in(file, *index, &modules))
            .collect();
        model
    }

    /// The port trait `item`.
    pub(crate) fn port_at(&self, item: &AppItem) -> Option<&PortTrait> {
        self.ports.iter().find(|port| port.item == *item)
    }

    /// The port traits named `name`: more than one when contexts share it.
    pub(crate) fn ports_named<'s>(
        &'s self,
        name: &str,
    ) -> impl Iterator<Item = &'s PortTrait> + use<'s> {
        let name = name.to_owned();
        self.ports.iter().filter(move |port| port.name == name)
    }

    /// The port the path `written`, written `at` a file, names: the one its
    /// imports or its own module lead to, or else, when the reader cannot
    /// follow the name, the only port of that name.
    pub(crate) fn port_written(
        &self,
        modules: &Modules<'_>,
        at: WrittenIn<'_>,
        written: &[String],
    ) -> PortLookup {
        let Some(name) = written.last() else {
            return PortLookup::NotAPort;
        };
        if let Origin::Declared(item) = modules.origin_in(at, written) {
            return match self.port_at(&item) {
                Some(_) => PortLookup::Found(item),
                None => PortLookup::NotAPort,
            };
        }
        let own = at
            .here
            .filter(|_| written.len() == 1)
            .map(|module| AppItem {
                module: module.to_vec(),
                name: name.clone(),
            })
            .filter(|item| self.port_at(item).is_some());
        match own {
            Some(item) => PortLookup::Found(item),
            None => self.only_port_named(name),
        }
    }

    /// The port a type written in `file` names, as [`Self::port_written`]
    /// reads each path in it.
    pub(crate) fn port_in_type(
        &self,
        modules: &Modules<'_>,
        file: &SourceFile,
        ty: &syn::Type,
    ) -> PortLookup {
        let here = (file.layer == Layer::App).then(|| file.module_path());
        let at = WrittenIn {
            syntax: file.syntax(),
            here: here.as_deref(),
        };
        let mut unplaced = None;
        for path in type_paths(ty) {
            match self.port_written(modules, at, &path) {
                PortLookup::Found(item) => return PortLookup::Found(item),
                PortLookup::Unplaced(name) => unplaced = unplaced.or(Some(name)),
                PortLookup::NotAPort => {}
            }
        }
        unplaced.map_or(PortLookup::NotAPort, PortLookup::Unplaced)
    }

    /// The one port named `name`, or that several are.
    fn only_port_named(&self, name: &str) -> PortLookup {
        let named: Vec<&PortTrait> = self.ports_named(name).collect();
        match named.as_slice() {
            [] => PortLookup::NotAPort,
            [only] => PortLookup::Found(only.item.clone()),
            _ => PortLookup::Unplaced(name.to_owned()),
        }
    }

    /// The `*Ports` struct `item`.
    pub(crate) fn ports_struct(&self, item: &AppItem) -> Option<&PortsStruct> {
        self.ports_structs.iter().find(|found| found.item == *item)
    }

    /// The `*Ports` struct the path `written` names in `file`: the one its
    /// imports lead to, the one `file` declares under that name, or else,
    /// when the reader cannot follow the name, the only one of that name.
    pub(crate) fn ports_struct_written(
        &self,
        modules: &Modules<'_>,
        file: &SourceFile,
        written: &[String],
    ) -> Option<&PortsStruct> {
        let (name, _) = written.split_last()?;
        let origin = modules.origin(file, written);
        if let Origin::Declared(item) = &origin {
            return self.ports_struct(item);
        }
        let own = (file.layer == Layer::App && written.len() == 1)
            .then(|| AppItem::in_file(file, name))
            .and_then(|item| self.ports_struct(&item));
        if own.is_some() {
            return own;
        }
        matches!(origin, Origin::Outside)
            .then(|| self.only_named(name))
            .flatten()
    }

    /// The one `*Ports` struct named `name`, when exactly one is.
    fn only_named(&self, name: &str) -> Option<&PortsStruct> {
        let mut named = self
            .ports_structs
            .iter()
            .filter(|found| found.item.name == name);
        let first = named.next()?;
        named.next().is_none().then_some(first)
    }

    /// The first `*Ports` struct declared in `module`, the one a use case
    /// beside it holds when it names none.
    fn first_ports_struct_in(&self, module: &[String]) -> Option<AppItem> {
        let found = self
            .ports_structs
            .iter()
            .find(|found| found.item.module == module)?;
        Some(found.item.clone())
    }

    /// The use cases `file` implements, each with the `*Ports` struct it
    /// holds, or else the first one declared beside it.
    fn use_cases_in(
        &self,
        file: &SourceFile,
        file_index: usize,
        modules: &Modules<'_>,
    ) -> Vec<UseCase> {
        let Some(syntax) = file.syntax() else {
            return Vec::new();
        };
        let items = items_of(syntax);
        let beside = self.first_ports_struct_in(&file.module_path());
        items
            .iter()
            .filter_map(|item| match item {
                Item::Impl(block) => Some(block),
                _ => None,
            })
            .filter_map(|block| {
                let kind =
                    implemented_trait(block).and_then(|name| UseCaseKind::of_trait(&name))?;
                let name = type_name(&block.self_ty)?;
                Some(UseCase {
                    ports_struct: struct_named(&items, &name)
                        .and_then(|declared| self.held_ports(declared, file, modules))
                        .or_else(|| beside.clone()),
                    name,
                    kind,
                    context: context_of(file),
                    place: Place::of(file, &block.self_ty),
                    file_index,
                })
            })
            .collect()
    }

    /// The `*Ports` struct a field of `declared`, a struct in `file`,
    /// holds.
    fn held_ports(
        &self,
        declared: &syn::ItemStruct,
        file: &SourceFile,
        modules: &Modules<'_>,
    ) -> Option<AppItem> {
        declared.fields.iter().find_map(|field| {
            let written = type_path(&field.ty)?;
            self.ports_struct_written(modules, file, &written)
                .map(|found| found.item.clone())
        })
    }

    /// The port traits a use case's `Ports` struct holds.
    pub(crate) fn ports_of(&self, use_case: &UseCase) -> Vec<&PortTrait> {
        let Some(ports) = use_case
            .ports_struct
            .as_ref()
            .and_then(|item| self.ports_struct(item))
        else {
            return Vec::new();
        };
        let mut found: Vec<&PortTrait> = ports
            .fields
            .iter()
            .filter_map(|field| self.port_at(field.port.found()?))
            .collect();
        found.sort_by(|a, b| (&a.name, &a.item).cmp(&(&b.name, &b.item)));
        found.dedup_by(|a, b| a.item == b.item);
        found
    }

    /// The public `*Ports` structs `file` declares, each field's port read
    /// through the file's imports.
    fn ports_structs_in(&self, file: &SourceFile, modules: &Modules<'_>) -> Vec<PortsStruct> {
        let Some(syntax) = file.syntax() else {
            return Vec::new();
        };
        items_of(syntax)
            .into_iter()
            .filter_map(|item| match item {
                Item::Struct(declared)
                    if is_public(&declared.vis)
                        && declared.ident.to_string().ends_with("Ports") =>
                {
                    Some(declared)
                }
                _ => None,
            })
            .map(|declared| PortsStruct {
                item: AppItem::in_file(file, &declared.ident.to_string()),
                fields: declared
                    .fields
                    .iter()
                    .filter_map(|field| {
                        Some(PortsField {
                            name: field.ident.as_ref()?.to_string(),
                            type_names: names_in_type(&field.ty),
                            written: type_text(&field.ty),
                            port: self.port_in_type(modules, file, &field.ty),
                        })
                    })
                    .collect(),
            })
            .collect()
    }
}

fn port_traits(file: &SourceFile) -> Vec<PortTrait> {
    let Some(syntax) = file.syntax() else {
        return Vec::new();
    };
    items_of(syntax)
        .into_iter()
        .filter_map(|item| match item {
            Item::Trait(declared) if is_public(&declared.vis) => Some(declared),
            _ => None,
        })
        .map(|declared| PortTrait {
            item: AppItem::in_file(file, &declared.ident.to_string()),
            name: declared.ident.to_string(),
            methods: (declared.items.iter())
                .filter_map(|member| match member {
                    TraitItem::Fn(function) => Some(port_method(file, function)),
                    _ => None,
                })
                .collect(),
            place: Place::of(file, &declared.ident),
        })
        .collect()
}

/// The method `function` of a port trait declared in `file`.
fn port_method(file: &SourceFile, function: &syn::TraitItemFn) -> PortMethod {
    PortMethod {
        name: function.sig.ident.to_string(),
        required: function.default.is_none(),
        returns: returned_core(&function.sig.output, None),
        items: returned_items(&function.sig.output, None),
        param_types: (function.sig.inputs.iter())
            .filter_map(|input| match input {
                syn::FnArg::Typed(typed) => Some(names_in_type(&typed.ty)),
                syn::FnArg::Receiver(_) => None,
            })
            .flatten()
            .collect(),
        place: Place::of(file, &function.sig.ident),
    }
}

/// The struct named `name` among `items`.
fn struct_named<'i>(items: &[&'i Item], name: &str) -> Option<&'i syn::ItemStruct> {
    items.iter().find_map(|item| match item {
        Item::Struct(declared) if declared.ident == name => Some(declared),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::planted::{app, workspace};

    const ARCHIVE: &str = r"
        pub struct ArchivePorts {
            pub topic_store: Arc<dyn TopicStore>,
        }
        pub struct ArchiveUseCase { ports: ArchivePorts }
        impl Command for ArchiveUseCase {
            type Caller = CallerContext;
            async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, id: TopicId) {}
        }
    ";

    const PORT: &str = r#"
        pub trait TopicStore: Send + Sync + TenantScoped {
            async fn find_by_id(&self, tenant: &ScopedTenant, id: &TopicId) -> Option<Topic>;
            async fn find_any(&self, id: &TopicId) -> Option<Topic>;
            fn kind(&self) -> &str { "topic" }
        }
    "#;

    fn model() -> AppModel {
        let ws = workspace(vec![
            app("use_cases/messaging/topics/archive_topic.rs", ARCHIVE),
            app("ports/messaging/topics.rs", PORT),
        ]);
        AppModel::build(&ws)
    }

    #[test]
    fn a_command_impl_is_a_use_case_with_its_ports_struct() {
        let found = model();

        let use_case = &found.use_cases[0];

        assert_eq!(use_case.name, "ArchiveUseCase");
        assert_eq!(use_case.kind, UseCaseKind::Command);
        assert_eq!(held_name(use_case), Some("ArchivePorts"));
    }

    fn held_name(use_case: &UseCase) -> Option<&str> {
        use_case
            .ports_struct
            .as_ref()
            .map(|item| item.name.as_str())
    }

    #[test]
    fn a_use_case_reaches_the_ports_its_struct_holds() {
        let found = model();

        let ports: Vec<&str> = found
            .ports_of(&found.use_cases[0])
            .iter()
            .map(|port| port.name.as_str())
            .collect();

        assert_eq!(ports, ["TopicStore"]);
    }

    #[test]
    fn a_port_method_with_a_default_body_is_not_required() {
        let found = model();

        let port = found.ports_named("TopicStore").next().unwrap();

        assert!(port.methods[0].required);
        assert!(!port.methods[2].required);
    }

    #[test]
    fn a_port_method_keeps_the_type_it_hands_back() {
        let found = model();

        let port = found.ports_named("TopicStore").next().unwrap();

        assert_eq!(port.methods[0].returns.as_deref(), Some("Topic"));
    }

    /// Two use cases share a file; the second holds a `Ports` struct
    /// declared in another file. Each gets the struct it holds, not the
    /// first one beside it.
    #[test]
    fn a_use_case_gets_the_ports_struct_its_field_holds() {
        let ws = workspace(vec![
            app(
                "use_cases/oauth/registration/manage.rs",
                "pub struct ReadPorts { pub store: Arc<dyn ClientStore> }
                 pub struct ReadUseCase { ports: ReadPorts }
                 impl Query for ReadUseCase {}
                 pub struct DeleteUseCase { ports: SelfManagementPorts }
                 impl Command for DeleteUseCase {}",
            ),
            app(
                "use_cases/oauth/registration/ports.rs",
                "pub struct SelfManagementPorts { pub store: Arc<dyn ClientStore> }",
            ),
        ]);

        let found = AppModel::build(&ws);

        let held: Vec<Option<&str>> = found.use_cases.iter().map(held_name).collect();
        assert_eq!(held, [Some("ReadPorts"), Some("SelfManagementPorts")]);
    }

    /// Two contexts each declare a `SharedPorts`; the use case imports the
    /// one of its own context. It gets that one, and the ports it holds.
    #[test]
    fn a_ports_struct_two_contexts_share_a_name_of_is_told_apart_by_its_import() {
        let found = AppModel::build(&two_shared_ports());

        let rename = &found.use_cases[0];
        let ports: Vec<&str> = found
            .ports_of(rename)
            .iter()
            .map(|port| port.name.as_str())
            .collect();
        assert_eq!(
            rename
                .ports_struct
                .as_ref()
                .map(|item| item.module.join("::")),
            Some("use_cases::groups::ports".to_owned())
        );
        assert_eq!(ports, ["GroupStore"]);
    }

    /// Topics' and groups' `SharedPorts`, and a groups use case importing
    /// its own.
    fn two_shared_ports() -> Workspace {
        workspace(vec![
            app(
                "use_cases/topics/ports.rs",
                "pub struct SharedPorts { pub store: Arc<dyn TopicStore> }",
            ),
            app(
                "use_cases/groups/ports.rs",
                "pub struct SharedPorts { pub store: Arc<dyn GroupStore> }",
            ),
            app(
                "use_cases/groups/rename.rs",
                "use super::ports::SharedPorts;
                 pub struct RenameUseCase { ports: SharedPorts }
                 impl Command for RenameUseCase {}",
            ),
            app(
                "ports/stores.rs",
                "pub trait TopicStore { fn find(&self); }\npub trait GroupStore { fn find(&self); }",
            ),
        ])
    }

    /// OAuth's and agents' `ReplayGuard`, one `*Ports` struct importing
    /// agents' and one whose import the reader cannot follow.
    fn two_replay_guards() -> Workspace {
        workspace(vec![
            app(
                "ports/oauth.rs",
                "pub trait ReplayGuard { fn first_use(&self); }",
            ),
            app(
                "ports/agents.rs",
                "pub trait ReplayGuard { fn consume(&self); }",
            ),
            app(
                "use_cases/agents/exchange.rs",
                "use crate::ports::agents::ReplayGuard;
                 pub struct ExchangePorts { pub guard: Arc<dyn ReplayGuard> }",
            ),
            app(
                "use_cases/oauth/token.rs",
                "use crate::ports::*;
                 pub struct TokenPorts { pub guard: Arc<dyn ReplayGuard> }",
            ),
        ])
    }

    /// Two contexts each declare a `ReplayGuard` port. A `*Ports` struct
    /// holding one is joined to the one its import names; one written
    /// without an import the reader can follow is joined to neither.
    #[test]
    fn a_port_two_contexts_share_a_name_of_is_told_apart_by_its_import() {
        let found = AppModel::build(&two_replay_guards());

        let guard = |name: &str| {
            found
                .ports_structs
                .iter()
                .find(|ports| ports.item.name == name)
                .map(|ports| ports.fields[0].port.clone())
        };
        assert_eq!(
            guard("ExchangePorts"),
            Some(PortLookup::Found(AppItem {
                module: vec!["ports".to_owned(), "agents".to_owned()],
                name: "ReplayGuard".to_owned(),
            }))
        );
        assert_eq!(
            guard("TokenPorts"),
            Some(PortLookup::Unplaced("ReplayGuard".to_owned()))
        );
    }
}
