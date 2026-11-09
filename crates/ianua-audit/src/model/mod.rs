//! What the audit knows about the codebase once it has read it: the
//! domain's aggregates, events and rules, the app's use cases and ports, and
//! the adapters' implementations, with who names what.

pub(crate) mod app;
pub(crate) mod domain;
pub(crate) mod evaluate;
pub(crate) mod facts;
pub(crate) mod gates;
pub(crate) mod machines;
pub(crate) mod paths;
pub(crate) mod raising;
pub(crate) mod rights;
pub(crate) mod rules;

use std::collections::{BTreeMap, BTreeSet};

use crate::model::app::{AppModel, PortLookup};
use crate::model::domain::{DomainLists, DomainModel};
use crate::model::paths::{AppItem, Modules, Origin, WrittenIn};
use crate::source::syntax::{impl_fns, implemented_path, items_of, line_of, type_name};
use crate::source::usage::Usage;
use crate::source::{Layer, Place, SourceFile, Workspace};

/// Everything the checks and graphs read.
pub(crate) struct Model {
    /// The domain's parts.
    pub(crate) domain: DomainModel,
    /// The app's parts.
    pub(crate) app: AppModel,
    /// Every `impl Trait for Type` outside the domain.
    pub(crate) impls: Vec<TraitImpl>,
    /// What the domain names outside its tests.
    pub(crate) domain_reach: Reach,
    /// What the app names outside its tests.
    pub(crate) app_reach: Reach,
    /// What the adapters name outside their tests.
    pub(crate) adapter_reach: Reach,
    /// What each domain file names, by its path from the workspace root.
    pub(crate) domain_files: Vec<(String, Reach)>,
}

impl Model {
    /// Reads `workspace`, with what the domain's conventions list: the
    /// caller proofs, on top of the `*Control` types found in it, and the
    /// observations that raise events no aggregate raises.
    pub(crate) fn build(workspace: &Workspace, lists: &DomainLists) -> Self {
        let app = AppModel::build(workspace);
        Self {
            domain: DomainModel::build(workspace, lists),
            impls: trait_impls(workspace, &app),
            app,
            domain_reach: Reach::of(workspace.layer(Layer::Domain)),
            app_reach: Reach::of(workspace.layer(Layer::App)),
            adapter_reach: Reach::of(workspace.layer(Layer::Adapter)),
            domain_files: workspace
                .layer(Layer::Domain)
                .map(|file| (file.display_path(), Reach::of([file])))
                .collect(),
        }
    }
}

/// One `impl Trait for Type` block.
#[derive(Clone, Debug)]
pub(crate) struct TraitImpl {
    /// The port it implements, read through the file's imports: an
    /// adapter crate's own trait of a port's name is none.
    pub(crate) port: PortLookup,
    /// The type's last name.
    pub(crate) self_type: String,
    /// The crate it is in.
    pub(crate) crate_name: String,
    /// The layer it is in.
    pub(crate) layer: Layer,
    /// The functions it defines.
    pub(crate) methods: Vec<String>,
    /// The line each function it defines is declared on.
    pub(crate) method_lines: BTreeMap<String, usize>,
    /// Where it starts.
    pub(crate) place: Place,
}

impl TraitImpl {
    /// Whether it implements the port `item`.
    pub(crate) fn implements(&self, item: &AppItem) -> bool {
        self.port.found() == Some(item)
    }

    /// Where it defines `method`, or where it starts when it does not.
    pub(crate) fn place_of(&self, method: &str) -> Place {
        self.method_lines.get(method).map_or_else(
            || self.place.clone(),
            |line| Place {
                file: self.place.file.clone(),
                line: *line,
            },
        )
    }
}

/// Every `impl Trait for Type` block outside the domain, each joined to
/// the port its path leads to.
fn trait_impls(workspace: &Workspace, app: &AppModel) -> Vec<TraitImpl> {
    let modules = Modules::of(workspace);
    let own = own_traits(workspace);
    workspace
        .files
        .iter()
        .filter(|file| file.layer != Layer::Domain)
        .flat_map(|file| impls_in(file, app, &modules, &own))
        .collect()
}

fn impls_in(
    file: &SourceFile,
    app: &AppModel,
    modules: &Modules<'_>,
    own: &BTreeSet<(String, String)>,
) -> Vec<TraitImpl> {
    let Some(syntax) = file.syntax() else {
        return Vec::new();
    };
    let here = (file.layer == Layer::App).then(|| file.module_path());
    let at = WrittenIn {
        syntax: Some(syntax),
        here: here.as_deref(),
    };
    items_of(syntax)
        .into_iter()
        .filter_map(|item| match item {
            syn::Item::Impl(block) => Some(block),
            _ => None,
        })
        .filter_map(|block| {
            let trait_path = implemented_path(block)?;
            let trait_name = trait_path.last()?.clone();
            let imported = matches!(modules.origin_in(at, &trait_path), Origin::Declared(_));
            let own_trait = !imported && own.contains(&(file.crate_name.clone(), trait_name));
            let port = match own_trait {
                true => PortLookup::NotAPort,
                false => app.port_written(modules, at, &trait_path),
            };
            Some(trait_impl(file, block, port))
        })
        .collect()
}

/// `block`, an implementation of a trait in `file`, whose trait is the
/// port `port` names.
fn trait_impl(file: &SourceFile, block: &syn::ItemImpl, port: PortLookup) -> TraitImpl {
    TraitImpl {
        port,
        self_type: type_name(&block.self_ty).unwrap_or_else(|| "_".to_owned()),
        crate_name: file.crate_name.clone(),
        layer: file.layer,
        methods: impl_fns(block)
            .map(|function| function.sig.ident.to_string())
            .collect(),
        method_lines: impl_fns(block)
            .map(|function| (function.sig.ident.to_string(), line_of(&function.sig.ident)))
            .collect(),
        place: Place::of(file, &block.self_ty),
    }
}

/// The traits each adapter crate declares itself, as `(crate, trait)`: an
/// `impl` of one by its bare name is of that trait, not of a port.
fn own_traits(workspace: &Workspace) -> BTreeSet<(String, String)> {
    workspace
        .layer(Layer::Adapter)
        .flat_map(|file| {
            file.syntax()
                .map(items_of)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|item| match item {
                    syn::Item::Trait(declared) => {
                        Some((file.crate_name.clone(), declared.ident.to_string()))
                    }
                    _ => None,
                })
        })
        .collect()
}

/// What a set of files names, for quick "does anyone call this" questions.
#[derive(Debug, Default)]
pub(crate) struct Reach {
    /// Every identifier.
    pub(crate) idents: BTreeSet<String>,
    /// Every `.method(` called.
    pub(crate) methods: BTreeSet<String>,
    /// Every `name(` called as a function.
    pub(crate) functions: BTreeSet<String>,
    /// Every `A::B` written, `A` read through the file's `use .. as ..`.
    pub(crate) pairs: BTreeSet<(String, String)>,
    /// Every `B` of an `A::B` written.
    pub(crate) pair_tails: BTreeSet<String>,
    /// Every `A` of an `A::B` written.
    pub(crate) pair_heads: BTreeSet<String>,
    /// Every struct written out with its fields.
    pub(crate) literals: BTreeSet<String>,
}

impl Reach {
    /// What `files` name together.
    pub(crate) fn of<'a>(files: impl IntoIterator<Item = &'a SourceFile>) -> Self {
        let mut reach = Self::default();
        for file in files {
            let usage = file.usage();
            reach.idents.extend(usage.idents.keys().cloned());
            let methods = usage.method_calls.iter().map(|call| call.name.clone());
            reach.methods.extend(methods);
            let functions = usage.fn_calls.iter().map(|call| call.name.clone());
            reach.functions.extend(functions);
            reach.add_pairs(usage);
            let literals = (usage.struct_literals.iter())
                .map(|literal| usage.unaliased(&literal.name).to_owned());
            reach.literals.extend(literals);
        }
        reach
    }

    /// Adds the `Owner::name` pairs `usage` writes, each part on its own
    /// too, owners unaliased.
    fn add_pairs(&mut self, usage: &Usage) {
        for pair in &usage.pairs {
            let owner = usage.unaliased(&pair.owner).to_owned();
            self.pairs.insert((owner.clone(), pair.name.clone()));
            self.pair_tails.insert(pair.name.clone());
            self.pair_heads.insert(owner);
        }
    }

    /// Whether `owner::name` is written.
    pub(crate) fn names_pair(&self, owner: &str, name: &str) -> bool {
        self.pairs.contains(&(owner.to_owned(), name.to_owned()))
    }

    /// Whether `name` is called: as a method, as a function, or through a
    /// path ending in it.
    pub(crate) fn calls(&self, name: &str) -> bool {
        self.methods.contains(name)
            || self.functions.contains(name)
            || self.pair_tails.contains(name)
    }

    /// Whether a value of the struct `name` is made: written out with its
    /// fields, or through a path starting with it, such as `Name::new`.
    pub(crate) fn makes(&self, name: &str) -> bool {
        self.literals.contains(name) || self.pair_heads.contains(name)
    }
}

/// The context of the domain file at `path` from the workspace root, such
/// as `audit` for `crates/ianua-domain/src/domains/audit/status.rs`, or
/// `kernel` for anything else.
pub(crate) fn context_of_path(path: &str) -> String {
    path.split_once("/domains/").map_or_else(
        || "kernel".to_owned(),
        |(_, rest)| {
            let name = rest.split('/').next().unwrap_or(rest);
            name.trim_end_matches(".rs").to_owned()
        },
    )
}

/// The context a file belongs to: the folder after `domains/` in the
/// domain, after `use_cases/`, `ports/` or `services/` in the app, or
/// `kernel` for anything else.
pub(crate) fn context_of(file: &SourceFile) -> String {
    let prefixes: &[&str] = match file.layer {
        Layer::Domain => &["domains/"],
        Layer::App => &["use_cases/", "ports/", "services/"],
        Layer::Adapter => &[],
    };
    prefixes
        .iter()
        .find_map(|prefix| file.path.strip_prefix(prefix))
        .map_or_else(
            || "kernel".to_owned(),
            |rest| {
                let name = rest.split('/').next().unwrap_or(rest);
                name.trim_end_matches(".rs").to_owned()
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::planted::{adapter, app, domain, workspace};

    #[test]
    fn a_file_belongs_to_the_folder_after_its_layer_root() {
        let topic = domain("domains/messaging/topic.rs", "");
        let use_case = app("use_cases/messaging/topics/archive_topic.rs", "");
        let kernel = domain("shared/clock.rs", "");

        assert_eq!(context_of(&topic), "messaging");
        assert_eq!(context_of(&use_case), "messaging");
        assert_eq!(context_of(&kernel), "kernel");
    }

    #[test]
    fn trait_impls_outside_the_domain_are_collected() {
        let ws = workspace(vec![adapter(
            "ianua-infra",
            "postgres/topics.rs",
            "impl TopicStore for PgTopicStore { fn find(&self) {} }",
        )]);

        let found = trait_impls(&ws, &AppModel::build(&ws));

        assert_eq!(found[0].port, PortLookup::NotAPort);
        assert_eq!(found[0].self_type, "PgTopicStore");
        assert_eq!(found[0].methods, ["find"]);
    }

    /// Two contexts declare a `ReplayGuard`. The adapter imports the oauth
    /// one, so its `impl` is of that port, whatever the other declares.
    #[test]
    fn an_impl_is_joined_to_the_port_its_import_leads_to() {
        let ws = workspace(vec![
            app(
                "ports/oauth.rs",
                "pub trait ReplayGuard { fn first_use(&self); }",
            ),
            app(
                "ports/agents.rs",
                "pub trait ReplayGuard { fn consume(&self); }",
            ),
            adapter(
                "ianua-infra",
                "postgres/oauth.rs",
                "use ianua_app::ports::oauth::ReplayGuard;
                 impl ReplayGuard for PgReplayGuard { fn first_use(&self) {} }",
            ),
        ]);

        let found = trait_impls(&ws, &AppModel::build(&ws));

        assert_eq!(
            found[0].port.found().map(AppItem::path).as_deref(),
            Some("ports::oauth::ReplayGuard")
        );
    }
}
