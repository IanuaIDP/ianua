//! What the body reader looks names up in: the domain's creators and
//! changes, the types functions hand back, the port traits and `*Ports`
//! structs, and the app's modules.

use std::collections::{BTreeMap, BTreeSet};

use syn::{FnArg, Item, ItemImpl};

use super::body::{Local, PortRef, reaches_out as holds_ports};
use super::scope::{FnRef, functions_of};
use crate::model::Model;
use crate::model::app::{PortLookup, PortMethod, PortsField};
use crate::model::domain::BehaviourKind;
use crate::model::evaluate::{Evaluator, Index, Value};
use crate::model::paths::{AppItem, Modules};
use crate::model::raising::Raising;
use crate::source::syntax::{
    core_type, impl_fns, implemented_trait, items_of, names_in_type, returned_core, type_name,
};
use crate::source::usage::Usage;
use crate::source::{Layer, SourceFile, Workspace};

/// A function by its owner type and name.
type Owned = (String, String);

/// How many `*Ports` structs deep held ones are flattened.
const NESTING: usize = 2;

/// One field of a `*Ports` struct, nested ones flattened.
pub(super) struct HeldField {
    /// The field, as `outer.inner` when it sits in a held `*Ports` struct.
    pub(super) path: String,
    /// Its port trait, when its type names one.
    pub(super) port: PortLookup,
    /// Its type as written.
    pub(super) written: Option<String>,
}

/// The lookups the body reader needs.
pub(super) struct Known<'a> {
    /// The files.
    pub(super) workspace: &'a Workspace,
    /// The model the facts are joined through.
    pub(super) model: &'a Model,
    behaviours: BTreeMap<Owned, BehaviourKind>,
    change_owners: BTreeMap<String, Vec<String>>,
    returns: BTreeMap<Owned, Option<String>>,
    params: BTreeMap<Owned, Vec<String>>,
    port_methods: BTreeMap<AppItem, BTreeMap<String, &'a PortMethod>>,
    modules: Modules<'a>,
    app_structs: BTreeMap<String, Option<(AppItem, &'a SourceFile)>>,
    domain_types: BTreeSet<String>,
    app_aliases: BTreeMap<String, String>,
    domain_enums: BTreeSet<String>,
    domain_traits: BTreeSet<String>,
    enum_variants: BTreeMap<String, Option<BTreeSet<String>>>,
    app_trait_impls: BTreeMap<String, Option<String>>,
    app_methods: BTreeMap<Owned, Option<FnRef<'a>>>,
    domain: Index<'a>,
    proofs: BTreeSet<String>,
}

impl<'a> Known<'a> {
    /// The lookups for `workspace` as `model` reads it.
    pub(super) fn new(workspace: &'a Workspace, model: &'a Model) -> Self {
        let (returns, params) = signatures(workspace);
        Self {
            workspace,
            model,
            behaviours: (model.domain.behaviours.iter())
                .map(|found| ((found.owner.clone(), found.name.clone()), found.kind))
                .collect(),
            change_owners: change_owners(model),
            returns,
            params,
            port_methods: port_methods(model),
            modules: Modules::of(workspace),
            app_structs: app_structs(workspace),
            domain_types: domain_type_names(workspace),
            app_aliases: app_aliases(workspace),
            domain_enums: declared_in_domain(workspace, enum_name),
            domain_traits: declared_in_domain(workspace, trait_name),
            enum_variants: enum_variants(workspace),
            app_trait_impls: app_trait_impls(workspace),
            app_methods: app_methods(workspace),
            domain: Index::of(&workspace.layer(Layer::Domain).collect::<Vec<_>>()),
            proofs: (model.domain.proofs.iter())
                .flat_map(|proof| proof.carriers.iter().cloned())
                .collect(),
        }
    }

    /// What the domain's events are read through.
    pub(super) fn raising(&self) -> &'a Raising {
        &self.model.domain.raising
    }

    /// Whether `owner::name` is a creator or a change, if either.
    pub(super) fn behaviour(&self, owner: &str, name: &str) -> Option<BehaviourKind> {
        self.behaviours
            .get(&(owner.to_owned(), name.to_owned()))
            .copied()
    }

    /// The aggregates with a change named `name`.
    pub(super) fn change_owners(&self, name: &str) -> &[String] {
        self.change_owners.get(name).map_or(&[], Vec::as_slice)
    }

    /// The core type `owner::name` hands back, when one function of that
    /// name says so.
    pub(super) fn returns(&self, owner: &str, name: &str) -> Option<String> {
        self.returns
            .get(&(owner.to_owned(), name.to_owned()))
            .cloned()
            .flatten()
    }

    /// The caller proofs the domain function `owner::name` takes.
    pub(super) fn proofs_taken(&self, owner: &str, name: &str) -> Vec<String> {
        let taken = self
            .params
            .get(&(owner.to_owned(), name.to_owned()))
            .into_iter()
            .flatten()
            .filter(|ty| self.proofs.contains(*ty))
            .cloned()
            .collect::<BTreeSet<String>>();
        taken.into_iter().collect()
    }

    /// The port a type written in `file` names, read through its imports.
    pub(super) fn port_in_type(&self, file: &SourceFile, ty: &syn::Type) -> PortLookup {
        self.model.app.port_in_type(&self.modules, file, ty)
    }

    /// The core type the port method `port::method` hands back.
    pub(super) fn port_returns(&self, port: &AppItem, method: &str) -> Option<String> {
        self.port_methods.get(port)?.get(method)?.returns.clone()
    }

    /// The type of the items the port method `port::method` hands back,
    /// when it hands back a collection.
    pub(super) fn port_items(&self, port: &AppItem, method: &str) -> Option<String> {
        self.port_methods.get(port)?.get(method)?.items.clone()
    }

    /// Whether a parameter of the port method `port::method` is of the
    /// type named `type_name`.
    pub(super) fn port_takes(&self, port: &AppItem, method: &str, type_name: &str) -> bool {
        self.port_methods
            .get(port)
            .and_then(|methods| methods.get(method))
            .is_some_and(|found| found.param_types.iter().any(|name| name == type_name))
    }

    /// The fields of the `*Ports` struct `item`, those of a `*Ports` struct
    /// it holds flattened in as `outer.inner`.
    pub(super) fn ports_fields(&self, item: &AppItem) -> Vec<HeldField> {
        self.flattened(item, "", NESTING)
    }

    fn flattened(&self, item: &AppItem, prefix: &str, depth: usize) -> Vec<HeldField> {
        let Some(ports) = self.model.app.ports_struct(item) else {
            return Vec::new();
        };
        ports
            .fields
            .iter()
            .flat_map(|field| match self.ports_field(item, field, prefix) {
                Local::Ports {
                    item: inner,
                    prefix,
                } if depth > 0 => self.flattened(&inner, &prefix, depth - 1),
                Local::Holder { fields, .. } => {
                    fields.into_values().filter_map(held_port).collect()
                }
                _ => vec![HeldField {
                    port: field.port.clone(),
                    written: field.written.clone(),
                    path: format!("{prefix}{}", field.name),
                }],
            })
            .collect()
    }

    /// The method `name` an `impl` of the app type `item`, such as a
    /// `*Ports` struct, defines in the type's own file.
    pub(super) fn method_of(&self, item: &AppItem, name: &str) -> Option<FnRef<'a>> {
        let file = self.modules.file(&item.module)?;
        functions_of(file)
            .into_iter()
            .find(|function| {
                function.owner.as_deref() == Some(item.name.as_str()) && function.name == name
            })
            .or_else(|| self.app_method(&item.name, name))
    }

    /// The function `name` of the app type `owner`, written in any app
    /// file, when exactly one is.
    pub(super) fn app_method(&self, owner: &str, name: &str) -> Option<FnRef<'a>> {
        self.app_methods
            .get(&(owner.to_owned(), name.to_owned()))?
            .clone()
    }

    /// The app struct named `name`, when the app declares exactly one and
    /// one of its fields holds a port, a `*Ports` struct or the auditor;
    /// with what its fields hold.
    pub(super) fn holding_type(&self, name: &str) -> Option<(AppItem, BTreeMap<String, Local>)> {
        self.app_type(name)
            .filter(|(_, fields)| fields.values().any(holds_ports))
    }

    /// The app struct named `name`, or the one an app type alias of that
    /// name stands for, when the app declares exactly one; with what its
    /// fields hold.
    pub(super) fn app_type(&self, name: &str) -> Option<(AppItem, BTreeMap<String, Local>)> {
        let (item, file) = self.app_struct(name)?;
        let fields = self.fields_of_struct(file, item, None);
        Some((item.clone(), fields))
    }

    /// Whether the reader knows what a value of type `name` is: one the
    /// domain declares, or exactly one app struct.
    pub(super) fn knows_type(&self, name: &str) -> bool {
        self.domain_types.contains(name) || self.app_struct(name).is_some()
    }

    /// The app struct named `name`, through an app type alias of that name
    /// when there is one.
    fn app_struct(&self, name: &str) -> Option<&(AppItem, &'a SourceFile)> {
        let aliased = self.app_aliases.get(name).map(String::as_str);
        self.app_structs.get(aliased.unwrap_or(name))?.as_ref()
    }

    /// What the field `field` of the `*Ports` struct `item`, held at
    /// `prefix`, holds: a nested `*Ports` struct, an app struct holding
    /// ports, or a port.
    pub(super) fn ports_field_local(
        &self,
        item: &AppItem,
        field: &str,
        prefix: &str,
    ) -> Option<Local> {
        let ports = self.model.app.ports_struct(item)?;
        let found = ports.fields.iter().find(|found| found.name == field)?;
        Some(self.ports_field(item, found, prefix))
    }

    fn ports_field(&self, item: &AppItem, field: &PortsField, prefix: &str) -> Local {
        let path = format!("{prefix}{}", field.name);
        if let Some(inner) = self.nested(item, field) {
            return Local::Ports {
                item: inner,
                prefix: format!("{path}."),
            };
        }
        if field.port != PortLookup::NotAPort {
            return Local::Port(PortRef::held(Some(path), &field.port));
        }
        if let Some(holder) = self.held_struct(field, &path) {
            return holder;
        }
        let implemented = field
            .type_names
            .iter()
            .find_map(|name| self.app_trait_impls.get(name).cloned().flatten());
        let domain_trait = field
            .type_names
            .iter()
            .find(|name| self.domain_traits.contains(*name))
            .cloned();
        match implemented.or(domain_trait) {
            Some(name) => Local::Type(name),
            None => Local::Port(PortRef::held(Some(path), &field.port)),
        }
    }

    /// The app struct holding ports that `field` holds, with its own
    /// ports named below `path`.
    fn held_struct(&self, field: &PortsField, path: &str) -> Option<Local> {
        field.type_names.iter().find_map(|name| {
            let (item, file) = self.app_struct(name)?;
            let fields = self.fields_of_struct(file, item, Some(&format!("{path}.")));
            fields.values().any(holds_ports).then(|| Local::Holder {
                item: Some(item.clone()),
                type_name: name.clone(),
                fields,
            })
        })
    }

    /// What each field of the struct `item`, declared in `file`, holds: a
    /// port by its trait, named below `prefix` when one is given, a
    /// `*Ports` struct, or a value of its type.
    fn fields_of_struct(
        &self,
        file: &SourceFile,
        item: &AppItem,
        prefix: Option<&str>,
    ) -> BTreeMap<String, Local> {
        let declared = file.syntax().and_then(|syntax| {
            items_of(syntax).into_iter().find_map(|found| match found {
                Item::Struct(declared) if declared.ident == item.name => Some(declared),
                _ => None,
            })
        });
        declared
            .into_iter()
            .flat_map(|declared| declared.fields.iter().enumerate())
            .filter_map(|(position, field)| {
                let name = field
                    .ident
                    .as_ref()
                    .map_or_else(|| position.to_string(), ToString::to_string);
                let path = prefix.map(|prefix| format!("{prefix}{name}"));
                Some((name, self.field_held(file, &field.ty, path)?))
            })
            .collect()
    }

    fn field_held(&self, file: &SourceFile, ty: &syn::Type, path: Option<String>) -> Option<Local> {
        let lookup = self.port_in_type(file, ty);
        if lookup != PortLookup::NotAPort {
            return Some(Local::Port(PortRef::held(path, &lookup)));
        }
        let names = names_in_type(ty);
        if let Some(ports) = names.iter().find_map(|name| self.ports_item(file, name)) {
            return Some(Local::Ports {
                item: ports,
                prefix: String::new(),
            });
        }
        core_type(ty, None)
            .map(Local::Type)
            .or_else(|| self.trait_object(ty))
    }

    /// What `self` holds inside a method of the `*Ports` struct `item`,
    /// held at `prefix` in the use case's own: its ports and the `*Ports`
    /// structs nested in it.
    pub(super) fn fields_of_ports(&self, item: &AppItem, prefix: &str) -> BTreeMap<String, Local> {
        let Some(ports) = self.model.app.ports_struct(item) else {
            return BTreeMap::new();
        };
        ports
            .fields
            .iter()
            .map(|field| (field.name.clone(), self.ports_field(item, field, prefix)))
            .collect()
    }

    /// The `*Ports` struct `field` of the `*Ports` struct `item` holds.
    fn nested(&self, item: &AppItem, field: &PortsField) -> Option<AppItem> {
        let file = self.modules.file(&item.module)?;
        field
            .type_names
            .iter()
            .find_map(|name| self.ports_item(file, name))
    }

    /// The `*Ports` struct `name`, written in `file`, stands for.
    pub(super) fn ports_item(&self, file: &SourceFile, name: &str) -> Option<AppItem> {
        self.model
            .app
            .ports_struct_written(&self.modules, file, &[name.to_owned()])
            .map(|found| found.item.clone())
    }

    /// Whether the domain declares an enum named `name`.
    pub(super) fn is_domain_enum(&self, name: &str) -> bool {
        self.domain_enums.contains(name)
    }

    /// The variants of the enum named `name`, when the domain or the app
    /// declares exactly one.
    pub(super) fn enum_variants(&self, name: &str) -> Option<&BTreeSet<String>> {
        self.enum_variants.get(name)?.as_ref()
    }

    /// The variants of the domain's enum `name` for which its method
    /// `method`, taking nothing else, answers `true`, when it is worked out
    /// for every one (see [`crate::model::evaluate`]).
    pub(super) fn answers_true(&self, name: &str, method: &str) -> Option<BTreeSet<String>> {
        let body = self.domain.method(name, method)?;
        let info = self.domain.enum_named(name)?;
        let evaluator = Evaluator::new(&self.domain);
        let mut holds = BTreeSet::new();
        for variant in &info.variants {
            let answer =
                evaluator.run(body, Some(Value::variant(name, &variant.name)), Vec::new())?;
            match answer.value {
                Value::Bool(true) => {
                    holds.insert(variant.name.clone());
                }
                Value::Bool(false) => {}
                _ => return None,
            }
        }
        Some(holds)
    }

    /// The domain trait `ty` names, such as `PasswordHasher` for `&dyn
    /// PasswordHasher`: an adapter implements it, and a call on it reaches
    /// none of the app's ports.
    pub(super) fn domain_trait_in(&self, ty: &syn::Type) -> Option<String> {
        names_in_type(ty)
            .into_iter()
            .find(|name| self.domain_traits.contains(name))
    }

    /// The one app type implementing the app trait `ty` names, such as the
    /// service behind `&dyn FreshProofs`, when the app has exactly one.
    pub(super) fn app_trait_impl(&self, ty: &syn::Type) -> Option<String> {
        names_in_type(ty)
            .into_iter()
            .find_map(|name| self.app_trait_impls.get(&name).cloned().flatten())
    }

    /// What a value of `ty` is, when its type is a domain trait or an app
    /// trait with one implementation.
    pub(super) fn trait_object(&self, ty: &syn::Type) -> Option<Local> {
        self.app_trait_impl(ty)
            .or_else(|| self.domain_trait_in(ty))
            .map(Local::Type)
    }

    /// The app's files by module, to follow imports with.
    pub(super) fn modules(&self) -> &Modules<'a> {
        &self.modules
    }

    /// The type `written` stands for in a file with `usage`: what the file
    /// imported it as, then what a domain alias stands for.
    pub(super) fn owner_named(&self, written: &str, usage: &Usage) -> String {
        let imported = usage.unaliased(written);
        self.model
            .domain
            .aliases
            .get(imported)
            .cloned()
            .unwrap_or_else(|| imported.to_owned())
    }
}

/// The port a field of an app struct holding ports holds, named by its
/// path, if it holds one.
fn held_port(local: Local) -> Option<HeldField> {
    let Local::Port(port) = local else {
        return None;
    };
    Some(HeldField {
        port: port.lookup(),
        path: port.field?,
        written: None,
    })
}

/// Every struct the app declares, by name; `None` for a name declared more
/// than once, or one the domain declares too, since a value of that name
/// may be either.
fn app_structs(workspace: &Workspace) -> BTreeMap<String, Option<(AppItem, &SourceFile)>> {
    let mut found: BTreeMap<String, Option<(AppItem, &SourceFile)>> = domain_type_names(workspace)
        .into_iter()
        .map(|name| (name, None))
        .collect();
    for file in workspace.layer(Layer::App) {
        let Some(syntax) = file.syntax() else {
            continue;
        };
        for item in items_of(syntax) {
            let Item::Struct(declared) = item else {
                continue;
            };
            let name = declared.ident.to_string();
            let entry = Some((AppItem::in_file(file, &name), file));
            found
                .entry(name)
                .and_modify(|seen| *seen = None)
                .or_insert(entry);
        }
    }
    found
}

/// The name of every struct and enum the domain declares.
fn domain_type_names(workspace: &Workspace) -> BTreeSet<String> {
    workspace
        .layer(Layer::Domain)
        .filter_map(SourceFile::syntax)
        .flat_map(items_of)
        .filter_map(|item| match item {
            Item::Struct(declared) => Some(declared.ident.to_string()),
            Item::Enum(declared) => Some(declared.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// Every app `type Name = Type<..>;`, as the name and the type's last name,
/// such as `SetupSteps` for `StepJobs<SetupStep>`.
fn app_aliases(workspace: &Workspace) -> BTreeMap<String, String> {
    workspace
        .layer(Layer::App)
        .filter_map(SourceFile::syntax)
        .flat_map(items_of)
        .filter_map(|item| match item {
            Item::Type(alias) => Some((alias.ident.to_string(), type_name(&alias.ty)?)),
            _ => None,
        })
        .collect()
}

/// Every function of an app type, by its owner and name; `None` for one two
/// types of that name, or two `impl`s, define.
fn app_methods(workspace: &Workspace) -> BTreeMap<Owned, Option<FnRef<'_>>> {
    let mut found: BTreeMap<Owned, Option<FnRef<'_>>> = BTreeMap::new();
    for function in workspace.layer(Layer::App).flat_map(functions_of) {
        let Some(owner) = function.owner.clone() else {
            continue;
        };
        found
            .entry((owner, function.name.clone()))
            .and_modify(|seen| *seen = None)
            .or_insert(Some(function));
    }
    found
}

/// The name `item` declares, when it is an enum.
fn enum_name(item: &Item) -> Option<String> {
    match item {
        Item::Enum(declared) => Some(declared.ident.to_string()),
        _ => None,
    }
}

/// The name `item` declares, when it is a trait.
fn trait_name(item: &Item) -> Option<String> {
    match item {
        Item::Trait(declared) => Some(declared.ident.to_string()),
        _ => None,
    }
}

/// Every trait the app declares and implements outside its tests, with the
/// one type implementing it; `None` for a trait two app types implement.
fn app_trait_impls(workspace: &Workspace) -> BTreeMap<String, Option<String>> {
    let declared: BTreeSet<String> = (workspace.layer(Layer::App))
        .filter_map(SourceFile::syntax)
        .flat_map(items_of)
        .filter_map(trait_name)
        .collect();
    let mut found: BTreeMap<String, Option<String>> = BTreeMap::new();
    for block in impls_in(workspace.layer(Layer::App)) {
        let (Some(trait_name), Some(implementing)) =
            (implemented_trait(block), type_name(&block.self_ty))
        else {
            continue;
        };
        if declared.contains(&trait_name) {
            keep_if_alike(&mut found, trait_name, Some(implementing));
        }
    }
    found
}

/// The `impl` blocks of `files`.
fn impls_in<'w>(files: impl Iterator<Item = &'w SourceFile>) -> impl Iterator<Item = &'w ItemImpl> {
    files
        .filter_map(SourceFile::syntax)
        .flat_map(items_of)
        .filter_map(|item| match item {
            Item::Impl(block) => Some(block),
            _ => None,
        })
}

/// Notes `value` for `key` in `kept`: kept while every value noted for
/// `key` is the same, `None` once two differ.
fn keep_if_alike<K: Ord, V: PartialEq>(
    kept: &mut BTreeMap<K, Option<V>>,
    key: K,
    value: Option<V>,
) {
    kept.entry(key)
        .and_modify(|seen| {
            if *seen != value {
                *seen = None;
            }
        })
        .or_insert(value);
}

/// The variants of every public enum of the domain and the app, by name;
/// `None` for a name declared more than once.
fn enum_variants(workspace: &Workspace) -> BTreeMap<String, Option<BTreeSet<String>>> {
    let mut found: BTreeMap<String, Option<BTreeSet<String>>> = BTreeMap::new();
    let declared = workspace
        .files
        .iter()
        .filter(|file| file.layer != Layer::Adapter)
        .filter_map(SourceFile::syntax)
        .flat_map(items_of)
        .filter_map(|item| match item {
            Item::Enum(declared) if !matches!(declared.vis, syn::Visibility::Inherited) => {
                Some(declared)
            }
            _ => None,
        });
    for declared in declared {
        let variants = declared
            .variants
            .iter()
            .map(|variant| variant.ident.to_string())
            .collect();
        found
            .entry(declared.ident.to_string())
            .and_modify(|seen| *seen = None)
            .or_insert(Some(variants));
    }
    found
}

/// The name of every item of the domain `named` picks.
fn declared_in_domain(
    workspace: &Workspace,
    named: impl Fn(&Item) -> Option<String>,
) -> BTreeSet<String> {
    workspace
        .layer(Layer::Domain)
        .filter_map(SourceFile::syntax)
        .flat_map(items_of)
        .filter_map(named)
        .collect()
}

fn change_owners(model: &Model) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for behaviour in model
        .domain
        .behaviours
        .iter()
        .filter(|behaviour| behaviour.kind == BehaviourKind::Change)
    {
        found
            .entry(behaviour.name.clone())
            .or_default()
            .push(behaviour.owner.clone());
    }
    found
}

fn port_methods(model: &Model) -> BTreeMap<AppItem, BTreeMap<String, &PortMethod>> {
    model
        .app
        .ports
        .iter()
        .map(|port| {
            let methods = port
                .methods
                .iter()
                .map(|method| (method.name.clone(), method))
                .collect();
            (port.item.clone(), methods)
        })
        .collect()
}

/// Every domain and app `impl` function's core return type and parameter
/// type names, by owner and name. Two functions of one name on one type
/// that hand back different types leave it unread.
fn signatures(
    workspace: &Workspace,
) -> (
    BTreeMap<Owned, Option<String>>,
    BTreeMap<Owned, Vec<String>>,
) {
    let mut returns: BTreeMap<Owned, Option<String>> = BTreeMap::new();
    let mut params: BTreeMap<Owned, Vec<String>> = BTreeMap::new();
    let read = (workspace.files.iter()).filter(|file| file.layer != Layer::Adapter);
    for block in impls_in(read) {
        let Some(owner) = type_name(&block.self_ty) else {
            continue;
        };
        for function in impl_fns(block) {
            let key = (owner.clone(), function.sig.ident.to_string());
            let core = returned_core(&function.sig.output, Some(&owner));
            keep_if_alike(&mut returns, key.clone(), core);
            let types = param_types(&function.sig);
            params.entry(key).or_default().extend(types);
        }
    }
    (returns, params)
}

/// The names the parameters' types mention, a generic parameter read as
/// the traits it is bound to, so `by: &P` with `P: Founding` takes a
/// `Founding`.
fn param_types(signature: &syn::Signature) -> Vec<String> {
    let bounds = generic_bounds(&signature.generics);
    signature
        .inputs
        .iter()
        .filter_map(|input| match input {
            FnArg::Typed(typed) => Some(names_in_type(&typed.ty)),
            FnArg::Receiver(_) => None,
        })
        .flatten()
        .flat_map(|name| {
            let bound = bounds.get(&name).cloned().unwrap_or_default();
            std::iter::once(name).chain(bound)
        })
        .collect()
}

/// Each generic type parameter with the names its bounds mention, in the
/// parameter list and the `where` clause.
fn generic_bounds(generics: &syn::Generics) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for param in generics.type_params() {
        found
            .entry(param.ident.to_string())
            .or_default()
            .extend(param.bounds.iter().flat_map(bound_names));
    }
    let predicates = generics
        .where_clause
        .iter()
        .flat_map(|clause| clause.predicates.iter());
    for predicate in predicates {
        let syn::WherePredicate::Type(typed) = predicate else {
            continue;
        };
        let Some(name) = crate::source::syntax::type_name(&typed.bounded_ty) else {
            continue;
        };
        found
            .entry(name)
            .or_default()
            .extend(typed.bounds.iter().flat_map(bound_names));
    }
    found
}

fn bound_names(bound: &syn::TypeParamBound) -> Vec<String> {
    match bound {
        syn::TypeParamBound::Trait(found) => found
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
        _ => Vec::new(),
    }
}
