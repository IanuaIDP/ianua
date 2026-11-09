//! The domain's parts the checks look at: aggregates and operation values
//! and what they offer, events, their types and what raises them,
//! `ensure_*` rules, caller proofs, rights and data classes.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens as _;
use syn::visit::Visit;
use syn::{Fields, ImplItemFn, Item, ItemImpl, ReturnType};

use crate::model::context_of;
use crate::model::machines::Machines;
use crate::model::raising::Raising;
use crate::source::syntax::{
    for_tests_only, impl_fns, implemented_trait, inherent_impl_of, is_public, items_of, line_of,
    type_mentions, type_name,
};
use crate::source::{Layer, Place, SourceFile, Workspace};

/// Where data classes are declared.
pub(crate) const DATA_CLASS: &str = "DataClassLevel";

/// The enum whose variants are the rights a role can grant.
const SYSTEM_PERMISSION: &str = "SystemPermission";

/// The enum that wraps each context's event type enum.
const EVENT_TYPE: &str = "EventType";

/// Type names ending in these carry a data class to or from somewhere
/// else, so they need not compare it themselves.
const CARRIER_SUFFIXES: &[&str] = &[
    "Row", "Params", "Input", "Request", "Draft", "Changes", "Update", "Config", "Spec", "View",
];

/// A stored type, which implements `Aggregate` or rebuilds from a row, or
/// an operation value that raises its own events (`Raises`,
/// `RaisesComplete`), such as `DirectoryBindAttempt`.
#[derive(Clone, Debug)]
pub(crate) struct Aggregate {
    /// Its name.
    pub(crate) name: String,
    /// The context it is in.
    pub(crate) context: String,
    /// Where it is declared.
    pub(crate) place: Place,
    /// Whether storage keeps it: it implements `Aggregate` or rebuilds
    /// from a row. An operation value is not kept.
    pub(crate) stored: bool,
}

/// Whether a behaviour makes a new value or changes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BehaviourKind {
    /// It returns a new value of the type.
    Create,
    /// It takes `&mut self`.
    Change,
}

impl BehaviourKind {
    /// The name reports use.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Change => "change",
        }
    }
}

/// A public creator or change of an aggregate.
#[derive(Clone, Debug)]
pub(crate) struct Behaviour {
    /// The aggregate.
    pub(crate) owner: String,
    /// The function's name.
    pub(crate) name: String,
    /// What it does to the aggregate.
    pub(crate) kind: BehaviourKind,
    /// Where it is declared.
    pub(crate) place: Place,
}

impl Behaviour {
    /// `Owner::name`.
    pub(crate) fn subject(&self) -> String {
        format!("{}::{}", self.owner, self.name)
    }
}

/// A domain event struct.
#[derive(Clone, Debug)]
pub(crate) struct Event {
    /// The struct's name.
    pub(crate) name: String,
    /// The context it is in.
    pub(crate) context: String,
    /// The event type it is recorded under, as `(enum, variant)`, when the
    /// declaration names it.
    pub(crate) event_type: Option<(String, String)>,
    /// Where it is declared.
    pub(crate) place: Place,
}

/// One variant of a context's event type enum.
#[derive(Clone, Debug)]
pub(crate) struct EventType {
    /// The enum, such as `MessagingEvent`.
    pub(crate) enum_name: String,
    /// The variant, such as `TopicCreated`.
    pub(crate) variant: String,
    /// The dotted string it is published under.
    pub(crate) text: String,
    /// Where it is listed.
    pub(crate) place: Place,
}

/// A public function whose name starts with `ensure_`.
#[derive(Clone, Debug)]
pub(crate) struct EnsureRule {
    /// The type whose `impl` it is in, if any.
    pub(crate) owner: Option<String>,
    /// Its name.
    pub(crate) name: String,
    /// Where it is declared.
    pub(crate) place: Place,
}

impl EnsureRule {
    /// `Owner::name`, or the bare name of a free function.
    pub(crate) fn subject(&self) -> String {
        self.owner.as_ref().map_or_else(
            || self.name.clone(),
            |owner| format!("{owner}::{}", self.name),
        )
    }
}

/// A caller proof: a type that says who is asking and what they hold.
#[derive(Clone, Debug)]
pub(crate) struct Proof {
    /// Its name.
    pub(crate) name: String,
    /// Where it is declared, when the domain declares it.
    pub(crate) place: Option<Place>,
    /// The types that carry it: itself, and when it is a trait, every
    /// domain type implementing it.
    pub(crate) carriers: Vec<String>,
    /// The public domain functions that hand out a carrier, as `(owner,
    /// name)`, the owner `None` for a free function. The app passes such a
    /// value on without ever writing its type.
    pub(crate) makers: Vec<Maker>,
}

/// A public domain function, by its owner and name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Maker {
    /// The type whose `impl` defines it, or `None` for a free function.
    pub(crate) owner: Option<String>,
    /// Its name.
    pub(crate) name: String,
}

/// One right a role can grant: a `SystemPermission` variant, with the
/// action of its action enum when it has one.
#[derive(Clone, Debug)]
pub(crate) struct Permission {
    /// The `SystemPermission` variant.
    pub(crate) variant: String,
    /// The action enum and variant, such as `("MessagingAction", "Delete")`.
    pub(crate) action: Option<(String, String)>,
    /// Where the right is declared.
    pub(crate) place: Place,
}

impl Permission {
    /// How the right reads, such as `Messaging(MessagingAction::Delete)`.
    pub(crate) fn subject(&self) -> String {
        match &self.action {
            Some((enum_name, action)) => format!("{}({enum_name}::{action})", self.variant),
            None => self.variant.clone(),
        }
    }
}

/// A field that holds a data class.
#[derive(Clone, Debug)]
pub(crate) struct DataClassField {
    /// The struct.
    pub(crate) owner: String,
    /// The field.
    pub(crate) field: String,
    /// Where it is declared.
    pub(crate) place: Place,
}

/// The domain's parts.
#[derive(Debug, Default)]
pub(crate) struct DomainModel {
    /// Stored types and operation values that raise events.
    pub(crate) aggregates: Vec<Aggregate>,
    /// Their public creators and changes.
    pub(crate) behaviours: Vec<Behaviour>,
    /// Event structs.
    pub(crate) events: Vec<Event>,
    /// Event type variants.
    pub(crate) event_types: Vec<EventType>,
    /// Event types left out of colleagues' notifications, as `(enum, variant)`.
    pub(crate) quiet_event_types: BTreeSet<(String, String)>,
    /// The context enum each `EventType` variant wraps, such as `Agents`
    /// to `AgentsEvent`.
    pub(crate) event_type_wrappers: BTreeMap<String, String>,
    /// Context enums `EventType::is_notifiable` leaves out whole.
    pub(crate) quiet_enums: BTreeSet<String>,
    /// Public `ensure_*` rules.
    pub(crate) ensure_rules: Vec<EnsureRule>,
    /// Caller proofs.
    pub(crate) proofs: Vec<Proof>,
    /// Public type aliases, by alias, each naming the type it stands for,
    /// such as `OrgVerificationToken` for `OrgToken`.
    pub(crate) aliases: BTreeMap<String, String>,
    /// Rights a role can grant.
    pub(crate) permissions: Vec<Permission>,
    /// Fields that hold a data class.
    pub(crate) data_class_fields: Vec<DataClassField>,
    /// Which functions raise each event.
    pub(crate) raising: Raising,
    /// The status machines, and the state enums mapped onto them.
    pub(crate) machines: Machines,
    /// The creators and changes the conventions list as nobody's, as
    /// `(type, function)`.
    pub(crate) uncalled: BTreeSet<(String, String)>,
}

impl DomainModel {
    /// Reads the domain files of `workspace`, with what the domain's
    /// conventions list.
    pub(crate) fn build(workspace: &Workspace, lists: &DomainLists) -> Self {
        let files: Vec<&SourceFile> = workspace.layer(Layer::Domain).collect();
        let aggregates = aggregates(&files);
        let behaviours = behaviours(&files, &aggregates);
        let event_types: Vec<EventType> = files.iter().flat_map(|f| event_types(f)).collect();
        let events = events(&files, &event_types);
        let event_names: BTreeSet<&str> = events.iter().map(|event| event.name.as_str()).collect();
        let event_type_wrappers = event_type_wrappers(&files);
        Self {
            machines: Machines::read(&files),
            uncalled: lists.uncalled.iter().cloned().collect(),
            raising: Raising::read(&files, &event_names, &lists.observations),
            quiet_event_types: quiet_event_types(&files),
            quiet_enums: quiet_enums(&files, &event_type_wrappers),
            event_type_wrappers,
            ensure_rules: files.iter().flat_map(|file| ensure_rules(file)).collect(),
            proofs: proofs(&files, &lists.proofs),
            aliases: aliases(&files),
            permissions: permissions(&files),
            data_class_fields: data_class_fields(&files, &event_names),
            aggregates,
            behaviours,
            event_types,
            events,
        }
    }
}

fn impls_of(file: &SourceFile) -> Vec<&ItemImpl> {
    let Some(syntax) = file.syntax() else {
        return Vec::new();
    };
    items_of(syntax)
        .into_iter()
        .filter_map(|item| match item {
            Item::Impl(block) => Some(block),
            _ => None,
        })
        .collect()
}

/// The traits whose implementors raise their own events: an aggregate
/// that does not hold its tenant, and one that knows its scope.
const RAISING_TRAITS: &[&str] = &["Raises", "RaisesComplete"];

fn aggregates(files: &[&SourceFile]) -> Vec<Aggregate> {
    let mut found: BTreeMap<String, Aggregate> = BTreeMap::new();
    for file in files {
        for block in impls_of(file) {
            let implemented = implemented_trait(block);
            let stored = implemented.as_deref() == Some("Aggregate") || rebuilds_from_a_row(block);
            let raises = implemented.is_some_and(|name| RAISING_TRAITS.contains(&name.as_str()));
            let Some(name) = type_name(&block.self_ty).filter(|_| stored || raises) else {
                continue;
            };
            found
                .entry(name.clone())
                .or_insert_with(|| Aggregate {
                    place: declaration(file, &name)
                        .unwrap_or_else(|| Place::of(file, &block.self_ty)),
                    context: context_of(file),
                    name,
                    stored: false,
                })
                .stored |= stored;
        }
    }
    found.into_values().collect()
}

fn rebuilds_from_a_row(block: &ItemImpl) -> bool {
    block.trait_.is_none() && impl_fns(block).any(|function| function.sig.ident == "reconstitute")
}

/// Where `file` declares a struct, enum or trait named `name`.
fn declaration(file: &SourceFile, name: &str) -> Option<Place> {
    items_of(file.syntax()?)
        .into_iter()
        .find_map(|item| match item {
            Item::Struct(declared) if declared.ident == name => {
                Some(Place::of(file, &declared.ident))
            }
            Item::Enum(declared) if declared.ident == name => {
                Some(Place::of(file, &declared.ident))
            }
            Item::Trait(declared) if declared.ident == name => {
                Some(Place::of(file, &declared.ident))
            }
            _ => None,
        })
}

fn behaviours(files: &[&SourceFile], aggregates: &[Aggregate]) -> Vec<Behaviour> {
    let stored: BTreeSet<&str> = aggregates.iter().map(|found| found.name.as_str()).collect();
    let mut found = Vec::new();
    for file in files {
        for block in impls_of(file) {
            let Some(owner) = inherent_impl_of(block).filter(|name| stored.contains(name.as_str()))
            else {
                continue;
            };
            found.extend(
                impl_fns(block)
                    .filter(|function| is_public(&function.vis) && !for_tests_only(&function.attrs))
                    .filter_map(|function| {
                        Some(Behaviour {
                            kind: kind_of(function, &owner)?,
                            owner: owner.clone(),
                            name: function.sig.ident.to_string(),
                            place: Place::of(file, &function.sig.ident),
                        })
                    }),
            );
        }
    }
    found
}

/// Whether `function` creates a value of `owner`, changes one, or neither.
/// Rebuilding from a row is neither: storage makes it, not a caller.
fn kind_of(function: &ImplItemFn, owner: &str) -> Option<BehaviourKind> {
    let receiver = function.sig.inputs.iter().find_map(|input| match input {
        syn::FnArg::Receiver(receiver) => Some(receiver),
        syn::FnArg::Typed(_) => None,
    });
    if let Some(receiver) = receiver {
        let changes = receiver.reference.is_some() && receiver.mutability.is_some();
        return changes.then_some(BehaviourKind::Change);
    }
    let makes = match &function.sig.output {
        ReturnType::Type(_, ty) => type_mentions(ty, "Self") || type_mentions(ty, owner),
        ReturnType::Default => false,
    };
    (makes && function.sig.ident != "reconstitute").then_some(BehaviourKind::Create)
}

/// The variants an `event_types!` invocation in `file` lists.
fn event_types(file: &SourceFile) -> Vec<EventType> {
    let Some(syntax) = file.syntax() else {
        return Vec::new();
    };
    items_of(syntax)
        .into_iter()
        .filter_map(|item| match item {
            Item::Macro(invocation) if invocation.mac.path.is_ident("event_types") => {
                Some(&invocation.mac.tokens)
            }
            _ => None,
        })
        .flat_map(|tokens| listed_event_types(file, tokens.clone()))
        .collect()
}

/// `pub enum Name { Variant => "text", .. }` read from macro tokens.
fn listed_event_types(file: &SourceFile, tokens: TokenStream) -> Vec<EventType> {
    let Some((enum_name, body)) = braced_enum(tokens) else {
        return Vec::new();
    };
    let inner: Vec<TokenTree> = body.into_iter().collect();
    inner
        .windows(4)
        .filter_map(|window| {
            let [
                TokenTree::Ident(variant),
                TokenTree::Punct(eq),
                TokenTree::Punct(gt),
                TokenTree::Literal(text),
            ] = window
            else {
                return None;
            };
            let arrow = eq.as_char() == '=' && gt.as_char() == '>';
            let text = syn::parse_str::<syn::LitStr>(&text.to_string()).ok()?;
            arrow.then(|| EventType {
                enum_name: enum_name.clone(),
                variant: variant.to_string(),
                text: text.value(),
                place: Place::at(file, variant.span().start().line),
            })
        })
        .collect()
}

/// The name and the braced body of the first `enum Name { .. }` in
/// `tokens`.
fn braced_enum(tokens: TokenStream) -> Option<(String, TokenStream)> {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let enum_at =
        (trees.iter()).position(|tree| matches!(tree, TokenTree::Ident(word) if word == "enum"))?;
    let (Some(TokenTree::Ident(enum_name)), Some(TokenTree::Group(body))) =
        (trees.get(enum_at + 1), trees.get(enum_at + 2))
    else {
        return None;
    };
    (body.delimiter() == Delimiter::Brace).then(|| (enum_name.to_string(), body.stream()))
}

/// The event types each context's `is_notifiable` leaves out, in a file
/// that lists that context's events: the `Self::Variant`s of
/// `!matches!(self, ..)`, or of the arms of a `match self` that answer
/// `false`. A body of another shape leaves out every variant it names.
fn quiet_event_types(files: &[&SourceFile]) -> BTreeSet<(String, String)> {
    let mut quiet = BTreeSet::new();
    for file in files {
        let enums: Vec<String> = event_types(file)
            .into_iter()
            .map(|listed| listed.enum_name)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let [enum_name] = enums.as_slice() else {
            continue;
        };
        let Some(syntax) = file.syntax() else {
            continue;
        };
        let left_out = items_of(syntax)
            .into_iter()
            .filter_map(|item| match item {
                Item::Impl(block) => Some(block),
                _ => None,
            })
            .flat_map(impl_fns)
            .filter(|function| function.sig.ident == "is_notifiable")
            .flat_map(left_out_by);
        quiet.extend(left_out.map(|variant| (enum_name.clone(), variant)));
    }
    quiet
}

/// The variants `function`, an `is_notifiable`, answers `false` for.
fn left_out_by(function: &ImplItemFn) -> Vec<String> {
    let Some(syn::Stmt::Expr(answer, None)) = function.block.stmts.last() else {
        return self_variants(function.block.to_token_stream());
    };
    match answer {
        syn::Expr::Unary(syn::ExprUnary {
            op: syn::UnOp::Not(_),
            expr,
            ..
        }) => self_variants(expr.to_token_stream()),
        syn::Expr::Match(choice) => choice
            .arms
            .iter()
            .filter(|arm| answers_false(&arm.body))
            .flat_map(|arm| self_variants(arm.pat.to_token_stream()))
            .collect(),
        other => self_variants(other.to_token_stream()),
    }
}

/// Whether `body` is the literal `false`.
fn answers_false(body: &syn::Expr) -> bool {
    matches!(
        body,
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Bool(answer),
            ..
        }) if !answer.value
    )
}

/// Every `Variant` written as `Self::Variant` in `tokens`.
fn self_variants(tokens: TokenStream) -> Vec<String> {
    let flat: Vec<TokenTree> = flattened(tokens);
    flat.windows(4)
        .filter_map(|window| match window {
            [
                TokenTree::Ident(owner),
                TokenTree::Punct(first),
                TokenTree::Punct(second),
                TokenTree::Ident(name),
            ] if owner == "Self" && first.as_char() == ':' && second.as_char() == ':' => {
                Some(name.to_string())
            }
            _ => None,
        })
        .collect()
}

/// `tokens` with every group opened, in order.
fn flattened(tokens: TokenStream) -> Vec<TokenTree> {
    tokens
        .into_iter()
        .flat_map(|tree| match tree {
            TokenTree::Group(group) => flattened(group.stream()),
            other => vec![other],
        })
        .collect()
}

/// The context enum each variant of `EventType` wraps.
fn event_type_wrappers(files: &[&SourceFile]) -> BTreeMap<String, String> {
    let enums = enums_by_name(files);
    let Some((_, event_type)) = enums.get(EVENT_TYPE) else {
        return BTreeMap::new();
    };
    event_type
        .variants
        .iter()
        .filter_map(|variant| match &variant.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                Some((variant.ident.to_string(), type_name(&fields.unnamed[0].ty)?))
            }
            _ => None,
        })
        .collect()
}

/// The context enums whose arm in `EventType::is_notifiable` is `false`.
fn quiet_enums(files: &[&SourceFile], wrappers: &BTreeMap<String, String>) -> BTreeSet<String> {
    let mut quiet = BTreeSet::new();
    for file in files {
        for block in impls_of(file) {
            if inherent_impl_of(block).as_deref() != Some(EVENT_TYPE) {
                continue;
            }
            let Some(function) =
                impl_fns(block).find(|function| function.sig.ident == "is_notifiable")
            else {
                continue;
            };
            let mut arms = FalseArms::default();
            arms.visit_block(&function.block);
            quiet.extend(
                arms.variants
                    .iter()
                    .filter_map(|variant| wrappers.get(variant).cloned()),
            );
        }
    }
    quiet
}

/// The variants named in the patterns of match arms whose body is `false`.
#[derive(Default)]
struct FalseArms {
    variants: Vec<String>,
}

impl<'ast> Visit<'ast> for FalseArms {
    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        let is_false = matches!(
            arm.body.as_ref(),
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Bool(value), .. }) if !value.value
        );
        if is_false {
            self.variants.extend(pattern_variants(&arm.pat));
        }
        syn::visit::visit_arm(self, arm);
    }
}

fn pattern_variants(pattern: &syn::Pat) -> Vec<String> {
    let last = |path: &syn::Path| {
        path.segments
            .last()
            .map(|segment| segment.ident.to_string())
    };
    match pattern {
        syn::Pat::TupleStruct(tuple) => last(&tuple.path).into_iter().collect(),
        syn::Pat::Path(path) => last(&path.path).into_iter().collect(),
        syn::Pat::Or(or) => or.cases.iter().flat_map(pattern_variants).collect(),
        _ => Vec::new(),
    }
}

/// Event structs: those an `*_event!` macro declares, and the public ones
/// that implement `DomainEventCore` by hand.
fn events(files: &[&SourceFile], event_types: &[EventType]) -> Vec<Event> {
    let mut found: BTreeMap<String, Event> = BTreeMap::new();
    for file in files {
        let Some(syntax) = file.syntax() else {
            continue;
        };
        for item in items_of(syntax) {
            let Some((name, event_type, line)) = declared_event(item, event_types) else {
                continue;
            };
            if declared_privately(file, &name) {
                continue;
            }
            found.entry(name.clone()).or_insert_with(|| Event {
                place: declaration(file, &name).unwrap_or_else(|| Place::at(file, line)),
                context: context_of(file),
                name,
                event_type,
            });
        }
    }
    found.into_values().collect()
}

/// Whether `file` declares the struct `name` without `pub`: a record the
/// event machinery keeps for itself, such as a stored event read back,
/// rather than an event anything raises.
fn declared_privately(file: &SourceFile, name: &str) -> bool {
    file.syntax().is_some_and(|syntax| {
        items_of(syntax).into_iter().any(|item| {
            matches!(item, Item::Struct(declared) if declared.ident == name && !is_public(&declared.vis))
        })
    })
}

type DeclaredEvent = (String, Option<(String, String)>, usize);

fn declared_event(item: &Item, event_types: &[EventType]) -> Option<DeclaredEvent> {
    match item {
        Item::Macro(invocation) => {
            let macro_name = invocation.mac.path.segments.last()?.ident.to_string();
            let declares = macro_name.ends_with("_event") && macro_name != "event_types";
            declares
                .then(|| event_macro_parts(invocation.mac.tokens.clone(), event_types))
                .flatten()
        }
        Item::Impl(block) if implemented_trait(block).as_deref() == Some("DomainEventCore") => {
            let name = type_name(&block.self_ty)?;
            Some((name, None, line_of(&block.self_ty)))
        }
        _ => None,
    }
}

/// `Name => path::Enum::Variant` from an event macro's tokens, doc
/// attributes skipped. A bare `Name => Variant` is matched to the only
/// event type with that variant.
fn event_macro_parts(tokens: TokenStream, event_types: &[EventType]) -> Option<DeclaredEvent> {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let start = trees
        .iter()
        .position(|tree| matches!(tree, TokenTree::Ident(_)))?;
    let TokenTree::Ident(name) = &trees[start] else {
        return None;
    };
    let path: Vec<String> = trees[start + 1..]
        .iter()
        .skip_while(
            |tree| matches!(tree, TokenTree::Punct(p) if p.as_char() == '=' || p.as_char() == '>'),
        )
        .take_while(|tree| !matches!(tree, TokenTree::Punct(p) if p.as_char() == ','))
        .filter_map(|tree| match tree {
            TokenTree::Ident(word) => Some(word.to_string()),
            _ => None,
        })
        .collect();
    let event_type = match path.as_slice() {
        [.., enum_name, variant] => Some((enum_name.clone(), variant.clone())),
        [variant] => only_type_named(variant, event_types),
        [] => None,
    };
    Some((name.to_string(), event_type, name.span().start().line))
}

fn only_type_named(variant: &str, event_types: &[EventType]) -> Option<(String, String)> {
    let mut matching = event_types
        .iter()
        .filter(|listed| listed.variant == variant);
    let first = matching.next()?;
    matching
        .next()
        .is_none()
        .then(|| (first.enum_name.clone(), first.variant.clone()))
}

fn ensure_rules(file: &SourceFile) -> Vec<EnsureRule> {
    let Some(syntax) = file.syntax() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for item in items_of(syntax) {
        match item {
            Item::Fn(function) if is_public(&function.vis) => {
                found.extend(ensure_rule(file, None, &function.sig.ident));
            }
            Item::Impl(block) => {
                let owner = type_name(&block.self_ty);
                found.extend(
                    impl_fns(block)
                        .filter(|function| is_public(&function.vis) || block.trait_.is_some())
                        .filter_map(|function| {
                            ensure_rule(file, owner.clone(), &function.sig.ident)
                        }),
                );
            }
            _ => {}
        }
    }
    found
}

fn ensure_rule(file: &SourceFile, owner: Option<String>, name: &syn::Ident) -> Option<EnsureRule> {
    let text = name.to_string();
    text.starts_with("ensure_").then(|| EnsureRule {
        owner,
        name: text,
        place: Place::of(file, name),
    })
}

/// The proofs the domain's lists name, and every public `*Control` type.
fn proofs(files: &[&SourceFile], listed: &[String]) -> Vec<Proof> {
    let mut names: BTreeSet<String> = listed.iter().cloned().collect();
    for file in files {
        let Some(syntax) = file.syntax() else {
            continue;
        };
        names.extend(items_of(syntax).into_iter().filter_map(|item| match item {
            Item::Struct(declared)
                if is_public(&declared.vis) && declared.ident.to_string().ends_with("Control") =>
            {
                Some(declared.ident.to_string())
            }
            _ => None,
        }));
    }
    let implementors = implementors(files);
    let returns = returning_functions(files);
    names
        .into_iter()
        .map(|name| {
            let mut carriers = vec![name.clone()];
            carriers.extend(implementors.get(&name).into_iter().flatten().cloned());
            Proof {
                place: files.iter().find_map(|file| declaration(file, &name)),
                makers: makers_of(&returns, &carriers),
                carriers,
                name,
            }
        })
        .collect()
}

/// Every trait the domain implements outside its tests, with the types
/// implementing it.
fn implementors(files: &[&SourceFile]) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for file in files {
        for block in impls_of(file)
            .into_iter()
            .filter(|block| !for_tests_only(&block.attrs))
        {
            let (Some(trait_name), Some(self_type)) =
                (implemented_trait(block), type_name(&block.self_ty))
            else {
                continue;
            };
            found.entry(trait_name).or_default().push(self_type);
        }
    }
    found
}

/// Every public domain function outside the tests, with the type it
/// returns.
fn returning_functions(files: &[&SourceFile]) -> Vec<(Maker, syn::Type)> {
    let mut found = Vec::new();
    for file in files {
        let Some(syntax) = file.syntax() else {
            continue;
        };
        for item in items_of(syntax) {
            found.extend(returned_by(item));
        }
    }
    found
}

/// The public functions `item` defines, with the type each returns.
fn returned_by(item: &Item) -> Vec<(Maker, syn::Type)> {
    match item {
        Item::Fn(function) if is_public(&function.vis) && !for_tests_only(&function.attrs) => {
            returned(None, &function.sig).into_iter().collect()
        }
        Item::Impl(block) if !for_tests_only(&block.attrs) => {
            let owner = inherent_impl_of(block);
            impl_fns(block)
                .filter(|function| is_public(&function.vis))
                .filter_map(|function| returned(owner.clone(), &function.sig))
                .collect()
        }
        _ => Vec::new(),
    }
}

fn returned(owner: Option<String>, signature: &syn::Signature) -> Option<(Maker, syn::Type)> {
    let ReturnType::Type(_, ty) = &signature.output else {
        return None;
    };
    let maker = Maker {
        owner,
        name: signature.ident.to_string(),
    };
    Some((maker, (**ty).clone()))
}

/// The functions among `returns` that hand out one of `carriers`.
fn makers_of(returns: &[(Maker, syn::Type)], carriers: &[String]) -> Vec<Maker> {
    returns
        .iter()
        .filter(|(_, ty)| carriers.iter().any(|carrier| type_mentions(ty, carrier)))
        .map(|(maker, _)| maker.clone())
        .collect()
}

/// Every public `type Alias = Target<..>;`, by alias.
fn aliases(files: &[&SourceFile]) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    for file in files {
        let Some(syntax) = file.syntax() else {
            continue;
        };
        for item in items_of(syntax) {
            let Item::Type(alias) = item else {
                continue;
            };
            let Some(target) = type_name(&alias.ty).filter(|_| is_public(&alias.vis)) else {
                continue;
            };
            found.insert(alias.ident.to_string(), target);
        }
    }
    found
}

fn enums_by_name<'a>(
    files: &[&'a SourceFile],
) -> BTreeMap<String, (&'a SourceFile, &'a syn::ItemEnum)> {
    let mut found = BTreeMap::new();
    for file in files {
        let Some(syntax) = file.syntax() else {
            continue;
        };
        for item in items_of(syntax) {
            if let Item::Enum(declared) = item {
                found
                    .entry(declared.ident.to_string())
                    .or_insert((*file, declared));
            }
        }
    }
    found
}

fn permissions(files: &[&SourceFile]) -> Vec<Permission> {
    let enums = enums_by_name(files);
    let Some((file, system)) = enums.get(SYSTEM_PERMISSION) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for variant in &system.variants {
        let action_enum = match &variant.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                type_name(&fields.unnamed[0].ty)
            }
            _ => None,
        };
        let Some((action_file, actions)) = action_enum.as_ref().and_then(|name| enums.get(name))
        else {
            found.push(Permission {
                variant: variant.ident.to_string(),
                action: None,
                place: Place::of(file, &variant.ident),
            });
            continue;
        };
        found.extend(actions.variants.iter().map(|action| Permission {
            variant: variant.ident.to_string(),
            action: Some((actions.ident.to_string(), action.ident.to_string())),
            place: Place::of(action_file, &action.ident),
        }));
    }
    found
}

fn data_class_fields(files: &[&SourceFile], events: &BTreeSet<&str>) -> Vec<DataClassField> {
    let mut found = Vec::new();
    for file in files {
        let Some(syntax) = file.syntax() else {
            continue;
        };
        for item in items_of(syntax) {
            let Item::Struct(declared) = item else {
                continue;
            };
            let owner = declared.ident.to_string();
            if events.contains(owner.as_str())
                || CARRIER_SUFFIXES.iter().any(|end| owner.ends_with(end))
            {
                continue;
            }
            found.extend(declared.fields.iter().filter_map(|field| {
                let name = field.ident.as_ref()?;
                type_mentions(&field.ty, DATA_CLASS).then(|| DataClassField {
                    owner: owner.clone(),
                    field: name.to_string(),
                    place: Place::of(file, name),
                })
            }));
        }
    }
    found
}

/// What the domain's conventions list in their `lists.rs`, read as text:
/// the audit reads the file, it does not build it.
#[derive(Clone, Debug, Default)]
pub(crate) struct DomainLists {
    /// The first element of every entry in `CALLER_PROOFS`, `PROOFS` and
    /// `CALLER_PROOF_CARRIERS`.
    pub(crate) proofs: Vec<String>,
    /// The type (or, for a free function, its file below `src/`) and the
    /// function of every entry in `OBSERVATIONS`: those that build a whole
    /// event outside an aggregate.
    pub(crate) observations: Vec<(String, String)>,
    /// The type and function of every entry in `UNCALLED_CHANGES`: public
    /// creators and changes of stored types nobody makes, so they name no
    /// caller.
    pub(crate) uncalled: Vec<(String, String)>,
}

impl DomainLists {
    /// The lists in `lists_text`; none when it does not parse.
    pub(crate) fn read(lists_text: &str) -> Self {
        let Ok(parsed) = syn::parse_file(lists_text) else {
            return Self::default();
        };
        let entries = |names: &[&str]| listed(&parsed, names);
        Self {
            proofs: entries(&["CALLER_PROOFS", "PROOFS", "CALLER_PROOF_CARRIERS"])
                .into_iter()
                .filter_map(|entry| entry.into_iter().next())
                .collect(),
            observations: pairs(entries(&["OBSERVATIONS"])),
            uncalled: pairs(entries(&["UNCALLED_CHANGES"])),
        }
    }
}

/// The leading strings of each entry of the `&[..]` constants of `parsed`
/// named `names`.
pub(crate) fn listed(parsed: &syn::File, names: &[&str]) -> Vec<Vec<String>> {
    parsed
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Const(constant) if names.iter().any(|name| constant.ident == name) => {
                Some(constant.expr.as_ref())
            }
            _ => None,
        })
        .flat_map(listed_strings)
        .collect()
}

/// The first two strings of each entry that has two.
pub(crate) fn pairs(entries: Vec<Vec<String>>) -> Vec<(String, String)> {
    entries
        .into_iter()
        .filter_map(|entry| match entry.as_slice() {
            [first, second, ..] => Some((first.clone(), second.clone())),
            _ => None,
        })
        .collect()
}

/// The leading string literals of each entry of a `&[..]` list: the string
/// itself, or those a tuple opens with.
fn listed_strings(expr: &syn::Expr) -> Vec<Vec<String>> {
    let syn::Expr::Reference(reference) = expr else {
        return Vec::new();
    };
    let syn::Expr::Array(array) = reference.expr.as_ref() else {
        return Vec::new();
    };
    array
        .elems
        .iter()
        .map(|element| match element {
            syn::Expr::Tuple(tuple) => tuple.elems.iter().map_while(string_value).collect(),
            other => string_value(other).into_iter().collect(),
        })
        .filter(|entry: &Vec<String>| !entry.is_empty())
        .collect()
}

fn string_value(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) => Some(text.value()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::planted::{domain, workspace};

    const TOPIC: &str = r#"
        pub struct Topic { data_class: DataClassLevel }
        impl Topic {
            pub fn create(by: &MessagingControl<'_>) -> Result<Self, DomainError> { todo() }
            pub fn reconstitute(row: TopicRow) -> Result<Self, DomainError> { todo() }
            pub fn archive(&mut self, by: &MessagingControl<'_>) -> Result<(), DomainError> { Ok(()) }
            pub fn name(&self) -> &str { "" }
            pub fn ensure_open(&self) -> Result<(), DomainError> { Ok(()) }
        }
        pub struct MessagingControl;
        tenant_event! {
            /// A topic was created.
            TopicCreated => crate::types::event_type::MessagingEvent::TopicCreated,
            fn payload(&self) -> EventData { EventData::new() }
        }
    "#;

    const EVENT_TYPES: &str = r#"
        event_types! {
            /// The events.
            pub enum MessagingEvent {
                /// Made.
                TopicCreated => "messaging.topic_created",
                /// Sent.
                MessagePublished => "messaging.message_published",
            }
        }
        impl MessagingEvent {
            pub fn is_notifiable(&self) -> bool { !matches!(self, Self::MessagePublished) }
        }
    "#;

    fn model() -> DomainModel {
        let ws = workspace(vec![
            domain("domains/messaging/topic.rs", TOPIC),
            domain("types/event_type/messaging.rs", EVENT_TYPES),
        ]);
        let lists = DomainLists {
            proofs: vec!["Founding".to_owned()],
            ..DomainLists::default()
        };
        DomainModel::build(&ws, &lists)
    }

    #[test]
    fn a_type_with_reconstitute_is_an_aggregate() {
        let found = model();

        assert_eq!(found.aggregates[0].name, "Topic");
        assert_eq!(found.aggregates[0].context, "messaging");
    }

    #[test]
    fn creators_and_changes_are_behaviours_and_getters_are_not() {
        let found = model();

        let names: Vec<(&str, BehaviourKind)> = found
            .behaviours
            .iter()
            .map(|behaviour| (behaviour.name.as_str(), behaviour.kind))
            .collect();

        assert_eq!(
            names,
            [
                ("create", BehaviourKind::Create),
                ("archive", BehaviourKind::Change)
            ]
        );
    }

    #[test]
    fn an_event_macro_names_its_struct_and_type() {
        let found = model();

        assert_eq!(found.events[0].name, "TopicCreated");
        assert_eq!(
            found.events[0].event_type,
            Some(("MessagingEvent".to_owned(), "TopicCreated".to_owned()))
        );
    }

    #[test]
    fn a_private_record_implementing_the_event_core_is_no_event() {
        let ws = workspace(vec![domain(
            "shared/events/event.rs",
            "struct Recorded { payload: EventData }
             impl DomainEventCore for Recorded { fn payload(&self) -> EventData { data() } }
             pub struct Wrapped(pub(crate) Change);
             impl DomainEventCore for Wrapped { fn payload(&self) -> EventData { data() } }",
        )]);

        let found = DomainModel::build(&ws, &DomainLists::default());

        let names: Vec<&str> = found
            .events
            .iter()
            .map(|event| event.name.as_str())
            .collect();
        assert_eq!(names, ["Wrapped"]);
    }

    /// Stops: an `is_notifiable` written as a `match` that names the events
    /// colleagues hear (`=> true`) beside those left out (`=> false`) marks
    /// every named event as left out, and the audit reports heard events as
    /// unheard.
    #[test]
    fn only_the_events_answered_false_are_left_out() {
        let file = domain(
            "domains/oauth/events.rs",
            r#"
            event_types! {
                /// The events.
                pub enum OAuthEvent {
                    /// Made.
                    ClientCreated => "oauth.client_created",
                    /// Handed out.
                    TokenIssued => "oauth.token_issued",
                }
            }
            impl OAuthEvent {
                pub fn is_notifiable(&self) -> bool {
                    match self {
                        Self::ClientCreated => true,
                        Self::TokenIssued => false,
                    }
                }
            }
            "#,
        );

        let quiet = quiet_event_types(&[&file]);

        assert!(quiet.contains(&("OAuthEvent".to_owned(), "TokenIssued".to_owned())));
        assert!(!quiet.contains(&("OAuthEvent".to_owned(), "ClientCreated".to_owned())));
    }

    #[test]
    fn event_types_are_read_with_their_text_and_quiet_ones_marked() {
        let found = model();

        assert_eq!(found.event_types[1].text, "messaging.message_published");
        assert!(
            found
                .quiet_event_types
                .contains(&("MessagingEvent".to_owned(), "MessagePublished".to_owned()))
        );
    }

    #[test]
    fn listed_proofs_and_control_types_are_proofs() {
        let found = model();

        let names: Vec<&str> = found
            .proofs
            .iter()
            .map(|proof| proof.name.as_str())
            .collect();

        assert_eq!(names, ["Founding", "MessagingControl"]);
    }

    #[test]
    fn ensure_rules_and_data_class_fields_are_found() {
        let found = model();

        assert_eq!(found.ensure_rules[0].subject(), "Topic::ensure_open");
        assert_eq!(found.data_class_fields[0].field, "data_class");
    }

    #[test]
    fn listed_proofs_are_read_from_the_lists_text() {
        let text = r#"
            pub const CALLER_PROOFS: &[&str] = &["Founding", "HeldBy"];
            pub const PROOFS: &[(&str, &str)] = &[("VerifiedEmail", "why")];
            pub const OTHER: &[&str] = &["Ignored"];
        "#;

        let lists = DomainLists::read(text);

        assert_eq!(lists.proofs, ["Founding", "HeldBy", "VerifiedEmail"]);
    }

    #[test]
    fn uncalled_changes_are_read_with_their_type_and_function() {
        let text = r#"
            const RUN_STEP: &str = "a step of the run";
            pub const UNCALLED_CHANGES: &[(&str, &str, &str)] = &[
                ("AgentRun", "complete", RUN_STEP),
                ("MappedHoldings", "none", "an empty record"),
            ];
        "#;

        let lists = DomainLists::read(text);

        assert_eq!(
            lists.uncalled,
            [
                ("AgentRun".to_owned(), "complete".to_owned()),
                ("MappedHoldings".to_owned(), "none".to_owned())
            ]
        );
    }

    #[test]
    fn observations_are_read_with_their_owner_and_function() {
        let text = r#"
            const SEEN: &str = "seen in traffic";
            pub const OBSERVATIONS: &[(&str, &str, &str)] = &[
                ("HoneypotHit", "observed", SEEN),
                ("domains/workflows/events.rs", "step_event", "why"),
            ];
        "#;

        let lists = DomainLists::read(text);

        assert_eq!(
            lists.observations,
            [
                ("HoneypotHit".to_owned(), "observed".to_owned()),
                (
                    "domains/workflows/events.rs".to_owned(),
                    "step_event".to_owned()
                )
            ]
        );
    }

    #[test]
    fn an_operation_value_that_raises_is_read_with_its_changes() {
        let ws = workspace(vec![domain(
            "domains/authentication/operations/directory_attempt.rs",
            "pub struct DirectoryBindAttempt<T> { raised: Raised<T> }
             impl<T: TenantScope> DirectoryBindAttempt<T> {
                 pub fn new(email: &Email) -> Self { make() }
                 pub fn refused(&mut self, reason: LoginFailureReason) {}
             }
             impl<T: TenantScope> Raises for DirectoryBindAttempt<T> {
                 fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> { take() }
             }",
        )]);

        let found = DomainModel::build(&ws, &DomainLists::default());

        let subjects: Vec<String> = found.behaviours.iter().map(Behaviour::subject).collect();
        assert_eq!(found.aggregates[0].name, "DirectoryBindAttempt");
        assert_eq!(
            subjects,
            ["DirectoryBindAttempt::new", "DirectoryBindAttempt::refused"]
        );
    }

    #[test]
    fn each_action_of_a_permission_is_its_own_right() {
        let ws = workspace(vec![domain(
            "domains/authorization/permission/system.rs",
            "pub enum SystemPermission { Messaging(MessagingAction), Everything }
             pub enum MessagingAction { Create, Delete }",
        )]);

        let found = DomainModel::build(&ws, &DomainLists::default());

        let subjects: Vec<String> = found.permissions.iter().map(Permission::subject).collect();
        assert_eq!(
            subjects,
            [
                "Messaging(MessagingAction::Create)",
                "Messaging(MessagingAction::Delete)",
                "Everything"
            ]
        );
    }
}
