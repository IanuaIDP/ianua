//! Small readers over `syn` nodes that several checks share.

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Expr, File, ImplItem, ImplItemFn, Item, ItemImpl, Type, Visibility};

/// The 1-based line a node starts on.
pub(crate) fn line_of(node: &impl Spanned) -> usize {
    node.span().start().line
}

/// The last segment of a type written as a path, such as `Uuid` for
/// `uuid::Uuid`.
pub(crate) fn type_name(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

/// The path of a type written as one, without its generic arguments, such
/// as `["ports", "CreatePorts"]` for `ports::CreatePorts`.
pub(crate) fn type_path(ty: &Type) -> Option<Vec<String>> {
    let Type::Path(path) = ty else {
        return None;
    };
    Some(
        path.path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
    )
}

/// Every name a type mentions, such as `Arc`, `dyn`'s `TopicStore` in
/// `Arc<dyn TopicStore>`.
pub(crate) fn names_in_type(ty: &Type) -> Vec<String> {
    let mut names = Names::default();
    names.visit_type(ty);
    names.found
}

/// Every path written in a type, as its segments' names, outermost first:
/// `["Arc"]` and `["ports", "TopicStore"]` for
/// `Arc<dyn ports::TopicStore>`.
pub(crate) fn type_paths(ty: &Type) -> Vec<Vec<String>> {
    let mut paths = Paths::default();
    paths.visit_type(ty);
    paths.found
}

#[derive(Default)]
struct Paths {
    found: Vec<Vec<String>>,
}

impl<'ast> Visit<'ast> for Paths {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.found.push(
            path.segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect(),
        );
        syn::visit::visit_path(self, path);
    }
}

/// Whether a type names `name` anywhere in it.
pub(crate) fn type_mentions(ty: &Type, name: &str) -> bool {
    names_in_type(ty).iter().any(|found| found == name)
}

/// Every identifier written in an expression, macros left out.
pub(crate) fn names_in_expr(expr: &Expr) -> Vec<String> {
    let mut names = Names::default();
    names.visit_expr(expr);
    names.found
}

#[derive(Default)]
struct Names {
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        self.found.push(ident.to_string());
    }
}

/// Every item in a file, those inside inline modules included.
pub(crate) fn items_of(file: &File) -> Vec<&Item> {
    let mut found = Vec::new();
    collect_items(&file.items, &mut found);
    found
}

fn collect_items<'a>(items: &'a [Item], found: &mut Vec<&'a Item>) {
    for item in items {
        found.push(item);
        if let Item::Mod(module) = item
            && let Some((_, inner)) = &module.content
        {
            collect_items(inner, found);
        }
    }
}

/// One name a `use` item brings in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Import {
    /// The name the file uses, which `as` may have changed.
    pub(crate) local: String,
    /// The path before the name, as written, such as `["crate", "ports"]`.
    pub(crate) prefix: Vec<String>,
    /// The name where it comes from.
    pub(crate) original: String,
}

/// What a glob import is recorded as, in place of a name.
const GLOB: &str = "*";

/// Every name the `use` items of a file bring in, those in inline modules
/// included; `self` in a group as the module it names, and a glob as the
/// name `*`.
pub(crate) fn imports_of(file: &File) -> Vec<Import> {
    let mut found = Vec::new();
    for item in items_of(file) {
        if let Item::Use(declared) = item {
            walk_use(&declared.tree, Vec::new(), &mut found);
        }
    }
    found
}

/// The path before each `use path::*` of a file.
pub(crate) fn globs_of(file: &File) -> Vec<Vec<String>> {
    imports_of(file)
        .into_iter()
        .filter(|import| import.local == GLOB)
        .map(|import| import.prefix)
        .collect()
}

fn walk_use(tree: &syn::UseTree, prefix: Vec<String>, found: &mut Vec<Import>) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut longer = prefix;
            longer.push(path.ident.to_string());
            walk_use(&path.tree, longer, found);
        }
        syn::UseTree::Name(name) if name.ident != "self" => {
            found.push(Import::named(name.ident.to_string(), prefix));
        }
        syn::UseTree::Name(_) => {
            if let Some((module, parent)) = prefix.split_last() {
                found.push(Import::named(module.clone(), parent.to_vec()));
            }
        }
        syn::UseTree::Rename(rename) => found.push(Import {
            local: rename.rename.to_string(),
            prefix,
            original: rename.ident.to_string(),
        }),
        syn::UseTree::Group(group) => {
            for inner in &group.items {
                walk_use(inner, prefix.clone(), found);
            }
        }
        syn::UseTree::Glob(_) => found.push(Import::named(GLOB.to_owned(), prefix)),
    }
}

impl Import {
    /// `name` imported from `prefix` under its own name.
    fn named(name: String, prefix: Vec<String>) -> Self {
        Self {
            local: name.clone(),
            prefix,
            original: name,
        }
    }
}

/// Whether attributes build an item only for tests or the `test-support`
/// feature, which ships to other crates' tests and not to production.
pub(crate) fn for_tests_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string().contains("test"))
    })
}

/// The trait an `impl` block implements, by its last name.
pub(crate) fn implemented_trait(item: &ItemImpl) -> Option<String> {
    item.trait_
        .as_ref()
        .and_then(|(_, path, _)| path.segments.last())
        .map(|segment| segment.ident.to_string())
}

/// The path of the trait an `impl` block implements, as written.
pub(crate) fn implemented_path(item: &ItemImpl) -> Option<Vec<String>> {
    item.trait_.as_ref().map(|(_, path, _)| {
        path.segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect()
    })
}

/// The type an inherent `impl` block is for.
pub(crate) fn inherent_impl_of(item: &ItemImpl) -> Option<String> {
    if item.trait_.is_some() {
        return None;
    }
    type_name(&item.self_ty)
}

/// The functions an `impl` block defines.
pub(crate) fn impl_fns(item: &ItemImpl) -> impl Iterator<Item = &ImplItemFn> {
    item.items.iter().filter_map(|member| match member {
        ImplItem::Fn(function) => Some(function),
        _ => None,
    })
}

/// Whether a function is plain `pub`.
pub(crate) fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

/// Types that hold the value a function hands out rather than being it.
const WRAPPERS: &[&str] = &["Result", "Option", "Box", "Arc", "Rc", "Cow"];

/// A type as it is written, such as `Result<CreatedSubscription, AppError>`;
/// `None` for the shapes this reader does not print (function pointers,
/// arrays, qualified paths, macros).
pub(crate) fn type_text(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) if path.qself.is_none() => path_text(&path.path),
        Type::Reference(reference) => {
            let lifetime = reference
                .lifetime
                .as_ref()
                .map_or_else(String::new, |lifetime| format!("'{} ", lifetime.ident));
            let mutable = reference.mutability.map_or("", |_| "mut ");
            Some(format!(
                "&{lifetime}{mutable}{}",
                type_text(&reference.elem)?
            ))
        }
        Type::Tuple(tuple) => {
            let parts: Option<Vec<String>> = tuple.elems.iter().map(type_text).collect();
            Some(format!("({})", parts?.join(", ")))
        }
        Type::Slice(slice) => Some(format!("[{}]", type_text(&slice.elem)?)),
        Type::Paren(inner) => type_text(&inner.elem),
        Type::Group(inner) => type_text(&inner.elem),
        Type::Never(_) => Some("!".to_owned()),
        Type::TraitObject(object) => bounds_text("dyn", &object.bounds),
        Type::ImplTrait(implemented) => bounds_text("impl", &implemented.bounds),
        _ => None,
    }
}

fn path_text(path: &syn::Path) -> Option<String> {
    let segments: Option<Vec<String>> = path.segments.iter().map(segment_text).collect();
    Some(segments?.join("::"))
}

fn segment_text(segment: &syn::PathSegment) -> Option<String> {
    let name = segment.ident.to_string();
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return matches!(segment.arguments, syn::PathArguments::None).then_some(name);
    };
    let parts: Option<Vec<String>> = arguments
        .args
        .iter()
        .map(|argument| match argument {
            syn::GenericArgument::Type(ty) => type_text(ty),
            syn::GenericArgument::Lifetime(lifetime) => Some(format!("'{}", lifetime.ident)),
            _ => None,
        })
        .collect();
    Some(format!("{name}<{}>", parts?.join(", ")))
}

fn bounds_text(
    keyword: &str,
    bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>,
) -> Option<String> {
    let traits: Option<Vec<String>> = bounds
        .iter()
        .filter_map(|bound| match bound {
            syn::TypeParamBound::Trait(found) => Some(path_text(&found.path)),
            _ => None,
        })
        .collect();
    Some(format!("{keyword} {}", traits?.join(" + ")))
}

/// The type a value of `ty` is about once its wrappers are taken off, by
/// its last name: `WebhookSubscription` for
/// `Result<WebhookSubscription<ResolvedTenant>, AppError>`, and `owner` for
/// `Self`. `None` for a tuple or any shape without one name.
pub(crate) fn core_type(ty: &Type, owner: Option<&str>) -> Option<String> {
    match ty {
        Type::Reference(reference) => core_type(&reference.elem, owner),
        Type::Paren(inner) => core_type(&inner.elem, owner),
        Type::Group(inner) => core_type(&inner.elem, owner),
        Type::Path(path) => core_of_path(path.path.segments.last()?, owner),
        _ => None,
    }
}

fn core_of_path(last: &syn::PathSegment, owner: Option<&str>) -> Option<String> {
    let name = last.ident.to_string();
    if name == "Self" {
        return owner.map(str::to_owned);
    }
    if !WRAPPERS.contains(&name.as_str()) {
        return Some(name);
    }
    let syn::PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return None;
    };
    arguments.args.iter().find_map(|argument| match argument {
        syn::GenericArgument::Type(inner) => core_type(inner, owner),
        _ => None,
    })
}

/// Collections whose items a loop or an iterator hands out one by one.
const COLLECTIONS: &[&str] = &["Vec", "VecDeque", "HashSet", "BTreeSet", "IndexSet"];

/// The core type of the items a value of `ty` holds, when it is a
/// collection, a slice or an `impl Iterator<Item = T>`, through `Result`,
/// `Option` and references: `User` for `Result<Vec<User>, AppError>`.
pub(crate) fn item_type(ty: &Type, owner: Option<&str>) -> Option<String> {
    match ty {
        Type::Reference(reference) => item_type(&reference.elem, owner),
        Type::Paren(inner) => item_type(&inner.elem, owner),
        Type::Group(inner) => item_type(&inner.elem, owner),
        Type::Slice(slice) => core_type(&slice.elem, owner),
        Type::Array(array) => core_type(&array.elem, owner),
        Type::ImplTrait(implemented) => implemented.bounds.iter().find_map(|bound| match bound {
            syn::TypeParamBound::Trait(found) => iterator_item(found.path.segments.last()?, owner),
            _ => None,
        }),
        Type::Path(path) => items_of_path(path.path.segments.last()?, owner),
        _ => None,
    }
}

fn items_of_path(last: &syn::PathSegment, owner: Option<&str>) -> Option<String> {
    let syn::PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return None;
    };
    let first = arguments.args.iter().find_map(|argument| match argument {
        syn::GenericArgument::Type(inner) => Some(inner),
        _ => None,
    })?;
    let name = last.ident.to_string();
    match name.as_str() {
        "Result" | "Option" | "Box" | "Arc" => item_type(first, owner),
        _ if COLLECTIONS.contains(&name.as_str()) => core_type(first, owner),
        _ => None,
    }
}

fn iterator_item(last: &syn::PathSegment, owner: Option<&str>) -> Option<String> {
    let syn::PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return None;
    };
    arguments.args.iter().find_map(|argument| match argument {
        syn::GenericArgument::AssocType(item) if item.ident == "Item" => core_type(&item.ty, owner),
        _ => None,
    })
}

/// The core type of the items a function hands back, as [`item_type`]
/// reads it.
pub(crate) fn returned_items(output: &syn::ReturnType, owner: Option<&str>) -> Option<String> {
    match output {
        syn::ReturnType::Type(_, ty) => item_type(ty, owner),
        syn::ReturnType::Default => None,
    }
}

/// The core type a function returns, as [`core_type`] reads it.
pub(crate) fn returned_core(output: &syn::ReturnType, owner: Option<&str>) -> Option<String> {
    match output {
        syn::ReturnType::Type(_, ty) => core_type(ty, owner),
        syn::ReturnType::Default => None,
    }
}

/// The lines of an item's doc comment, each without the space after `///`.
pub(crate) fn doc_lines(attributes: &[Attribute]) -> Vec<String> {
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("doc"))
        .filter_map(|attribute| match &attribute.meta {
            syn::Meta::NameValue(pair) => match &pair.value {
                Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(text),
                    ..
                }) => Some(text.value()),
                _ => None,
            },
            _ => None,
        })
        .map(|line| line.strip_prefix(' ').map(str::to_owned).unwrap_or(line))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dyn_trait_inside_an_arc_is_named() {
        let ty: Type = syn::parse_str("Arc<dyn TopicStore>").unwrap();

        assert!(type_mentions(&ty, "TopicStore"));
    }

    #[test]
    fn every_path_in_a_type_is_read_outermost_first() {
        let ty: Type = syn::parse_str("Arc<dyn ports::TopicStore + Send>").unwrap();

        assert_eq!(
            type_paths(&ty),
            [vec!["Arc"], vec!["ports", "TopicStore"], vec!["Send"]]
        );
    }

    #[test]
    fn a_type_is_printed_as_written() {
        let ty: Type = syn::parse_str("Result<Vec<&'a dyn TopicStore>, (AppError, u8)>").unwrap();

        assert_eq!(
            type_text(&ty).as_deref(),
            Some("Result<Vec<&'a dyn TopicStore>, (AppError, u8)>")
        );
    }

    #[test]
    fn a_type_this_reader_does_not_print_is_none() {
        let ty: Type = syn::parse_str("fn(u8) -> u8").unwrap();

        assert!(type_text(&ty).is_none());
    }

    #[test]
    fn the_core_type_takes_off_results_options_and_references() {
        let ty: Type =
            syn::parse_str("Result<Option<&WebhookSubscription<ResolvedTenant>>, AppError>")
                .unwrap();
        let own: Type = syn::parse_str("Result<Self, DomainError>").unwrap();

        assert_eq!(core_type(&ty, None).as_deref(), Some("WebhookSubscription"));
        assert_eq!(core_type(&own, Some("Topic")).as_deref(), Some("Topic"));
    }

    #[test]
    fn the_items_of_a_collection_are_read_through_results_and_iterators() {
        let listed: Type = syn::parse_str("Result<Vec<ApprovalRequest<T>>, AppError>").unwrap();
        let iterated: Type = syn::parse_str("impl Iterator<Item = &Role>").unwrap();
        let single: Type = syn::parse_str("Result<User, AppError>").unwrap();

        assert_eq!(item_type(&listed, None).as_deref(), Some("ApprovalRequest"));
        assert_eq!(item_type(&iterated, None).as_deref(), Some("Role"));
        assert!(item_type(&single, None).is_none());
    }

    #[test]
    fn imports_are_read_through_groups_and_renames() {
        let file = syn::parse_file(
            "use crate::use_cases::{lookup::existing, keeping::kept as stored};\nuse std::sync::*;",
        )
        .unwrap();

        let found = imports_of(&file);

        assert_eq!(found.len(), 3);
        assert_eq!(globs_of(&file), [["std", "sync"]]);
        assert_eq!(found[1].local, "stored");
        assert_eq!(found[1].original, "kept");
        assert_eq!(found[1].prefix, ["crate", "use_cases", "keeping"]);
    }

    #[test]
    fn self_in_a_group_imports_the_module_it_names() {
        let file =
            syn::parse_file("use crate::services::sign_in_gate::{self, ClientOrigin};").unwrap();

        let found = imports_of(&file);

        assert_eq!(found[0].local, "sign_in_gate");
        assert_eq!(found[0].prefix, ["crate", "services"]);
    }

    #[test]
    fn doc_lines_are_read_without_their_leading_space() {
        let item: syn::ItemFn = syn::parse_str("/// One.\n///  Two.\nfn f() {}").unwrap();

        assert_eq!(doc_lines(&item.attrs), ["One.", " Two."]);
    }
}
