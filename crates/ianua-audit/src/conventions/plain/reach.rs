//! What a crate shows to others.
//!
//! - **The smallest visibility.** An item a library marks `pub` is written
//!   by another crate, or by the library's own binaries, tests, benches or
//!   examples, which reach it only as an outsider does. A type an outsider
//!   only receives, such as what a public method it calls returns, is
//!   reached too, though never spelled. Anything else is `pub(crate)`.

use std::collections::{BTreeMap, BTreeSet};

use quote::ToTokens;
use syn::{Ident, ImplItem, Item, Visibility};

use crate::conventions::infra::source::{Findings, SourceFile, line_of};

/// Libraries whose public items are generated or read by the compiler, not
/// written by hand for other crates.
const LEFT_OUT: &[&str] = &["ianua-proto", "ianua-workspace-hack", "ianua-macros"];

/// A library's public item: where it is, and the names an outsider who
/// reaches it is handed with it.
struct Public<'a> {
    path: &'a str,
    ident: &'a Ident,
    hands_on: BTreeSet<String>,
}

/// Every top-level `pub` item of a library among `shipping` that no file
/// of `readers` outside that library writes or is handed.
pub(crate) fn public_items_used_only_inside(
    shipping: &[SourceFile],
    readers: &[SourceFile],
) -> Findings {
    let libraries: BTreeSet<&str> = shipping
        .iter()
        .filter(|file| file.path.ends_with("/src/lib.rs"))
        .map(|file| crate_of(&file.path))
        .filter(|name| !LEFT_OUT.contains(name))
        .collect();
    let written = names_by_reader(readers, &libraries);
    let mut found = Findings::default();
    for library in &libraries {
        let publics = publics_of(shipping, library);
        let reached = reached(&publics, &written, library);
        for public in publics
            .values()
            .filter(|public| !reached.contains(&public.ident.to_string()))
        {
            found.flag_at(
                public.path,
                line_of(public.ident),
                format!(
                    "`{}` is public but used only inside its crate; make it `pub(crate)`",
                    public.ident
                ),
            );
        }
    }
    found
}

/// The public items of `library` among `shipping`, by name, each with the
/// names its signature and its public methods hand on.
fn publics_of<'a>(shipping: &'a [SourceFile], library: &str) -> BTreeMap<String, Public<'a>> {
    let mut publics = BTreeMap::new();
    let mut methods: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let files = shipping
        .iter()
        .filter(|file| crate_of(&file.path) == library && is_library_source(&file.path));
    for file in files {
        for item in flattened(file.items()) {
            if let Some((ident, hands_on)) = public_name(item) {
                let public = Public {
                    path: &file.path,
                    ident,
                    hands_on: BTreeSet::new(),
                };
                let kept = publics.entry(ident.to_string()).or_insert(public);
                kept.hands_on.extend(hands_on);
            }
            if let Some((owner, handed)) = public_methods(item) {
                methods.entry(owner).or_default().extend(handed);
            }
        }
    }
    for (owner, handed) in methods {
        if let Some(public) = publics.get_mut(&owner) {
            public.hands_on.extend(handed);
        }
    }
    publics
}

/// The names among `publics` an outsider reaches: those written outside
/// `library`, and every name a reached item hands on.
fn reached(
    publics: &BTreeMap<String, Public<'_>>,
    written: &BTreeMap<String, BTreeSet<String>>,
    library: &str,
) -> BTreeSet<String> {
    let mut reached: BTreeSet<String> = publics
        .keys()
        .filter(|name| {
            written
                .get(*name)
                .is_some_and(|readers| readers.iter().any(|reader| reader != library))
        })
        .cloned()
        .collect();
    let mut waiting: Vec<String> = reached.iter().cloned().collect();
    while let Some(name) = waiting.pop() {
        let Some(public) = publics.get(&name) else {
            continue;
        };
        for handed in &public.hands_on {
            if publics.contains_key(handed) && reached.insert(handed.clone()) {
                waiting.push(handed.clone());
            }
        }
    }
    reached
}

/// For each name written in `readers`, who wrote it: a library's name for
/// its own source, the file's path for anything reaching it from outside.
fn names_by_reader(
    readers: &[SourceFile],
    libraries: &BTreeSet<&str>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut written: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for file in readers {
        let owner = crate_of(&file.path);
        let reader = if libraries.contains(owner) && is_library_source(&file.path) {
            owner.to_owned()
        } else {
            file.path.clone()
        };
        for name in file.lines().into_iter().flat_map(identifiers) {
            written.entry(name).or_default().insert(reader.clone());
        }
    }
    written
}

/// `items` with the items of inline modules among them.
fn flattened(items: &[Item]) -> Vec<&Item> {
    items
        .iter()
        .flat_map(|item| match item {
            Item::Mod(module) => module
                .content
                .as_ref()
                .map_or_else(Vec::new, |(_, inner)| flattened(inner)),
            other => vec![other],
        })
        .collect()
}

/// The name of `item` when it is a plain `pub` item of a kind others name,
/// with the names it hands on: what its signature, fields or alias spell.
fn public_name(item: &Item) -> Option<(&Ident, BTreeSet<String>)> {
    let (visibility, ident, shown) = match item {
        Item::Fn(item) => (&item.vis, &item.sig.ident, item.sig.to_token_stream()),
        Item::Struct(item) => (&item.vis, &item.ident, item.fields.to_token_stream()),
        Item::Enum(item) => (&item.vis, &item.ident, item.variants.to_token_stream()),
        Item::Trait(item) => (&item.vis, &item.ident, item.to_token_stream()),
        Item::Const(item) => (&item.vis, &item.ident, item.ty.to_token_stream()),
        Item::Static(item) => (&item.vis, &item.ident, item.ty.to_token_stream()),
        Item::Type(item) => (&item.vis, &item.ident, item.ty.to_token_stream()),
        Item::Union(item) => (&item.vis, &item.ident, item.fields.to_token_stream()),
        _ => return None,
    };
    let hands_on = identifiers(&shown.to_string()).collect();
    matches!(visibility, Visibility::Public(_)).then_some((ident, hands_on))
}

/// For an `impl` block, the type it is for and the names an outsider
/// meets through it: its bounds, its `pub` methods' signatures and, for a
/// trait, every method and associated type.
fn public_methods(item: &Item) -> Option<(String, BTreeSet<String>)> {
    let Item::Impl(block) = item else {
        return None;
    };
    let syn::Type::Path(owner) = block.self_ty.as_ref() else {
        return None;
    };
    let owner = owner.path.segments.last()?.ident.to_string();
    let for_trait = block.trait_.is_some();
    let shown = (block.items.iter()).filter_map(|inner| match inner {
        ImplItem::Fn(method) if for_trait || matches!(method.vis, Visibility::Public(_)) => {
            Some(method.sig.to_token_stream().to_string())
        }
        ImplItem::Type(alias) if for_trait => Some(alias.ty.to_token_stream().to_string()),
        _ => None,
    });
    let bounds = block.generics.to_token_stream().to_string();
    let handed = (shown.chain([bounds]))
        .flat_map(|written| identifiers(&written).collect::<Vec<_>>())
        .collect();
    Some((owner, handed))
}

/// The identifiers `text` spells.
fn identifiers(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
}

/// Whether a workspace path is a library's own source, not one of its
/// binaries.
fn is_library_source(path: &str) -> bool {
    let Some((_, inside)) = path.split_once("/src/") else {
        return false;
    };
    inside != "main.rs" && !inside.starts_with("bin/")
}

/// The crate folder a workspace path is in.
fn crate_of(path: &str) -> &str {
    path.split('/').next().unwrap_or_default()
}
