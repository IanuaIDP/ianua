//! How a domain file is laid out and what it lets through at its edges: the
//! mistakes a review of the reorganised domain found once, each made a check
//! so it cannot come back unnoticed.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{TokenStream, TokenTree};
use syn::{ImplItem, Item, UseTree, Visibility};

use crate::conventions::domain::lists::{HAND_WRITTEN_EVENTS, TRAITS_IMPORTED_FOR_METHODS};
use crate::conventions::domain::source::{
    Findings, SourceFile, line_of, option_of, path_text, tokens_name, type_name,
};

/// The words of a piece of source, for asking whether it names something.
fn words(text: &str) -> BTreeSet<&str> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .collect()
}

/// Whether an item is the file's `#[cfg(test)]` module.
fn is_test_module(item: &Item) -> bool {
    let Item::Mod(module) = item else {
        return false;
    };
    module.attrs.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .parse_args::<syn::Ident>()
                .is_ok_and(|condition| condition == "test")
    })
}

/// Where a test module sits anywhere but last, or a file has more than one.
pub(crate) fn misplaced_test_modules(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let items = file.items();
        let tests: Vec<usize> = (0..items.len())
            .filter(|index| is_test_module(&items[*index]))
            .collect();
        if tests.len() > 1 {
            findings.flag(
                file,
                &items[tests[1]],
                "a second test module; keep one, at the end",
            );
        }
        let Some(first) = tests.first() else {
            continue;
        };
        if *first + 1 != items.len() && tests.len() == 1 {
            findings.flag(
                file,
                &items[*first],
                "the test module is not the last item in the file",
            );
        }
    }
    findings
}

/// Where a `// ──` divider splits a file into sections, at any indent and
/// in tests too: a file that needs sections holds more than one thing.
pub(crate) fn divider_comments(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (index, line) in file.lines().iter().enumerate() {
            if line.trim_start().starts_with("// ──") {
                findings.flag_line(file, index + 1, "a section divider; split the file instead");
            }
        }
    }
    findings
}

/// Where an em dash sits before a file's tests, in docs, comments or text: a
/// sentence that needs one reads better split, or with a comma or a colon.
/// Test data may hold one, as a label someone typed may.
pub(crate) fn em_dashes(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (index, line) in file.lines_before_tests().iter().enumerate() {
            if line.contains('\u{2014}') {
                findings.flag_line(
                    file,
                    index + 1,
                    "an em dash; use a comma, a colon or two sentences",
                );
            }
        }
    }
    findings
}

/// Whether a type has a public associated function returning what `wanted`
/// names: a constructor that can refuse, or one that always builds.
fn has_constructor(file: &SourceFile, name: &str, wanted: Returns) -> bool {
    file.inventory().impls.iter().any(|block| {
        let for_it = type_name(&block.self_ty).is_some_and(|ty| ty == name);
        for_it
            && block.trait_.is_none()
            && block.items.iter().any(|item| {
                let ImplItem::Fn(function) = item else {
                    return false;
                };
                let public = matches!(function.vis, Visibility::Public(_));
                let no_self = function.sig.receiver().is_none();
                public && no_self && wanted.matches(file, &function.sig.output)
            })
    })
}

/// What a constructor gives back.
#[derive(Clone, Copy)]
enum Returns {
    /// The value or a refusal.
    MaybeRefused,
    /// The value, always.
    Always,
}

impl Returns {
    fn matches(self, file: &SourceFile, output: &syn::ReturnType) -> bool {
        let syn::ReturnType::Type(_, ty) = output else {
            return false;
        };
        let text = file.text_of(ty.as_ref());
        match self {
            Self::MaybeRefused => text.starts_with("Result<Self"),
            Self::Always => text == "Self",
        }
    }
}

/// Whether a type is a bare primitive, which checks nothing about itself.
fn is_raw(ty: &syn::Type) -> bool {
    const RAW: &[&str] = &[
        "String", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
        "isize", "f32", "f64",
    ];
    type_name(ty).is_some_and(|name| RAW.contains(&name.to_string().as_str()))
}

/// Where a struct with private fields, built only by a constructor that can
/// refuse, derives `Deserialize` directly while holding a bare primitive the
/// constructor checks, so JSON builds what the constructor would have turned
/// away. Fields that are checked types check themselves when read.
pub(crate) fn deserialize_skipping_the_constructor(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for item in file.inventory().structs {
            let private = item
                .fields
                .iter()
                .all(|field| matches!(field.vis, Visibility::Inherited));
            let attributes: String = item.attrs.iter().map(|a| file.text_of(a)).collect();
            let derives = attributes.contains("Deserialize");
            let routed = attributes.contains("try_from")
                || attributes.contains("from =")
                || attributes.contains("transparent");
            let name = item.ident.to_string();
            let only_checked = has_constructor(file, &name, Returns::MaybeRefused)
                && !has_constructor(file, &name, Returns::Always);
            let holds_raw = item.fields.iter().any(|field| is_raw(&field.ty));
            if private && derives && !routed && only_checked && holds_raw {
                findings.flag(
                    file,
                    item,
                    format!("`{name}` deserializes past its constructor; read it through `serde(try_from)`"),
                );
            }
        }
    }
    findings
}

/// Where a public `stored` function builds a value from loose parts: the
/// way back from storage goes through the row and `reconstitute`, so a
/// caller cannot use it to make up a value the domain never produced.
pub(crate) fn public_stored_constructors(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for block in file.inventory().impls {
            for item in &block.items {
                let ImplItem::Fn(function) = item else {
                    continue;
                };
                let public = matches!(function.vis, Visibility::Public(_));
                let builds = Returns::Always.matches(file, &function.sig.output);
                if public && builds && function.sig.ident == "stored" {
                    findings.flag(
                        file,
                        function,
                        "a public `stored` constructor; carry the stored parts in the row instead",
                    );
                }
            }
        }
    }
    findings
}

/// The types each file declares at its top level, by name, with the files
/// declaring them.
fn declaring_files(files: &[SourceFile]) -> BTreeMap<String, Vec<&str>> {
    let mut declared: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for file in files {
        for item in file.items() {
            let name = match item {
                Item::Struct(item) => &item.ident,
                Item::Enum(item) => &item.ident,
                _ => continue,
            };
            declared
                .entry(name.to_string())
                .or_default()
                .push(file.path.as_str());
        }
    }
    declared
}

/// Every name a `use` tree brings in, with the full path it names.
fn use_paths(tree: &UseTree, prefix: &str, found: &mut Vec<(String, String)>) {
    let joined = |ident: &syn::Ident| match prefix {
        "" => ident.to_string(),
        _ => format!("{prefix}::{ident}"),
    };
    match tree {
        UseTree::Path(path) => use_paths(&path.tree, &joined(&path.ident), found),
        UseTree::Name(name) => found.push((name.ident.to_string(), joined(&name.ident))),
        UseTree::Rename(rename) => found.push((rename.rename.to_string(), joined(&rename.ident))),
        UseTree::Group(group) => group
            .items
            .iter()
            .for_each(|item| use_paths(item, prefix, found)),
        UseTree::Glob(_) => {}
    }
}

/// The file declaring the type an `impl` in `file` is for, when more than
/// one file declares a type of that name: the file itself, or the one the
/// file imports it from. One name declared once needs no telling apart.
fn owner_of<'a>(
    file: &SourceFile,
    name: &str,
    written: &syn::Path,
    declarers: &[&'a str],
) -> Option<&'a str> {
    if declarers.len() < 2 {
        return None;
    }
    if let Some(own) = declarers.iter().copied().find(|path| *path == file.path) {
        return Some(own);
    }
    let mut imported = Vec::new();
    for import in file.inventory().uses {
        use_paths(&import.tree, "", &mut imported);
    }
    let full = match written.segments.len() {
        1 => imported
            .into_iter()
            .find(|(visible, _)| visible == name)
            .map(|(_, full)| full)?,
        _ => path_text(written),
    };
    let folder = full
        .trim_start_matches("crate::")
        .rsplit_once("::")
        .map(|(module, _)| module.replace("::", "/"))?;
    declarers
        .iter()
        .find(|path| path.starts_with(&format!("{folder}/")) || **path == format!("{folder}.rs"))
        .copied()
}

/// A type by its name and the file declaring it, when one can be told.
type OwnedType<'a> = (String, Option<&'a str>);

/// Where an `impl` block sits: the index of its file and its line.
type BlockAt = (usize, usize);

/// Where a type's inherent methods are spread over more than one `impl`
/// block, unless the type is listed with the reason it is: a reader looking
/// for what a type does should find it in one place. Two types of one name
/// in different modules are told apart by the file declaring each.
pub(crate) fn split_impls(files: &[SourceFile], allowed: &[(&str, &str)]) -> Findings {
    let mut findings = Findings::default();
    for ((name, _), blocks) in inherent_blocks(files) {
        if blocks.len() < 2 || allowed.iter().any(|(listed, _)| *listed == name) {
            continue;
        }
        for (index, line) in blocks.into_iter().skip(1) {
            findings.flag_line(
                &files[index],
                line,
                format!("a further `impl {name}` block; keep its methods in one"),
            );
        }
    }
    findings
}

/// Where each type's inherent `impl` blocks are, by the type and the file
/// declaring it.
fn inherent_blocks(files: &[SourceFile]) -> BTreeMap<OwnedType<'_>, Vec<BlockAt>> {
    let declared = declaring_files(files);
    let mut seen: BTreeMap<OwnedType<'_>, Vec<BlockAt>> = BTreeMap::new();
    for (index, file) in files.iter().enumerate() {
        for block in file.inventory().impls {
            if block.trait_.is_some() {
                continue;
            }
            let syn::Type::Path(self_type) = block.self_ty.as_ref() else {
                continue;
            };
            let Some(name) = self_type.path.segments.last() else {
                continue;
            };
            let name = name.ident.to_string();
            let declarers = declared.get(&name).map_or(&[][..], Vec::as_slice);
            let owner = owner_of(file, &name, &self_type.path, declarers);
            seen.entry((name, owner))
                .or_default()
                .push((index, line_of(block)));
        }
    }
    seen
}

/// The most lines of code a file holds before its tests, comments and
/// blank lines left out. A file past it holds more than one topic.
pub(crate) const MAX_CODE_LINES: usize = 550;

/// Where a file holds more than `cap` lines of code before its tests: it
/// should be split by topic, as the domain's files were.
pub(crate) fn files_longer_than(files: &[SourceFile], cap: usize) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let code = file
            .lines_before_tests()
            .into_iter()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("//"))
            .count();
        if code > cap {
            findings.flag_line(
                file,
                1,
                format!("{code} lines of code, more than {cap}; split it by topic"),
            );
        }
    }
    findings
}

/// Where a function is named `set_`: a change to a domain value is a named
/// action that checks its own rules, such as `rename`, `replace_scopes` or
/// `raise_data_class`, never a setter that writes whatever it is handed.
pub(crate) fn setters(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for block in file.inventory().impls {
            for item in &block.items {
                let ImplItem::Fn(function) = item else {
                    continue;
                };
                if function.sig.ident.to_string().starts_with("set_") {
                    findings.flag(
                        file,
                        function,
                        "a setter; name the action the change is and check its rules there",
                    );
                }
            }
        }
    }
    findings
}

/// Where a `reconstitute` cannot refuse its row: every aggregate checks a
/// stored row against the rules it keeps, and refuses one that breaks them
/// as corrupt, so none may promise to rebuild whatever it is handed.
pub(crate) fn infallible_reconstitutes(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for block in file.inventory().impls {
            for item in &block.items {
                let ImplItem::Fn(function) = item else {
                    continue;
                };
                if function.sig.ident == "reconstitute"
                    && !Returns::MaybeRefused.matches(file, &function.sig.output)
                {
                    findings.flag(
                        file,
                        function,
                        "a `reconstitute` that cannot refuse; return `Result<Self, DomainError>` and check the row",
                    );
                }
            }
        }
    }
    findings
}

/// The text of every `fn payload` body in a file's building part.
fn payload_bodies(lines: &[&str]) -> Vec<(usize, String)> {
    let mut bodies = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !lines[index].trim_start().starts_with("fn payload(") {
            index += 1;
            continue;
        }
        let start = index;
        let mut depth = 0i32;
        let mut text = String::new();
        loop {
            let line = lines[index];
            depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
            text.push_str(line);
            text.push('\n');
            index += 1;
            if depth <= 0 || index == lines.len() {
                break;
            }
        }
        bodies.push((start + 1, text));
    }
    bodies
}

/// The methods an audit payload names a value with, its key first.
const PAYLOAD_KEY_METHODS: [&str; 6] = [
    "field",
    "optional",
    "reference",
    "optional_reference",
    "change",
    "change_between",
];

/// Every key an audit payload is written under, once each, sorted. Pinned
/// by a snapshot, so a misspelt or renamed key fails a test instead of
/// quietly giving readers of stored records a field they never look for.
pub(crate) fn payload_keys(files: &[SourceFile]) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for file in files {
        let text = file.lines_before_tests().join("\n");
        if !text.contains("EventData") {
            continue;
        }
        let compact: String = text
            .split('(')
            .map(str::trim_start)
            .collect::<Vec<_>>()
            .join("(");
        for method in PAYLOAD_KEY_METHODS {
            let opening = format!(".{method}(\"");
            for (at, _) in compact.match_indices(&opening) {
                let rest = &compact[at + opening.len()..];
                if let Some(end) = rest.find('"') {
                    keys.insert(rest[..end].to_owned());
                }
            }
        }
    }
    keys
}

/// Where an audit payload writes a value through `Debug`: renaming a variant
/// would then quietly change records already stored. A stable name belongs
/// there instead.
pub(crate) fn debug_formatting_in_payloads(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (line, body) in payload_bodies(&file.lines_before_tests()) {
            if body.contains(":?}") {
                findings.flag_line(
                    file,
                    line,
                    "a payload written with `{:?}`; record a stable name",
                );
            }
        }
    }
    findings
}

/// Where a field's doc speaks of `None` though the field is no `Option`:
/// a doc left from before the field was given a type that names its cases.
pub(crate) fn docs_naming_a_none_that_is_not_there(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for declared in file.inventory().fields {
            let docs: String = declared
                .field
                .attrs
                .iter()
                .filter(|attribute| attribute.path().is_ident("doc"))
                .map(|attribute| file.text_of(attribute))
                .collect();
            if docs.contains("`None`") && option_of(&declared.field.ty).is_none() {
                findings.flag(
                    file,
                    declared.field,
                    format!(
                        "`{}.{}` is documented as `None`, but it is not an `Option`",
                        declared.owner, declared.name
                    ),
                );
            }
        }
    }
    findings
}

/// Where a function checks a list for a repeat by hand, with a set it
/// inserts into, instead of the shared `first_repeat`.
pub(crate) fn repeat_checks_by_hand(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        if file.path == "shared/validation/distinct.rs" {
            continue;
        }
        for function in file.inventory().functions {
            let body = file.text_of(function.body);
            let tracks_a_path = body.contains(".remove(");
            if body.contains("HashSet::") && !tracks_a_path && finds_a_repeat(&body) {
                findings.flag(
                    file,
                    function.body,
                    "a repeat found by hand; use `distinct::first_repeat`",
                );
            }
        }
    }
    findings
}

/// Whether code inserts into a set to find a repeat: a refused insert inside
/// `any`, `find` or `all`, or one that is returned on. A walk that skips
/// what it has seen goes on instead, and a set that values also leave
/// tracks a path; neither is one.
fn finds_a_repeat(body: &str) -> bool {
    body.match_indices(".insert(").any(|(at, _)| {
        let before = &body[..at];
        let name_start = before.trim_end_matches(|c: char| c.is_alphanumeric() || c == '_');
        if !name_start.ends_with('!') {
            return false;
        }
        let lead = &before[before.len().saturating_sub(40)..];
        let in_a_search = ["any(|", "find(|", "all(|"]
            .iter()
            .any(|open| lead.contains(open));
        let tail = &body[at..body.len().min(at + 80)];
        in_a_search || tail.contains("return")
    })
}

/// The events a file declares through the event macros.
fn declared_events(lines: &[&str]) -> Vec<String> {
    let mut events = Vec::new();
    for pair in lines.windows(2) {
        let opens = [
            "tenant_event! {",
            "organization_event! {",
            "platform_event! {",
        ]
        .iter()
        .any(|open| pair[0].trim() == *open);
        let Some((name, _)) = pair[1].trim().split_once(" =>") else {
            continue;
        };
        if opens {
            events.push(name.to_owned());
        }
    }
    events
}

/// Every event the domain declares, through the event macros or by hand.
fn event_names(files: &[SourceFile]) -> BTreeSet<String> {
    files
        .iter()
        .flat_map(|file| declared_events(&file.lines()))
        .chain(
            HAND_WRITTEN_EVENTS
                .iter()
                .map(|(name, _)| (*name).to_owned()),
        )
        .collect()
}

/// The macros the domain declares its events with.
const EVENT_MACROS: [&str; 3] = ["tenant_event", "organization_event", "platform_event"];

/// The fields declared `pub` in a macro's tokens: `pub` followed by a name
/// and a single `:`.
fn public_fields_in(tokens: &TokenStream) -> Vec<String> {
    let trees: Vec<TokenTree> = tokens.clone().into_iter().collect();
    let nested = trees.iter().flat_map(|tree| match tree {
        TokenTree::Group(group) => public_fields_in(&group.stream()),
        _ => Vec::new(),
    });
    let here = trees.windows(4).filter_map(|window| match window {
        [
            TokenTree::Ident(public),
            TokenTree::Ident(name),
            TokenTree::Punct(colon),
            next,
        ] if public == "pub"
            && colon.as_char() == ':'
            && !matches!(next, TokenTree::Punct(more) if more.as_char() == ':') =>
        {
            Some(name.to_string())
        }
        _ => None,
    });
    here.chain(nested).collect()
}

/// Whether a `macro_rules!` declares events, by calling an event macro.
fn declares_events(item: &syn::ItemMacro) -> bool {
    item.ident.is_some()
        && EVENT_MACROS
            .iter()
            .any(|name| tokens_name(&item.mac.tokens, name))
}

/// Where an event struct has a `pub` field: one the application could read
/// or, with every field `pub`, fill in itself.
pub(crate) fn public_event_fields(files: &[SourceFile]) -> Findings {
    let events = event_names(files);
    let mut findings = Findings::default();
    for file in files {
        let inventory = file.inventory();
        for item in &inventory.structs {
            if !events.contains(&item.ident.to_string()) {
                continue;
            }
            let why = format!(
                "`{}` is an event with a `pub` field; make it `pub(crate)`",
                item.ident
            );
            for field in
                (item.fields.iter()).filter(|field| matches!(field.vis, Visibility::Public(_)))
            {
                findings.flag(file, field, why.clone());
            }
        }
        flag_event_macros(file, &mut findings);
    }
    findings
}

/// Flags each `pub` field of the events the `event_types!` macros of
/// `file` declare.
fn flag_event_macros(file: &SourceFile, findings: &mut Findings) {
    let inventory = file.inventory();
    for item in inventory
        .item_macros
        .iter()
        .filter(|item| declares_events(item))
    {
        for field in public_fields_in(&item.mac.tokens) {
            let why = format!(
                "events from this macro have a `pub` field `{field}`; make it `pub(crate)`"
            );
            findings.flag(file, *item, why);
        }
    }
}

/// The folder a file sits in, below `src/`.
fn folder_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(folder, _)| folder)
}

/// Where a folder keeps an `every_event` list for its guard tests but an
/// event of the folder is missing from it, so the guard never checks it.
pub(crate) fn events_missing_from_their_list(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    let mut lists: BTreeMap<&str, (&SourceFile, String)> = BTreeMap::new();
    for file in files {
        let text = file.lines().join("\n");
        let Some(start) = text.find("fn every_event(") else {
            continue;
        };
        let list = text[start..]
            .split("\n    }\n")
            .next()
            .unwrap_or_default()
            .to_owned();
        lists.insert(folder_of(&file.path), (file, list));
    }
    for file in files {
        let Some((owner, list)) = lists.get(folder_of(&file.path)) else {
            continue;
        };
        for event in declared_events(&file.lines_before_tests()) {
            let listed = list.contains(&format!("{event} {{"));
            if !listed {
                findings.flag_line(
                    owner,
                    1,
                    format!("`{event}` from {} is missing from `every_event`", file.path),
                );
            }
        }
    }
    findings
}

/// The names a `use` tree brings in, leaving out globs and `self`.
fn imported_names(tree: &UseTree, names: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => imported_names(&path.tree, names),
        UseTree::Name(name) if name.ident != "self" => names.push(name.ident.to_string()),
        UseTree::Rename(rename) => names.push(rename.rename.to_string()),
        UseTree::Group(group) => group
            .items
            .iter()
            .for_each(|item| imported_names(item, names)),
        UseTree::Name(_) | UseTree::Glob(_) => {}
    }
}

/// The code of `file` before its tests, its `use` lines left out.
fn code_without_imports(file: &SourceFile) -> String {
    let is_import = |line: &str| {
        let line = line.trim_start();
        line.starts_with("use ") || line.starts_with("pub use ")
    };
    let lines = file.lines_before_tests();
    (lines.iter().copied())
        .filter(|line| !is_import(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Where a file imports a name it never uses itself, kept only so a child
/// module's glob import of it picks the name up. Each file imports what it
/// uses.
pub(crate) fn imports_held_for_others(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let code = code_without_imports(file);
        let used = words(&code);
        for item in file.items() {
            let Item::Use(import) = item else {
                continue;
            };
            if !matches!(import.vis, Visibility::Inherited) || is_test_module(item) {
                continue;
            }
            let mut names = Vec::new();
            imported_names(&import.tree, &mut names);
            let for_methods = |name: &str| {
                (TRAITS_IMPORTED_FOR_METHODS.iter())
                    .any(|(path, trait_name, _)| *path == file.path && *trait_name == name)
            };
            for name in names
                .iter()
                .filter(|name| !used.contains(name.as_str()) && !for_methods(name))
            {
                findings.flag_line(
                    file,
                    line_of(import),
                    format!("`{name}` is imported but not used here"),
                );
            }
        }
    }
    findings
}

/// Files whose name repeats their folder's name, or, outside `types/`, the
/// name of the folder above it, anywhere in it, singular or plural. A path
/// reads as one phrase: `grants/refresh.rs`, never `grants/refresh_grant.rs`.
pub(crate) fn files_repeating_their_folder(
    files: &[SourceFile],
    allowed: &[(&str, &str)],
) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let parts: Vec<&str> = file.path.trim_end_matches(".rs").split('/').collect();
        let Some((stem, folders)) = parts.split_last() else {
            continue;
        };
        if *stem == "mod" || allowed.iter().any(|(path, _)| *path == file.path) {
            continue;
        }
        let folder = folders.last().copied().unwrap_or("");
        let parent = if file.path.starts_with("types/") {
            ""
        } else {
            folders.iter().rev().nth(1).copied().unwrap_or("")
        };
        let repeated = [folder, parent]
            .into_iter()
            .filter(|name| !name.is_empty() && *name != "domains")
            .find(|name| repeats(stem, name));
        if let Some(name) = repeated {
            findings.flag_line(
                file,
                1,
                format!("`{stem}` repeats its folder `{name}`; name it by what it adds"),
            );
        }
    }
    findings
}

/// Whether `stem` holds `folder`'s words in a row, singular or plural,
/// beside at least one word of its own.
fn repeats(stem: &str, folder: &str) -> bool {
    let words: Vec<&str> = stem.split('_').collect();
    let plural: Vec<String> = folder.split('_').map(str::to_owned).collect();
    let mut single = plural.clone();
    if let Some(last) = single.last_mut() {
        *last = singular(last);
    }
    [plural, single].iter().any(|form| {
        words.len() > form.len()
            && words
                .windows(form.len())
                .any(|window| window.iter().zip(form).all(|(word, part)| word == part))
    })
}

/// `word` with a plural ending taken off.
fn singular(word: &str) -> String {
    if let Some(root) = word.strip_suffix("ies") {
        return format!("{root}y");
    }
    if let Some(root) = word.strip_suffix("sses") {
        return format!("{root}ss");
    }
    if word.ends_with('s') && !word.ends_with("ss") {
        return word[..word.len() - 1].to_owned();
    }
    word.to_owned()
}

/// Paths climbing with `super::`, in code or docs, other than a test
/// module's `use super::*;`. A module is named by its full `crate::` path.
pub(crate) fn relative_paths(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (index, line) in file.lines().iter().enumerate() {
            let climbs = line
                .match_indices("super::")
                .any(|(at, _)| !line[at..].starts_with("super::*"));
            if climbs {
                findings.flag_line(
                    file,
                    index + 1,
                    "names a module through `super::`; write its `crate::` path",
                );
            }
        }
    }
    findings
}
