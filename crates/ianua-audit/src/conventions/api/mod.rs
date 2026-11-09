//! The rules the API is written to, checked on its source.
//!
//! Each rule says what it stops. A break is reported with its file and what
//! is wrong, so the fix is clear from the message.

use std::fs;
use std::path::{Path, PathBuf};

use syn::{Item, Visibility};

/// What the source says, by path under `src/`.
struct Source {
    path: String,
    text: String,
}

/// Every Rust file under `src/<under>`, sorted by path.
fn sources(under: &str) -> Vec<Source> {
    let root = crate::conventions::crate_dir("ianua-api").join("src");
    let mut found = Vec::new();
    collect(&root.join(under), &root, &mut found);
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

/// Adds every Rust file under `dir` to `found`, named by its path from
/// `root`. A missing folder adds nothing.
fn collect(dir: &Path, root: &Path, found: &mut Vec<Source>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect(&path, root, found);
            continue;
        }
        if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(Source {
                path: path.strip_prefix(root).unwrap().display().to_string(),
                text: fs::read_to_string(&path).unwrap(),
            });
        }
    }
}

/// Fails with the rule and every break when there are any.
fn assert_none(breaks: &[String], rule: &str) {
    assert!(breaks.is_empty(), "{rule}:\n  {}", breaks.join("\n  "));
}

/// The functions a handler file defines, with whether each is a handler:
/// `async`, seen by the router outside its file (`pub` or `pub(crate)`),
/// and carrying its OpenAPI path.
fn handler_items(source: &Source) -> Vec<(String, bool)> {
    let file = syn::parse_file(&source.text).unwrap();
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) => Some((
                function.sig.ident.to_string(),
                !matches!(function.vis, Visibility::Inherited)
                    && function.sig.asyncness.is_some()
                    && function.attrs.iter().any(|attr| {
                        let path = attr.path();
                        path.segments.len() == 2
                            && path.segments[0].ident == "utoipa"
                            && path.segments[1].ident == "path"
                    }),
            )),
            Item::Use(_) | Item::Mod(_) => None,
            other => Some((format!("a non-function item ({})", item_kind(other)), false)),
        })
        .collect()
}

/// What kind of item this is, for the message.
fn item_kind(item: &Item) -> &'static str {
    match item {
        Item::Struct(_) => "struct",
        Item::Enum(_) => "enum",
        Item::Impl(_) => "impl",
        Item::Const(_) => "const",
        Item::Static(_) => "static",
        Item::Trait(_) => "trait",
        _ => "other",
    }
}

/// Stops: a parsing helper or a mapper written into a handler file, where
/// the next handler copies it. Parsing goes in `extractors/`, mapping in
/// `dto/`. A handler file holds handlers only, each `async`, seen by the
/// router, with its OpenAPI path.
#[cfg_attr(test, test)]
pub(crate) fn handler_files_hold_only_handlers() {
    let breaks: Vec<String> = sources("handlers")
        .iter()
        .filter(|source| !source.path.ends_with("mod.rs"))
        .flat_map(|source| {
            handler_items(source)
                .into_iter()
                .filter(|(_, handler)| !handler)
                .map(|(name, _)| format!("{}: `{name}` is not a documented handler", source.path))
                .collect::<Vec<_>>()
        })
        .collect();

    assert_none(&breaks, "handler files hold only handlers");
}

/// Stops: an endpoint that answers but is missing from the documentation,
/// or a documented endpoint nothing routes to. Every handler is named in its
/// context's `routes/<context>.rs` twice: in a route and in the document.
#[cfg_attr(test, test)]
pub(crate) fn every_handler_is_routed_and_documented() {
    let routes = sources("routes");
    let breaks: Vec<String> = sources("handlers")
        .iter()
        .filter(|source| !source.path.ends_with("mod.rs"))
        .flat_map(|source| {
            let context = context_of(&source.path);
            let route_file = routes
                .iter()
                .find(|route| route.path == format!("routes/{context}.rs"));
            handler_items(source)
                .into_iter()
                .filter(|(_, handler)| *handler)
                .filter(move |(name, _)| {
                    route_file
                        .is_none_or(|route| route.text.matches(&format!("::{name}")).count() < 2)
                })
                .map(|(name, _)| {
                    format!(
                        "{}: `{name}` is not both routed and documented in routes/{}.rs",
                        source.path,
                        context_of(&source.path)
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();

    assert_none(&breaks, "every handler is routed and documented");
}

/// The context a handler file belongs to: `handlers/<context>.rs` or
/// `handlers/<context>/<area>.rs`.
fn context_of(path: &str) -> String {
    let rest = path.trim_start_matches("handlers/");
    rest.split('/')
        .next()
        .unwrap()
        .trim_end_matches(".rs")
        .to_owned()
}

/// Stops: a context whose routes are written but never served, or served
/// but left out of the document. Each `routes/<context>.rs` is documented
/// in `routes/mod.rs` and served there, or from `router.rs` when its routes
/// need the built state (a per-address limit).
#[cfg_attr(test, test)]
pub(crate) fn every_context_is_served_and_documented() {
    let routes = sources("routes");
    let index = routes
        .iter()
        .find(|source| source.path == "routes/mod.rs")
        .unwrap();
    let router = sources("")
        .into_iter()
        .find(|source| source.path == "router.rs")
        .unwrap();
    let breaks: Vec<String> = routes
        .iter()
        .filter(|source| source.path != "routes/mod.rs")
        .map(|source| {
            source
                .path
                .trim_start_matches("routes/")
                .trim_end_matches(".rs")
                .to_owned()
        })
        .filter(|context| {
            let served = index.text.contains(&format!("{context}::routes()"))
                || router.text.contains(&format!("routes::{context}::"));
            !served
                || !index
                    .text
                    .contains(&format!("{context}::Document::openapi()"))
        })
        .map(|context| format!("routes/{context}.rs is not served and documented"))
        .collect();

    assert_none(&breaks, "every context is served and documented");
}

/// What decides what a caller may do, which only the app reads.
const RIGHTS: &[&str] = &[
    "SystemPermission",
    "OrgPermission",
    "OrgRole",
    "ensure_holds",
    "Authorizer",
];

/// Stops: a right checked in the API as well as in the app, which drifts
/// from the app's own check and answers differently from it. The API says
/// who is calling; only the app decides what they may do. Bodies may carry
/// rights as data (a role lists its permissions), so `dto/` is not read,
/// and `state/` only hands the app the ports it checks rights with.
#[cfg_attr(test, test)]
pub(crate) fn the_api_checks_no_right() {
    let breaks: Vec<String> = ["handlers", "extractors", "middleware", "routes"]
        .iter()
        .flat_map(|area| sources(area))
        .flat_map(|source| {
            RIGHTS
                .iter()
                .filter(|right| source.text.contains(**right))
                .map(|right| format!("{} names `{right}`", source.path))
                .collect::<Vec<_>>()
        })
        .collect();

    assert_none(&breaks, "the API checks no right");
}

/// The source is written without em dashes.
#[cfg_attr(test, test)]
pub(crate) fn no_em_dashes() {
    let tests = crate::conventions::crate_dir("ianua-api").join("tests");
    let mut found: Vec<Source> = sources("");
    collect(&tests, &tests, &mut found);
    let breaks: Vec<String> = found
        .iter()
        .filter(|source| source.text.contains('\u{2014}'))
        .map(|source| source.path.clone())
        .collect();

    assert_none(&breaks, "no em dashes");
}

/// Every function in `items` without a doc comment, by name, its line and
/// what it is. Methods of a trait impl are documented by the trait.
fn undocumented(items: &[Item], found: &mut Vec<(String, usize)>) {
    for item in items {
        match item {
            Item::Fn(function) if !documented(&function.attrs) => {
                found.push((function.sig.ident.to_string(), line(&function.sig.ident)));
            }
            Item::Impl(block) if block.trait_.is_none() => {
                for member in &block.items {
                    let syn::ImplItem::Fn(method) = member else {
                        continue;
                    };
                    if !documented(&method.attrs) {
                        found.push((method.sig.ident.to_string(), line(&method.sig.ident)));
                    }
                }
            }
            Item::Mod(module) => {
                if let Some((_, inner)) = &module.content {
                    undocumented(inner, found);
                }
            }
            _ => {}
        }
    }
}

/// Whether the item carries a doc comment.
fn documented(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("doc"))
}

/// The line a name is written on.
fn line(ident: &syn::Ident) -> usize {
    ident.span().start().line
}

/// Stops: a function, method or test whose purpose a reader has to work
/// out from its body. Each says what it does or what it shows, in a `///`
/// comment.
#[cfg_attr(test, test)]
pub(crate) fn every_function_and_test_is_documented() {
    let tests = crate::conventions::crate_dir("ianua-api").join("tests");
    let mut files = sources("");
    collect(&tests, &tests, &mut files);
    let breaks: Vec<String> = files
        .iter()
        .flat_map(|source| {
            let file = syn::parse_file(&source.text).unwrap();
            let mut found = Vec::new();
            undocumented(&file.items, &mut found);
            found
                .into_iter()
                .map(|(name, line)| format!("{}:{line}: `{name}`", source.path))
                .collect::<Vec<_>>()
        })
        .collect();

    assert_none(&breaks, "every function and test is documented");
}

/// The one file that wraps the framework's JSON extractor.
const JSON_EXTRACTOR: &str = "extractors/json.rs";

/// The files that wrap the framework's query and form extractors, by the
/// extractor each wraps.
const QUERY_AND_FORM_EXTRACTORS: &[(&str, &str)] = &[
    ("Query", "extractors/query.rs"),
    ("Form", "extractors/form.rs"),
];

/// Every path to the framework's extractor `name` a source names: in its
/// `use` items, grouped, renamed or behind a glob, and written out in its
/// code.
fn framework_paths(text: &str, name: &str) -> Vec<String> {
    let file = syn::parse_file(text).unwrap();
    let mut imported = Vec::new();
    for item in &file.items {
        let Item::Use(item) = item else {
            continue;
        };
        use_paths(&item.tree, "", &mut imported);
    }
    let written = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("use "))
        .flat_map(written_paths);
    imported
        .into_iter()
        .chain(written)
        .filter(|path| reaches_framework(path, name))
        .collect()
}

/// Every `axum` path written out on `line`.
fn written_paths(line: &str) -> Vec<String> {
    line.match_indices("axum::")
        .map(|(at, _)| path_at(&line[at..]))
        .collect()
}

/// Whether `path` reaches the framework's extractor `name`: names it, or
/// takes all of an `axum` module.
fn reaches_framework(path: &str, name: &str) -> bool {
    path.starts_with("axum::") && (path.ends_with(&format!("::{name}")) || path.ends_with("::*"))
}

/// Adds every path `tree` imports to `found`, each after `prefix`.
fn use_paths(tree: &syn::UseTree, prefix: &str, found: &mut Vec<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            use_paths(&path.tree, &format!("{prefix}{}::", path.ident), found);
        }
        syn::UseTree::Name(name) => found.push(format!("{prefix}{}", name.ident)),
        syn::UseTree::Rename(rename) => found.push(format!("{prefix}{}", rename.ident)),
        syn::UseTree::Glob(_) => found.push(format!("{prefix}*")),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                use_paths(tree, prefix, found);
            }
        }
    }
}

/// The path written at the start of `code`, up to the first character
/// that cannot be part of one.
fn path_at(code: &str) -> String {
    code.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
        .collect::<String>()
        .trim_end_matches(':')
        .to_owned()
}

/// Stops: a handler or extractor taking the framework's `Json` straight,
/// whose refusal of a broken, oversized or mistyped body is a plain-text
/// page instead of the platform's problem body. Bodies are taken, and JSON
/// answered, through `extractors::json::Json` alone.
#[cfg_attr(test, test)]
pub(crate) fn bodies_are_taken_through_the_platform_json() {
    let breaks: Vec<String> = ["handlers", "extractors"]
        .iter()
        .flat_map(|area| sources(area))
        .filter(|source| source.path != JSON_EXTRACTOR)
        .flat_map(|source| {
            framework_paths(&source.text, "Json")
                .into_iter()
                .map(|path| format!("{} names `{path}`", source.path))
                .collect::<Vec<_>>()
        })
        .collect();

    assert_none(&breaks, "bodies are taken through the platform's Json");
}

/// The check above finds the framework's `Json` however it is reached:
/// grouped, renamed, behind a glob, and written out in code. A planted
/// handler file naming it each way is caught four times.
#[cfg_attr(test, test)]
pub(crate) fn a_planted_framework_json_is_caught() {
    let planted = r"
use axum::{Form, Json};
use axum::extract::Json as Body;
use axum::response::*;

async fn sign_in(body: axum::Json<String>) {}
";

    let found = framework_paths(planted, "Json");

    assert_eq!(
        found,
        [
            "axum::Json",
            "axum::extract::Json",
            "axum::response::*",
            "axum::Json"
        ]
    );
}

/// Stops: a handler or extractor taking the framework's `Query` or `Form`
/// straight, whose refusal of a query or form of the wrong shape is a
/// plain-text page that quotes what was sent, instead of the platform's
/// problem body. Queries are taken through `extractors::query::Query`
/// alone, and forms through `extractors::form::Form`.
#[cfg_attr(test, test)]
pub(crate) fn queries_and_forms_are_taken_through_the_platform_extractors() {
    let breaks: Vec<String> = sources("")
        .iter()
        .flat_map(|source| {
            QUERY_AND_FORM_EXTRACTORS
                .iter()
                .filter(|(_, wrapper)| source.path != *wrapper)
                .flat_map(|(name, _)| framework_paths(&source.text, name))
                .map(|path| format!("{} names `{path}`", source.path))
                .collect::<Vec<_>>()
        })
        .collect();

    assert_none(
        &breaks,
        "queries and forms are taken through the platform's Query and Form",
    );
}

/// The check above finds the framework's `Query` and `Form` however they
/// are reached: grouped, renamed, behind a glob, and written out in code. A
/// planted extractor file naming them each way is caught for each, and the
/// platform's own wrappers are not.
#[cfg_attr(test, test)]
pub(crate) fn a_planted_framework_query_or_form_is_caught() {
    let planted = r"
use axum::extract::{Form, Path, Query};
use axum::Form as Posted;
use crate::extractors::query::Query as Platform;

async fn list(params: axum::extract::Query<String>) {}
";

    let queries = framework_paths(planted, "Query");
    let forms = framework_paths(planted, "Form");

    assert_eq!(queries, ["axum::extract::Query", "axum::extract::Query"]);
    assert_eq!(forms, ["axum::extract::Form", "axum::Form"]);
}

/// The fields holding a time, in the structs of `text` that serde reads or
/// writes, that do not name the RFC 3339 module: each as `Struct.field`.
fn times_written_other_than_rfc3339(text: &str) -> Vec<String> {
    struct Times(Vec<String>);
    impl<'ast> syn::visit::Visit<'ast> for Times {
        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            if derives_serde(&item.attrs) {
                for field in &item.fields {
                    let unwritten = holds_a_time(&field.ty) && !names_rfc3339(&field.attrs);
                    if let (true, Some(name)) = (unwritten, &field.ident) {
                        self.0.push(format!("{}.{name}", item.ident));
                    }
                }
            }
            syn::visit::visit_item_struct(self, item);
        }
    }
    let file = syn::parse_file(text).unwrap();
    let mut times = Times(Vec::new());
    syn::visit::Visit::visit_file(&mut times, &file);
    times.0
}

/// Whether `attrs` derive serde's `Serialize` or `Deserialize`.
fn derives_serde(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("derive")
            && attr.meta.require_list().is_ok_and(|list| {
                let derived = list.tokens.to_string();
                derived.contains("Serialize") || derived.contains("Deserialize")
            })
    })
}

/// Whether `ty` is a time or an optional one.
fn holds_a_time(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    let Some(last) = path.path.segments.last() else {
        return false;
    };
    if last.ident == "OffsetDateTime" {
        return true;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return false;
    };
    last.ident == "Option"
        && arguments.args.iter().any(
            |argument| matches!(argument, syn::GenericArgument::Type(inner) if holds_a_time(inner)),
        )
}

/// Whether one of `attrs` is a serde attribute naming the RFC 3339 module.
fn names_rfc3339(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("serde")
            && attr
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string().contains("rfc3339"))
    })
}

/// Stops: a time in a request or an answer written in the time crate's
/// own human-readable form, which no client parses as a standard time and
/// the API's own filters refuse to read back. Every time field of a
/// struct serde reads or writes names `time::serde::rfc3339`.
#[cfg_attr(test, test)]
pub(crate) fn every_time_in_the_json_is_rfc3339() {
    let breaks: Vec<String> = sources("")
        .iter()
        .flat_map(|source| {
            times_written_other_than_rfc3339(&source.text)
                .into_iter()
                .map(|field| format!("{} writes `{field}` other than RFC 3339", source.path))
                .collect::<Vec<_>>()
        })
        .collect();

    assert_none(&breaks, "every time in the JSON is RFC 3339");
}

/// The check above finds a time and an optional time left in the default
/// form, and passes those naming RFC 3339 and structs serde never sees.
#[cfg_attr(test, test)]
pub(crate) fn a_planted_time_in_the_default_form_is_caught() {
    let planted = r#"
#[derive(Serialize)]
struct Answer {
    at: OffsetDateTime,
    until: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    written: OffsetDateTime,
    count: u32,
}

struct Internal {
    at: OffsetDateTime,
}
"#;

    let found = times_written_other_than_rfc3339(planted);

    assert_eq!(found, ["Answer.at", "Answer.until"]);
}
