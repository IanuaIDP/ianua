//! Gives every outward refusal its catalog key in the source: each literal,
//! `format!` message or text constant handed to a refusal is wrapped as
//! `message!("<key>", <the same message>)`, so the error carries the key
//! and its named values beside the English text.
//!
//! Nothing else changes: the message keeps its exact source text, a
//! message already keyed is left alone, and a run over rewritten source
//! changes nothing. An application error built from other text is given
//! the conversion its `Refusal` needs; other messages passed through a
//! variable or helper are listed, not guessed at. Test code is converted
//! where a type needs it and never keyed.

mod edit;
mod imports;
mod sites;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{fmt, fs};

use self::edit::{Offsets, Replacement, applied};
use self::sites::{Code, Receiver, Shape, Site, sites};
use crate::catalog::{Catalog, MessageKey, Syntax};
use crate::error::{Error, Result, io_at};

/// The crate whose files name the macro through `crate::`.
const DOMAIN_SOURCE: &str = "crates/ianua-domain/src/";

/// Crates that build no refusal of the platform's.
const SKIPPED_CRATES: &[&str] = &[
    "ianua-audit",
    "ianua-macros",
    "ianua-proto",
    "ianua-scenarios",
    "ianua-translate",
    "ianua-workspace-hack",
];

/// Folders whose code only tests or the demo seeder compile.
const TEST_FOLDERS: &[&str] = &["tests", "test_support", "demo"];

/// Whether a run writes the rewritten files or only counts what it would change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Count and list, writing nothing.
    DryRun,
    /// Write every rewritten file.
    Apply,
}

/// What a run found and changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// Refusals given their key.
    pub(crate) keyed: usize,
    /// Application errors given the conversion into a `Refusal`.
    pub(crate) converted: usize,
    /// Refusals that already carried a key.
    pub(crate) already_keyed: usize,
    /// Files changed, or that would change.
    pub(crate) files: usize,
    /// Refusals whose message comes through a variable or helper, by location.
    pub(crate) dynamic: Vec<String>,
    /// Refusal text the catalog has no key for, by location.
    pub(crate) unknown: Vec<String>,
}

impl fmt::Display for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "{} refusals keyed and {} converted in {} files; {} already keyed; {} passed through a variable or helper; {} not in the catalog",
            self.keyed,
            self.converted,
            self.files,
            self.already_keyed,
            self.dynamic.len(),
            self.unknown.len()
        )?;
        for location in &self.unknown {
            writeln!(formatter, "not in the catalog: {location}")?;
        }
        for location in &self.dynamic {
            writeln!(formatter, "through a variable or helper: {location}")?;
        }
        Ok(())
    }
}

/// The keys a rewrite gives: by message text, and by the constant that
/// holds it, defined in the same file or imported from the nearest file
/// that defines a constant of that name.
struct Keys<'a> {
    by_text: HashMap<(&'a str, Syntax), &'a MessageKey>,
    by_constant_name: HashMap<&'a str, Vec<(&'a str, &'a MessageKey)>>,
}

impl<'a> Keys<'a> {
    fn of(catalog: &'a Catalog) -> Self {
        let keyed = catalog
            .messages
            .iter()
            .filter_map(|message| Some((message, message.key.as_ref()?)));
        let by_text = keyed
            .clone()
            .map(|(message, key)| ((message.english.as_str(), message.syntax), key))
            .collect();
        let mut by_constant_name: HashMap<&str, Vec<(&str, &MessageKey)>> = HashMap::new();
        let constants = keyed
            .filter(|(message, _)| message.syntax == Syntax::Plain)
            .flat_map(|(message, key)| {
                message
                    .occurrences
                    .iter()
                    .map(move |occurrence| (occurrence, key))
            });
        for (occurrence, key) in constants {
            by_constant_name
                .entry(occurrence.context.as_str())
                .or_default()
                .push((occurrence.path.as_str(), key));
        }
        Self {
            by_text,
            by_constant_name,
        }
    }

    /// The key of a site's message, when it has one.
    fn of_site(&self, path: &str, shape: &Shape) -> Option<&'a MessageKey> {
        if let Shape::Constant { name } = shape {
            return self.of_constant(path, name);
        }
        let english = shape.english()?;
        let syntax = shape.syntax()?;
        self.by_text.get(&(english, syntax)).copied()
    }

    /// The key of the constant `name` whose defining file shares the most
    /// folders with `path`, when exactly one is nearest.
    fn of_constant(&self, path: &str, name: &str) -> Option<&'a MessageKey> {
        let candidates = self.by_constant_name.get(name)?;
        let nearness = |defined: &str| shared_folders(path, defined);
        let nearest = candidates
            .iter()
            .map(|(defined, _)| nearness(defined))
            .max()?;
        let mut keys = candidates
            .iter()
            .filter(|(defined, _)| nearness(defined) == nearest)
            .map(|(_, key)| *key);
        let key = keys.next()?;
        keys.all(|other| other == key).then_some(key)
    }
}

/// How many leading folders two paths share; the same file counts one more.
fn shared_folders(first: &str, second: &str) -> usize {
    if first == second {
        return usize::MAX;
    }
    first
        .split('/')
        .zip(second.split('/'))
        .take_while(|(left, right)| left == right)
        .count()
}

/// Rewrites every file that builds a refusal.
///
/// # Errors
///
/// Refuses a catalog with unkeyed messages, an unreadable or unparsable
/// file, and a rewritten file that no longer parses; in that case nothing
/// of that file is written.
pub(crate) fn rewrite(root: &Path, catalog: &Catalog, mode: Mode) -> Result<Report> {
    catalog.ensure_keyed()?;
    let keys = Keys::of(catalog);
    let mut report = Report::default();
    for file in rust_files(root)? {
        let path = relative(root, &file);
        let source = fs::read_to_string(&file).map_err(io_at(&file))?;
        let Some(result) = rewritten(&path, &source, &keys, &mut report)? else {
            continue;
        };
        report.files += 1;
        if mode == Mode::Apply {
            fs::write(&file, result).map_err(io_at(&file))?;
        }
    }
    Ok(report)
}

/// Every Rust file of the platform's crates, sources and tests, in path order.
fn rust_files(root: &Path) -> Result<Vec<PathBuf>> {
    let crates = root.join("crates");
    let mut found = Vec::new();
    for entry in fs::read_dir(&crates).map_err(io_at(&crates))? {
        let entry = entry.map_err(io_at(&crates))?;
        if SKIPPED_CRATES
            .iter()
            .any(|skipped| entry.file_name() == *skipped)
        {
            continue;
        }
        for folder in ["src", "tests"] {
            let directory = entry.path().join(folder);
            if directory.is_dir() {
                walk(&directory, &mut found)?;
            }
        }
    }
    found.sort();
    Ok(found)
}

fn walk(directory: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory).map_err(io_at(directory))? {
        let path = entry.map_err(io_at(directory))?.path();
        if path.is_dir() {
            walk(&path, found)?;
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Whether a file is test code by where it lives.
fn code_of(path: &str) -> Code {
    let in_test_folder = path.split('/').any(|part| TEST_FOLDERS.contains(&part));
    if in_test_folder {
        return Code::Test;
    }
    Code::Production
}

/// The source of `path` with its refusals keyed, or none when nothing changes.
fn rewritten(
    path: &str,
    source: &str,
    keys: &Keys<'_>,
    report: &mut Report,
) -> Result<Option<String>> {
    let parsed = parsed(path, source)?;
    let file = FileSites {
        path,
        offsets: Offsets::new(source),
        keys,
    };
    let replacements: Vec<Replacement> = sites(&parsed, code_of(path))
        .iter()
        .filter_map(|site| file.replacement(site, report))
        .collect();
    let keyed = rewritten_with(path, source, replacements, report)?;
    let current = keyed.as_deref().unwrap_or(source);
    let short = short_named(path, current, report)?;
    Ok(short.or(keyed))
}

/// `source` with the refusal macro named short in production code and
/// imported once, or none when nothing changes. Test files keep the path.
fn short_named(path: &str, source: &str, report: &mut Report) -> Result<Option<String>> {
    if code_of(path) == Code::Test {
        return Ok(None);
    }
    let import = format!("use {};", macro_path(path));
    let replacements = imports::shortened(&parsed(path, source)?, source, &import);
    rewritten_with(path, source, replacements, report)
}

/// `source` with `replacements` made and checked to parse, or none when
/// there are none.
fn rewritten_with(
    path: &str,
    source: &str,
    replacements: Vec<Replacement>,
    report: &mut Report,
) -> Result<Option<String>> {
    if replacements.is_empty() {
        return Ok(None);
    }
    let (result, skipped) = applied(source, replacements);
    report.unknown.extend(skipped.iter().map(|replacement| {
        format!(
            "{path}:{}: overlaps another rewrite",
            replacement.start.line
        )
    }));
    parsed(path, &result)?;
    Ok(Some(result))
}

fn parsed(path: &str, source: &str) -> Result<syn::File> {
    syn::parse_file(source).map_err(|cause| Error::Rust {
        path: path.to_owned(),
        source: cause,
    })
}

/// One file whose refusals are being keyed: its path, where its lines
/// start, and the keys the catalog holds.
struct FileSites<'a, 'k> {
    path: &'a str,
    offsets: Offsets<'a>,
    keys: &'a Keys<'k>,
}

impl FileSites<'_, '_> {
    /// The replacement one site needs, counting what it cannot key.
    fn replacement(&self, site: &Site, report: &mut Report) -> Option<Replacement> {
        let location = format!(
            "{}:{}:{}",
            self.path,
            site.start.line,
            site.start.column + 1
        );
        match &site.shape {
            Shape::Keyed => {
                report.already_keyed += 1;
                None
            }
            Shape::Dynamic => converted(&self.offsets, site, location, report),
            Shape::Literal { .. } | Shape::Formatted { .. } | Shape::Constant { .. } => {
                self.keyed(site, location, report)
            }
        }
    }

    /// The site's message wrapped with its key.
    fn keyed(&self, site: &Site, location: String, report: &mut Report) -> Option<Replacement> {
        let Some(key) = self.keys.of_site(self.path, &site.shape) else {
            report.unknown.push(location);
            return None;
        };
        let message = match &site.shape {
            Shape::Literal { source, .. } | Shape::Formatted { source, .. } => {
                self.offsets.text(source.start, source.end)?.to_owned()
            }
            Shape::Constant { name } => name.clone(),
            Shape::Keyed | Shape::Dynamic => return None,
        };
        report.keyed += 1;
        Some(Replacement {
            start: site.start,
            end: site.end,
            text: format!("{}!(\"{key}\", {message})", macro_path(self.path)),
        })
    }
}

/// An application error's other text given its conversion into a `Refusal`.
fn converted(
    offsets: &Offsets<'_>,
    site: &Site,
    location: String,
    report: &mut Report,
) -> Option<Replacement> {
    report.dynamic.push(location);
    if site.receiver != Receiver::AppVariant {
        return None;
    }
    let source = offsets.text(site.start, site.end)?;
    if !plainly_text(source) {
        return None;
    }
    report.converted += 1;
    Some(Replacement {
        start: site.start,
        end: site.end,
        text: format!("{source}.into()"),
    })
}

/// Whether an expression is plainly owned text, which an application
/// error's `Refusal` is made from with `.into()`. Anything else, such as a
/// helper's answer, may already be a `Refusal`, and is left as it is.
fn plainly_text(source: &str) -> bool {
    [".to_owned()", ".to_string()", ".clone()"]
        .iter()
        .any(|ending| source.ends_with(ending))
        || source.starts_with("format!")
}

/// How a file names the macro: through `crate::` in the domain, through
/// the domain crate everywhere else.
fn macro_path(path: &str) -> &'static str {
    if path.starts_with(DOMAIN_SOURCE) {
        return "crate::message";
    }
    "ianua_domain::message"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Evidence, Message, Occurrence};

    fn catalog(entries: &[(&str, Syntax, &str, &str)]) -> Catalog {
        let mut catalog = Catalog::new();
        for (english, syntax, key, context) in entries {
            let mut message = Message::new(
                (*english).to_owned(),
                *syntax,
                Occurrence {
                    path: "crates/ianua-app/src/x.rs".to_owned(),
                    line: 1,
                    column: 1,
                    context: (*context).to_owned(),
                    evidence: Evidence::CustomerError,
                    keyed: None,
                },
            );
            message.key = Some(MessageKey::try_from((*key).to_owned()).unwrap());
            catalog.messages.push(message);
        }
        catalog
    }

    fn run(path: &str, source: &str, catalog: &Catalog) -> (Option<String>, Report) {
        let keys = Keys::of(catalog);
        let mut report = Report::default();
        let result = rewritten(path, source, &keys, &mut report).unwrap();
        (result, report)
    }

    /// A literal and a formatted refusal are wrapped with their keys, the
    /// text kept exactly; a conversion of either is dropped.
    #[test]
    fn literal_and_formatted_refusals_are_keyed() {
        let catalog = catalog(&[
            ("Not yours", Syntax::Plain, "people-not-yours", "f"),
            (
                "{name} is taken",
                Syntax::RustFormat,
                "people-is-taken",
                "f",
            ),
        ]);
        let source = "fn f() {\n    AppError::Forbidden(\"Not yours\".into());\n    DomainError::conflict(format!(\"{name} is taken\").into());\n}\n";

        let (result, report) = run("crates/ianua-app/src/x.rs", source, &catalog);

        assert_eq!(
            result.unwrap(),
            "use ianua_domain::message;\nfn f() {\n    AppError::Forbidden(message!(\"people-not-yours\", \"Not yours\"));\n    DomainError::conflict(message!(\"people-is-taken\", format!(\"{name} is taken\")));\n}\n"
        );
        assert_eq!(report.keyed, 2);
    }

    /// A text constant is keyed by the catalog's entry where it is defined.
    #[test]
    fn a_text_constant_is_keyed() {
        let catalog = catalog(&[(
            "changed meanwhile",
            Syntax::Plain,
            "app-changed-meanwhile",
            "CHANGED",
        )]);
        let source = "const CHANGED: &str = \"changed meanwhile\";\nfn f() { DomainError::conflict(CHANGED); }\n";

        let (result, _) = run("crates/ianua-app/src/x.rs", source, &catalog);

        assert!(
            result
                .unwrap()
                .contains("DomainError::conflict(message!(\"app-changed-meanwhile\", CHANGED))")
        );
    }

    /// Domain files import the macro through `crate::`.
    #[test]
    fn domain_files_import_through_the_crate() {
        let catalog = catalog(&[("Choose a name", Syntax::Plain, "values-choose-a-name", "f")]);
        let source = "fn f() { DomainError::invalid(\"Choose a name\"); }";

        let (result, _) = run("crates/ianua-domain/src/types/name.rs", source, &catalog);

        assert_eq!(
            result.unwrap(),
            "use crate::message;\nfn f() { DomainError::invalid(message!(\"values-choose-a-name\", \"Choose a name\")); }"
        );
    }

    /// Running the rewrite twice leaves the source unchanged and counts the existing keyed refusal.
    #[test]
    fn a_second_run_changes_nothing() {
        let catalog = catalog(&[("Choose a name", Syntax::Plain, "values-choose-a-name", "f")]);
        let source = "fn f() { DomainError::invalid(\"Choose a name\"); AppError::Conflict(why.to_owned()); }";
        let (first, _) = run("crates/ianua-app/src/x.rs", source, &catalog);

        let (second, report) = run("crates/ianua-app/src/x.rs", &first.unwrap(), &catalog);

        assert_eq!(second, None);
        assert_eq!(report.already_keyed, 1);
    }

    /// An application error built from other text is converted into its
    /// `Refusal`; a domain refusal, which takes any text, is left alone.
    #[test]
    fn other_text_is_converted_only_where_a_refusal_is_needed() {
        let catalog = catalog(&[]);
        let source = "fn f(m: String) { AppError::Conflict(m.clone()); DomainError::invalid(m); }";

        let (result, report) = run("crates/ianua-app/src/x.rs", source, &catalog);

        assert_eq!(
            result.unwrap(),
            "fn f(m: String) { AppError::Conflict(m.clone().into()); DomainError::invalid(m); }"
        );
        assert_eq!(report.converted, 1);
        assert_eq!(report.dynamic.len(), 2);
    }

    /// Passing a helper's result to an application error leaves the source
    /// unchanged, with no conversion recorded.
    #[test]
    fn a_helpers_answer_is_not_converted() {
        let catalog = catalog(&[]);
        let source = "fn f() { AppError::NotFound(invalid_link()); }";

        let (result, report) = run("crates/ianua-app/src/x.rs", source, &catalog);

        assert_eq!(result, None);
        assert_eq!(report.converted, 0);
    }

    /// Test code is converted but never keyed, even when its text is in the catalog.
    #[test]
    fn messages_in_tests_are_never_keyed() {
        let catalog = catalog(&[("Not yours", Syntax::Plain, "people-not-yours", "f")]);
        let source = "fn t() { AppError::Forbidden(\"Not yours\".to_owned()); }";

        let (result, report) = run("crates/ianua-app/tests/x.rs", source, &catalog);

        assert_eq!(
            result.unwrap(),
            "fn t() { AppError::Forbidden(\"Not yours\".to_owned().into()); }"
        );
        assert_eq!(report.keyed, 0);
    }
}
