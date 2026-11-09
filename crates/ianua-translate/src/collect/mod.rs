//! Workspace discovery and collection of backend Rust and built-in templates.

pub(crate) mod rust;
pub(crate) mod scope;
pub(crate) mod tokens;

use std::fs;
use std::path::{Path, PathBuf};

use crate::catalog::{Catalog, Evidence, Message, Occurrence, Syntax};
use crate::error::{Error, Result, io_at};

/// Tooling, generated protocol bindings and test crates are not customer message sources.
const EXCLUDED_CRATES: &[&str] = &[
    "ianua-audit",
    "ianua-macros",
    "ianua-proto",
    "ianua-scenarios",
    "ianua-translate",
    "ianua-workspace-hack",
];

/// Folders below a crate's `src` that hold only tests, fixtures or build output.
const EXCLUDED_FOLDERS: &[&str] = &["test_support", "tests", "demo", "target"];

/// Where the built-in mail and page templates live, relative to the workspace.
pub(crate) const TEMPLATES: &str = "crates/ianua-infra/templates";

/// Collects production Rust messages and complete built-in templates from a workspace.
///
/// # Errors
///
/// Refuses a missing workspace, unreadable files or any Rust parse failure.
/// It never reports a successful inventory after skipping an unreadable source.
pub(crate) fn collect(root: &Path) -> Result<Catalog> {
    ensure_workspace(root)?;
    let mut catalog = Catalog::new();
    collect_rust(root, &mut catalog)?;
    promote_refused_constants(&mut catalog);
    collect_templates(root, &mut catalog)?;
    catalog.finish();
    Ok(catalog)
}

/// Marks the text of every constant handed to a refusal as a refusal's
/// own text. The constant may be defined in another file than the
/// refusal, so it is matched by name.
fn promote_refused_constants(catalog: &mut Catalog) {
    let refused: std::collections::BTreeSet<&str> = catalog
        .dynamic_messages
        .iter()
        .map(|dynamic| dynamic.expression.as_str())
        .filter(|expression| constant_name(expression))
        .collect();
    let occurrences = catalog
        .messages
        .iter_mut()
        .flat_map(|message| message.occurrences.iter_mut());
    for occurrence in occurrences {
        if occurrence.evidence == Evidence::Review && refused.contains(occurrence.context.as_str())
        {
            occurrence.evidence = Evidence::CustomerError;
        }
    }
}

/// Whether an expression is a constant's name, such as `CHANGED_MEANWHILE`.
fn constant_name(expression: &str) -> bool {
    !expression.is_empty()
        && expression.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
}

fn ensure_workspace(root: &Path) -> Result<()> {
    let manifest = root.join("Cargo.toml");
    let text = fs::read_to_string(&manifest).map_err(io_at(&manifest))?;
    if text.contains("[workspace]") {
        return Ok(());
    }
    Err(Error::NotWorkspace(root.to_path_buf()))
}

/// Reads every production Rust file, then drops those inside modules
/// another file compiles only for tests.
fn collect_rust(root: &Path, catalog: &mut Catalog) -> Result<()> {
    let mut scanned = Vec::new();
    let mut excluded = Vec::new();
    for path in rust_sources(root)? {
        let relative = relative(root, &path);
        let text = fs::read_to_string(&path).map_err(io_at(&path))?;
        let found = rust::collect(&relative, &text)?;
        excluded.extend(found.excluded_modules.iter().cloned());
        scanned.push((relative, found));
    }
    let live = scanned
        .into_iter()
        .filter(|(path, _)| !excluded.iter().any(|module| belongs_to(path, module)));
    for (path, found) in live {
        catalog.scanned_files.push(path);
        catalog.messages.extend(found.messages);
        catalog.dynamic_messages.extend(found.dynamic);
    }
    Ok(())
}

/// Every Rust file below production crate roots, in deterministic path order.
fn rust_sources(root: &Path) -> Result<Vec<PathBuf>> {
    let crates = root.join("crates");
    let mut found = Vec::new();
    for entry in fs::read_dir(&crates).map_err(io_at(&crates))? {
        let entry = entry.map_err(io_at(&crates))?;
        let source = entry.path().join("src");
        if excluded_crate(&entry.file_name()) || !source.is_dir() {
            continue;
        }
        files(&source, &["rs"], &mut found)?;
    }
    found.sort();
    Ok(found)
}

fn excluded_crate(name: &std::ffi::OsStr) -> bool {
    EXCLUDED_CRATES.iter().any(|excluded| name == *excluded)
}

/// Adds regular files with the given extensions, without following
/// symlinks or entering fixture folders.
pub(crate) fn files(directory: &Path, extensions: &[&str], found: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory).map_err(io_at(directory))? {
        let entry = entry.map_err(io_at(directory))?;
        let kind = entry.file_type().map_err(io_at(entry.path()))?;
        let path = entry.path();
        if kind.is_dir() && !excluded_folder(&entry.file_name()) {
            files(&path, extensions, found)?;
            continue;
        }
        if kind.is_file() && has_extension(&path, extensions) {
            found.push(path);
        }
    }
    Ok(())
}

fn excluded_folder(name: &std::ffi::OsStr) -> bool {
    EXCLUDED_FOLDERS.iter().any(|excluded| name == *excluded)
}

fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extensions.contains(&extension))
}

/// Keeps each mail and page template whole so sentence order and inline markup are not lost.
fn collect_templates(root: &Path, catalog: &mut Catalog) -> Result<()> {
    let mut paths = Vec::new();
    files(&root.join(TEMPLATES), &["html", "txt"], &mut paths)?;
    if paths.is_empty() {
        return Err(Error::NoTemplates);
    }
    paths.sort();
    for path in paths {
        let relative = relative(root, &path);
        let english = fs::read_to_string(&path).map_err(io_at(&path))?;
        catalog.scanned_files.push(relative.clone());
        catalog.messages.push(template(english, relative));
    }
    Ok(())
}

fn template(english: String, path: String) -> Message {
    Message::new(
        english,
        Syntax::MiniJinja,
        Occurrence {
            path,
            line: 1,
            column: 1,
            context: "complete_template".to_owned(),
            evidence: Evidence::Template,
            keyed: None,
        },
    )
}

/// A portable source path below the explicit workspace root.
fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Whether a path is either on-disk layout of a disabled external Rust module.
fn belongs_to(path: &str, module: &str) -> bool {
    path == format!("{module}.rs") || path.starts_with(&format!("{module}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a source fixture below a temporary workspace without touching real source files.
    fn write(root: &Path, path: &str, source: &str) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, source).unwrap();
    }

    /// A small workspace with a real outward error and one page template for collection tests.
    fn workspace() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        write(directory.path(), "Cargo.toml", "[workspace]\n");
        write(
            directory.path(),
            "crates/ianua-app/src/lib.rs",
            "fn invite() { AppError::Forbidden(\"Invitation refused\".into()); }",
        );
        write(
            directory.path(),
            "crates/ianua-infra/templates/pages/login.html",
            "<h1>Hello {{ name }}</h1>",
        );
        directory
    }

    /// The catalog includes whole page content and excludes inline tests and external fixtures.
    #[test]
    fn a_workspace_scan_collects_templates_and_leaves_test_modules_out() {
        let directory = workspace();
        write(
            directory.path(),
            "crates/ianua-app/src/lib.rs",
            r#"
            fn invite() { AppError::Forbidden("Invitation refused".into()); }
            #[cfg(test)] mod fixtures;
        "#,
        );
        write(
            directory.path(),
            "crates/ianua-app/src/fixtures.rs",
            "fn fixture() { AppError::Forbidden(\"A fixture refusal\".into()); }",
        );
        let catalog = collect(directory.path()).unwrap();
        assert_eq!(catalog.messages.len(), 2);
        assert_eq!(catalog.scanned_files.len(), 2);
        assert!(
            catalog
                .messages
                .iter()
                .any(|message| message.english == "<h1>Hello {{ name }}</h1>")
        );
    }

    /// Invalid Rust aborts collection and the error identifies the source file that failed parsing.
    #[test]
    fn an_unreadable_rust_file_refuses_the_complete_collection() {
        let directory = workspace();
        write(
            directory.path(),
            "crates/ianua-app/src/lib.rs",
            "fn broken(",
        );
        let error = collect(directory.path()).unwrap_err();
        assert!(error.to_string().contains("crates/ianua-app/src/lib.rs"));
    }

    /// A package manifest without a workspace section is refused as a collection root.
    #[test]
    fn a_folder_that_is_not_the_workspace_is_refused() {
        let directory = workspace();
        write(directory.path(), "Cargo.toml", "[package]\n");
        assert!(matches!(
            collect(directory.path()),
            Err(Error::NotWorkspace(_))
        ));
    }

    /// Repeating collection over unchanged sources produces byte-for-byte identical exchange data.
    #[test]
    fn collection_is_deterministic() {
        let directory = workspace();
        let first = serde_json::to_vec(&collect(directory.path()).unwrap()).unwrap();
        let second = serde_json::to_vec(&collect(directory.path()).unwrap()).unwrap();
        assert_eq!(first, second);
    }

    /// Startup diagnostics, stored-row labels and protocol payloads are
    /// excluded; the scan retains only the public refusal and page template.
    #[test]
    fn internal_prose_and_error_displays_do_not_enter_the_catalog() {
        let directory = workspace();
        write(
            directory.path(),
            "crates/ianua-boot/src/env.rs",
            r#"
            #[derive(thiserror::Error)]
            enum Error { #[error("the startup setting is invalid")] Invalid }
            fn setup() { let message = "opening the internal database"; }
            "#,
        );
        write(
            directory.path(),
            "crates/ianua-infra/src/postgres/example.rs",
            r#"
            fn reconstitute() {
                RowCheck::of("stored account").holds(false, "changed before creation");
                let wire = "<Assertion Subject=\"{subject}\">{body}</Assertion>";
            }
            "#,
        );
        let catalog = collect(directory.path()).unwrap();
        assert_eq!(catalog.messages.len(), 2);
        assert!(catalog.messages.iter().all(Message::outward));
    }

    /// Customer setup instructions and typed pipeline refusals are returned
    /// indirectly. They remain translatable when general prose is excluded.
    #[test]
    fn indirect_response_text_remains_in_the_catalog() {
        let directory = workspace();
        write(
            directory.path(),
            "crates/ianua-api/src/dto/organization/cloud_accounts.rs",
            "fn steps() { vec![\"Paste the token here.\"] }",
        );
        write(
            directory.path(),
            "crates/ianua-domain/src/domains/proxy/pipeline/error.rs",
            r#"
            #[derive(thiserror::Error)]
            enum PipelineError { #[error("stage not found in the pipeline")] StageNotFound }
            "#,
        );
        let catalog = collect(directory.path()).unwrap();
        for expected in ["Paste the token here.", "stage not found in the pipeline"] {
            assert!(
                catalog
                    .messages
                    .iter()
                    .any(|message| message.english == expected && message.outward())
            );
        }
    }

    /// A refusal using a constant from another file brings that constant's
    /// text into the catalog as an outward message.
    #[test]
    fn a_constant_handed_to_a_refusal_is_collected() {
        let directory = workspace();
        write(
            directory.path(),
            "crates/ianua-infra/src/http/messages.rs",
            "pub(crate) const REFUSED: &str = \"the address may not be reached\";",
        );
        write(
            directory.path(),
            "crates/ianua-infra/src/http/calls.rs",
            "fn call() { DomainError::invalid(REFUSED); }",
        );
        let catalog = collect(directory.path()).unwrap();
        assert!(catalog.messages.iter().any(|message| message.english
            == "the address may not be reached"
            && message.outward()));
    }

    /// A custom validation rule has public message text and protocol field
    /// identifiers. Only its prose and a traced topic-rule fragment survive.
    #[test]
    fn custom_validation_messages_keep_their_fields_out_of_the_catalog() {
        let directory = workspace();
        write(
            directory.path(),
            "crates/ianua-domain/src/example.rs",
            r#"
            fn check() {
                ValidationError::Custom {
                    field: "internal field label",
                    code: "stable error code",
                    message: "Choose a valid value".into(),
                }
            }
            "#,
        );
        write(
            directory.path(),
            "crates/ianua-domain/src/domains/agents/authority/capability/topic.rs",
            "fn check() { Some(\"topic pattern must not contain empty tokens\") }",
        );
        let catalog = collect(directory.path()).unwrap();
        let texts: Vec<_> = catalog
            .messages
            .iter()
            .map(|message| message.english.as_str())
            .collect();
        assert!(texts.contains(&"Choose a valid value"));
        assert!(texts.contains(&"topic pattern must not contain empty tokens"));
        assert!(!texts.contains(&"internal field label"));
        assert!(!texts.contains(&"stable error code"));
    }
}
