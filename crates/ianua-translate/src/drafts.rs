//! Imports explicitly authored language drafts without invoking a translation service.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::catalog::{Catalog, Message};
use crate::error::{Error, Result, io_at, json_at};
use crate::language::Language;

/// Whether an explicit import fills gaps or applies corrections to existing draft text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportMode {
    /// Preserve every translation already supplied.
    Fill,
    /// Apply the explicitly selected draft table as the new draft text.
    Revise,
}

/// One reviewable table of complete messages, in the catalog's fixed language order.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftFile {
    /// Explicit columns make a swapped language order fail rather than corrupt a catalog.
    languages: [Language; 8],
    /// Complete English sources followed by their seven target-language drafts.
    messages: Vec<[String; 8]>,
}

/// Imports complete-message drafts from one directory, refusing conflicts and unknown sources.
/// Returns how many translations changed.
///
/// # Errors
///
/// Refuses unreadable files, invalid tables, unknown sources or conflicting drafts.
pub(crate) fn import(catalog: &mut Catalog, directory: &Path, mode: ImportMode) -> Result<usize> {
    let mut changed = 0;
    for (english, row) in read(directory)? {
        let mut matching = catalog
            .messages
            .iter_mut()
            .filter(|message| message.english == english)
            .peekable();
        if matching.peek().is_none() {
            return Err(Error::UnknownDraft(english));
        }
        for message in matching {
            changed += apply(message, &row, mode)?;
        }
    }
    Ok(changed)
}

/// Writes one draft row into a message and counts the target languages it changed.
fn apply(message: &mut Message, row: &[String; 8], mode: ImportMode) -> Result<usize> {
    let mut changed = 0;
    for (language, text) in Language::ALL.into_iter().zip(row) {
        let current = message.text(language);
        if mode == ImportMode::Fill && current.is_some_and(|old| old != text) {
            return Err(Error::DraftReplaces {
                id: message.id.clone(),
                language: language.tag(),
            });
        }
        if language != Language::English && current != Some(text.as_str()) {
            changed += 1;
        }
        message.translations.insert(language, Some(text.clone()));
    }
    Ok(changed)
}

/// Loads sorted draft tables and refuses duplicate English rows with different translations.
fn read(directory: &Path) -> Result<BTreeMap<String, [String; 8]>> {
    let mut drafts = BTreeMap::new();
    for path in tables(directory)? {
        let bytes = fs::read(&path).map_err(io_at(&path))?;
        let table: DraftFile = serde_json::from_slice(&bytes).map_err(json_at(&path))?;
        if table.languages != Language::ALL {
            return Err(Error::DraftColumns(path));
        }
        for row in table.messages {
            add_row(&mut drafts, &path, row)?;
        }
    }
    Ok(drafts)
}

/// The JSON tables directly inside the directory, in path order.
fn tables(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(directory).map_err(io_at(directory))? {
        let path = entry.map_err(io_at(directory))?.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            found.push(path);
        }
    }
    found.sort();
    Ok(found)
}

fn add_row(
    drafts: &mut BTreeMap<String, [String; 8]>,
    path: &Path,
    row: [String; 8],
) -> Result<()> {
    if row.iter().any(|text| text.trim().is_empty()) {
        return Err(Error::EmptyDraft(path.to_path_buf()));
    }
    if drafts.get(&row[0]).is_some_and(|previous| previous != &row) {
        return Err(Error::ConflictingDrafts {
            path: path.to_path_buf(),
            english: row[0].clone(),
        });
    }
    drafts.insert(row[0].clone(), row);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Evidence, Occurrence, Syntax};

    /// An outward message with a named parameter, as collected from production source.
    fn catalog() -> Catalog {
        let mut catalog = Catalog::new();
        catalog.messages.push(Message::new(
            "Hello {name}".to_owned(),
            Syntax::RustFormat,
            Occurrence {
                path: "example.rs".to_owned(),
                line: 1,
                column: 1,
                context: "greeting".to_owned(),
                evidence: Evidence::Presentation,
                keyed: None,
            },
        ));
        catalog
    }

    /// A folder holding one complete greeting table.
    fn greetings() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let table = serde_json::json!({
            "languages": Language::ALL,
            "messages": [["Hello {name}", "Вітаємо, {name}", "Hallo {name}", "Bonjour {name}", "გამარჯობა, {name}", "Hola {name}", "你好，{name}", "こんにちは、{name}"]]
        });
        fs::write(
            directory.path().join("greetings.json"),
            serde_json::to_vec(&table).unwrap(),
        )
        .unwrap();
        directory
    }

    /// A complete authored table imports all seven targets while preserving the English source.
    #[test]
    fn complete_drafts_import_in_the_declared_language_order() {
        let directory = greetings();
        let mut catalog = catalog();
        assert_eq!(
            import(&mut catalog, directory.path(), ImportMode::Fill).unwrap(),
            7
        );
        assert_eq!(
            catalog.messages[0].text(Language::Japanese),
            Some("こんにちは、{name}")
        );
        catalog
            .save(&directory.path().join("saved.catalog"))
            .unwrap();
    }

    /// Filling drafts reports a conflict when the German translation already has different text.
    #[test]
    fn an_existing_different_translation_is_not_overwritten() {
        let directory = greetings();
        let mut catalog = catalog();
        catalog.messages[0]
            .translations
            .insert(Language::German, Some("Guten Tag {name}".to_owned()));
        assert!(matches!(
            import(&mut catalog, directory.path(), ImportMode::Fill),
            Err(Error::DraftReplaces { language: "de", .. })
        ));
    }

    /// An explicitly requested revision applies a corrected wording and is idempotent afterward.
    #[test]
    fn explicit_draft_revisions_can_correct_existing_wording() {
        let directory = greetings();
        let mut catalog = catalog();
        catalog.messages[0]
            .translations
            .insert(Language::German, Some("Guten Tag {name}".to_owned()));
        assert_eq!(
            import(&mut catalog, directory.path(), ImportMode::Revise).unwrap(),
            7
        );
        assert_eq!(
            catalog.messages[0].text(Language::German),
            Some("Hallo {name}")
        );
        assert_eq!(
            import(&mut catalog, directory.path(), ImportMode::Revise).unwrap(),
            0
        );
    }

    /// Importing into an empty catalog reports the draft's English source as unknown.
    #[test]
    fn a_draft_for_unknown_english_is_refused() {
        let directory = greetings();
        let mut catalog = Catalog::new();
        assert!(matches!(
            import(&mut catalog, directory.path(), ImportMode::Fill),
            Err(Error::UnknownDraft(_))
        ));
    }
}
