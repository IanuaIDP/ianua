//! One source message, the places it appears and its translations.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::catalog::key::MessageKey;
use crate::collect::tokens::placeholders;
use crate::error::{Error, Result};
use crate::language::Language;
use crate::validation;

/// How the original message receives its values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Syntax {
    /// Literal text without interpolated values.
    Plain,
    /// A Rust format string, whose escaped braces and format specifiers are kept.
    RustFormat,
    /// A complete MiniJinja template, including its markup and template expressions.
    MiniJinja,
}

/// Why a literal belongs in the inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Evidence {
    /// Passed into a recognized outward error constructor or lookup helper.
    CustomerError,
    /// Appears in a mail, page, notification or other outward rendering module.
    Presentation,
    /// A complete built-in mail or page template.
    Template,
    /// A mail subject, whose context names the template it heads.
    Subject,
    /// A published event description, whose context names the event type.
    Event,
    /// An error display awaiting classification before the catalog is finished.
    ErrorDisplay,
    /// Unclassified prose, excluded unless a response helper is explicitly traced.
    Review,
}

impl Evidence {
    /// Whether this use alone proves the text reaches someone outside.
    pub(crate) fn outward(self) -> bool {
        match self {
            Self::CustomerError
            | Self::Presentation
            | Self::Template
            | Self::Subject
            | Self::Event => true,
            Self::ErrorDisplay | Self::Review => false,
        }
    }
}

/// One exact place the message appears in the workspace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Occurrence {
    /// Workspace-relative path, suitable for opening in an editor.
    pub(crate) path: String,
    /// One-based source line.
    pub(crate) line: usize,
    /// One-based source column.
    pub(crate) column: usize,
    /// The enclosing function, constant or error variant, the event type
    /// of a description, or the template a subject heads.
    pub(crate) context: String,
    /// What the collector knows about this use.
    pub(crate) evidence: Evidence,
    /// The Fluent key the source gives the message here through `message!`,
    /// which the runtime looks its wording up by; none where it gives none.
    #[serde(
        rename = "source_fluent_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) keyed: Option<String>,
}

/// A message with an unchanged English source and explicitly optional translations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Message {
    /// A source identity for this inventory, not a runtime API message key.
    pub(crate) id: String,
    /// The Fluent message identifier, given once and kept across
    /// recollection. Stored as `fluent_id`: a `key` field holding a long
    /// hyphenated word reads to secret scanners as an API key.
    #[serde(rename = "fluent_id", default, skip_serializing_if = "Option::is_none")]
    pub(crate) key: Option<MessageKey>,
    /// The original source, kept byte for byte after Rust literal decoding.
    pub(crate) english: String,
    /// The interpolation grammar the source uses today.
    pub(crate) syntax: Syntax,
    /// Original placeholder expressions that translations must retain.
    pub(crate) placeholders: BTreeSet<String>,
    /// Every source location sharing this exact text and interpolation grammar.
    pub(crate) occurrences: Vec<Occurrence>,
    /// Empty values mean untranslated, never an English copy posing as a translation.
    pub(crate) translations: BTreeMap<Language, Option<String>>,
}

impl Message {
    /// Keeps a source message under a deterministic identity that survives line moves.
    pub(crate) fn new(english: String, syntax: Syntax, occurrence: Occurrence) -> Self {
        Self {
            id: identity(&english, syntax),
            key: None,
            placeholders: placeholders(&english, syntax),
            translations: untranslated(&english),
            english,
            syntax,
            occurrences: vec![occurrence],
        }
    }

    /// Whether any source occurrence proves this text is outward facing.
    pub(crate) fn outward(&self) -> bool {
        self.occurrences
            .iter()
            .any(|occurrence| occurrence.evidence.outward())
    }

    /// Whether every language has a translation.
    pub(crate) fn complete(&self) -> bool {
        self.translations.values().all(Option::is_some)
    }

    /// The text for one language, if it has been translated.
    pub(crate) fn text(&self, language: Language) -> Option<&str> {
        self.translations.get(&language)?.as_deref()
    }

    /// The key the source gives this message through `message!`, if it
    /// gives one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyedTwice`] when two places key the same text
    /// differently, and [`Error::BadKey`] for a malformed key.
    pub(crate) fn source_key(&self) -> Result<Option<MessageKey>> {
        let keys: BTreeSet<&str> = self
            .occurrences
            .iter()
            .filter_map(|occurrence| occurrence.keyed.as_deref())
            .collect();
        match Vec::from_iter(keys).as_slice() {
            [] => Ok(None),
            [key] => MessageKey::try_from((*key).to_owned()).map(Some),
            _ => Err(Error::KeyedTwice(self.id.clone())),
        }
    }

    /// The same message as collection finds it: no key and no translations.
    pub(crate) fn as_collected(&self) -> Self {
        Self {
            key: None,
            translations: untranslated(&self.english),
            ..self.clone()
        }
    }

    /// Refuses altered identities, missing language columns and broken placeholders.
    ///
    /// # Errors
    ///
    /// Returns the first of these problems found, naming the message.
    pub(crate) fn validate(&self) -> Result<()> {
        self.ensure_unchanged_source()?;
        self.ensure_language_columns()?;
        self.translations
            .iter()
            .filter_map(|(language, text)| Some((*language, text.as_deref()?)))
            .try_for_each(|(language, text)| self.ensure_translation_keeps_inputs(language, text))
    }

    fn ensure_unchanged_source(&self) -> Result<()> {
        if self.id == identity(&self.english, self.syntax)
            && self.placeholders == placeholders(&self.english, self.syntax)
        {
            return Ok(());
        }
        Err(Error::ChangedSource(self.id.clone()))
    }

    fn ensure_language_columns(&self) -> Result<()> {
        let every_language = Language::ALL
            .iter()
            .all(|language| self.translations.contains_key(language));
        if every_language && self.text(Language::English) == Some(self.english.as_str()) {
            return Ok(());
        }
        Err(Error::LanguageColumns(self.id.clone()))
    }

    fn ensure_translation_keeps_inputs(&self, language: Language, text: &str) -> Result<()> {
        let name = format!("{}/{}", self.id, language.tag());
        if !text.trim().is_empty()
            && validation::same_inputs(&self.english, text, self.syntax, &name)?
        {
            return Ok(());
        }
        Err(Error::BrokenTranslation {
            id: self.id.clone(),
            language: language.tag(),
        })
    }
}

/// An outward message supplied through a variable or helper rather than a literal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct DynamicMessage {
    /// Where the constructor receives its value.
    pub(crate) occurrence: Occurrence,
    /// The expression to follow while assigning runtime message keys.
    pub(crate) expression: String,
}

/// English filled in, every other language explicitly untranslated.
fn untranslated(english: &str) -> BTreeMap<Language, Option<String>> {
    Language::ALL
        .into_iter()
        .map(|language| {
            let text = (language == Language::English).then(|| english.to_owned());
            (language, text)
        })
        .collect()
}

/// Gives exact source text and its grammar an identity independent of traversal order.
fn identity(text: &str, syntax: Syntax) -> String {
    let mut hash = Sha256::new();
    hash.update(format!("{syntax:?}\0"));
    hash.update(text.as_bytes());
    format!("source-{:x}", hash.finalize())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A sample outward message with one named value, used to exercise exchange checks.
    pub(crate) fn message(text: &str) -> Message {
        Message::new(
            text.to_owned(),
            Syntax::RustFormat,
            Occurrence {
                path: "crates/ianua-app/src/use_cases/people/invite.rs".to_owned(),
                line: 1,
                column: 1,
                context: "invite".to_owned(),
                evidence: Evidence::CustomerError,
                keyed: None,
            },
        )
    }

    /// A translation without the name placeholder is refused; restoring the placeholder validates.
    #[test]
    fn a_translation_must_keep_the_original_placeholders() {
        let mut entry = message("Invite {name}");
        entry
            .translations
            .insert(Language::German, Some("Einladen".to_owned()));
        assert!(entry.validate().is_err());
        entry
            .translations
            .insert(Language::German, Some("{name} einladen".to_owned()));
        entry.validate().unwrap();
    }

    /// An English translation column differing from the collected source fails validation.
    #[test]
    fn the_english_column_must_match_the_source() {
        let mut entry = message("Invite {name}");
        entry
            .translations
            .insert(Language::English, Some("Invite {name} now".to_owned()));
        assert!(matches!(entry.validate(), Err(Error::LanguageColumns(_))));
    }

    /// A blank translation is refused instead of rendering an empty message.
    #[test]
    fn a_blank_translation_is_refused() {
        let mut entry = message("Invite {name}");
        entry
            .translations
            .insert(Language::French, Some("  ".to_owned()));
        assert!(matches!(
            entry.validate(),
            Err(Error::BrokenTranslation { language: "fr", .. })
        ));
    }
}
