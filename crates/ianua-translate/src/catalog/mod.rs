//! The translation inventory: source messages, their locations, their
//! Fluent keys and the translations a reviewer supplies.

pub(crate) mod key;
pub(crate) mod message;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub(crate) use self::key::MessageKey;
pub(crate) use self::message::{DynamicMessage, Evidence, Message, Occurrence, Syntax};
use crate::collect::scope;
use crate::error::{Error, Result, io_at, json_at};
use crate::language::Language;

/// The exchange format this build reads and writes.
const SCHEMA_VERSION: u32 = 2;

/// A deterministic, reviewable inventory with no generated timestamp churn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Catalog {
    /// The exchange format, independent of a future runtime response contract.
    pub(crate) schema_version: u32,
    /// The exact eight language tags this work covers.
    pub(crate) languages: Vec<Language>,
    /// Production files actually read by the collector.
    pub(crate) scanned_files: Vec<String>,
    /// Response messages and their fragments, with evidence at every location.
    pub(crate) messages: Vec<Message>,
    /// Expressions that need following before the runtime migration can be complete.
    pub(crate) dynamic_messages: Vec<DynamicMessage>,
    /// Removed response sources, excluding discarded internal prose.
    pub(crate) retired: Vec<Message>,
}

impl Catalog {
    /// Starts an inventory with the agreed language columns.
    pub(crate) fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            languages: Language::ALL.to_vec(),
            scanned_files: Vec::new(),
            messages: Vec::new(),
            dynamic_messages: Vec::new(),
            retired: Vec::new(),
        }
    }

    /// Keeps response sources and groups identical messages without merging grammars.
    pub(crate) fn finish(&mut self) {
        self.messages.retain_mut(scope::retain);
        self.retired.retain_mut(scope::retain);
        self.messages = grouped(std::mem::take(&mut self.messages));
        self.scanned_files.sort();
        self.scanned_files.dedup();
        self.dynamic_messages.sort();
        self.dynamic_messages.dedup();
    }

    /// Reads a saved catalog, refusing invalid exchange data.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable files, invalid JSON or inconsistent catalog records.
    pub(crate) fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(io_at(path))?;
        let catalog: Self = serde_json::from_slice(&bytes).map_err(json_at(path))?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Preserves existing translations and keys, gives new messages keys,
    /// then writes the catalog.
    ///
    /// # Errors
    ///
    /// Refuses an invalid existing catalog or an unwritable destination.
    pub(crate) fn write(&mut self, path: &Path) -> Result<()> {
        match Self::read(path) {
            Ok(previous) => self.preserve(previous),
            Err(error) if error.is_not_found() => {}
            Err(error) => return Err(error),
        }
        self.adopt_source_keys()?;
        self.assign_keys();
        self.save(path)
    }

    /// Atomically saves an explicitly edited catalog after validating every supplied translation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid translations or a destination that cannot be replaced.
    pub(crate) fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(&self).map_err(json_at(path))?;
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut pending = tempfile::NamedTempFile::new_in(directory).map_err(io_at(directory))?;
        pending.write_all(&bytes).map_err(io_at(pending.path()))?;
        pending
            .as_file()
            .sync_all()
            .map_err(io_at(pending.path()))?;
        pending
            .persist(path)
            .map_err(|error| io_at(path)(error.error))?;
        Ok(())
    }

    /// Refuses source changes hidden by an old inventory and messages left
    /// without a key, while accepting translation edits.
    ///
    /// # Errors
    ///
    /// Returns an error when source coverage is stale, a key is missing or
    /// a supplied translation is invalid.
    pub(crate) fn check_sources(&self, expected: &Self) -> Result<()> {
        self.validate()?;
        self.ensure_keyed()?;
        self.ensure_source_keys()?;
        let collected = Self {
            messages: self.messages.iter().map(Message::as_collected).collect(),
            retired: Vec::new(),
            ..self.clone()
        };
        if collected != *expected {
            return Err(Error::StaleCatalog);
        }
        Ok(())
    }

    /// Refuses active messages that have no Fluent key yet.
    ///
    /// # Errors
    ///
    /// Names the first message without a key.
    pub(crate) fn ensure_keyed(&self) -> Result<()> {
        match self.messages.iter().find(|message| message.key.is_none()) {
            Some(message) => Err(Error::MissingKey(message.id.clone())),
            None => Ok(()),
        }
    }

    /// Counts response sources, supplied translations and unresolved expressions.
    pub(crate) fn summary(&self) -> String {
        let outward: Vec<_> = self
            .messages
            .iter()
            .filter(|message| message.outward())
            .collect();
        let translated = outward.iter().filter(|message| message.complete()).count();
        format!(
            "{} files; {} response messages; {} unclassified entries; {} dynamic expressions; {translated}/{} response messages supplied in all eight languages",
            self.scanned_files.len(),
            outward.len(),
            self.messages.len() - outward.len(),
            self.dynamic_messages.len(),
            outward.len(),
        )
    }

    /// Refuses unknown schemas, duplicate identities or keys and malformed message records.
    fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION || self.languages != Language::ALL {
            return Err(Error::UnsupportedSchema);
        }
        let mut identities = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for message in self.messages.iter().chain(&self.retired) {
            message.validate()?;
            if message.occurrences.is_empty() || !identities.insert(&message.id) {
                return Err(Error::DuplicateIdentity(message.id.clone()));
            }
            if let Some(key) = &message.key {
                ensure_new_key(&mut keys, key)?;
            }
        }
        Ok(())
    }

    /// Retains unchanged translations and keys, and archives sources removed
    /// since the last collection.
    fn preserve(&mut self, mut previous: Self) {
        previous.finish();
        let mut previous: BTreeMap<_, _> = previous
            .messages
            .into_iter()
            .chain(previous.retired)
            .map(|message| (message.id.clone(), message))
            .collect();
        for message in &mut self.messages {
            let Some(old) = previous.remove(&message.id) else {
                continue;
            };
            message.translations = old.translations;
            message.key = old.key;
        }
        self.retired = previous.into_values().collect();
    }

    /// Gives every message the key its source gives it through `message!`,
    /// in place of one kept or given before, since the runtime looks its
    /// wording up by that key. A retired message holding such a key gives
    /// it up.
    ///
    /// # Errors
    ///
    /// Returns an error when the source keys one text two ways, or gives a
    /// malformed key.
    fn adopt_source_keys(&mut self) -> Result<()> {
        let mut adopted = BTreeSet::new();
        for message in &mut self.messages {
            if let Some(key) = message.source_key()? {
                adopted.insert(key.clone());
                message.key = Some(key);
            }
        }
        for message in &mut self.retired {
            if message
                .key
                .as_ref()
                .is_some_and(|key| adopted.contains(key))
            {
                message.key = None;
            }
        }
        Ok(())
    }

    /// Refuses a message whose key is not the one its source gives it.
    ///
    /// # Errors
    ///
    /// Names the first such message.
    fn ensure_source_keys(&self) -> Result<()> {
        for message in &self.messages {
            let Some(source) = message.source_key()? else {
                continue;
            };
            if message.key.as_ref() != Some(&source) {
                return Err(Error::KeyDiffersFromSource(message.id.clone()));
            }
        }
        Ok(())
    }

    /// Gives every message without a key one that no active or retired message holds.
    fn assign_keys(&mut self) {
        let mut taken: BTreeSet<MessageKey> = self
            .messages
            .iter()
            .chain(&self.retired)
            .filter_map(|message| message.key.clone())
            .collect();
        key::assign(&mut self.messages, &mut taken);
    }
}

/// Identical messages merged into one entry with every location, sorted by identity.
fn grouped(messages: Vec<Message>) -> Vec<Message> {
    let mut grouped: BTreeMap<String, Message> = BTreeMap::new();
    for message in messages {
        match grouped.get_mut(&message.id) {
            Some(existing) => existing.occurrences.extend(message.occurrences),
            None => {
                grouped.insert(message.id.clone(), message);
            }
        }
    }
    grouped
        .into_values()
        .map(|mut message| {
            message.occurrences.sort();
            message.occurrences.dedup();
            message
        })
        .collect()
}

fn ensure_new_key<'a>(keys: &mut BTreeSet<&'a MessageKey>, key: &'a MessageKey) -> Result<()> {
    if keys.insert(key) {
        return Ok(());
    }
    Err(Error::BadKey(key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::message::tests::message;

    /// Recollecting after line moves keeps translations and keys, and
    /// removing a source archives its work.
    #[test]
    fn recollection_preserves_translations_keys_and_retires_removed_sources() {
        let mut previous = Catalog::new();
        let mut retained = message("Invite {name}");
        retained
            .translations
            .insert(Language::Ukrainian, Some("Запросити {name}".to_owned()));
        retained.key = Some(MessageKey::try_from("people-ask".to_owned()).unwrap());
        previous.messages = vec![retained, message("Remove {name}")];
        let mut next = Catalog::new();
        let mut moved = message("Invite {name}");
        moved.occurrences[0].line = 20;
        next.messages.push(moved);
        next.preserve(previous);
        assert_eq!(
            next.messages[0].text(Language::Ukrainian),
            Some("Запросити {name}")
        );
        assert_eq!(
            next.messages[0].key.as_ref().unwrap().as_str(),
            "people-ask"
        );
        assert_eq!(next.retired.len(), 1);
        assert_eq!(next.messages[0].occurrences[0].line, 20);
    }

    /// The source keys "Invite {name}" as `people-invite`, though the
    /// catalog gave it `people-ask` before. Recollection takes the source's
    /// key, the one the runtime looks its wording up by, and keeps its
    /// translation.
    #[test]
    fn recollection_takes_the_key_the_source_gives() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.json");
        let mut previous = Catalog::new();
        let mut kept = message("Invite {name}");
        kept.key = Some(MessageKey::try_from("people-ask".to_owned()).unwrap());
        kept.translations
            .insert(Language::Ukrainian, Some("Запросити {name}".to_owned()));
        previous.messages.push(kept);
        previous.save(&path).unwrap();
        let mut next = Catalog::new();
        let mut keyed = message("Invite {name}");
        keyed.occurrences[0].keyed = Some("people-invite".to_owned());
        next.messages.push(keyed);
        let expected = next.clone();

        next.write(&path).unwrap();

        let written = Catalog::read(&path).unwrap();
        assert_eq!(
            written.messages[0].key.as_ref().unwrap().as_str(),
            "people-invite"
        );
        assert_eq!(
            written.messages[0].text(Language::Ukrainian),
            Some("Запросити {name}")
        );
        written.check_sources(&expected).unwrap();
    }

    /// A catalog key differing from the source's key fails verification,
    /// even when the collected wording matches.
    #[test]
    fn a_key_other_than_the_sources_fails_the_check() {
        let mut catalog = Catalog::new();
        let mut keyed = message("Invite {name}");
        keyed.occurrences[0].keyed = Some("people-invite".to_owned());
        keyed.key = Some(MessageKey::try_from("people-ask".to_owned()).unwrap());
        catalog.messages.push(keyed);
        let expected = Catalog {
            messages: catalog.messages.iter().map(Message::as_collected).collect(),
            ..catalog.clone()
        };

        let checked = catalog.check_sources(&expected);

        assert!(matches!(checked, Err(Error::KeyDiffersFromSource(_))));
    }

    /// Two source occurrences assigning different keys to one text produce
    /// a duplicate-keying error.
    #[test]
    fn one_text_keyed_two_ways_is_refused() {
        let mut twice = message("Invite {name}");
        twice.occurrences[0].keyed = Some("people-invite".to_owned());
        let mut other = twice.occurrences[0].clone();
        other.line = 40;
        other.keyed = Some("people-ask".to_owned());
        twice.occurrences.push(other);

        let key = twice.source_key();

        assert!(matches!(key, Err(Error::KeyedTwice(_))));
    }

    /// An empty catalog fails verification when the collected source contains a new message.
    #[test]
    fn a_new_message_makes_the_inventory_stale() {
        let previous = Catalog::new();
        let mut next = previous.clone();
        next.messages.push(message("Invite {name}"));
        assert!(previous.check_sources(&next).is_err());
    }

    /// A written catalog is current against a fresh collection of the same source.
    #[test]
    fn a_written_catalog_passes_the_source_check() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.json");
        let mut collected = Catalog::new();
        collected.messages.push(message("Invite {name}"));
        let expected = collected.clone();
        collected.write(&path).unwrap();
        Catalog::read(&path)
            .unwrap()
            .check_sources(&expected)
            .unwrap();
    }

    /// A message without a Fluent key fails verification even when source coverage matches.
    #[test]
    fn a_message_without_a_key_fails_the_check() {
        let mut catalog = Catalog::new();
        catalog.messages.push(message("Invite {name}"));
        let expected = catalog.clone();
        assert!(matches!(
            catalog.check_sources(&expected),
            Err(Error::MissingKey(_))
        ));
    }

    /// Two different messages sharing one Fluent key make catalog validation fail.
    #[test]
    fn a_duplicate_key_is_refused() {
        let key = MessageKey::try_from("people-invite".to_owned()).unwrap();
        let mut catalog = Catalog::new();
        let mut first = message("Invite {name}");
        first.key = Some(key.clone());
        let mut second = message("Remove {name}");
        second.key = Some(key);
        catalog.messages = vec![first, second];
        assert!(matches!(catalog.validate(), Err(Error::BadKey(_))));
    }

    /// A maintainer recollects into an existing catalog without losing completed translations.
    #[test]
    fn writing_a_catalog_preserves_previously_supplied_translations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.json");
        let mut first = Catalog::new();
        first.messages.push(message("Invite {name}"));
        first.messages[0]
            .translations
            .insert(Language::French, Some("Inviter {name}".to_owned()));
        first.write(&path).unwrap();
        let key = Catalog::read(&path).unwrap().messages[0].key.clone();
        let mut next = Catalog::new();
        next.messages.push(message("Invite {name}"));
        next.write(&path).unwrap();
        let written = Catalog::read(&path).unwrap();
        assert_eq!(
            written.messages[0].text(Language::French),
            Some("Inviter {name}")
        );
        assert_eq!(written.messages[0].key, key);
    }

    /// Writing over a malformed catalog fails and leaves its original bytes intact.
    #[test]
    fn an_invalid_existing_catalog_is_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.json");
        fs::write(&path, "not a catalog").unwrap();
        assert!(Catalog::new().write(&path).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "not a catalog");
    }

    /// A translated greeting may conditionally show an optional name while retaining its value.
    #[test]
    fn a_translated_template_can_use_a_natural_optional_name_greeting() {
        let directory = tempfile::tempdir().unwrap();
        let mut catalog = Catalog::new();
        let mut greeting = Message::new(
            "{% macro greeting(name) %}Hi {{ name }},{% endmacro %}".to_owned(),
            Syntax::MiniJinja,
            message("sample").occurrences.remove(0),
        );
        greeting.translations.insert(
            Language::German,
            Some(
                "{% macro greeting(name) %}Hallo{% if name %} {{ name }}{% endif %},{% endmacro %}"
                    .to_owned(),
            ),
        );
        catalog.messages.push(greeting);
        catalog
            .save(&directory.path().join("catalog.json"))
            .unwrap();
    }

    /// Recollection drops internal prose from active and retired entries,
    /// preserves the public translation and retires the removed response.
    #[test]
    fn recollection_discards_internal_text_without_retiring_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.json");
        let mut previous = Catalog::new();
        let mut retained = message("Invite {name}");
        retained
            .translations
            .insert(Language::Ukrainian, Some("Запросити {name}".to_owned()));
        let mut internal = message("opening the internal database");
        internal.occurrences[0].path = "crates/ianua-boot/src/env.rs".to_owned();
        internal.occurrences[0].evidence = Evidence::Review;
        let archived_internal = Message::new(
            "internal log detail".to_owned(),
            Syntax::Plain,
            internal.occurrences[0].clone(),
        );
        previous.messages = vec![retained, internal, message("Remove {name}")];
        previous.retired.push(archived_internal);
        previous.save(&path).unwrap();
        let mut next = Catalog::new();
        next.messages.push(message("Invite {name}"));
        next.write(&path).unwrap();
        assert_eq!(
            next.messages[0].text(Language::Ukrainian),
            Some("Запросити {name}")
        );
        assert_eq!(next.retired.len(), 1);
        assert_eq!(next.retired[0].english, "Remove {name}");
    }
}
