//! Fluent message names: given once from where a message lives and what
//! it says, then kept in the catalog so later edits never rename them.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::catalog::message::{Evidence, Message, Occurrence};
use crate::error::Error;

/// How many words of the English source a new key takes.
const SLUG_WORDS: usize = 6;

/// A Fluent message identifier of the form `<topic>-<words>`, such as
/// `authorization-role-already-held`. The topic names the resource file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct MessageKey(String);

impl MessageKey {
    /// The resource file this message belongs to, without its extension.
    pub(crate) fn topic(&self) -> &str {
        self.0.split_once('-').map_or(&self.0, |(topic, _)| topic)
    }

    /// The identifier as written in a Fluent resource.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MessageKey {
    type Error = Error;

    /// Accepts a lowercase topic, a hyphen and lowercase words joined by hyphens.
    fn try_from(text: String) -> Result<Self, Error> {
        let Some((topic, words)) = text.split_once('-') else {
            return Err(Error::BadKey(text));
        };
        if !well_formed_topic(topic) || !well_formed_words(words) {
            return Err(Error::BadKey(text));
        }
        Ok(Self(text))
    }
}

impl From<MessageKey> for String {
    fn from(key: MessageKey) -> Self {
        key.0
    }
}

impl fmt::Display for MessageKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Gives every message without a key a new one no other message holds.
/// Keys already given are never changed.
pub(crate) fn assign<'a>(
    messages: impl IntoIterator<Item = &'a mut Message>,
    taken: &mut BTreeSet<MessageKey>,
) {
    for message in messages {
        if message.key.is_some() {
            continue;
        }
        let key = unique(&proposed(message), taken);
        taken.insert(key.clone());
        message.key = Some(key);
    }
}

/// The key a message would get if nothing else held it.
fn proposed(message: &Message) -> String {
    let named = message.occurrences.iter().find_map(named_by_context);
    if let Some(named) = named {
        return named;
    }
    let topic = message
        .occurrences
        .iter()
        .find(|occurrence| occurrence.evidence.outward())
        .or(message.occurrences.first())
        .map_or_else(|| "app".to_owned(), |occurrence| topic(&occurrence.path));
    format!("{topic}-{}", slug(&without_placeholders(&message.english)))
}

/// Events and mail subjects are named after what they describe, not their wording.
fn named_by_context(occurrence: &Occurrence) -> Option<String> {
    match occurrence.evidence {
        Evidence::Event => Some(format!("event-{}", slug(&occurrence.context))),
        Evidence::Subject => Some(format!("mail-subject-{}", slug(&occurrence.context))),
        _ => None,
    }
}

/// The proposed key, or the first numbered variant of it nobody holds.
fn unique(proposed: &str, taken: &BTreeSet<MessageKey>) -> MessageKey {
    let mut candidate = MessageKey(proposed.to_owned());
    let mut number = 1_usize;
    while taken.contains(&candidate) {
        number += 1;
        candidate = MessageKey(format!("{proposed}-{number}"));
    }
    candidate
}

/// The bounded context, use-case folder or crate a source file belongs to.
fn topic(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let topic = match parts.as_slice() {
        ["crates", "ianua-domain", "src", "domains", context, _, ..] => context,
        ["crates", "ianua-domain", "src", "shared" | "types", ..] => "values",
        [
            "crates",
            "ianua-app",
            "src",
            "use_cases" | "services",
            context,
            _,
            ..,
        ] => context,
        ["crates", "ianua-infra", "src", "mail", ..] => "mail",
        ["crates", "ianua-infra", "src", "pages", ..] => "pages",
        ["crates", "ianua-infra", "templates", ..] => "templates",
        ["crates", krate, ..] => krate.strip_prefix("ianua-").unwrap_or(krate),
        _ => "app",
    };
    topic
        .chars()
        .map(|character| match character {
            'a'..='z' | '0'..='9' => character,
            'A'..='Z' => character.to_ascii_lowercase(),
            _ => '_',
        })
        .collect()
}

/// The source without its Rust format fields or template expressions.
fn without_placeholders(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut depth = 0_usize;
    for character in text.chars() {
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ if depth == 0 => kept.push(character),
            _ => {}
        }
    }
    kept
}

/// Up to six lowercase ASCII words joined by hyphens, or `message` when none remain.
fn slug(text: &str) -> String {
    let words: Vec<String> = text
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .take(SLUG_WORDS)
        .map(str::to_ascii_lowercase)
        .collect();
    if words.is_empty() {
        return "message".to_owned();
    }
    words.join("-")
}

fn well_formed_topic(topic: &str) -> bool {
    topic.starts_with(|character: char| character.is_ascii_lowercase())
        && topic
            .chars()
            .all(|character| matches!(character, 'a'..='z' | '0'..='9' | '_'))
}

fn well_formed_words(words: &str) -> bool {
    words.split('-').all(|word| {
        !word.is_empty()
            && word
                .chars()
                .all(|character| matches!(character, 'a'..='z' | '0'..='9'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::message::Syntax;
    use crate::catalog::message::tests::message;

    fn keyed(messages: &mut [Message]) -> Vec<String> {
        assign(messages.iter_mut(), &mut BTreeSet::new());
        messages
            .iter()
            .map(|message| message.key.as_ref().unwrap().to_string())
            .collect()
    }

    /// A refusal is named after its use-case folder and its first words, without its values.
    #[test]
    fn a_key_names_the_topic_and_the_wording() {
        let mut messages = [message("Cannot invite {name}: the role is already held")];
        assert_eq!(
            keyed(&mut messages),
            ["people-cannot-invite-the-role-is-already"]
        );
    }

    /// Two messages starting with the same words get distinct keys.
    #[test]
    fn colliding_keys_are_numbered() {
        let mut messages = [message("Invite {name}"), message("Invite {name}!")];
        assert_eq!(keyed(&mut messages), ["people-invite", "people-invite-2"]);
    }

    /// Assigning keys preserves an existing key even when the wording suggests another name.
    #[test]
    fn a_given_key_is_never_changed() {
        let mut kept = message("Invite {name}");
        kept.key = Some(MessageKey::try_from("people-ask-to-join".to_owned()).unwrap());
        let mut messages = [kept];
        assert_eq!(keyed(&mut messages), ["people-ask-to-join"]);
    }

    /// An event description takes its event type, a mail subject its template.
    #[test]
    fn events_and_subjects_are_named_after_what_they_describe() {
        let occurrence = |evidence, context: &str| Occurrence {
            path: "crates/ianua-domain/src/types/event_type/tenant.rs".to_owned(),
            line: 1,
            column: 1,
            context: context.to_owned(),
            evidence,
            keyed: None,
        };
        let mut messages = [
            Message::new(
                "A new tenant was provisioned.".to_owned(),
                Syntax::Plain,
                occurrence(Evidence::Event, "tenant.provisioned"),
            ),
            Message::new(
                "Reset your password".to_owned(),
                Syntax::MiniJinja,
                occurrence(Evidence::Subject, "sign_in/password_reset"),
            ),
        ];
        assert_eq!(
            keyed(&mut messages),
            [
                "event-tenant-provisioned",
                "mail-subject-sign-in-password-reset"
            ]
        );
    }

    /// Text with no ASCII words still gets a valid key.
    #[test]
    fn wordless_text_falls_back_to_message() {
        let mut messages = [message("{name}: {count}")];
        assert_eq!(keyed(&mut messages), ["people-message"]);
    }

    /// Keys with invalid topic, separator or word characters are refused at construction.
    #[test]
    fn malformed_keys_are_refused() {
        for text in [
            "People-invite",
            "people",
            "people-",
            "people-in vite",
            "1x-a",
        ] {
            assert!(MessageKey::try_from(text.to_owned()).is_err(), "{text}");
        }
    }
}
