//! Words read out of names and comments: a name split into its words, a
//! comment's words, and whether a word is a past participle.

use std::collections::BTreeSet;

/// Past participles that do not end in `-ed`, each different from its
/// verb's plain form, so a name starting with one reads as a result rather
/// than an action: `kept`, `made`, `held`.
const IRREGULAR_PARTICIPLES: &[&str] = &[
    "kept",
    "made",
    "held",
    "taken",
    "given",
    "written",
    "sent",
    "built",
    "found",
    "known",
    "shown",
    "done",
    "gone",
    "seen",
    "left",
    "brought",
    "caught",
    "told",
    "sold",
    "paid",
    "laid",
    "said",
    "meant",
    "led",
    "won",
    "begun",
    "chosen",
    "drawn",
    "driven",
    "eaten",
    "fallen",
    "forgotten",
    "frozen",
    "hidden",
    "risen",
    "spoken",
    "stolen",
    "thrown",
    "torn",
    "worn",
    "broken",
    "bound",
    "lost",
    "thought",
    "stood",
    "spent",
    "lent",
    "felt",
    "dealt",
    "slept",
    "swept",
    "sought",
    "taught",
    "fought",
    "stuck",
    "hung",
    "spun",
];

/// Words ending in `-ed` that are a verb's plain form or no verb at all,
/// so a name may start with them: `need_`, `seed_`, `embed_`.
const NOT_PARTICIPLES: &[&str] = &[
    "need", "feed", "speed", "seed", "proceed", "exceed", "succeed", "bleed", "breed", "heed",
    "embed", "shed", "bed", "red", "shred", "wed", "sled", "bred",
];

/// Words a comment uses to join others, which say nothing of their own.
const JOINING: &[&str] = &[
    "the", "a", "an", "its", "it", "this", "that", "these", "those", "of", "for", "to", "is",
    "are", "be", "by", "in", "on", "at", "as", "and", "or", "one", "whose", "which", "with",
    "from", "their", "his", "her",
];

/// The words of `name`, lower case: `snake_case` split at underscores, and
/// `CamelCase` at each capital.
pub(crate) fn name_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    for part in name.split('_').filter(|part| !part.is_empty()) {
        let mut word = String::new();
        for c in part.chars() {
            if c.is_uppercase() && !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            word.extend(c.to_lowercase());
        }
        if !word.is_empty() {
            words.push(word);
        }
    }
    words
}

/// The words of `text` that say something: lower case, letters only, the
/// joining words left out.
pub(crate) fn meaningful_words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .filter(|word| !JOINING.contains(&word.as_str()))
        .collect()
}

/// Whether `word` is a past participle: `kept`, `recorded`, `put_in`'s
/// `put` is not, since it reads as the plain verb.
pub(crate) fn is_participle(word: &str) -> bool {
    if IRREGULAR_PARTICIPLES.contains(&word) {
        return true;
    }
    word.len() > 3 && word.ends_with("ed") && !NOT_PARTICIPLES.contains(&word)
}

/// Whether every word of `said` is one of `names` or a form of one: the
/// comment only says the name again.
pub(crate) fn only_restates(said: &[String], names: &[String]) -> bool {
    let known: BTreeSet<String> = names.iter().flat_map(|name| forms(name)).collect();
    said.iter()
        .all(|word| forms(word).iter().any(|form| known.contains(form)))
}

/// The forms a word is matched in: itself, without a plural `s`, and its
/// usual long or short spelling.
fn forms(word: &str) -> Vec<String> {
    let mut found = vec![word.to_owned()];
    if let Some(single) = word.strip_suffix('s').filter(|stem| stem.len() > 2) {
        found.push(single.to_owned());
    }
    let spelled = match word {
        "id" => Some("identifier"),
        "identifier" => Some("id"),
        "url" => Some("address"),
        "config" => Some("configuration"),
        "configuration" => Some("config"),
        _ => None,
    };
    found.extend(spelled.map(str::to_owned));
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Snake and camel case names split into their words.
    #[test]
    fn a_name_splits_into_its_words() {
        assert_eq!(
            name_words("registered_and_kept"),
            ["registered", "and", "kept"]
        );
        assert_eq!(name_words("DnsZoneWriter"), ["dns", "zone", "writer"]);
    }

    /// Regular and irregular participles are told apart from plain verbs.
    #[test]
    fn participles_are_told_from_plain_verbs() {
        assert!(is_participle("kept"));
        assert!(is_participle("recorded"));
        assert!(!is_participle("save"));
        assert!(!is_participle("seed"));
        assert!(!is_participle("read"));
    }

    /// "Its id." on `id` only says the name again; "Shown in its address."
    /// says something.
    #[test]
    fn a_comment_only_restating_the_name_is_told_apart() {
        let names = name_words("id");

        assert!(only_restates(&meaningful_words("Its id."), &names));
        assert!(only_restates(&meaningful_words("The identifier."), &names));
        assert!(!only_restates(
            &meaningful_words("Shown in its address."),
            &names
        ));
    }
}
