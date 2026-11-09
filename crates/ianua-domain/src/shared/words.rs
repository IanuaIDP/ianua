//! Reading keywords out of text as whole words.
//!
//! A keyword counts only as a whole word, or as one of its regular forms
//! such as "deleted", "notifies", "messaging" or "dropping". A keyword
//! inside another word never counts, so "already" never reads as reading,
//! "badminton" as administering or "payload" as paying. A text only ever
//! reads as less than it says, never as more.

/// The endings a keyword takes as it stands: "reads", "processes",
/// "checked", "sending".
const ENDINGS: &[&str] = &["s", "es", "ed", "ing"];

/// The endings a keyword ending in "e" takes once the "e" is dropped:
/// "deleted", "deleting", "deletion".
const ENDINGS_AFTER_E: &[&str] = &["ed", "ing", "ion", "ions"];

/// The endings a keyword ending in "y" takes once the "y" turns to "i":
/// "notifies", "queried".
const ENDINGS_AFTER_Y: &[&str] = &["es", "ed"];

/// The endings a keyword takes once its last letter is doubled:
/// "dropped", "cancelling".
const ENDINGS_AFTER_DOUBLING: &[&str] = &["ed", "ing"];

/// The words of `text`, lower-cased: its runs of letters and digits.
#[must_use]
pub fn words_of(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Whether `word` is `keyword` itself or one of its regular forms. Both
/// are lower case.
#[must_use]
pub fn is_form_of(word: &str, keyword: &str) -> bool {
    word == keyword
        || stems_of(keyword).any(|(stem, endings)| {
            word.strip_prefix(stem.as_str())
                .is_some_and(|ending| endings.contains(&ending))
        })
}

/// The stems `keyword` takes an ending on, each with the endings it takes:
/// the keyword as it stands, without its final "e", with its final "y"
/// turned to "i", and with its last letter doubled.
fn stems_of(keyword: &str) -> impl Iterator<Item = (String, &'static [&'static str])> {
    let without_e = keyword
        .strip_suffix('e')
        .map(|stem| (stem.to_owned(), ENDINGS_AFTER_E));
    let y_to_i = keyword
        .strip_suffix('y')
        .map(|stem| (format!("{stem}i"), ENDINGS_AFTER_Y));
    let doubled = keyword
        .chars()
        .last()
        .map(|last| (format!("{keyword}{last}"), ENDINGS_AFTER_DOUBLING));
    std::iter::once((keyword.to_owned(), ENDINGS))
        .chain(without_e)
        .chain(y_to_i)
        .chain(doubled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_splits_into_lower_case_words() {
        assert_eq!(
            words_of("/Admin/user-Settings_v2"),
            ["admin", "user", "settings", "v2"]
        );
    }

    #[test]
    fn regular_forms_of_a_keyword_count() {
        for (word, keyword) in [
            ("deletes", "delete"),
            ("deleted", "delete"),
            ("deletion", "delete"),
            ("notifies", "notify"),
            ("messaging", "message"),
            ("dropped", "drop"),
            ("payments", "payment"),
        ] {
            assert!(is_form_of(word, keyword), "{word} of {keyword}");
        }
    }

    /// Keywords embedded in unrelated words are not recognized as their
    /// grammatical forms, including administrative and payment substrings.
    #[test]
    fn a_keyword_inside_another_word_does_not_count() {
        for (word, keyword) in [
            ("badminton", "admin"),
            ("payload", "pay"),
            ("already", "read"),
            ("administrator", "admin"),
        ] {
            assert!(!is_form_of(word, keyword), "{word} of {keyword}");
        }
    }
}
