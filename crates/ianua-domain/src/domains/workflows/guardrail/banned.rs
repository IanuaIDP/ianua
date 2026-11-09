//! The words a company bans from what a workflow sends on.
//!
//! They are kept on the guardrail step itself, beside its other settings,
//! so a run checks exactly the words reviewed when its version was
//! published, and changing them is a new version, recorded like every
//! other change to what runs. A word or phrase matches whole words in any
//! case: "acme corp" matches "ACME Corp." but not "acmecorporation".

use crate::domains::workflows::guardrail::words::{Span, Word, words};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{TextValue, Validator, text_value};

/// The most words one guardrail bans.
pub(crate) const MAX_BANNED_WORDS: usize = 200;

text_value! {
    /// One banned word or phrase, kept as its words in lower case, one
    /// space apart: "Acme-Corp!" is kept as "acme corp".
    pub struct BannedWord;
}

impl TextValue for BannedWord {
    const FIELD: &'static str = "banned_word";

    fn normalized(value: String) -> String {
        words(&value)
            .into_iter()
            .map(|word| word.text)
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_blank().char_length(1..=64)
    }
}

/// The words a guardrail bans, each once.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "Vec<BannedWord>"))]
pub struct BannedWords(Vec<BannedWord>);

impl BannedWords {
    /// Bans `words`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for more than [`MAX_BANNED_WORDS`]
    ///   words, or one named twice.
    pub fn new(words: Vec<BannedWord>) -> Result<Self, DomainError> {
        validate_count("banned_words", words.len(), 0..=MAX_BANNED_WORDS)?;
        if let Some(twice) = first_repeat(&words) {
            return Err(DomainError::invalid(message!(
                "workflows-a-banned-word-is-named-twice",
                format!("the banned word {twice} is named twice")
            )));
        }
        Ok(Self(words))
    }

    /// The words banned.
    #[must_use]
    pub fn words(&self) -> &[BannedWord] {
        &self.0
    }

    /// Whether no word is banned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Where in a text, read as `read`, a banned word is written.
    pub(crate) fn found_in(&self, read: &[Word]) -> Vec<Span> {
        self.0
            .iter()
            .flat_map(|banned| written_at(read, &words(banned.as_str())))
            .collect()
    }
}

impl TryFrom<Vec<BannedWord>> for BannedWords {
    type Error = DomainError;

    fn try_from(words: Vec<BannedWord>) -> Result<Self, Self::Error> {
        Self::new(words)
    }
}

/// Every place the words of `phrase` stand together, in order, in `read`.
fn written_at(read: &[Word], phrase: &[Word]) -> Vec<Span> {
    if phrase.is_empty() {
        return Vec::new();
    }
    read.windows(phrase.len())
        .filter(|window| {
            window
                .iter()
                .zip(phrase)
                .all(|(word, wanted)| word.text == wanted.text)
        })
        .filter_map(|window| Some(window.first()?.span.through(window.last()?.span)))
        .collect()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn banned(list: &[&str]) -> BannedWords {
        BannedWords::new(
            list.iter()
                .map(|word| BannedWord::new(*word).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn found(list: &[&str], text: &str) -> Vec<Span> {
        banned(list).found_in(&words(text))
    }

    /// "Acme-Corp!" is kept as its words, "acme corp".
    #[test]
    fn a_banned_word_is_kept_as_its_words() {
        assert_eq!(
            BannedWord::new("  Acme-Corp! ").unwrap().as_str(),
            "acme corp"
        );
    }

    /// An entry of punctuation alone has no word to ban, and is refused.
    #[test]
    fn punctuation_alone_is_refused() {
        assert!(BannedWord::new("!!!").is_err());
    }

    /// "Acme" and "ACME" are one word, so naming both is refused.
    #[test]
    fn a_word_named_twice_in_another_case_is_refused() {
        let twice = BannedWords::new(vec![
            BannedWord::new("Acme").unwrap(),
            BannedWord::new("ACME").unwrap(),
        ]);

        assert!(matches!(twice, Err(DomainError::Validation(_))));
    }

    /// "guaranteed returns" is found in "GUARANTEED returns!", placed over
    /// both words; "guaranteedreturns" holds no whole word of it.
    #[test]
    fn a_phrase_matches_whole_words_in_any_case() {
        assert_eq!(
            found(&["guaranteed returns"], "We promise GUARANTEED returns!"),
            [Span::between(11, 29)]
        );
        assert!(found(&["guaranteed returns"], "guaranteedreturns").is_empty());
    }

    proptest! {
        /// Wherever a banned word stands among other words, and in whatever
        /// case it is written, it is found once.
        #[test]
        fn a_banned_word_is_found_wherever_it_stands(
            before in proptest::collection::vec("[a-z]{3,8}", 0..10),
            after in proptest::collection::vec("[a-z]{3,8}", 0..10),
            upper in any::<bool>(),
        ) {
            prop_assume!(!before.iter().chain(&after).any(|word| word == "zyzzyva"));
            let written = if upper { "ZYZZYVA" } else { "Zyzzyva" };
            let text = format!("{} {written}. {}", before.join(" "), after.join(" "));

            prop_assert_eq!(found(&["zyzzyva"], &text).len(), 1);
        }
    }
}
