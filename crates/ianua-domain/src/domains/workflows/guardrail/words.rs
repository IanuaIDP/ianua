//! Reading a text as words, and saying where in the text something stands.
//!
//! A word is a run of letters and digits, compared in lower case, so
//! `Ignore`, `IGNORE` and `ignore` read alike and `ignore,` reads as
//! `ignore`. Where it stands is counted in characters, not bytes, so a
//! place shown to a person matches the text they see.

use crate::domains::data_classification::classification::MASK;

/// Where something found stands in one text, in characters from its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span {
    start: u32,
    length: u32,
}

impl Span {
    /// The characters from `start` up to, not including, `end`.
    pub(crate) fn between(start: usize, end: usize) -> Self {
        let start_at = u32::try_from(start).unwrap_or(u32::MAX);
        let end_at = u32::try_from(end).unwrap_or(u32::MAX).max(start_at);
        Self {
            start: start_at,
            length: end_at.saturating_sub(start_at),
        }
    }

    /// The first character, counted from zero.
    #[must_use]
    pub fn start(self) -> u32 {
        self.start
    }

    /// How many characters it covers.
    #[must_use]
    pub fn length(self) -> u32 {
        self.length
    }

    /// The character just past its end.
    #[must_use]
    pub fn end(self) -> u32 {
        self.start.saturating_add(self.length)
    }

    /// From this span's start to the end of `last`.
    pub(crate) fn through(self, last: Self) -> Self {
        Self::between(self.start as usize, last.end() as usize)
    }
}

/// One word of a text, lower-cased, and where it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Word {
    /// The word in lower case.
    pub(crate) text: String,
    /// Where it stands in the text.
    pub(crate) span: Span,
}

/// The words of `text`, in order.
pub(crate) fn words(text: &str) -> Vec<Word> {
    let mut found = Vec::new();
    let mut chars = text.chars().enumerate().peekable();
    while let Some((start, first)) = chars.next() {
        if !first.is_alphanumeric() {
            continue;
        }
        let mut word: String = first.to_lowercase().collect();
        let mut end = start.saturating_add(1);
        while let Some((at, next)) = chars.next_if(|(_, next)| next.is_alphanumeric()) {
            word.extend(next.to_lowercase());
            end = at.saturating_add(1);
        }
        found.push(Word {
            text: word,
            span: Span::between(start, end),
        });
    }
    found
}

/// `text` with every character `spans` cover replaced, each run of
/// covered characters by one mask, as the gateway masks a field. The spans
/// are walked once in order beside the text, so a long text with many
/// findings takes time in proportion to both.
pub(crate) fn masked(text: &str, spans: &[Span]) -> String {
    let mut sorted = spans.to_vec();
    sorted.sort_unstable();
    let mut pending = sorted.into_iter().peekable();
    let mut covered_until: u32 = 0;
    let mut in_mask = false;
    let mut out = String::with_capacity(text.len());
    for (at, ch) in text.chars().enumerate() {
        let at = u32::try_from(at).unwrap_or(u32::MAX);
        while let Some(span) = pending.next_if(|span| span.start <= at) {
            covered_until = covered_until.max(span.end());
        }
        let covered = at < covered_until;
        match (covered, in_mask) {
            (true, false) => out.push_str(MASK),
            (true, true) => {}
            (false, _) => out.push(ch),
        }
        in_mask = covered;
    }
    out
}

/// Byte ranges of `text`, each starting and ending where a character
/// does, as spans of characters. A text of ASCII alone counts the same
/// either way; any other is indexed once, so many ranges cost no more than
/// one walk of the text and a search each.
pub(crate) fn char_spans(text: &str, ranges: &[(usize, usize)]) -> Vec<Span> {
    if text.is_ascii() {
        return ranges
            .iter()
            .map(|(start, end)| Span::between(*start, *end))
            .collect();
    }
    let starts: Vec<usize> = text.char_indices().map(|(byte, _)| byte).collect();
    let char_of = |byte: usize| starts.partition_point(|start| *start < byte);
    ranges
        .iter()
        .map(|(start, end)| Span::between(char_of(*start), char_of(*end)))
        .collect()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn texts(found: &[Word]) -> Vec<&str> {
        found.iter().map(|word| word.text.as_str()).collect()
    }

    /// "Ignore, ALL rules!" reads as three lower-case words, each placed at
    /// the characters it was written in.
    #[test]
    fn words_are_read_in_lower_case_without_punctuation() {
        let found = words("Ignore, ALL rules!");

        assert_eq!(texts(&found), ["ignore", "all", "rules"]);
        assert_eq!(found[1].span, Span::between(8, 11));
    }

    /// "Grüße an Zoë" counts characters, not bytes: the third word starts at
    /// the ninth character although the umlauts take two bytes each.
    #[test]
    fn places_count_characters_not_bytes() {
        let found = words("Grüße an Zoë");

        assert_eq!(found[2].span, Span::between(9, 12));
    }

    /// Masking two touching spans writes one mask, and the text around them
    /// stays as it was.
    #[test]
    fn touching_spans_mask_as_one() {
        let text = "card 4111 1111 now";

        let out = masked(text, &[Span::between(5, 9), Span::between(9, 14)]);

        assert_eq!(out, "card *** now");
    }

    proptest! {
        /// Whatever the text, every word read is the lower-cased text at its
        /// place, and nothing but letters and digits.
        #[test]
        fn every_word_is_the_text_at_its_place(text in "\\PC{0,80}") {
            let chars: Vec<char> = text.chars().collect();

            for word in words(&text) {
                let start = word.span.start() as usize;
                let end = word.span.end() as usize;
                let original: String = chars[start..end].iter().collect();
                prop_assert!(original.chars().all(char::is_alphanumeric));
                prop_assert_eq!(original.to_lowercase(), word.text);
            }
        }

        /// Masking never leaves a covered character in the text: masking
        /// every word leaves no letter or digit behind.
        #[test]
        fn masking_every_word_leaves_none(text in "[a-zA-Z0-9 ,.!]{0,80}") {
            let spans: Vec<Span> = words(&text).iter().map(|word| word.span).collect();

            let out = masked(&text, &spans);

            prop_assert!(words(&out).is_empty());
        }
    }
}
