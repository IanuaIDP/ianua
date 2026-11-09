//! The checks a sample case makes of a test run's results, and what a
//! check that does not hold found instead.
//!
//! Every check is decided by the data alone, the same way each time: the
//! value at a path equals the one expected, its text contains a piece of
//! text, or its text matches a short pattern. A check graded by a model is
//! not offered: two runs of the same model may grade the same output
//! differently, and a failing evaluation must mean the workflow changed.
//!
//! A path reads the results the way a step reads its input: `trigger` for
//! the case's input, then a step's key for what that step handed on, such
//! as `summarise.answer`. A step's key alone compares its whole output.

use crate::domains::workflows::data::{DataPath, FlowData, FlowValue};
use crate::shared::validation::{TextValue, Validator, text_value};

/// The longest a piece of expected text may be, in characters.
pub(crate) const MAX_EXPECTED_TEXT: usize = 2_000;

/// The longest a pattern may be, in characters.
pub(crate) const MAX_PATTERN: usize = 200;

/// The longest text a pattern is matched against, in bytes. Longer text
/// does not match, so one check never costs more than this times the
/// pattern's length.
pub(crate) const MAX_MATCHED_TEXT: usize = 64 * 1024;

/// The most of a found value a failed check keeps, in characters.
pub const MAX_FOUND: usize = 500;

text_value! {
    /// A piece of text a result must contain.
    pub struct ExpectedText;
}

impl TextValue for ExpectedText {
    const FIELD: &'static str = "expected_text";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .char_length(1..=MAX_EXPECTED_TEXT)
            .no_control_chars_but_line_breaks()
    }
}

text_value! {
    /// A short pattern a result's whole text must match: `*` stands for any
    /// run of characters, `?` for any one, and every other character for
    /// itself. There is no escape, so `*` and `?` are always wildcards.
    ///
    /// It is not a regular expression. A pattern cannot nest or repeat a
    /// group, so matching one never takes longer than the text times the
    /// pattern's length, however it is written.
    pub struct TextPattern;
}

impl TextValue for TextPattern {
    const FIELD: &'static str = "pattern";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.char_length(1..=MAX_PATTERN).no_control_chars()
    }
}

impl TextPattern {
    /// Whether all of `text` matches. Text longer than
    /// [`MAX_MATCHED_TEXT`] never does.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        if text.len() > MAX_MATCHED_TEXT {
            return false;
        }
        let pattern: Vec<char> = self.as_str().chars().collect();
        let text: Vec<char> = text.chars().collect();
        wildcard_match(&pattern, &text)
    }
}

/// One check of a test run's results.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum Expectation {
    /// The value at `at` is exactly `value`: the same JSON, fields in any
    /// order.
    Equals {
        /// Where in the results the value is read.
        at: DataPath,
        /// The value it must be.
        value: FlowData,
    },
    /// The value at `at`, as text, contains `text`.
    Contains {
        /// Where in the results the value is read.
        at: DataPath,
        /// The text it must contain.
        text: ExpectedText,
    },
    /// The value at `at`, as text, matches `pattern` from start to end.
    Matches {
        /// Where in the results the value is read.
        at: DataPath,
        /// The pattern it must match.
        pattern: TextPattern,
    },
}

impl Expectation {
    /// Where in the results the check reads.
    #[must_use]
    pub fn at(&self) -> &DataPath {
        match self {
            Self::Equals { at, .. } | Self::Contains { at, .. } | Self::Matches { at, .. } => at,
        }
    }

    /// The data the check carries towards its set's size: the expected
    /// value, or the text.
    pub(super) fn size(&self) -> usize {
        match self {
            Self::Equals { value, .. } => value.size(),
            Self::Contains { text, .. } => text.as_str().len(),
            Self::Matches { pattern, .. } => pattern.as_str().len(),
        }
    }

    /// Whether the check holds in `results`. When it does not, what was
    /// found at its path, if anything.
    pub(super) fn verdict(&self, results: &FlowData) -> Result<(), Option<Found>> {
        let Some(found) = results.at(self.at()) else {
            return Err(None);
        };
        if self.holds_for(found) {
            return Ok(());
        }
        Err(Some(Found::of(found)))
    }

    fn holds_for(&self, found: &FlowData) -> bool {
        match self {
            Self::Equals { value, .. } => same_value(value, found),
            Self::Contains { text, .. } => text_of(found).contains(text.as_str()),
            Self::Matches { pattern, .. } => pattern.matches(&text_of(found)),
        }
    }
}

text_value! {
    /// What a check that did not hold found at its path, as text, cut to
    /// [`MAX_FOUND`] characters.
    pub struct Found;
}

impl TextValue for Found {
    const FIELD: &'static str = "found";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.char_length(0..=MAX_FOUND)
    }
}

impl Found {
    /// What `value` reads as, cut to [`MAX_FOUND`] characters, which its
    /// rules always hold.
    #[must_use]
    pub fn of(value: &FlowData) -> Self {
        Self(text_of(value).chars().take(MAX_FOUND).collect())
    }
}

/// `value` as text: a text as itself, anything else as its JSON.
fn text_of(value: &FlowData) -> String {
    match value.value() {
        FlowValue::Text(text) => text.to_owned(),
        FlowValue::Null
        | FlowValue::Bool(_)
        | FlowValue::Number(_)
        | FlowValue::List(_)
        | FlowValue::Map(_) => value.render(),
    }
}

/// Whether `expected` and `found` hold the same value. A map's fields may
/// come in any order; a list's items must come in the same order.
fn same_value(expected: &FlowData, found: &FlowData) -> bool {
    match (expected.value(), found.value()) {
        (FlowValue::Map(want), FlowValue::Map(got)) => {
            want.len() == got.len()
                && want.iter().all(|(name, value)| {
                    got.iter()
                        .find(|(other, _)| other == name)
                        .is_some_and(|(_, other)| same_value(value, other))
                })
        }
        (FlowValue::List(want), FlowValue::List(got)) => {
            want.len() == got.len()
                && want
                    .iter()
                    .zip(got)
                    .all(|(value, other)| same_value(value, other))
        }
        (want, got) => want == got,
    }
}

/// Whether all of `text` matches `pattern`, `*` standing for any run of
/// characters and `?` for any one. Each mismatch goes back to the last `*`
/// and lets it take one more character, so no character of `text` is
/// tried against more than every position of `pattern`.
fn wildcard_match(pattern: &[char], text: &[char]) -> bool {
    let mut at_pattern = 0;
    let mut at_text = 0;
    let mut last_star: Option<(usize, usize)> = None;
    while let Some(&wanted) = text.get(at_text) {
        match pattern.get(at_pattern) {
            Some('*') => {
                last_star = Some((at_pattern, at_text));
                at_pattern = at_pattern.saturating_add(1);
            }
            Some(&one) if one == '?' || one == wanted => {
                at_pattern = at_pattern.saturating_add(1);
                at_text = at_text.saturating_add(1);
            }
            Some(_) | None => {
                let Some((star, taken)) = last_star else {
                    return false;
                };
                last_star = Some((star, taken.saturating_add(1)));
                at_pattern = star.saturating_add(1);
                at_text = taken.saturating_add(1);
            }
        }
    }
    pattern.iter().skip(at_pattern).all(|&rest| rest == '*')
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::domains::workflows::data::FieldName;

    fn path(text: &str) -> DataPath {
        DataPath::parse(text).unwrap()
    }

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn pattern(text: &str) -> TextPattern {
        TextPattern::new(text).unwrap()
    }

    /// What a summarising step handed on, under the results' step key.
    fn results(answer: FlowData) -> FlowData {
        let step = FlowData::map(vec![(field("answer"), answer)]).unwrap();
        FlowData::map(vec![(field("summarise"), step)]).unwrap()
    }

    /// Ann expects the summary step's whole output. The same fields in
    /// another order pass; one value different fails and says what was
    /// there.
    #[test]
    fn an_exact_value_passes_in_any_field_order_and_fails_on_a_difference() {
        let expected = FlowData::map(vec![
            (field("answer"), FlowData::text("refund").unwrap()),
            (field("score"), FlowData::number(2.0).unwrap()),
        ])
        .unwrap();
        let reordered = FlowData::map(vec![
            (field("score"), FlowData::number(2.0).unwrap()),
            (field("answer"), FlowData::text("refund").unwrap()),
        ])
        .unwrap();
        let other = FlowData::map(vec![
            (field("score"), FlowData::number(3.0).unwrap()),
            (field("answer"), FlowData::text("refund").unwrap()),
        ])
        .unwrap();
        let check = Expectation::Equals {
            at: path("summarise"),
            value: expected,
        };
        let wrap = |output: FlowData| FlowData::map(vec![(field("summarise"), output)]).unwrap();

        let same = check.verdict(&wrap(reordered));
        let differs = check.verdict(&wrap(other));

        assert_eq!(same, Ok(()));
        assert_eq!(
            differs.unwrap_err().unwrap().as_str(),
            r#"{"score":3,"answer":"refund"}"#
        );
    }

    /// A field that equals passes; a field the run never produced fails
    /// with nothing found.
    #[test]
    fn a_field_equals_or_is_missing() {
        let check = Expectation::Equals {
            at: path("summarise.answer"),
            value: FlowData::text("refund").unwrap(),
        };
        let missing = Expectation::Equals {
            at: path("summarise.reason"),
            value: FlowData::text("late").unwrap(),
        };
        let output = results(FlowData::text("refund").unwrap());

        assert_eq!(check.verdict(&output), Ok(()));
        assert_eq!(missing.verdict(&output), Err(None));
    }

    /// Text that contains the expected words passes; text without them
    /// fails with what was there.
    #[test]
    fn text_contains_its_expected_words() {
        let check = Expectation::Contains {
            at: path("summarise.answer"),
            text: ExpectedText::new("refund").unwrap(),
        };

        let passes = check.verdict(&results(FlowData::text("issue a refund").unwrap()));
        let fails = check.verdict(&results(FlowData::text("close it").unwrap()));

        assert_eq!(passes, Ok(()));
        assert_eq!(fails.unwrap_err().unwrap().as_str(), "close it");
    }

    /// A ticket number in the shape `INC-` and four characters matches;
    /// one with a missing character does not.
    #[test]
    fn a_pattern_matches_the_whole_text() {
        let check = Expectation::Matches {
            at: path("summarise.answer"),
            pattern: pattern("INC-????"),
        };

        let passes = check.verdict(&results(FlowData::text("INC-2041").unwrap()));
        let fails = check.verdict(&results(FlowData::text("INC-204").unwrap()));

        assert_eq!(passes, Ok(()));
        assert!(fails.is_err());
    }

    /// Stars take any run of characters, none included.
    #[test]
    fn stars_take_any_run_of_characters() {
        assert!(pattern("*refund*").matches("refund"));
        assert!(pattern("*refund*").matches("we refund it"));
        assert!(pattern("a*b*c").matches("axxbyyc"));
        assert!(!pattern("a*b*c").matches("axxbyy"));
        assert!(pattern("*").matches(""));
    }

    /// Text past the matching limit never matches, so a long result cannot
    /// make a check slow.
    #[test]
    fn text_past_the_limit_never_matches() {
        let long = "a".repeat(MAX_MATCHED_TEXT + 1);

        assert!(!pattern("*").matches(&long));
    }

    /// A pattern longer than the limit, or with a control character, is
    /// refused.
    #[test]
    fn a_pattern_is_short_and_printable() {
        assert!(TextPattern::new("a".repeat(MAX_PATTERN + 1)).is_err());
        assert!(TextPattern::new("a\u{7}").is_err());
    }

    /// A found value is cut to what a check keeps.
    #[test]
    fn a_found_value_is_cut_short() {
        let long = FlowData::text("x".repeat(MAX_FOUND * 2)).unwrap();

        assert_eq!(Found::of(&long).as_str().chars().count(), MAX_FOUND);
    }

    proptest! {
        /// A pattern with no wildcard matches exactly its own text.
        #[test]
        fn a_plain_pattern_matches_only_itself(text in "[a-z]{1,40}", other in "[a-z]{1,40}") {
            let plain = pattern(&text);

            prop_assert!(plain.matches(&text));
            prop_assert_eq!(plain.matches(&other), text == other);
        }

        /// A star matches any text at all.
        #[test]
        fn a_star_matches_anything(text in ".{0,200}") {
            prop_assert!(pattern("*").matches(&text));
        }
    }
}
