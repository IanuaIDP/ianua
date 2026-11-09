//! Putting a refusal into the words of a language its reader reads.

use ianua_domain::shared::errors::Refusal;

/// The most languages read from one list; the rest are ignored.
const MOST_LANGUAGES: usize = 8;

/// The longest tag read; a longer one is no language anyone ships.
const LONGEST_TAG: usize = 35;

/// The languages a reader asked for, most wanted first, as BCP 47 tags
/// such as `de-AT` or `ja`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreferredLanguages(Vec<String>);

impl PreferredLanguages {
    /// The languages `tags` name, in the order given.
    #[must_use]
    pub fn new(tags: Vec<String>) -> Self {
        Self(tags)
    }

    /// The languages an `Accept-Language` value asks for, most wanted
    /// first: by quality, then in the order written. A language weighted
    /// `q=0`, a wildcard or a tag that is not one is left out; no value, or
    /// one that does not read, asks for none.
    #[must_use]
    pub fn from_accept_language(value: Option<&str>) -> Self {
        let Some(text) = value else {
            return Self::default();
        };
        let mut weighted: Vec<(u16, &str)> = text
            .split(',')
            .take(MOST_LANGUAGES)
            .filter_map(weighted_tag)
            .collect();
        weighted.sort_by(|(left, _), (right, _)| right.cmp(left));
        Self(
            weighted
                .into_iter()
                .map(|(_, tag)| tag.to_owned())
                .collect(),
        )
    }

    /// The tags, most wanted first.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.0
    }

    /// Whether the reader asked for no language at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Port wording a refusal in a reader's language from its message key.
pub trait RefusalWording: Send + Sync {
    /// `refusal` in the first of `languages` the platform words it in,
    /// filled with its values. None when it has no key, when no language
    /// asked for is shipped, or when the wording cannot be made: the
    /// refusal's own English text applies.
    fn worded(&self, refusal: &Refusal, languages: &PreferredLanguages) -> Option<String>;
}

/// One entry's tag and its quality in thousandths, when it asks for a language.
fn weighted_tag(entry: &str) -> Option<(u16, &str)> {
    let mut parts = entry.split(';');
    let tag = parts.next()?.trim();
    let quality = parts
        .find_map(|parameter| parameter.trim().strip_prefix("q="))
        .map_or(Some(1000), thousandths)?;
    let readable = !tag.is_empty()
        && tag.len() <= LONGEST_TAG
        && tag
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-');
    (readable && quality > 0).then_some((quality, tag))
}

/// A quality value such as `0.8`, in thousandths; none when it does not read.
fn thousandths(quality: &str) -> Option<u16> {
    let (whole, fraction) = quality
        .trim()
        .split_once('.')
        .unwrap_or((quality.trim(), ""));
    let digits: String = fraction.chars().chain("000".chars()).take(3).collect();
    let whole: u16 = whole.parse().ok()?;
    let fraction: u16 = digits.parse().ok()?;
    let value = whole.checked_mul(1000)?.checked_add(fraction)?;
    (value <= 1000).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(value: &str) -> Vec<String> {
        PreferredLanguages::from_accept_language(Some(value))
            .tags()
            .to_vec()
    }

    /// Languages are ordered by quality, ties kept in the order written.
    #[test]
    fn languages_are_ordered_by_quality() {
        assert_eq!(
            read("fr;q=0.5, de-AT, de;q=0.9, en;q=0.5"),
            ["de-AT", "de", "fr", "en"]
        );
    }

    /// A refused language, a wildcard and junk are left out.
    #[test]
    fn refused_wildcard_and_junk_are_left_out() {
        assert_eq!(read("ja;q=0, *, <script>, uk;q=abc, es;q=2, ka"), ["ka"]);
    }

    /// No value asks for no language.
    #[test]
    fn no_value_asks_for_none() {
        assert!(PreferredLanguages::from_accept_language(None).is_empty());
    }
}
