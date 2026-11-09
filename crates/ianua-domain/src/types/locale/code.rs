use crate::shared::validation::{TextValue, Validator, text_value};

/// All supported BCP 47 locale tags, embedded at compile time.
const LOCALES: &str = include_str!("data/locales.txt");

text_value! {
    /// A BCP 47 locale tag, such as `en-US` or `de-DE`.
    ///
    /// It must be exactly one of the supported tags in the embedded list.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ianua_domain::types::Locale;
    /// let locale = Locale::new("en-US").unwrap();
    /// assert_eq!(locale.as_str(), "en-US");
    /// ```
    pub struct Locale;
}

impl TextValue for Locale {
    const FIELD: &'static str = "locale";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.listed(LOCALES, "BCP 47 locale tag")
    }
}

impl Locale {
    /// Every supported BCP 47 locale tag, in list order.
    pub fn all() -> impl Iterator<Item = &'static str> {
        LOCALES.lines().filter(|line| !line.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `en-US` is on the supported list and is accepted.
    #[test]
    fn accepts_en_us() {
        assert!(Locale::new("en-US").is_ok());
    }

    /// `de-DE` is on the supported list and is accepted.
    #[test]
    fn accepts_de_de() {
        assert!(Locale::new("de-DE").is_ok());
    }

    /// `ja-JP` is on the supported list and is accepted.
    #[test]
    fn accepts_ja_jp() {
        assert!(Locale::new("ja-JP").is_ok());
    }

    /// `xx-XX` looks like a tag but is not on the list. It is refused.
    #[test]
    fn unlisted_locale_tags_are_refused() {
        assert!(Locale::new("xx-XX").is_err());
    }

    /// Empty text cannot select a locale outside the supported tag catalogue.
    #[test]
    fn an_empty_locale_is_refused() {
        assert!(Locale::new("").is_err());
    }

    /// The embedded list holds at least 60 tags. A shorter list would mean
    /// the file was cut.
    #[test]
    fn list_has_expected_count() {
        let count = LOCALES.lines().filter(|l| !l.is_empty()).count();
        assert!(count >= 60, "expected 60+ locales, got {count}");
    }

    /// A settings screen offers every tag from [`Locale::all`]. Each one,
    /// `en-US` among them, is accepted, and no blank line shows up as a
    /// choice.
    #[test]
    fn every_offered_tag_is_one_this_type_accepts() {
        let offered: Vec<&str> = Locale::all().collect();

        assert!(offered.len() >= 60, "{}", offered.len());
        assert!(offered.contains(&"en-US"), "{offered:?}");
        for tag in offered {
            assert!(!tag.is_empty(), "a blank line was offered as a locale");
            assert!(Locale::new(tag).is_ok(), "{tag}");
        }
    }

    /// The locale `en-US` prints as `en-US`.
    #[test]
    fn renders_as_the_tag_it_was_built_from() {
        assert_eq!(Locale::new("en-US").unwrap().to_string(), "en-US");
    }
}
