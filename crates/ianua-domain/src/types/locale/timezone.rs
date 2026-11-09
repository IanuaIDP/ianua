use crate::shared::validation::{TextValue, Validator, text_value};

/// All supported IANA timezone identifiers, embedded at compile time.
const TIMEZONES: &str = include_str!("data/timezones.txt");

text_value! {
    /// An IANA timezone name, such as `UTC` or `America/New_York`.
    ///
    /// It must be exactly one of the supported names in the embedded list.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ianua_domain::types::Timezone;
    /// let tz = Timezone::new("America/New_York").unwrap();
    /// assert_eq!(tz.as_str(), "America/New_York");
    /// ```
    pub struct Timezone;
}

impl TextValue for Timezone {
    const FIELD: &'static str = "timezone";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.listed(TIMEZONES, "IANA time zone")
    }
}

impl Timezone {
    /// Every supported IANA timezone identifier, in list order.
    pub fn all() -> impl Iterator<Item = &'static str> {
        TIMEZONES.lines().filter(|line| !line.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `UTC` is on the supported list and is accepted.
    #[test]
    fn utc_is_a_supported_timezone() {
        assert!(Timezone::new("UTC").is_ok());
    }

    /// City zones from five regions, such as `America/New_York`,
    /// `Asia/Tokyo` and `Africa/Cairo`, are accepted.
    #[test]
    fn accepts_major_cities() {
        assert!(Timezone::new("America/New_York").is_ok());
        assert!(Timezone::new("Europe/Berlin").is_ok());
        assert!(Timezone::new("Asia/Tokyo").is_ok());
        assert!(Timezone::new("Australia/Sydney").is_ok());
        assert!(Timezone::new("Africa/Cairo").is_ok());
    }

    /// `Mars/Olympus_Mons` has the shape of a zone name but is not on the
    /// list. It is refused.
    #[test]
    fn unlisted_timezone_names_are_refused() {
        assert!(Timezone::new("Mars/Olympus_Mons").is_err());
    }

    /// Empty text is refused rather than supplying an unspecified timezone.
    #[test]
    fn an_empty_timezone_is_refused() {
        assert!(Timezone::new("").is_err());
    }

    /// The embedded list holds at least 90 zones. A shorter list would mean
    /// the file was cut.
    #[test]
    fn list_has_expected_count() {
        let count = TIMEZONES.lines().filter(|l| !l.is_empty()).count();
        assert!(count >= 90, "expected 90+ timezones, got {count}");
    }

    /// A settings screen offers every name from [`Timezone::all`]. Each one,
    /// `UTC` among them, is accepted, and no blank line shows up as a
    /// choice.
    #[test]
    fn every_offered_identifier_is_one_this_type_accepts() {
        let offered: Vec<&str> = Timezone::all().collect();

        assert!(offered.len() >= 90, "{}", offered.len());
        assert!(offered.contains(&"UTC"), "{offered:?}");
        for identifier in offered {
            assert!(
                !identifier.is_empty(),
                "a blank line was offered as a timezone"
            );
            assert!(Timezone::new(identifier).is_ok(), "{identifier}");
        }
    }

    /// The zone `Europe/Berlin` prints as `Europe/Berlin`.
    #[test]
    fn renders_as_the_identifier_it_was_built_from() {
        assert_eq!(
            Timezone::new("Europe/Berlin").unwrap().to_string(),
            "Europe/Berlin"
        );
    }
}
