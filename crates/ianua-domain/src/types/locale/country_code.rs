use crate::shared::validation::{Charset, TextValue, Validator, text_value};

/// All ISO 3166-1 alpha-2 country codes, embedded at compile time.
const CODES: &str = include_str!("data/country_codes.txt");

text_value! {
    /// An ISO 3166-1 alpha-2 country code, such as `US`, `DE` or `JP`.
    ///
    /// It must be two upper-case ASCII letters and a code the standard
    /// lists. A made-up code such as `XX` is refused.
    pub struct CountryCode;
}

impl TextValue for CountryCode {
    const FIELD: &'static str = "country_code";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(2..=2)
            .charset_single(Charset::UPPERCASE)
            .listed(CODES, "ISO 3166-1 country code")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real codes such as `US`, `DE`, `JP`, `NL` and `BR` are accepted.
    #[test]
    fn accepts_valid_codes() {
        assert!(CountryCode::new("US").is_ok());
        assert!(CountryCode::new("DE").is_ok());
        assert!(CountryCode::new("JP").is_ok());
        assert!(CountryCode::new("NL").is_ok());
        assert!(CountryCode::new("BR").is_ok());
    }

    /// `XX` and `ZZ` have the right shape but name no country. Both are
    /// refused.
    #[test]
    fn rejects_fictional_code() {
        assert!(CountryCode::new("XX").is_err());
        assert!(CountryCode::new("ZZ").is_err());
    }

    /// `us` in lower case is refused. Codes are upper case only.
    #[test]
    fn lowercase_country_codes_are_refused() {
        assert!(CountryCode::new("us").is_err());
    }

    /// The three-letter code `USA` is refused. Only the two-letter form is
    /// kept.
    #[test]
    fn rejects_three_letters() {
        assert!(CountryCode::new("USA").is_err());
    }

    /// Empty text is refused rather than accepted as a country identifier.
    #[test]
    fn an_empty_country_code_is_refused() {
        assert!(CountryCode::new("").is_err());
    }

    /// `U1` has two characters but one is a digit. It is refused.
    #[test]
    fn country_codes_with_digits_are_refused() {
        assert!(CountryCode::new("U1").is_err());
    }

    /// The code `NL` prints as `NL`.
    #[test]
    fn display_returns_value() {
        let cc = CountryCode::new("NL").unwrap();
        assert_eq!(cc.to_string(), "NL");
    }

    /// The embedded list holds at least 240 codes. A shorter list would
    /// mean the file was cut and real countries would be refused.
    #[test]
    fn list_has_expected_count() {
        let count = CODES.lines().filter(|l| !l.is_empty()).count();
        assert!(count >= 240, "expected 240+ codes, got {count}");
    }
}
