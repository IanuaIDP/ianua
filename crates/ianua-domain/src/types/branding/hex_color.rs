use crate::message;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

text_value! {
    /// A hex colour, such as `#FFF` or `#FF5733`.
    ///
    /// It is a `#` and then three or six hex digits, in either case. It is
    /// stored in upper case.
    pub struct HexColor;
}

impl TextValue for HexColor {
    const FIELD: &'static str = "color";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.rule(&HexColorShape)
    }

    fn normalized(value: String) -> String {
        value.to_ascii_uppercase()
    }
}

/// A `#` and then three or six hex digits.
struct HexColorShape;

impl Rule for HexColorShape {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let Some(digits) = value.strip_prefix('#') else {
            return Some(invalid_color(field));
        };
        let shaped = matches!(digits.len(), 3 | 6) && digits.bytes().all(|b| b.is_ascii_hexdigit());
        if shaped {
            return None;
        }
        Some(invalid_color(field))
    }
}

fn invalid_color(field: &'static str) -> ValidationError {
    ValidationError::Custom {
        field,
        code: "invalid_color".to_owned(),
        message: message!(
            "values-must-be-and-3-or-6",
            format!("{field} must be '#' and 3 or 6 hex digits (e.g. #FFF or #FF5733).")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant picks `#FFF` or `#FF5733` as a brand colour. Both are
    /// accepted as written.
    #[test]
    fn a_three_or_six_digit_colour_is_accepted() {
        assert_eq!(HexColor::new("#FFF").unwrap().as_str(), "#FFF");
        assert_eq!(HexColor::new("#FF5733").unwrap().as_str(), "#FF5733");
    }

    /// A tenant types `#ff5733` or `#abc`. They are kept as `#FF5733` and
    /// `#ABC`, so the same colour always reads the same.
    #[test]
    fn a_colour_is_stored_in_upper_case() {
        assert_eq!(HexColor::new("#ff5733").unwrap().as_str(), "#FF5733");
        assert_eq!(HexColor::new("#abc").unwrap().as_str(), "#ABC");
    }

    /// An empty value, a missing `#`, five digits, non-hex letters, a
    /// trailing `;` or newline, and a colour name like `red` are all refused.
    #[test]
    fn anything_but_a_hash_and_three_or_six_hex_digits_is_refused() {
        for value in [
            "", "FF5733", "#FF573", "#GGGGGG", "#FF5733;", "#FFF\n", "red",
        ] {
            assert!(HexColor::new(value).is_err(), "{value:?} was accepted");
        }
    }

    /// A colour followed by an extra CSS declaration is refused before it can
    /// add resource loading to a page's stylesheet.
    #[test]
    fn a_colour_cannot_carry_more_css() {
        assert!(HexColor::new("#FFF;background:url(x)").is_err());
    }
}
