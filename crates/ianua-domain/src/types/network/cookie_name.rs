use crate::shared::validation::{Charset, TextValue, Validator, text_value};

text_value! {
    /// A cookie name.
    ///
    /// It is an HTTP token as RFC 6265 section 4.1.1 defines it: letters,
    /// digits and the token symbols. So it can be read from a `Cookie` header
    /// and never splits one. Unlike a header name it keeps its case, because
    /// cookie names are case-sensitive.
    pub struct CookieName;
}

impl TextValue for CookieName {
    const FIELD: &'static str = "cookie_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=256,
            Charset::LOWERCASE | Charset::UPPERCASE | Charset::DIGIT | Charset::HTTP_TOKEN_SYMBOL,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Session_ID` is accepted and keeps its capitals, since cookie names
    /// are case-sensitive.
    #[test]
    fn a_token_is_accepted_with_its_case() {
        assert_eq!(
            CookieName::new("Session_ID").unwrap().as_str(),
            "Session_ID"
        );
    }

    /// Cookie names containing separators, spaces, quotes or line breaks
    /// are refused, as is an empty name, before they can split a header.
    #[test]
    fn a_name_that_would_split_a_cookie_header_is_refused() {
        for value in ["", "a=b", "a;b", "a b", "a,b", "a\"b", "a\r\nb"] {
            assert!(CookieName::new(value).is_err(), "{value:?} was accepted");
        }
    }
}
