use crate::shared::validation::{Charset, TextValue, Validator, text_value};

text_value! {
    /// An HTTP header name.
    ///
    /// It is an HTTP token of up to 256 letters, digits and token symbols.
    /// Header names ignore case, so it is stored in lower case and compares
    /// the same however it was written.
    pub struct HeaderName;
}

impl TextValue for HeaderName {
    const FIELD: &'static str = "header_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=256,
            Charset::LOWERCASE | Charset::UPPERCASE | Charset::DIGIT | Charset::HTTP_TOKEN_SYMBOL,
        )
    }

    fn normalized(value: String) -> String {
        value.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Content-Type` is kept as `content-type`, so it compares equal to any
    /// other spelling.
    #[test]
    fn lowercases_on_creation() {
        let h = HeaderName::new("Content-Type").unwrap();
        assert_eq!(h.as_str(), "content-type");
    }

    /// An empty name is refused before it can identify an HTTP header.
    #[test]
    fn an_empty_header_name_is_refused() {
        assert!(HeaderName::new("").is_err());
    }

    /// Header names with spaces, colons, line breaks, tabs, quotes or brackets
    /// are refused, including a line break followed by another header name.
    #[test]
    fn rejects_characters_outside_an_http_token() {
        for name in [
            "x evil",
            "x:evil",
            "x-evil\r\nset-cookie",
            "x\tevil",
            "x\"evil",
            "(x)",
        ] {
            assert!(HeaderName::new(name).is_err(), "{name:?} was accepted");
        }
    }

    /// A name using every HTTP token symbol, from `!` to `~`, is accepted.
    #[test]
    fn accepts_every_token_symbol() {
        assert!(HeaderName::new("x!#$%&'*+-.^_`|~1").is_ok());
    }

    /// Common names such as `Authorization` and `X-Request-Id` are accepted.
    #[test]
    fn accepts_standard_headers() {
        assert!(HeaderName::new("Authorization").is_ok());
        assert!(HeaderName::new("X-Request-Id").is_ok());
        assert!(HeaderName::new("x-custom-header").is_ok());
    }

    /// `X-Forwarded-User` prints as `x-forwarded-user`. That is the text the
    /// proxy writes onto a forwarded request.
    #[test]
    fn renders_as_the_lowercased_name() {
        let header = HeaderName::new("X-Forwarded-User").unwrap();

        assert_eq!(header.to_string(), "x-forwarded-user");
        assert_eq!(header.to_string(), header.as_str());
    }
}
