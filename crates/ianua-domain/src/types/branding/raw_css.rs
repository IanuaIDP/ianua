use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// Custom CSS for the tenant's login page, exactly as the tenant wrote
    /// it. It is untrusted and never placed in a page.
    ///
    /// It is kept only so the tenant can edit what they wrote. A page
    /// renders the [`SanitizedCss`](crate::types::branding::SanitizedCss) a sanitizer made
    /// from it, which holds only plain rules. The page's content security
    /// policy is the second check. It must not let a style reach any origin
    /// but the page's own.
    pub struct RawCss;
}

/// The most bytes a tenant's custom CSS may hold, as written and as
/// sanitized. A sanitizer refuses anything longer before it reads a
/// character of it.
pub const MAX_CSS_BYTES: usize = 65536;

impl TextValue for RawCss {
    const FIELD: &'static str = "custom_css";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_empty().max_bytes(MAX_CSS_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant saves `body { background: #fff; }`. It reads back unchanged,
    /// so the tenant can edit exactly what they wrote.
    #[test]
    fn css_reads_back_as_written() {
        let css = RawCss::new("body { background: #fff; }").unwrap();

        assert_eq!(css.as_str(), "body { background: #fff; }");
    }

    /// A tenant saves an empty stylesheet. It is refused, so a blank value
    /// never replaces the default look.
    #[test]
    fn empty_css_is_refused() {
        assert!(RawCss::new("").is_err());
    }

    /// A stylesheet at the byte limit is accepted, but one additional byte
    /// is refused before storage and sanitization can carry it.
    #[test]
    fn css_past_the_limit_is_refused() {
        let at_limit = "a".repeat(MAX_CSS_BYTES);
        let past_limit = "a".repeat(MAX_CSS_BYTES + 1);

        assert!(RawCss::new(at_limit).is_ok());
        assert!(RawCss::new(past_limit).is_err());
    }
}
