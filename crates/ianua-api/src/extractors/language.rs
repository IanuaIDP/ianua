//! The languages a request asks for, read from `Accept-Language`.

use axum::http::HeaderValue;
use ianua_app::ports::shared::PreferredLanguages;

/// The languages `header` asks for, most wanted first; a header that is
/// not text asks for none.
#[must_use]
pub(crate) fn preferred_languages(header: Option<&HeaderValue>) -> PreferredLanguages {
    PreferredLanguages::from_accept_language(header.and_then(|value| value.to_str().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header's languages are read most wanted first.
    #[test]
    fn a_header_is_read_most_wanted_first() {
        let header = HeaderValue::from_static("en;q=0.5, de");

        assert_eq!(preferred_languages(Some(&header)).tags(), ["de", "en"]);
    }

    /// No header asks for no language.
    #[test]
    fn no_header_asks_for_none() {
        assert!(preferred_languages(None).is_empty());
    }
}
