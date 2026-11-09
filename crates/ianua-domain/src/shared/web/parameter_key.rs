//! The one way a request parameter's name is compared, wherever it is.
//!
//! Servers read one name under many spellings:
//! - any case, as ASP.NET does
//! - `+` for a space and percent-escapes, as form decoding does
//! - a trailing `[]` or `[key]`, as qs, Express, Rails, Rack and PHP do
//! - leading spaces dropped, and `.` or a space read as `_`, as PHP does
//!
//! A rule written for `debug` must catch every one of them. So the query
//! transform and the parameter rules compare names only through this type,
//! and always agree.

/// A parameter name folded to what every lenient server reads it as.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ParameterKey(String);

impl ParameterKey {
    /// The key for a name as a client sent it in a query string.
    ///
    /// `+` and percent-escapes are decoded first, as a form-reading server
    /// does.
    pub(crate) fn sent_in_query(raw: &str) -> Self {
        Self::written(&crate::shared::web::percent::decode_lenient(
            &raw.replace('+', " "),
        ))
    }

    /// The key for a name that is already plain text.
    ///
    /// That is a configured rule's name, a JSON key, or a query name the
    /// caller decoded itself. It is not form-decoded again, so a configured
    /// `a+b` stays `a+b`.
    pub(crate) fn written(name: &str) -> Self {
        let base = name
            .split('[')
            .next()
            .unwrap_or(name)
            .trim_start_matches(' ');
        let folded = base
            .chars()
            .map(|c| match c {
                '.' | ' ' => '_',
                other => other.to_ascii_lowercase(),
            })
            .collect();
        Self(folded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(raw: &str) -> ParameterKey {
        ParameterKey::sent_in_query(raw)
    }

    /// Case variants, percent encoding and bracket suffixes produce the same
    /// parameter key as `debug`, keeping lenient server spellings comparable.
    #[test]
    fn every_spelling_a_server_reads_as_one_name_is_one_key() {
        let debug = ParameterKey::written("debug");

        for sent in [
            "debug",
            "DEBUG",
            "Debug",
            "debu%67",
            "debug[]",
            "debug[x]",
            "DEBUG[][]",
        ] {
            assert_eq!(key(sent), debug, "{sent:?}");
        }
    }

    /// `user.id`, `user+id` and `user%20id` all reach a PHP app as `user_id`.
    /// So all three match a rule written for `user_id`.
    #[test]
    fn php_reads_a_dot_or_a_space_as_an_underscore() {
        let key_name = ParameterKey::written("user_id");

        assert_eq!(key("user.id"), key_name);
        assert_eq!(key("user+id"), key_name);
        assert_eq!(key("user%20id"), key_name);
    }

    /// Leading spaces encoded with plus signs or percent escapes are removed
    /// so the parameter key agrees with PHP's interpretation.
    #[test]
    fn php_drops_the_spaces_a_name_starts_with() {
        let debug = ParameterKey::written("debug");

        assert_eq!(key("+debug"), debug);
        assert_eq!(key("%20%20debug"), debug);
    }

    /// A literal plus in a configured name matches an encoded plus in a query,
    /// while a query plus decoded as a space stays distinct.
    #[test]
    fn a_configured_name_is_not_form_decoded_again() {
        assert_eq!(key("a%2Bb"), ParameterKey::written("a+b"));
        assert_ne!(key("a+b"), ParameterKey::written("a+b"));
    }

    /// Folding does not merge real names. `debug` and `debugger` stay apart,
    /// and so do `url` and `uri`.
    #[test]
    fn different_names_stay_different() {
        assert_ne!(key("debug"), key("debugger"));
        assert_ne!(key("url"), key("uri"));
    }
}
