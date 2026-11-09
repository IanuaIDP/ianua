//! The path of a proxied request, as a report on it may carry it.

use crate::types::UntrustedText;

/// The path a request arrived on, without its query string or fragment,
/// recorded as untrusted text.
///
/// Sign-in codes, reset tokens and signed links travel in the query string,
/// and a client may put anything after a `#`. A request log is read by many
/// people and shipped to a tenant's own log store, so neither part is ever
/// kept. Whoever builds an observation cannot keep them by mistake: the only
/// way in is [`ObservedPath::record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPath(UntrustedText);

impl ObservedPath {
    /// Records the path in `raw`, the request target as it arrived, cut at
    /// its first `?` or `#`.
    #[must_use]
    pub fn record(raw: &str) -> Self {
        let path = raw.split(['?', '#']).next().unwrap_or_default();
        Self(UntrustedText::record(path))
    }

    /// The recorded path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The recorded path as untrusted text, for a record that keeps it as
    /// such.
    #[must_use]
    pub fn as_text(&self) -> &UntrustedText {
        &self.0
    }
}

impl std::fmt::Display for ObservedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recording a callback URL keeps its path and removes the query
    /// containing the code and state.
    #[test]
    fn a_query_string_is_never_kept() {
        let path = ObservedPath::record("/callback?code=abc123&state=xyz");

        assert_eq!(path.as_str(), "/callback");
    }

    /// Recording a path removes its fragment, including any query-like text
    /// following the fragment delimiter.
    #[test]
    fn a_fragment_is_never_kept() {
        assert_eq!(ObservedPath::record("/app#access_token=t").as_str(), "/app");
        assert_eq!(ObservedPath::record("/app#x?token=t").as_str(), "/app");
    }

    /// A plain path is kept as it arrived.
    #[test]
    fn a_plain_path_is_kept() {
        assert_eq!(
            ObservedPath::record("/reports/2026").as_str(),
            "/reports/2026"
        );
    }
}
