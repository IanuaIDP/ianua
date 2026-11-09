//! What a person sent to an app's sign-in address: a form post, a JSON
//! body, or the query of an address a link or a provider opened.

use std::collections::HashMap;

use http::HeaderMap;
use http::header::{ACCEPT, CONTENT_TYPE};

/// How the person's client asked: a browser posting a form expects to be
/// sent somewhere, a script posting JSON expects JSON back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Client {
    /// A browser submitting a form or following a link.
    Browser,
    /// A JSON client that expects a structured response instead of a browser redirect.
    Script,
}

impl Client {
    /// How the client asked, from what it sends and says it accepts.
    pub(super) fn of(headers: &HeaderMap) -> Self {
        let accepts_json_only = header(headers, ACCEPT.as_str()).is_some_and(|accept| {
            accept.contains("application/json") && !accept.contains("text/html")
        });
        if accepts_json_only || is_json(header(headers, CONTENT_TYPE.as_str())) {
            return Self::Script;
        }
        Self::Browser
    }
}

/// The fields sent, whichever way they were encoded. Holds credentials, so
/// it has no `Debug`.
pub(super) struct Fields(HashMap<String, String>);

impl Fields {
    /// Reads `body` as JSON when the content type says so, as a form
    /// otherwise. JSON values that are not strings are left out.
    pub(super) fn read(content_type: Option<&str>, body: &[u8]) -> Self {
        if is_json(content_type) {
            return Self::from_json(body);
        }
        Self::from_form(body)
    }

    /// The fields of a query string.
    pub(super) fn from_query(query: Option<&str>) -> Self {
        Self::from_form(query.unwrap_or_default().as_bytes())
    }

    fn from_json(body: &[u8]) -> Self {
        let fields = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body)
            .map(|object| {
                object
                    .into_iter()
                    .filter_map(|(key, value)| value.as_str().map(|text| (key, text.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        Self(fields)
    }

    fn from_form(body: &[u8]) -> Self {
        Self(url::form_urlencoded::parse(body).into_owned().collect())
    }

    /// The value of `name`, if it was sent and is not empty.
    pub(super) fn value(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    /// Takes the value of `name`, if it was sent and is not empty.
    pub(super) fn take(&mut self, name: &str) -> Option<String> {
        self.0.remove(name).filter(|value| !value.is_empty())
    }

    /// Takes the value of `name`, which the action cannot go without.
    pub(super) fn require(&mut self, name: &'static str) -> Result<String, Unread> {
        self.take(name).ok_or(Unread::Missing(name))
    }
}

/// Why what was sent could not be read as the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unread {
    /// A field the action needs was not sent.
    Missing(&'static str),
    /// A field was sent in a shape it cannot have.
    Malformed,
}

impl Unread {
    /// The reason a refusal names: `missing_<field>` or `malformed`.
    pub(super) fn code(self) -> String {
        match self {
            Self::Missing(field) => format!("missing_{field}"),
            Self::Malformed => "malformed".to_owned(),
        }
    }
}

fn is_json(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| ct.starts_with("application/json"))
}

/// The value of the header `name`, when it is plain text.
pub(super) fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn a_form_post_is_read_as_its_fields() {
        let fields = Fields::read(
            Some("application/x-www-form-urlencoded"),
            b"email=a%40example.com&password=p%26w",
        );

        assert_eq!(fields.value("email"), Some("a@example.com"));
        assert_eq!(fields.value("password"), Some("p&w"));
    }

    #[test]
    fn a_json_body_keeps_only_its_strings() {
        let fields = Fields::read(
            Some("application/json; charset=utf-8"),
            br#"{"email":"a@example.com","admin":true}"#,
        );

        assert_eq!(fields.value("email"), Some("a@example.com"));
        assert_eq!(fields.value("admin"), None);
    }

    #[test]
    fn an_empty_field_counts_as_not_sent() {
        let mut fields = Fields::from_query(Some("email=&code=1"));

        assert_eq!(fields.require("email"), Err(Unread::Missing("email")));
        assert_eq!(fields.require("code").as_deref(), Ok("1"));
    }

    #[test]
    fn a_form_post_from_a_browser_is_a_browser() {
        let sent = headers(&[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "text/html,application/json"),
        ]);

        assert_eq!(Client::of(&sent), Client::Browser);
    }

    #[test]
    fn json_sent_or_asked_for_alone_is_a_script() {
        assert_eq!(
            Client::of(&headers(&[("content-type", "application/json")])),
            Client::Script
        );
        assert_eq!(
            Client::of(&headers(&[("accept", "application/json")])),
            Client::Script
        );
    }

    #[test]
    fn a_missing_field_names_itself_and_a_malformed_one_does_not() {
        assert_eq!(Unread::Missing("code").code(), "missing_code");
        assert_eq!(Unread::Malformed.code(), "malformed");
    }
}
