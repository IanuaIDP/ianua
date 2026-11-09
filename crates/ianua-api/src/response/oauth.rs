//! What a browser in an OAuth flow is answered with: sent on to an address
//! (`302`), or handed a page whose form posts the answer to the client
//! (OAuth 2.0 Form Post Response Mode), so a code never sits in an address
//! bar or a server log.

use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// The only script the form page runs is its own, which posts the form;
/// nothing else loads and no one may frame it.
const FORM_POST_POLICY: &str =
    "default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'";

/// Where a browser goes next.
pub(crate) enum BrowserReply {
    /// `302` to this address.
    Redirect(String),
    /// A page whose form posts `fields` to `action` once it loads.
    FormPost {
        /// The client's redirect URI.
        action: String,
        /// The answer's parameters, by name.
        fields: Vec<(&'static str, String)>,
    },
}

impl IntoResponse for BrowserReply {
    fn into_response(self) -> Response {
        match self {
            Self::Redirect(to) => (StatusCode::FOUND, [(LOCATION, to)]).into_response(),
            Self::FormPost { action, fields } => form_post(&action, &fields),
        }
    }
}

/// The page posting `fields` to `action`.
fn form_post(action: &str, fields: &[(&'static str, String)]) -> Response {
    let inputs: String = fields
        .iter()
        .map(|(name, value)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                escape(name),
                escape(value)
            )
        })
        .collect();
    let page = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Continue</title></head>\
         <body onload=\"document.forms[0].submit()\">\
         <form method=\"post\" action=\"{}\">{inputs}\
         <noscript><button type=\"submit\">Continue</button></noscript></form></body></html>",
        escape(action)
    );
    let headers = [
        (
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        ),
        (
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(FORM_POST_POLICY),
        ),
    ];
    (StatusCode::OK, headers, page).into_response()
}

/// `value` made safe to print inside a quoted attribute.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Quotes and markup in state are escaped before entering an HTML attribute.
    #[test]
    fn a_value_cannot_leave_its_attribute() {
        assert_eq!(escape("\"><script>"), "&quot;&gt;&lt;script&gt;");
    }

    /// A form post answers a page, not a redirect.
    #[test]
    fn a_form_post_answers_a_page() {
        let response = BrowserReply::FormPost {
            action: "https://app.example.com/cb".to_owned(),
            fields: vec![("code", "abc".to_owned())],
        }
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(LOCATION).is_none());
    }
}
