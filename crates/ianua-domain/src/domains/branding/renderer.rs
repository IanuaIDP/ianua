//! A rendered email: a subject, an optional HTML body and a plain-text body.
//!
//! Filling a template with its values happens in the mail adapter, when the
//! queued mail is sent, and behind the `TemplateRenderer` port for a
//! preview. This module holds only the finished result the transport sends.

/// A fully rendered email ready for delivery.
///
/// The plain-text body is for clients that do not show HTML. When both bodies
/// exist, transports send them as a `multipart/alternative` message.
///
/// The bodies carry one-time reset, sign-in and verification links, so
/// `Debug` shows the subject and which parts exist, never their text.
#[derive(Clone, PartialEq, Eq)]
pub struct RenderedEmail {
    subject: String,
    html: Option<String>,
    text: String,
}

impl RenderedEmail {
    /// Creates a plain-text-only rendered email.
    #[must_use]
    pub fn text_only(subject: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            html: None,
            text: text.into(),
        }
    }

    /// Creates a multipart rendered email with both HTML and plain text.
    #[must_use]
    pub fn multipart(
        subject: impl Into<String>,
        html: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            html: Some(html.into()),
            text: text.into(),
        }
    }

    /// The rendered subject line.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The rendered HTML body, or `None` for a plain-text-only email.
    #[must_use]
    pub fn html(&self) -> Option<&str> {
        self.html.as_deref()
    }

    /// The rendered plain-text body.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Debug for RenderedEmail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenderedEmail")
            .field("subject", &self.subject)
            .field("html", &self.html.as_ref().map(|_| "<redacted>"))
            .field("text", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Debug output for a reset email hides the token present in both
    /// bodies while retaining the subject.
    #[test]
    fn debug_never_shows_the_body_that_holds_a_one_time_link() {
        let email = RenderedEmail::multipart(
            "Reset your password",
            "<a href=\"https://acme.com/reset?token=s3cret\">reset</a>",
            "https://acme.com/reset?token=s3cret",
        );

        let shown = format!("{email:?}");

        assert!(!shown.contains("s3cret"));
        assert!(shown.contains("Reset your password"));
    }

    /// An email is built with a subject, an HTML body and a text body. Each
    /// getter gives back exactly the part it was built with.
    #[test]
    fn a_multipart_email_hands_the_mailer_the_parts_it_was_rendered_with() {
        let email =
            RenderedEmail::multipart("Verify your email", "<p>Hello Alice</p>", "Hello Alice");

        assert_eq!(email.subject(), "Verify your email");
        assert_eq!(email.html(), Some("<p>Hello Alice</p>"));
        assert_eq!(email.text(), "Hello Alice");
    }

    /// An email is built as text only. It has no HTML part, so the mailer
    /// never sends a multipart message with an empty HTML half.
    #[test]
    fn a_plain_text_email_carries_no_html_part() {
        let email = RenderedEmail::text_only("Verify your email", "Hello Alice");

        assert_eq!(email.subject(), "Verify your email");
        assert_eq!(email.html(), None);
        assert_eq!(email.text(), "Hello Alice");
    }
}
