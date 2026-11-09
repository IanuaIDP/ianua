//! The platform's mail, received over SMTP the way a mail server would
//! take it, and read per recipient: the links and codes in it.
//!
//! The platform's own SMTP adapter sends to [`Mailbox`] unencrypted and
//! without signing in, which it allows outside production only, so the
//! receiver speaks the part of RFC 5321 that takes such a mail: `EHLO`,
//! `MAIL`, `RCPT`, `DATA` and `QUIT`, with `RSET` and `NOOP` answered too.
//! The message is decoded from its MIME parts, plain text and HTML, in
//! quoted-printable or base64.

mod mime;
mod smtp;

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;
use tokio::net::TcpListener;
use url::Url;

use crate::inbox::Inbox;

/// How long [`Mailbox::next_for`] waits for a mail to come.
const MAIL_WAIT: Duration = Duration::from_secs(30);

/// The SMTP receiver of the platform's mail.
pub struct Mailbox {
    address: SocketAddr,
    inbox: Inbox<Mail>,
}

impl fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mailbox")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Mailbox {
    /// A receiver listening on a port of loopback, until `shutdown` stops
    /// it.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub async fn open(shutdown: &Shutdown) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let inbox = Inbox::open();
        smtp::serve(listener, inbox.clone(), shutdown);
        Ok(Self { address, inbox })
    }

    /// Where the receiver listens, for the platform's SMTP settings.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The next mail for `address`, waiting up to thirty seconds for one.
    ///
    /// # Panics
    ///
    /// When no mail for `address` comes in that time, naming the address.
    pub async fn next_for(&self, address: &str) -> Mail {
        let next = self.inbox.next_for(address, MAIL_WAIT).await;
        let Some(mail) = next else {
            panic!("no mail reached {address} within {MAIL_WAIT:?}");
        };
        mail
    }

    /// The next mail for `address` if one comes within `wait`, for a mail
    /// the platform may or may not send, such as a notice it holds back
    /// because the address was mailed a moment ago.
    pub async fn within(&self, address: &str, wait: Duration) -> Option<Mail> {
        self.inbox.next_for(address, wait).await
    }

    /// Asserts that no mail for `address` comes within `quiet`: a refused
    /// request mails nobody, and an injected header reaches no second
    /// recipient.
    ///
    /// # Panics
    ///
    /// When a mail for `address` does come, naming its subject.
    pub async fn nothing_for(&self, address: &str, quiet: Duration) {
        let Some(mail) = self.inbox.next_for(address, quiet).await else {
            return;
        };
        panic!(
            "{address} was mailed {:?}, but should have got nothing",
            mail.subject()
        );
    }
}

/// One mail as its recipient got it.
#[derive(Clone)]
pub struct Mail {
    sender: String,
    recipient: String,
    subject: String,
    text: Option<String>,
    html: Option<String>,
}

impl fmt::Debug for Mail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mail")
            .field("sender", &self.sender)
            .field("recipient", &self.recipient)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl Mail {
    /// The address the envelope says it came from.
    #[must_use]
    pub fn sender(&self) -> &str {
        &self.sender
    }

    /// The address it was delivered to.
    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Its subject, decoded.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Its plain-text part, decoded, when it has one.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Its HTML part, decoded, when it has one.
    #[must_use]
    pub fn html(&self) -> Option<&str> {
        self.html.as_deref()
    }

    /// Every link in it, from the plain text when it has one and from the
    /// HTML otherwise, in the order they appear.
    #[must_use]
    pub fn links(&self) -> Vec<Url> {
        let readable = self
            .text
            .clone()
            .or_else(|| self.html.as_deref().map(unescaped))
            .unwrap_or_default();
        links_in(&readable)
    }

    /// The first link whose path starts with `path_prefix`, such as
    /// `/signup/confirm`.
    ///
    /// # Panics
    ///
    /// When it has no such link, naming the paths it has: never their
    /// queries, which hold the tokens.
    #[must_use]
    pub fn link_to(&self, path_prefix: &str) -> Url {
        let links = self.links();
        let found = links
            .iter()
            .find(|link| link.path().starts_with(path_prefix));
        let Some(link) = found else {
            let paths: Vec<&str> = links.iter().map(Url::path).collect();
            panic!(
                "the mail {:?} to {} has no link to {path_prefix}; its links go to {paths:?}",
                self.subject, self.recipient
            );
        };
        link.clone()
    }

    /// The `token` the first link to `path_prefix` carries in its query.
    ///
    /// # Panics
    ///
    /// When it has no such link, or the link carries no token.
    #[must_use]
    pub fn token_in(&self, path_prefix: &str) -> String {
        let link = self.link_to(path_prefix);
        let token = link
            .query_pairs()
            .find(|(name, _)| name == "token")
            .map(|(_, value)| value.into_owned());
        let Some(token) = token else {
            panic!(
                "the link to {path_prefix} in the mail {:?} carries no token",
                self.subject
            );
        };
        token
    }

    /// The code it carries: the first word of six to eight digits.
    ///
    /// # Panics
    ///
    /// When it carries none.
    #[must_use]
    pub fn code(&self) -> String {
        let readable = self.text.as_deref().or(self.html.as_deref()).unwrap_or("");
        let Some(code) = code_in(readable) else {
            panic!("the mail {:?} carries no code", self.subject);
        };
        code
    }
}

/// HTML text with the entities a link's query holds written out again.
fn unescaped(html: &str) -> String {
    html.replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("&quot;", "\"")
}

/// Every `http` and `https` link in `text`, ended by white space, a quote
/// or a bracket, with a sentence's closing punctuation left off.
fn links_in(text: &str) -> Vec<Url> {
    let ends = |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']');
    let mut links = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("http") {
        let candidate = &rest[start..];
        let length = candidate.find(ends).unwrap_or(candidate.len());
        let written = candidate[..length].trim_end_matches(['.', ',', ';', ':', '!', '?']);
        links.extend(web_link(written));
        rest = &candidate[length..];
    }
    links
}

/// `written` as a link, when it reads as an `http` or `https` URL.
fn web_link(written: &str) -> Option<Url> {
    Url::parse(written)
        .ok()
        .filter(|link| matches!(link.scheme(), "http" | "https"))
}

/// The first word of `text` made of six to eight digits and nothing else.
pub(crate) fn code_in(text: &str) -> Option<String> {
    text.split(|c: char| !c.is_ascii_digit())
        .find(|word| (6..=8).contains(&word.len()))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail(text: Option<&str>, html: Option<&str>) -> Mail {
        Mail {
            sender: "noreply@example.test".to_owned(),
            recipient: "ann@example.test".to_owned(),
            subject: "Confirm".to_owned(),
            text: text.map(str::to_owned),
            html: html.map(str::to_owned),
        }
    }

    /// The link to a page is found by its path, its token read from its
    /// query.
    #[test]
    fn the_link_to_a_page_is_found_by_its_path() {
        let ann = mail(
            Some("Hello.\nConfirm: https://app.s1.test/signup/confirm?token=abc123.\nBye."),
            None,
        );

        assert_eq!(ann.link_to("/signup").path(), "/signup/confirm");
        assert_eq!(ann.token_in("/signup/confirm"), "abc123");
    }

    /// A mail with HTML alone has its links read with the entities undone.
    #[test]
    fn a_link_in_html_alone_is_read_with_its_entities_undone() {
        let ann = mail(
            None,
            Some(r#"<a href="https://app.s1.test/confirm-sign-in?org=acme&amp;token=t0k">go</a>"#),
        );

        assert_eq!(ann.token_in("/confirm-sign-in"), "t0k");
    }

    /// The code is the first word of six to eight digits.
    #[test]
    fn the_code_is_the_first_word_of_six_to_eight_digits() {
        let ann = mail(
            Some("Use 12345 or not. Your code is 482913, valid 10 minutes."),
            None,
        );

        assert_eq!(ann.code(), "482913");
    }

    /// Asking for a reset link in a signup mail fails with a message naming
    /// the missing destination.
    #[test]
    #[should_panic(expected = "has no link to /reset")]
    fn asking_for_a_page_the_mail_does_not_link_to_fails() {
        let ann = mail(Some("https://app.s1.test/signup/confirm?token=abc"), None);

        let _ = ann.link_to("/reset");
    }
}
