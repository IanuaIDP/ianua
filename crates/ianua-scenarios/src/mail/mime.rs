//! A mail message read from the text an SMTP client handed over: its
//! headers, its subject, and its plain-text and HTML parts decoded.
//!
//! Enough of RFC 5322, 2045, 2046 and 2047 for what the platform's mail
//! builder writes: folded headers, nested `multipart/*` bodies split at
//! their boundary, `quoted-printable` and `base64` transfer encodings, and
//! encoded words in the subject. Every text is read as UTF-8.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// What a message holds once decoded.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Decoded {
    /// The subject, its encoded words decoded.
    pub(super) subject: String,
    /// The first plain-text part.
    pub(super) text: Option<String>,
    /// The first HTML part.
    pub(super) html: Option<String>,
}

/// The message `raw` decoded.
pub(super) fn decoded(raw: &str) -> Decoded {
    let normalized = raw.replace("\r\n", "\n");
    let entity = Entity::of(&normalized);
    let mut decoded = Decoded {
        subject: entity.header("subject").map(words).unwrap_or_default(),
        ..Decoded::default()
    };
    entity.collect_into(&mut decoded);
    decoded
}

/// One MIME entity: its unfolded headers and its body.
struct Entity<'a> {
    headers: Vec<(String, String)>,
    body: &'a str,
}

impl<'a> Entity<'a> {
    /// The entity `text` writes, its headers ended by the first blank line.
    fn of(text: &'a str) -> Self {
        let (head, body) = text.split_once("\n\n").unwrap_or((text, ""));
        Self {
            headers: unfolded(head),
            body,
        }
    }

    /// The value of the header `name`, matched without regard to case.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The media type, in lowercase, `text/plain` when none is given.
    fn media_type(&self) -> String {
        self.header("content-type")
            .and_then(|value| value.split(';').next())
            .map_or_else(
                || "text/plain".to_owned(),
                |kind| kind.trim().to_ascii_lowercase(),
            )
    }

    /// Fills `decoded` with the first plain-text and HTML parts of this
    /// entity and the entities nested in it.
    fn collect_into(&self, decoded: &mut Decoded) {
        let media_type = self.media_type();
        if media_type.starts_with("multipart/") {
            let boundary = self
                .header("content-type")
                .and_then(|value| parameter(value, "boundary"));
            let Some(boundary) = boundary else {
                return;
            };
            for part in parts(self.body, &boundary) {
                Entity::of(&part).collect_into(decoded);
            }
            return;
        }
        let slot = match media_type.as_str() {
            "text/plain" => &mut decoded.text,
            "text/html" => &mut decoded.html,
            _ => return,
        };
        if slot.is_none() {
            *slot = Some(self.content());
        }
    }

    /// The body with its transfer encoding undone.
    fn content(&self) -> String {
        let encoding = self
            .header("content-transfer-encoding")
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        match encoding.as_str() {
            "base64" => base64_text(self.body),
            "quoted-printable" => quoted_printable(self.body),
            _ => self.body.to_owned(),
        }
    }
}

/// The headers of `head`, each continuation line joined to the one before.
fn unfolded(head: &str) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.lines() {
        let continues = line.starts_with([' ', '\t']);
        match (continues, headers.last_mut()) {
            (true, Some((_, value))) => {
                value.push(' ');
                value.push_str(line.trim());
            }
            _ => {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                headers.push((name.trim().to_owned(), value.trim().to_owned()));
            }
        }
    }
    headers
}

/// The parameter `name` of a header value such as
/// `multipart/alternative; boundary="b1"`, its quotes taken off.
fn parameter(value: &str, name: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|pair| {
        let (key, given) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| given.trim().trim_matches('"').to_owned())
    })
}

/// What a line of a multipart body is.
enum Line {
    /// The boundary between two parts.
    Delimiter,
    /// The boundary after the last part.
    Close,
    /// A line of a part.
    Content,
}

/// The parts of a multipart `body` split at `boundary`, the preamble and
/// the epilogue left out.
fn parts(body: &str, boundary: &str) -> Vec<String> {
    let delimiter = format!("--{boundary}");
    let close = format!("--{boundary}--");
    let mut parts = Vec::new();
    let mut current: Option<String> = None;
    for line in body.lines() {
        let kind = match line.trim_end() {
            written if written == close => Line::Close,
            written if written == delimiter => Line::Delimiter,
            _ => Line::Content,
        };
        match kind {
            Line::Close => break,
            Line::Delimiter => parts.extend(current.replace(String::new())),
            Line::Content => append_line(current.as_mut(), line),
        }
    }
    parts.extend(current);
    parts
}

/// Adds `line` to `part`, when a part has begun.
fn append_line(part: Option<&mut String>, line: &str) {
    let Some(part) = part else {
        return;
    };
    part.push_str(line);
    part.push('\n');
}

/// `body` decoded from base64, its line breaks ignored.
fn base64_text(body: &str) -> String {
    let joined: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD
        .decode(joined)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// `body` decoded from quoted-printable: `=XX` is the byte `XX`, and `=`
/// at a line's end joins it to the next.
fn quoted_printable(body: &str) -> String {
    let bytes = body.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let (byte, read) = quoted_at(bytes, at);
        decoded.extend(byte);
        at += read;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// The byte quoted-printable text writes at `at`, if any, and how many
/// bytes it takes.
fn quoted_at(bytes: &[u8], at: usize) -> (Option<u8>, usize) {
    if bytes[at] != b'=' {
        return (Some(bytes[at]), 1);
    }
    if bytes.get(at + 1) == Some(&b'\n') {
        return (None, 2);
    }
    let pair = bytes.get(at + 1..at + 3).and_then(hex_byte);
    match pair {
        Some(byte) => (Some(byte), 3),
        None => (Some(b'='), 1),
    }
}

/// The byte two hex digits write.
fn hex_byte(digits: &[u8]) -> Option<u8> {
    let text = std::str::from_utf8(digits).ok()?;
    u8::from_str_radix(text, 16).ok()
}

/// A header value with its RFC 2047 encoded words decoded; the space
/// between two encoded words is dropped, as the RFC says.
fn words(value: &str) -> String {
    let mut written = String::new();
    let mut after_word = false;
    for token in value.split_whitespace() {
        let word = encoded_word(token);
        let between_words = after_word && word.is_some();
        let separated = !(written.is_empty() || between_words);
        if separated {
            written.push(' ');
        }
        after_word = word.is_some();
        written.push_str(&word.unwrap_or_else(|| token.to_owned()));
    }
    written
}

/// `token` decoded when it is one encoded word, `=?charset?B|Q?text?=`.
fn encoded_word(token: &str) -> Option<String> {
    let inner = token.strip_prefix("=?")?.strip_suffix("?=")?;
    let mut pieces = inner.splitn(3, '?');
    let _charset = pieces.next()?;
    let encoding = pieces.next()?;
    let text = pieces.next()?;
    match encoding {
        "B" | "b" => Some(base64_text(text)),
        "Q" | "q" => Some(quoted_printable(&text.replace('_', " "))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message of plain text and HTML alternatives, the text in
    /// quoted-printable and the HTML in base64, is read whole.
    #[test]
    fn alternatives_in_both_encodings_are_decoded() {
        let html = STANDARD.encode("<p>Hello <b>Ann</b></p>");
        let raw = format!(
            "From: noreply@example.test\r\n\
             Subject: =?utf-8?b?Q29uZmlybSB5b3Vy?= =?utf-8?b?IHNpZ24tdXA=?=\r\n\
             Content-Type: multipart/alternative;\r\n boundary=\"b1\"\r\n\
             \r\n\
             --b1\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             Go to https://app.s1.test/signup/confirm?token=3Dabc and a long =\r\n\
             line =C3=A9.\r\n\
             --b1\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {html}\r\n\
             --b1--\r\n"
        );

        let decoded = decoded(&raw);

        assert_eq!(decoded.subject, "Confirm your sign-up");
        assert_eq!(
            decoded.text.as_deref(),
            Some("Go to https://app.s1.test/signup/confirm?token=abc and a long line \u{e9}.\n")
        );
        assert_eq!(decoded.html.as_deref(), Some("<p>Hello <b>Ann</b></p>"));
    }

    /// A message with no MIME headers is one plain-text part.
    #[test]
    fn a_message_without_mime_headers_is_plain_text() {
        let decoded = decoded("Subject: Hi\r\n\r\nYour code is 123456.\r\n");

        assert_eq!(decoded.subject, "Hi");
        assert_eq!(decoded.text.as_deref(), Some("Your code is 123456.\n"));
        assert_eq!(decoded.html, None);
    }
}
