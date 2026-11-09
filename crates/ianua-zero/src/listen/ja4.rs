//! The JA4 fingerprint of a TLS client, from its ClientHello.
//!
//! JA4 (FoxIO) names what a TLS library offers rather than who runs it:
//! every browser build, HTTP library and bot framework sends its own mix of
//! versions, cipher suites, extensions and signature algorithms, and the
//! fingerprint stays the same across connections from the same software.
//! A request stage reads it to tell a browser from automation that claims
//! to be one.
//!
//! It reads `a_b_c`:
//!
//! - `a`: `t` for TLS over TCP; the highest version offered (`13`, `12`,
//!   ...); `d` when the client named a server, `i` when not; the number of
//!   cipher suites and of extensions, two digits each, at most 99; the
//!   first and last character of the first ALPN protocol, or `00`.
//! - `b`: the first 12 hex digits of the SHA-256 of the cipher suites,
//!   sorted, as four-digit hex joined by commas.
//! - `c`: the same of the extensions, sorted, without the server name and
//!   ALPN, then `_` and the signature algorithms in the order sent.
//!
//! GREASE values (RFC 8701), which clients send at random to keep servers
//! tolerant, are left out everywhere.

use std::fmt;

use sha2::{Digest, Sha256};

use super::hello::{ALPN, ClientHello, SERVER_NAME};

/// What an empty list hashes to.
const NOTHING: &str = "000000000000";

/// The largest count written.
const MAX_COUNT: usize = 99;

/// A client's JA4 fingerprint, such as `t13d1516h2_8daaf6152771_e5627efa2ab1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Ja4(String);

impl Ja4 {
    /// The fingerprint of `hello`.
    pub(crate) fn of(hello: &ClientHello) -> Self {
        Self(format!(
            "{}_{}_{}",
            summary(hello),
            cipher_hash(hello),
            extension_hash(hello)
        ))
    }

    /// The fingerprint as text.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `value` is one of the sixteen GREASE values, `0x0a0a` to
/// `0xfafa`.
fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0x00ff
}

fn real(values: &[u16]) -> impl Iterator<Item = u16> + '_ {
    values.iter().copied().filter(|value| !is_grease(*value))
}

fn count(values: &[u16]) -> usize {
    real(values).count().min(MAX_COUNT)
}

fn summary(hello: &ClientHello) -> String {
    format!(
        "t{}{}{:02}{:02}{}",
        version(hello),
        server_named(hello),
        count(hello.cipher_suites()),
        count(hello.extensions()),
        alpn(hello.first_protocol())
    )
}

/// The highest version offered: from `supported_versions` when sent, else
/// from the ClientHello's own header.
fn version(hello: &ClientHello) -> &'static str {
    let highest = real(hello.supported_versions())
        .max()
        .unwrap_or(hello.legacy_version());
    match highest {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn server_named(hello: &ClientHello) -> char {
    if hello.extensions().contains(&SERVER_NAME) {
        return 'd';
    }
    'i'
}

/// The first and last character of the first protocol; their hex digits
/// when either is not an ASCII letter or digit; `00` when none is offered.
fn alpn(first: Option<&[u8]>) -> String {
    let Some((&head, &tail)) = first.and_then(|protocol| protocol.first().zip(protocol.last()))
    else {
        return "00".to_owned();
    };
    if head.is_ascii_alphanumeric() && tail.is_ascii_alphanumeric() {
        return format!("{}{}", char::from(head), char::from(tail));
    }
    let head = format!("{head:02x}");
    let tail = format!("{tail:02x}");
    format!("{}{}", &head[..1], &tail[1..])
}

fn cipher_hash(hello: &ClientHello) -> String {
    let mut ciphers: Vec<u16> = real(hello.cipher_suites()).collect();
    ciphers.sort_unstable();
    truncated_hash(&joined(&ciphers))
}

fn extension_hash(hello: &ClientHello) -> String {
    let mut extensions: Vec<u16> = real(hello.extensions())
        .filter(|kind| *kind != SERVER_NAME && *kind != ALPN)
        .collect();
    extensions.sort_unstable();
    if extensions.is_empty() {
        return NOTHING.to_owned();
    }
    let signature_algorithms: Vec<u16> = real(hello.signature_algorithms()).collect();
    if signature_algorithms.is_empty() {
        return truncated_hash(&joined(&extensions));
    }
    truncated_hash(&format!(
        "{}_{}",
        joined(&extensions),
        joined(&signature_algorithms)
    ))
}

fn joined(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// The first 12 hex digits of the SHA-256 of `text`, or [`NOTHING`] for
/// no text.
fn truncated_hash(text: &str) -> String {
    if text.is_empty() {
        return NOTHING.to_owned();
    }
    Sha256::digest(text.as_bytes())[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listen::hello::{read_client_hello, samples};

    async fn ja4_of(record: Vec<u8>) -> Ja4 {
        let recorded = read_client_hello(&mut std::io::Cursor::new(record))
            .await
            .unwrap();
        Ja4::of(recorded.hello())
    }

    /// The example the JA4 specification publishes, sent with GREASE
    /// values and out of order, fingerprints as the specification says.
    #[tokio::test]
    async fn the_published_example_fingerprints_as_published() {
        let ja4 = ja4_of(samples::published_example()).await;

        assert_eq!(ja4.as_str(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    /// Without `supported_versions` the version comes from the header;
    /// without a server name, ALPN or extensions the parts say so.
    #[tokio::test]
    async fn a_bare_hello_fingerprints_from_its_header() {
        let ja4 = ja4_of(samples::record(&[0x002f], &[])).await;

        assert_eq!(ja4.as_str(), "t12i010000_ba72b8082249_000000000000");
    }

    /// An extension list without signature algorithms is hashed without
    /// the underscore.
    #[tokio::test]
    async fn extensions_without_signature_algorithms_hash_alone() {
        let ja4 = ja4_of(samples::record(&[0x1301], &[(0x0017, Vec::new())])).await;

        assert_eq!(&ja4.as_str()[24..], truncated_hash("0017"));
    }

    /// Every GREASE value is recognised, and nothing else is.
    #[test]
    fn grease_values_are_the_sixteen_doubled_nibbles() {
        let grease: Vec<u16> = (0..=u16::MAX).filter(|value| is_grease(*value)).collect();

        assert_eq!(grease.len(), 16);
        assert_eq!(grease[0], 0x0a0a);
        assert_eq!(grease[15], 0xfafa);
    }

    /// The ALPN part takes the first and last characters, repeats a single
    /// one, and falls back to hex digits for anything not alphanumeric.
    #[test]
    fn the_alpn_part_follows_the_specification() {
        assert_eq!(alpn(Some(b"h2")), "h2");
        assert_eq!(alpn(Some(b"http/1.1")), "h1");
        assert_eq!(alpn(Some(b"h")), "hh");
        assert_eq!(alpn(Some(&[0xab])), "ab");
        assert_eq!(alpn(Some(&[0xab, 0xcd])), "ad");
        assert_eq!(alpn(Some(&[0x30, 0xab])), "3b");
        assert_eq!(alpn(Some(b"")), "00");
        assert_eq!(alpn(None), "00");
    }

    /// Counts stop at 99.
    #[test]
    fn counts_stop_at_ninety_nine() {
        let many: Vec<u16> = (1..=150).collect();

        assert_eq!(count(&many), 99);
    }
}
