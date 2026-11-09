//! Percent-encoding (RFC 3986) for paths and query strings.
//!
//! There are two decoders, because callers want different things from a
//! malformed escape. A rewrite passes it through untouched. A check refuses it.

/// The byte a `%XX` escape at the start of `rest` stands for, and the bytes
/// after it.
///
/// `None` when `rest` does not start with a well-formed escape. The escape
/// needs exactly two hex digits. `u8::from_str_radix` alone would also take a
/// leading `+` and read `%+1` as the byte 1.
fn escaped_byte(rest: &[u8]) -> Option<(u8, &[u8])> {
    let [b'%', high, low, after @ ..] = rest else {
        return None;
    };
    let digit = |byte: &u8| char::from(*byte).to_digit(16);
    let value = digit(high)?.checked_mul(16)?.checked_add(digit(low)?)?;
    Some((u8::try_from(value).ok()?, after))
}

/// Decodes every `%XX` escape, or `None` if any `%` does not start one.
pub(crate) fn decode_strict(raw: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw.as_bytes();
    while let [first, tail @ ..] = rest {
        let (byte, after) = match first {
            b'%' => escaped_byte(rest)?,
            _ => (*first, tail),
        };
        out.push(byte);
        rest = after;
    }
    Some(out)
}

/// Decodes `%XX` escapes, leaving anything malformed as written.
pub(crate) fn decode_lenient(raw: &str) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw.as_bytes();
    while let [first, tail @ ..] = rest {
        let (byte, after) = escaped_byte(rest).unwrap_or((*first, tail));
        out.push(byte);
        rest = after;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encodes everything outside the unreserved set.
pub(crate) fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Percent-encodes every byte of a decoded path segment outside the plain
/// path characters of RFC 3986 (`pchar`, less `;`, which servlet stacks read
/// as a parameter).
pub(crate) fn encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b'='
            | b':'
            | b'@' => out.push(char::from(byte)),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `a%20b%2F` decodes to `a b/` with both the strict and the lenient
    /// decoder.
    #[test]
    fn well_formed_escapes_decode_both_ways() {
        assert_eq!(decode_strict("a%20b%2F").unwrap(), b"a b/");
        assert_eq!(decode_lenient("a%20b%2F"), "a b/");
    }

    /// `%+1` is not an escape for the byte 1, since a sign is not a hex
    /// digit. The strict decoder refuses it and the lenient one keeps it as
    /// written.
    #[test]
    fn a_signed_escape_is_malformed() {
        assert!(decode_strict("%+1").is_none());
        assert_eq!(decode_lenient("%+1"), "%+1");
    }

    /// `ab%4` ends one digit short, and `%` has no digits at all. The strict
    /// decoder refuses them. The lenient one returns them unchanged.
    #[test]
    fn a_truncated_escape_is_refused_strictly_and_kept_leniently() {
        assert!(decode_strict("ab%4").is_none());
        assert_eq!(decode_lenient("ab%4"), "ab%4");
        assert_eq!(decode_lenient("%"), "%");
    }

    /// Encoding `a b/~` escapes the space and slash and keeps the letters and
    /// the tilde.
    #[test]
    fn encoding_leaves_only_unreserved_characters_bare() {
        assert_eq!(encode("a b/~"), "a%20b%2F~");
    }

    /// A path segment keeps the characters a request line carries plainly
    /// and escapes the rest: `a b;c/é@x` is `a%20b%3Bc%2F%C3%A9@x`.
    #[test]
    fn a_path_segment_escapes_only_what_a_request_line_cannot_carry() {
        assert_eq!(encode_path_segment("a b;c/é@x"), "a%20b%3Bc%2F%C3%A9@x");
        assert_eq!(encode_path_segment("v1.2~!$&'()*+,=:"), "v1.2~!$&'()*+,=:");
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// For any text, encoding then decoding, strictly or leniently,
            /// gives back the same text.
            #[test]
            fn decoding_an_encoding_gives_back_the_text(text in ".*") {
                prop_assert_eq!(decode_lenient(&encode(&text)), text.clone());
                prop_assert_eq!(decode_strict(&encode(&text)).unwrap(), text.into_bytes());
            }

            /// Any text a client sends, however malformed, goes through both
            /// decoders without a panic.
            #[test]
            fn lenient_decoding_never_panics(raw in ".*") {
                let _ = decode_lenient(&raw);
                let _ = decode_strict(&raw);
            }
        }
    }
}
