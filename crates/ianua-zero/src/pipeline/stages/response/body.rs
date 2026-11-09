//! What an answer's headers say about its body: whether it is JSON, and
//! whether the bytes read are the body as written or an encoding of it.

use ianua_app::ports::proxy::ResponseMeta;
use ianua_domain::domains::proxy::stages::decision::HeaderEntry;

/// How the bytes the gateway read stand to the body the upstream wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Encoding {
    /// The bytes are the body itself.
    Plain,
    /// The bytes are compressed or otherwise encoded, so nothing in them can
    /// be read or rewritten as written.
    Encoded,
}

/// What the answer's `Content-Encoding` says of its bytes.
///
/// No header, or only `identity`, is the body itself. Anything else is an
/// encoding the stages cannot see through, including one they do not know.
pub(super) fn encoding(response: &ResponseMeta) -> Encoding {
    let encoded = headers_named(&response.headers, "content-encoding")
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity"));
    if encoded {
        return Encoding::Encoded;
    }
    Encoding::Plain
}

/// Whether the answer declares a JSON body: `application/json`, or any
/// `+json` media type, whatever its parameters.
pub(super) fn is_json(response: &ResponseMeta) -> bool {
    headers_named(&response.headers, "content-type")
        .next()
        .is_some_and(|value| {
            let media = value.split(';').next().unwrap_or_default().trim();
            media.eq_ignore_ascii_case("application/json")
                || media.to_ascii_lowercase().ends_with("+json")
        })
}

/// The values of every header named `name`, which must be lower case.
pub(super) fn headers_named<'a>(
    headers: &'a [HeaderEntry],
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |entry| entry.name().as_str() == name)
        .map(|entry| entry.value().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::stages::response::fixtures::answer;

    #[test]
    fn json_and_its_subtypes_are_json() {
        for media in [
            "application/json",
            "Application/JSON; charset=utf-8",
            "application/problem+json",
        ] {
            assert!(is_json(&answer(200, &[("content-type", media)])), "{media}");
        }
        assert!(!is_json(&answer(200, &[("content-type", "text/html")])));
        assert!(!is_json(&answer(200, &[])));
    }

    /// A body with no encoding, or `identity`, is read as written. Gzip, an
    /// encoding the gateway does not know, or a chain of encodings is not.
    #[test]
    fn only_an_unencoded_body_is_plain() {
        assert_eq!(encoding(&answer(200, &[])), Encoding::Plain);
        assert_eq!(
            encoding(&answer(200, &[("content-encoding", "identity")])),
            Encoding::Plain
        );
        for coding in ["gzip", "x-unknown", "identity, br"] {
            assert_eq!(
                encoding(&answer(200, &[("content-encoding", coding)])),
                Encoding::Encoded,
                "{coding}"
            );
        }
    }
}
