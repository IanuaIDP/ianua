//! What an agent's request carries, read for the route's parameter rules:
//! its query, its body's fields, its path captures and its headers.
//!
//! A body is read only from the prefix the gateway peeked, and only when
//! that prefix is the whole body and a JSON object. Anything else is
//! unreadable, never empty: a form or a cut-off body can carry an address
//! as well as JSON can, and a rule that read only what it could parse would
//! wave the rest through. Every key is kept in the order sent, duplicates
//! too, since an upstream may read the one a parser that keeps the last
//! would have dropped.

use std::fmt;

use http::HeaderMap;
use http::header::CONTENT_TYPE;
use ianua_app::use_cases::agents::enforcement::CarriedValues;
use ianua_domain::domains::routing::matching::parameter::{BodyFields, BodyValue};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::pipeline::facts::RequestFacts;
use crate::request::BodyRead;

/// What the request `facts` describe carries, for the route's parameter
/// rules.
pub(super) fn carried_values(facts: &RequestFacts) -> CarriedValues {
    CarriedValues {
        query: facts.query.clone(),
        body: body_fields(&facts.body, &facts.headers),
        captured: facts.captured.clone(),
        headers: header_pairs(&facts.headers),
    }
}

/// The top-level fields of a whole JSON object body, no body, or that it
/// could not be read.
fn body_fields(body: &BodyRead, headers: &HeaderMap) -> BodyFields {
    let BodyRead::Read { prefix, extent } = body else {
        return BodyFields::Unreadable;
    };
    if !extent.is_whole() {
        return BodyFields::Unreadable;
    }
    if prefix.is_empty() {
        return BodyFields::None;
    }
    if !declares_json(headers) {
        return BodyFields::Unreadable;
    }
    let Ok(Kept(mut value)) = serde_json::from_slice::<Kept>(prefix) else {
        return BodyFields::Unreadable;
    };
    let BodyValue::Object(fields) = &mut value else {
        return BodyFields::Unreadable;
    };
    BodyFields::Fields(std::mem::take(fields))
}

fn declares_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("json"))
}

/// Every header as sent, a value that is not text read with replacement
/// characters rather than dropped.
fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let text = String::from_utf8_lossy(value.as_bytes()).into_owned();
            (name.as_str().to_owned(), text)
        })
        .collect()
}

/// A JSON value read with every object key kept, in order, duplicates too.
struct Kept(BodyValue);

impl<'de> Deserialize<'de> for Kept {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(KeptVisitor)
    }
}

struct KeptVisitor;

impl<'de> Visitor<'de> for KeptVisitor {
    type Value = Kept;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Kept, E> {
        Ok(Kept(BodyValue::Flag(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Kept, E> {
        Ok(Kept(BodyValue::Number(value.to_string())))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Kept, E> {
        Ok(Kept(BodyValue::Number(value.to_string())))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Kept, E> {
        Ok(Kept(BodyValue::Number(value.to_string())))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Kept, E> {
        Ok(Kept(BodyValue::Text(value.to_owned())))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Kept, E> {
        Ok(Kept(BodyValue::Text(value)))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Kept, E> {
        Ok(Kept(BodyValue::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<Kept, E> {
        Ok(Kept(BodyValue::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Kept, A::Error> {
        let mut items = Vec::new();
        while let Some(Kept(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Kept(BodyValue::List(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Kept, A::Error> {
        let mut entries = Vec::new();
        while let Some((key, Kept(value))) = map.next_entry::<String, Kept>()? {
            entries.push((key, value));
        }
        Ok(Kept(BodyValue::Object(entries)))
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use hyper::body::Bytes;
    use ianua_domain::domains::proxy::request::body::BodyExtent;

    use super::*;

    fn json_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    fn read(bytes: &'static [u8], extent: BodyExtent) -> BodyRead {
        BodyRead::Read {
            prefix: Bytes::from_static(bytes),
            extent,
        }
    }

    fn text(value: &str) -> BodyValue {
        BodyValue::Text(value.to_owned())
    }

    #[test]
    fn a_whole_json_object_is_read_field_by_field() {
        let body = read(br#"{"url":"https://a.test","n":2}"#, BodyExtent::Whole);

        let fields = body_fields(&body, &json_headers());

        assert_eq!(
            fields,
            BodyFields::Fields(vec![
                ("url".to_owned(), text("https://a.test")),
                ("n".to_owned(), BodyValue::Number("2".to_owned())),
            ])
        );
    }

    /// Duplicate JSON URL fields retain both values in their original order.
    #[test]
    fn a_repeated_key_is_kept_twice() {
        let body = read(
            br#"{"url":"https://evil.test","url":"https://a.test"}"#,
            BodyExtent::Whole,
        );

        let fields = body_fields(&body, &json_headers());

        assert_eq!(
            fields,
            BodyFields::Fields(vec![
                ("url".to_owned(), text("https://evil.test")),
                ("url".to_owned(), text("https://a.test")),
            ])
        );
    }

    #[test]
    fn an_empty_whole_body_is_no_body() {
        let fields = body_fields(&read(b"", BodyExtent::Whole), &HeaderMap::new());

        assert_eq!(fields, BodyFields::None);
    }

    /// Partial, form, array, trailing-garbage and unread bodies are marked
    /// unreadable instead of becoming an empty field set.
    #[test]
    fn what_cannot_be_read_whole_as_an_object_is_unreadable() {
        let mut form = HeaderMap::new();
        form.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let cases = [
            (read(br#"{"url":"#, BodyExtent::Prefix), json_headers()),
            (read(b"url=https://evil.test", BodyExtent::Whole), form),
            (
                read(br#"["https://evil.test"]"#, BodyExtent::Whole),
                json_headers(),
            ),
            (
                read(br#"{"a":1} trailing"#, BodyExtent::Whole),
                json_headers(),
            ),
            (BodyRead::Unread, json_headers()),
        ];

        for (body, headers) in cases {
            assert_eq!(body_fields(&body, &headers), BodyFields::Unreadable);
        }
    }
}
