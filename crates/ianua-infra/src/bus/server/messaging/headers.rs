//! The headers a message travels with: the publisher's own, and the ones
//! the plane keeps for itself (the server's, a dead letter's count, the
//! message's type), which no publisher may set and no reader is handed.

use async_nats::HeaderMap;
use async_nats::jetstream::message::Info;
use ianua_app::ports::messaging::{MessageKey, ReceivedMessage};
use ianua_domain::domains::messaging::message_type::MessageType;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

/// The prefix of the headers the server itself reads.
const SERVER_HEADERS: &str = "nats-";

/// The prefix of the headers a dead letter keeps of its own.
const DEAD_HEADERS: &str = "ianua-dead-";

/// The header a dead letter keeps its delivery count in.
pub(super) const DELIVERED_HEADER: &str = "Ianua-Dead-Delivered";

/// The header a dead letter, and its replay, keep the moment the bus first
/// took the message in, so neither starts its topic's limit over.
pub(super) const FIRST_PUBLISHED_HEADER: &str = "Ianua-Dead-Published";

/// The header a message's type travels in.
pub(super) const TYPE_HEADER: &str = "Ianua-Message-Type";

/// A message as a consumer reads it, under `key`: its payload, its type,
/// when the bus took it, and the headers it was published with, without
/// those the plane keeps for itself.
pub(super) fn received(
    key: MessageKey,
    published_at: OffsetDateTime,
    headers: Option<&HeaderMap>,
    payload: &[u8],
) -> ReceivedMessage {
    ReceivedMessage {
        key,
        payload: payload.to_vec(),
        headers: headers.map(published_headers).unwrap_or_default(),
        message_type: headers.and_then(type_of),
        published_at,
    }
}

/// The key of the message `info` describes: its stream and its place in
/// it, which every delivery of it shares.
pub(super) fn key_of(info: &Info<'_>) -> MessageKey {
    MessageKey::new(format!("{}-{}", info.stream, info.stream_sequence))
}

fn type_of(headers: &HeaderMap) -> Option<MessageType> {
    MessageType::new(headers.get(TYPE_HEADER)?.as_str()).ok()
}

fn published_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| is_publishers(name.as_ref()))
        .flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| (name.to_string(), value.as_str().to_owned()))
        })
        .collect()
}

/// The headers a dead letter puts back when it is replayed: the publisher's,
/// the message's type, and when the bus first took it.
pub(super) fn replayed_headers(headers: &HeaderMap) -> HeaderMap {
    let mut kept = HeaderMap::new();
    for (name, value) in published_headers(headers) {
        kept.insert(name.as_str(), value.as_str());
    }
    if let Some(message_type) = headers.get(TYPE_HEADER) {
        kept.insert(TYPE_HEADER, message_type.as_str());
    }
    if let Some(first) = headers.get(FIRST_PUBLISHED_HEADER) {
        kept.insert(FIRST_PUBLISHED_HEADER, first.as_str());
    }
    kept
}

/// When the bus first took the message `headers` travel with: the moment a
/// dead letter kept, or `here`, its time on the stream it is read from,
/// when it kept none, as a letter set aside before this was kept did not.
pub(super) fn first_published(headers: &HeaderMap, here: OffsetDateTime) -> OffsetDateTime {
    headers
        .get(FIRST_PUBLISHED_HEADER)
        .and_then(|value| value.as_str().parse::<i128>().ok())
        .and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
        .unwrap_or(here)
}

/// Notes on `headers` when the bus first took their message, keeping the
/// moment already noted on a replay set aside again.
pub(super) fn note_first_published(headers: &mut HeaderMap, here: OffsetDateTime) {
    let first = first_published(headers, here).unix_timestamp_nanos();
    headers.insert(FIRST_PUBLISHED_HEADER, first.to_string().as_str());
}

fn is_publishers(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !lower.starts_with(SERVER_HEADERS)
        && !lower.starts_with(DEAD_HEADERS)
        && !lower.eq_ignore_ascii_case(TYPE_HEADER)
}

/// The headers a publisher sent, refused when one is malformed or one the
/// plane keeps for itself.
pub(super) fn checked_headers(headers: &[(String, String)]) -> Result<HeaderMap, DomainError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let name_fits = !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_graphic() && b != b':')
            && is_publishers(name);
        if !name_fits || value.bytes().any(|b| b.is_ascii_control()) {
            return Err(DomainError::invalid(message!(
                "infra-a-message-header-is-malformed-or",
                "a message header is malformed or reserved"
            )));
        }
        map.insert(name.as_str(), value.as_str());
    }
    Ok(map)
}

/// How many times a dead letter was delivered before it was set aside.
pub(super) fn delivered_of(headers: &HeaderMap) -> u32 {
    headers
        .get(DELIVERED_HEADER)
        .and_then(|value| value.as_str().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Header validation rejects reserved names, malformed names and newline
    /// values, preventing callers from supplying the plane's own headers.
    #[test]
    fn a_reserved_or_malformed_header_is_refused() {
        for name in [
            "Nats-Msg-Id",
            "ianua-dead-delivered",
            "Ianua-Message-Type",
            "bad:name",
            "",
        ] {
            let headers = [(name.to_owned(), "x".to_owned())];
            assert!(checked_headers(&headers).is_err(), "{name} was taken");
        }
        assert!(checked_headers(&[("trace".to_owned(), "a\nb".to_owned())]).is_err());
    }

    /// A reader gets the publisher's headers and the type, and none of the
    /// plane's own.
    #[test]
    fn a_reader_gets_the_publishers_headers_and_the_type() {
        let mut headers = HeaderMap::new();
        headers.insert("trace", "abc");
        headers.insert(TYPE_HEADER, "order.created");
        headers.insert(DELIVERED_HEADER, "3");
        headers.insert("Nats-Msg-Id", "1");

        let message = received(
            MessageKey::new("orders-1"),
            OffsetDateTime::now_utc(),
            Some(&headers),
            b"x",
        );

        assert_eq!(message.headers, [("trace".to_owned(), "abc".to_owned())]);
        assert_eq!(
            message.message_type.as_ref().map(MessageType::as_str),
            Some("order.created")
        );
        assert_eq!(delivered_of(&headers), 3);
    }
}
