//! Proving a service sent a delivery: the signature it carries is the
//! keyed hash of what was sent under a secret only the service and the
//! platform hold; or, for a service that sends back a token it was given or
//! signs with a key the platform cannot read, that token or the secret in
//! the address the delivery came to. Every comparison takes the same time
//! however much of it matches, so a forger learns nothing from how fast a
//! guess is refused.

#[cfg(test)]
use base64::Engine as _;
#[cfg(test)]
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac as _};
#[cfg(test)]
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
#[cfg(test)]
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
#[cfg(test)]
use time::{Duration, OffsetDateTime};

/// How far from now a signed timestamp may be: past it, a captured delivery
/// is no longer taken again.
#[cfg(test)]
const TIMESTAMP_TOLERANCE: Duration = Duration::minutes(5);

/// The HMAC-SHA256 of `parts`, joined, under `key`.
#[must_use]
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return Vec::new();
    };
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

/// Whether `given`, written in hexadecimal, is `expected`. An empty
/// `expected` matches nothing.
#[must_use]
pub fn matches_hex(expected: &[u8], given: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let written = hex_of(expected);
    written
        .as_bytes()
        .ct_eq(given.to_ascii_lowercase().as_bytes())
        .into()
}

/// Whether `given` is the secret `expected` itself, as a service that
/// sends back a token it was given proves a delivery, such as Google's
/// channel token. An empty `expected` matches nothing.
#[must_use]
pub fn same_secret(expected: &str, given: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    expected.as_bytes().ct_eq(given.as_bytes()).into()
}

/// Whether `given`, written in Base64, is `expected`. An empty `expected`
/// matches nothing.
#[cfg(test)]
#[must_use]
pub(crate) fn matches_base64(expected: &[u8], given: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    STANDARD
        .encode(expected)
        .as_bytes()
        .ct_eq(given.as_bytes())
        .into()
}

/// One request as a service signs it together with when it sent it.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct TimedRequest<'a> {
    /// Its method, such as `POST`.
    pub(crate) method: &'a str,
    /// The full address it was sent to.
    pub(crate) address: &'a str,
    /// Its body, as sent.
    pub(crate) body: &'a [u8],
    /// When it was sent, in milliseconds since the epoch, as written.
    pub(crate) timestamp_millis: &'a str,
}

/// Whether `given`, in Base64, is the HMAC-SHA256 under `key` of `request`'s
/// method, address, body and timestamp joined in that order, and the
/// timestamp is within five minutes of `now`, as HubSpot signs its v3
/// webhooks. A delivery with no readable timestamp matches nothing.
#[cfg(test)]
#[must_use]
pub(crate) fn timed_request_signed(
    key: &[u8],
    request: TimedRequest<'_>,
    given: &str,
    now: OffsetDateTime,
) -> bool {
    if !timestamp_is_recent(request.timestamp_millis, now) {
        return false;
    }
    let signed = hmac_sha256(
        key,
        &[
            request.method.as_bytes(),
            request.address.as_bytes(),
            request.body,
            request.timestamp_millis.as_bytes(),
        ],
    );
    matches_base64(&signed, given)
}

/// Whether `written`, milliseconds since the epoch, is close enough to
/// `now`, in either direction.
#[cfg(test)]
fn timestamp_is_recent(written: &str, now: OffsetDateTime) -> bool {
    let Ok(millis) = written.parse::<i64>() else {
        return false;
    };
    let nanos = i128::from(millis).saturating_mul(1_000_000);
    let Ok(sent) = OffsetDateTime::from_unix_timestamp_nanos(nanos) else {
        return false;
    };
    clock::between(sent, now).abs() <= TIMESTAMP_TOLERANCE
}

/// Whether the JSON `body` lists at least one item under `list`, and every
/// one carries `secret` itself in `field`, as Microsoft Graph sends back
/// each subscription's `clientState` in each notification.
#[cfg(test)]
#[must_use]
pub(crate) fn every_item_carries(body: &[u8], list: &str, field: &str, secret: &Secret) -> bool {
    let Ok(payload) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let Some(items) = payload.get(list).and_then(Value::as_array) else {
        return false;
    };
    !items.is_empty()
        && items.iter().all(|item| {
            item.get(field)
                .and_then(Value::as_str)
                .is_some_and(|given| same_secret(secret.expose(), given))
        })
}

/// The name a registration's secret is given in its address.
const SECRET_PARAMETER: &str = "token";

/// `address` with `secret` added to it, as a service is given it when it
/// signs with a key the platform cannot read, such as Mailgun's: the
/// address itself then proves a delivery. `None` when `address` is no
/// address.
#[must_use]
pub fn with_secret(address: &str, secret: &Secret) -> Option<String> {
    let mut address = url::Url::parse(address).ok()?;
    address
        .query_pairs_mut()
        .append_pair(SECRET_PARAMETER, secret.expose());
    Some(address.to_string())
}

/// Whether `address`, the one a delivery was sent to, carries `secret`
/// once and only once.
#[must_use]
pub fn carries_secret(address: &str, secret: &Secret) -> bool {
    let Ok(address) = url::Url::parse(address) else {
        return false;
    };
    let given: Vec<String> = address
        .query_pairs()
        .filter(|(name, _)| name == SECRET_PARAMETER)
        .map(|(_, value)| value.into_owned())
        .collect();
    match given.as_slice() {
        [only] => same_secret(secret.expose(), only),
        _ => false,
    }
}

/// `bytes` in lowercase hexadecimal.
fn hex_of(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GitHub's own example: the secret and body it documents give the
    /// signature it documents.
    #[test]
    fn githubs_documented_example_matches() {
        let signed = hmac_sha256(b"It's a Secret to Everybody", &[b"Hello, World!"]);

        assert!(matches_hex(
            &signed,
            "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
        ));
    }

    /// A different secret's signature, a truncated signature and empty
    /// signatures all fail comparison.
    #[test]
    fn another_secret_or_a_short_signature_does_not_match() {
        let signed = hmac_sha256(b"the right secret words", &[b"Hello, World!"]);
        let other = hmac_sha256(b"some other secret words", &[b"Hello, World!"]);
        let written = hex_of(&signed);

        assert!(!matches_hex(&signed, &hex_of(&other)));
        assert!(!matches_hex(&signed, &written[..10]));
        assert!(!matches_hex(&signed, ""));
        assert!(!matches_hex(&[], ""));
    }

    /// A token sent back matches only itself, and an empty one nothing.
    #[test]
    fn a_secret_sent_back_matches_only_itself() {
        assert!(same_secret("the channel's token", "the channel's token"));
        assert!(!same_secret("the channel's token", "the channel's tokens"));
        assert!(!same_secret("", ""));
    }

    /// An address given its secret carries it; the bare address, one with
    /// another secret, and one carrying it twice do not.
    #[test]
    fn an_address_carries_only_its_own_secret_once() {
        let secret = Secret::new("the registration's words".to_owned());
        let other = Secret::new("mallory's words".to_owned());
        let bare = "https://ianua.test/api/v1/integrations/events/one";
        let given = with_secret(bare, &secret).unwrap();
        let twice = with_secret(&given, &secret).unwrap();

        assert!(carries_secret(&given, &secret));
        assert!(!carries_secret(bare, &secret));
        assert!(!carries_secret(
            &with_secret(bare, &other).unwrap(),
            &secret
        ));
        assert!(!carries_secret(&twice, &secret));
    }

    /// Parts are hashed as if joined, as Slack signs `v0:`, the time and the
    /// body.
    #[test]
    fn parts_hash_as_one_message() {
        assert_eq!(
            hmac_sha256(b"key words", &[b"v0:", b"1700000000:", b"{}"]),
            hmac_sha256(b"key words", &[b"v0:1700000000:{}"]),
        );
    }

    const KEY: &[u8] = b"the app's client secret words";

    /// When a request is signed, as HubSpot writes it.
    const SENT: i64 = 1_700_000_000;

    fn sent() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(SENT).unwrap()
    }

    fn request<'a>(body: &'a [u8], timestamp_millis: &'a str) -> TimedRequest<'a> {
        TimedRequest {
            method: "POST",
            address: "https://ianua.test/api/v1/integrations/events/channels/one",
            body,
            timestamp_millis,
        }
    }

    fn signature_of(request: TimedRequest<'_>) -> String {
        STANDARD.encode(hmac_sha256(
            KEY,
            &[
                request.method.as_bytes(),
                request.address.as_bytes(),
                request.body,
                request.timestamp_millis.as_bytes(),
            ],
        ))
    }

    /// HubSpot signs method, address, body and time. A delivery just sent
    /// checks out.
    #[test]
    fn a_fresh_signed_request_matches() {
        let timestamp = format!("{SENT}000");
        let signed = request(b"[]", &timestamp);

        assert!(timed_request_signed(
            KEY,
            signed,
            &signature_of(signed),
            sent()
        ));
    }

    /// Stops: Mallory captures a real delivery and replays it an hour
    /// later. Its signature is right, but it is too old to be taken, and
    /// one dated too far ahead is no better.
    #[test]
    fn a_signed_request_outside_five_minutes_does_not_match() {
        let timestamp = format!("{SENT}000");
        let signed = request(b"[]", &timestamp);
        let signature = signature_of(signed);

        assert!(!timed_request_signed(
            KEY,
            signed,
            &signature,
            sent() + Duration::hours(1)
        ));
        assert!(!timed_request_signed(
            KEY,
            signed,
            &signature,
            sent() - Duration::hours(1)
        ));
    }

    /// Stops: Mallory keeps a real signature and changes the body or the
    /// time it covers. Neither checks out, nor does a time that is no
    /// number.
    #[test]
    fn a_changed_request_or_a_bad_timestamp_does_not_match() {
        let timestamp = format!("{SENT}000");
        let later = format!("{SENT}001");
        let signed = request(b"[]", &timestamp);
        let signature = signature_of(signed);

        assert!(!timed_request_signed(
            KEY,
            request(b"[1]", &timestamp),
            &signature,
            sent()
        ));
        assert!(!timed_request_signed(
            KEY,
            request(b"[]", &later),
            &signature,
            sent()
        ));
        assert!(!timed_request_signed(
            KEY,
            request(b"[]", "soon"),
            &signature,
            sent()
        ));
    }

    /// Microsoft Graph sends each subscription's `clientState` back in each
    /// notification. A batch counts only if every one of them carries it.
    #[test]
    fn every_item_must_carry_the_secret() {
        let secret = Secret::new("the client state".to_owned());
        let all =
            br#"{"value":[{"clientState":"the client state"},{"clientState":"the client state"}]}"#;
        let one_bad = br#"{"value":[{"clientState":"the client state"},{"clientState":"guess"}]}"#;
        let one_missing = br#"{"value":[{"clientState":"the client state"},{}]}"#;

        assert!(every_item_carries(all, "value", "clientState", &secret));
        assert!(!every_item_carries(
            one_bad,
            "value",
            "clientState",
            &secret
        ));
        assert!(!every_item_carries(
            one_missing,
            "value",
            "clientState",
            &secret
        ));
    }

    /// An empty list, another shape or no JSON at all proves nothing.
    #[test]
    fn nothing_to_check_proves_nothing() {
        let secret = Secret::new("the client state".to_owned());

        assert!(!every_item_carries(
            br#"{"value":[]}"#,
            "value",
            "clientState",
            &secret
        ));
        assert!(!every_item_carries(
            br#"{"other":1}"#,
            "value",
            "clientState",
            &secret
        ));
        assert!(!every_item_carries(
            b"nope",
            "value",
            "clientState",
            &secret
        ));
    }
}
