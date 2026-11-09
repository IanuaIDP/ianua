//! How a webhook delivery is signed, as Standard Webhooks lays it out.
//!
//! The adapter computes each HMAC-SHA256 over [`SignedDelivery::signed_content`]
//! and sends one `v1,<base64>` entry per secret in the signature header.
//! The domain decides what is signed and with which secrets; the secret
//! before a rotation keeps signing as
//! [`PreviousSigningSecret`](crate::types::PreviousSigningSecret) says.

use time::OffsetDateTime;

use crate::types::WebhookMessageId;

/// The facts one delivery attempt is signed over, as Standard Webhooks
/// names them.
///
/// The receiver checks the signature over `id.timestamp.body`, refuses a
/// timestamp far from its own clock and drops an id it handled before. So a
/// captured delivery cannot be replayed later, and a retry is not handled
/// twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedDelivery {
    message_id: WebhookMessageId,
    sent_at: OffsetDateTime,
}

impl SignedDelivery {
    /// The header carrying the message id.
    pub const ID_HEADER: &'static str = "webhook-id";
    /// The header carrying when the attempt was sent, in seconds.
    pub const TIMESTAMP_HEADER: &'static str = "webhook-timestamp";
    /// The header carrying one signature per signing secret.
    pub const SIGNATURE_HEADER: &'static str = "webhook-signature";
    /// The version each signature is marked with: HMAC-SHA256.
    pub const SIGNATURE_VERSION: &'static str = "v1";

    /// The facts of an attempt, sent now, to deliver message `message_id`.
    /// Every attempt of one message keeps its id and gets its own time.
    #[must_use]
    pub fn now(message_id: WebhookMessageId) -> Self {
        Self {
            message_id,
            sent_at: crate::shared::clock::now(),
        }
    }

    /// The message id, the same on every attempt.
    #[must_use]
    pub fn message_id(&self) -> &WebhookMessageId {
        &self.message_id
    }

    /// When the attempt was sent.
    #[must_use]
    pub fn sent_at(&self) -> OffsetDateTime {
        self.sent_at
    }

    /// The value of the id header.
    #[must_use]
    pub fn id_header(&self) -> String {
        self.message_id.to_string()
    }

    /// The value of the timestamp header: whole seconds since the epoch.
    #[must_use]
    pub fn timestamp_header(&self) -> String {
        self.sent_at.unix_timestamp().to_string()
    }

    /// The bytes each signature is computed over: the id, the timestamp and
    /// the body, joined by dots.
    #[must_use]
    pub fn signed_content(&self, body: &[u8]) -> Vec<u8> {
        let prefix = format!("{}.{}.", self.id_header(), self.timestamp_header());
        let mut content = Vec::with_capacity(prefix.len().saturating_add(body.len()));
        content.extend_from_slice(prefix.as_bytes());
        content.extend_from_slice(body);
        content
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    /// An attempt sent at second 1,700,000,000 for a message signs
    /// `<id>.1700000000.{"a":1}`, the layout Standard Webhooks receivers
    /// rebuild.
    #[test]
    fn the_signed_content_is_id_timestamp_and_body_joined_by_dots() {
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let _frozen = crate::shared::clock::freeze(at);
        let message = WebhookMessageId::new();

        let delivery = SignedDelivery::now(message);

        assert_eq!(delivery.timestamp_header(), "1700000000");
        assert_eq!(
            delivery.signed_content(br#"{"a":1}"#),
            format!("{message}.1700000000.{{\"a\":1}}").into_bytes()
        );
    }

    /// A retry created an hour later retains the message's ID header and
    /// has a different timestamp header.
    #[test]
    fn a_retry_keeps_the_message_id_and_takes_a_new_time() {
        let start = crate::shared::clock::now();
        let message = WebhookMessageId::new();
        let first = {
            let _frozen = crate::shared::clock::freeze(start);
            SignedDelivery::now(message)
        };
        let _later = crate::shared::clock::freeze(start + Duration::hours(1));

        let retry = SignedDelivery::now(message);

        assert_eq!(retry.id_header(), first.id_header());
        assert_ne!(retry.timestamp_header(), first.timestamp_header());
    }
}
