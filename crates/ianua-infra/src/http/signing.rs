//! Signatures over an outgoing post, as Standard Webhooks lays them out:
//! one `v1,<base64 HMAC-SHA256>` entry per secret, separated by spaces,
//! each over the id, the send time and the body joined by dots.
//!
//! Webhook deliveries, pushes and notification posts are signed this way,
//! so a receiver checks each the same. A secret is handed out as its
//! prefix and the key in base64, `whsec_<base64>`, and the key of each
//! signature is those decoded bytes, so an off-the-shelf Standard Webhooks
//! library checks it. The receiver keeps a timestamp near its own clock
//! and drops an id it handled before, so a captured post cannot be
//! replayed.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac as _};
use ianua_domain::domains::webhooks::signing::SignedDelivery;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use sha2::Sha256;
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// The three headers of one signed post, with their values.
pub(crate) struct SignedHeaders {
    /// The id every try of the post carries.
    pub(crate) id: String,
    /// When it was sent, in whole seconds since the epoch.
    pub(crate) timestamp: String,
    /// One signature per secret.
    pub(crate) signature: String,
}

impl SignedHeaders {
    /// The headers of a post of `body` under `id`, sent at `sent_at`, signed
    /// with each of `secrets`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a signature cannot be
    /// made.
    pub(crate) fn of(
        id: String,
        sent_at: OffsetDateTime,
        body: &[u8],
        secrets: &[Secret],
    ) -> Result<Self, DomainError> {
        let timestamp = sent_at.unix_timestamp().to_string();
        let dot = b".".as_slice();
        let content = [id.as_bytes(), dot, timestamp.as_bytes(), dot, body].concat();
        let signature = signatures(&content, secrets)?;
        Ok(Self {
            id,
            timestamp,
            signature,
        })
    }

    /// Adds the headers to `request`.
    pub(crate) fn applied(self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request
            .header(SignedDelivery::ID_HEADER, self.id)
            .header(SignedDelivery::TIMESTAMP_HEADER, self.timestamp)
            .header(SignedDelivery::SIGNATURE_HEADER, self.signature)
    }
}

/// The signature header's value over `content`: one entry per secret, in
/// the order given, separated by spaces.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a signature cannot be made.
pub(crate) fn signatures(content: &[u8], secrets: &[Secret]) -> Result<String, DomainError> {
    let entries = secrets
        .iter()
        .map(|secret| signature(content, secret))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries.join(" "))
}

/// One `v1,<base64>` entry: the HMAC-SHA256 of `content` under `secret`.
fn signature(content: &[u8], secret: &Secret) -> Result<String, DomainError> {
    let key = key_of(secret)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
        .map_err(|_| DomainError::infra_msg("a signing key could not be used"))?;
    mac.update(content);
    Ok(format!(
        "{},{}",
        SignedDelivery::SIGNATURE_VERSION,
        STANDARD.encode(mac.finalize().into_bytes())
    ))
}

/// The key `secret` signs with: the bytes the base64 after its prefix
/// holds, as a Standard Webhooks library reads a `whsec_` secret.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the secret is not in the form
/// it was handed out in.
fn key_of(secret: &Secret) -> Result<Zeroizing<Vec<u8>>, DomainError> {
    let text = secret.expose();
    let encoded = text.split_once('_').map_or(text, |(_, key)| key);
    STANDARD.decode(encoded).map(Zeroizing::new).map_err(|_| {
        DomainError::infra_msg("a signing secret is not in the form it was handed out in")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The HMAC-SHA256 of `content` under the key `key`, worked out apart
    /// from the signer, to check it against.
    fn expected(key: &[u8], content: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(content);
        format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()))
    }

    /// A webhook secret holding `key`, as it is handed out.
    fn secret_of(key: &[u8]) -> Secret {
        Secret::new(format!("whsec_{}", STANDARD.encode(key)))
    }

    /// Signing the Standard Webhooks example produces the specification's
    /// exact signature header.
    #[test]
    fn the_specifications_example_signs_as_it_says() {
        let secret = Secret::new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
        let content = br#"msg_p5jXN8AQM9LWM0D4loKWxJek.1614265330.{"test": 2432232314}"#;

        let header = signatures(content, &[secret]).unwrap();

        assert_eq!(header, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
    }

    /// A signing secret containing invalid base64 returns an infrastructure
    /// error.
    #[test]
    fn a_secret_not_in_its_form_is_refused() {
        let broken = Secret::new("whsec_not base64!");

        let result = signatures(b"msg.1.{}", &[broken]);

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A post signed with the current secret and the one before a rotation
    /// carries both signatures, the current one first, so a receiver that
    /// has not moved over yet still verifies it.
    #[test]
    fn each_secret_signs_in_turn() {
        let secrets = [secret_of(b"new"), secret_of(b"old")];

        let header = signatures(b"msg.1.{}", &secrets).unwrap();

        assert_eq!(
            header,
            format!(
                "{} {}",
                expected(b"new", b"msg.1.{}"),
                expected(b"old", b"msg.1.{}")
            )
        );
    }

    /// The headers sign the id, the time in seconds and the body, joined by
    /// dots, as a Standard Webhooks receiver rebuilds them.
    #[test]
    fn the_headers_sign_id_time_and_body() {
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        let headers =
            SignedHeaders::of("msg_1".to_owned(), at, br#"{"a":1}"#, &[secret_of(b"k")]).unwrap();

        assert_eq!(headers.timestamp, "1700000000");
        assert_eq!(
            headers.signature,
            expected(b"k", br#"msg_1.1700000000.{"a":1}"#)
        );
    }

    /// Changing the body amount while keeping the key, ID and timestamp
    /// produces a different signature.
    #[test]
    fn a_changed_body_signs_differently() {
        let secrets = [secret_of(b"k")];

        let sent = signatures(b"id.1.{\"amount\":1}", &secrets).unwrap();
        let altered = signatures(b"id.1.{\"amount\":9}", &secrets).unwrap();

        assert_ne!(sent, altered);
    }
}
