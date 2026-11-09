//! The check on a notice's `Stripe-Signature` header: an HMAC-SHA256 of
//! the moment it was signed and the body, under the endpoint's signing
//! secret, compared in constant time, and refused when it was signed too
//! long ago or too far ahead.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac as _};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use sha2::Sha256;

/// How far, in seconds, a notice's signing moment may lie from now.
const TOLERANCE_SECONDS: u64 = 300;

/// What a signature header says: when it was signed, and every `v1`
/// signature it carries, decoded.
struct SignatureHeader {
    signed_at: i64,
    signatures: Vec<Vec<u8>>,
}

/// The parts of `header`, or none when it names no moment or no `v1`
/// signature.
fn parsed(header: &str) -> Option<SignatureHeader> {
    let mut signed_at = None;
    let mut signatures = Vec::new();
    for (key, value) in header
        .split(',')
        .filter_map(|part| part.trim().split_once('='))
    {
        match key {
            "t" => signed_at = value.parse::<i64>().ok(),
            "v1" => signatures.extend(
                data_encoding::HEXLOWER_PERMISSIVE
                    .decode(value.as_bytes())
                    .ok(),
            ),
            _ => {}
        }
    }
    let signed_at = signed_at?;
    (!signatures.is_empty()).then_some(SignatureHeader {
        signed_at,
        signatures,
    })
}

/// Refuses `payload` unless `header` signs it under `secret`, at a moment
/// within the tolerance of `now`.
///
/// # Errors
///
/// - `DomainError::Unauthorized` when the header is malformed, no
///   signature matches, or the moment lies outside the tolerance.
/// - `DomainError::Infrastructure` when the key cannot be used.
pub(crate) fn ensure_signed(
    header: &str,
    payload: &[u8],
    secret: &Secret,
    now: i64,
) -> Result<(), DomainError> {
    let Some(parts) = parsed(header) else {
        return Err(DomainError::unauthorized(message!(
            "infra-the-notice-carries-no-usable-signature",
            "the notice carries no usable signature"
        )));
    };
    if now.abs_diff(parts.signed_at) > TOLERANCE_SECONDS {
        return Err(DomainError::unauthorized(message!(
            "infra-the-notice-was-not-signed-just",
            "the notice was not signed just now"
        )));
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.expose().as_bytes())
        .map_err(DomainError::infra)?;
    mac.update(parts.signed_at.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let matches = parts
        .signatures
        .iter()
        .any(|signature| mac.clone().verify_slice(signature).is_ok());
    if !matches {
        return Err(DomainError::unauthorized(message!(
            "infra-the-notice-s-signature-does-not",
            "the notice's signature does not verify"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test_signing_secret";
    const BODY: &[u8] = br#"{"id":"evt_1","type":"invoice.paid"}"#;
    const NOW: i64 = 1_800_000_000;

    /// The `v1` signature Stripe would send for `body` at `at`.
    fn signature(at: i64, body: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(format!("{at}.").as_bytes());
        mac.update(body);
        data_encoding::HEXLOWER.encode(&mac.finalize().into_bytes())
    }

    fn secret() -> Secret {
        Secret::new(SECRET)
    }

    /// A notice signed just now under the endpoint's secret passes.
    #[test]
    fn a_fresh_signed_notice_passes() {
        let header = format!("t={NOW},v1={}", signature(NOW, BODY));

        assert!(ensure_signed(&header, BODY, &secret(), NOW + 10).is_ok());
    }

    /// While the secret is being rolled, a header carries two `v1`
    /// signatures. The one that matches is enough.
    #[test]
    fn one_matching_signature_among_several_passes() {
        let header = format!(
            "t={NOW},v1={},v1={},v0=ignored",
            "00".repeat(32),
            signature(NOW, BODY)
        );

        assert!(ensure_signed(&header, BODY, &secret(), NOW).is_ok());
    }

    /// Changing a signed notice's body makes signature verification fail.
    #[test]
    fn a_changed_body_is_refused() {
        let header = format!("t={NOW},v1={}", signature(NOW, BODY));

        let refused = ensure_signed(&header, br#"{"id":"evt_2"}"#, &secret(), NOW);

        assert!(matches!(refused, Err(DomainError::Unauthorized(_))));
    }

    /// A correctly signed notice replayed an hour later is unauthorized.
    #[test]
    fn a_replayed_old_notice_is_refused() {
        let header = format!("t={NOW},v1={}", signature(NOW, BODY));

        let refused = ensure_signed(&header, BODY, &secret(), NOW + 3600);

        assert!(matches!(refused, Err(DomainError::Unauthorized(_))));
    }

    /// Verification rejects signatures from another secret, missing signatures
    /// and malformed signature headers.
    #[test]
    fn a_foreign_or_missing_signature_is_refused() {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"whsec_other").unwrap();
        mac.update(format!("{NOW}.").as_bytes());
        mac.update(BODY);
        let foreign = data_encoding::HEXLOWER.encode(&mac.finalize().into_bytes());

        let other_secret = ensure_signed(&format!("t={NOW},v1={foreign}"), BODY, &secret(), NOW);
        let unsigned = ensure_signed(&format!("t={NOW}"), BODY, &secret(), NOW);
        let garbage = ensure_signed("garbage", BODY, &secret(), NOW);

        assert!(matches!(other_secret, Err(DomainError::Unauthorized(_))));
        assert!(matches!(unsigned, Err(DomainError::Unauthorized(_))));
        assert!(matches!(garbage, Err(DomainError::Unauthorized(_))));
    }
}
