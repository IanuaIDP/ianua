//! The seal on the threat verdicts the gateway's instances share.
//!
//! An instance that blocks a client broadcasts the verdict on the bus, and
//! the others enforce it. Reaching the bus is no authority to block a
//! tenant's clients, so each verdict is sealed with its subject under a key
//! derived for this use alone: a seal made for an event, a live update or a
//! relayed request never holds here.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_domain::types::TokenHash;

use crate::crypto::keys::{Purpose, PurposeKey, RootSecret, hmac_sha256};

/// The seal the gateway's instances put on the verdicts they share.
#[derive(Debug, Clone)]
pub struct FleetVerdictSeal {
    key: PurposeKey,
}

impl FleetVerdictSeal {
    /// The seal under the key `root` derives for fleet verdicts.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::FleetVerdicts),
        }
    }

    /// The seal on `body` broadcast on `subject`, as URL-safe base64, which
    /// never holds a `.`.
    #[must_use]
    pub fn seal(&self, subject: &str, body: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(hmac_sha256(
            self.key.bytes(),
            &[subject.as_bytes(), b"\0", body],
        ))
    }

    /// Whether `seal` is the seal on `body` broadcast on `subject`,
    /// compared in constant time.
    #[must_use]
    pub fn holds(&self, subject: &str, body: &[u8], seal: &str) -> bool {
        TokenHash::from_stored(self.seal(subject, body)) == TokenHash::from_stored(seal.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    const SUBJECT: &str = "fleet.verdicts";

    /// A verdict's seal holds for its own subject and body, and not once
    /// either is changed.
    #[test]
    fn a_seal_holds_for_its_own_verdict_only() {
        let seal = FleetVerdictSeal::new(&test_root());
        let sealed = seal.seal(SUBJECT, b"{\"block\":\"203.0.113.7\"}");

        assert!(seal.holds(SUBJECT, b"{\"block\":\"203.0.113.7\"}", &sealed));
        assert!(!seal.holds(SUBJECT, b"{\"block\":\"198.51.100.1\"}", &sealed));
        assert!(!seal.holds("fleet.other", b"{\"block\":\"203.0.113.7\"}", &sealed));
        assert!(!seal.holds(SUBJECT, b"{\"block\":\"203.0.113.7\"}", "forged"));
    }

    /// A data-plane event seal cannot verify as a fleet verdict seal.
    #[test]
    fn a_seal_of_another_use_never_holds() {
        let body = b"{}";
        let as_event = crate::crypto::EventSeal::data_plane(&test_root()).seal(SUBJECT, body);
        let as_update = crate::crypto::BroadcastSeal::data_plane(&test_root()).seal(SUBJECT, body);

        let seal = FleetVerdictSeal::new(&test_root());

        assert!(!seal.holds(SUBJECT, body, &as_event));
        assert!(!seal.holds(SUBJECT, body, &as_update));
    }

    /// The seal can be carried in a dot-separated frame: it never holds a
    /// `.`.
    #[test]
    fn a_seal_holds_no_dot() {
        let sealed = FleetVerdictSeal::new(&test_root()).seal(SUBJECT, b"{}");

        assert!(!sealed.contains('.'));
    }
}
