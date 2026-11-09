//! The seal on every live update broadcast to dashboards, and the check a
//! listener makes before it hands one on.
//!
//! A live update reaches a person's open dashboard as it is: a notification
//! they are told to act on, a tenant's setup, a decided request. Who may
//! connect to the bus says nothing of who wrote an update, so each
//! publisher seals the subject and the update under a key of its kind, and
//! a listener drops an update whose seal does not hold, or that carries
//! none.
//!
//! Two kinds of publisher, two keys, as for events. The data plane (the
//! gateway) faces the internet, so its key vouches only for the updates it
//! raises, the requests it decided; every other update is sealed under the
//! control plane's key, derived from a root secret the data plane is never
//! given. A compromised gateway, or anything holding the bus's credentials,
//! cannot show a member a notification nobody sent.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_domain::types::TokenHash;

use crate::crypto::keys::{Purpose, PurposeKey, RootSecret, hmac_sha256};

/// The seal one kind of publisher puts on its live updates.
#[derive(Debug, Clone)]
pub struct BroadcastSeal {
    key: PurposeKey,
}

impl BroadcastSeal {
    /// The control plane's seal, under the key `root` derives for it. The
    /// root must be one the data plane is never given.
    #[must_use]
    pub fn control_plane(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::RealtimeSeals),
        }
    }

    /// The data plane's seal, under the key `root` derives for it.
    #[must_use]
    pub fn data_plane(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::DataPlaneRealtimeSeals),
        }
    }

    /// The seal on `update` broadcast on `subject`, as URL-safe base64.
    pub(crate) fn seal(&self, subject: &str, update: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(hmac_sha256(
            self.key.bytes(),
            &[subject.as_bytes(), b"\0", update],
        ))
    }

    /// Whether `seal` is this publisher's seal on `update` broadcast on
    /// `subject`, compared in constant time.
    fn holds(&self, subject: &str, update: &[u8], seal: &str) -> bool {
        TokenHash::from_stored(self.seal(subject, update))
            == TokenHash::from_stored(seal.to_owned())
    }
}

/// Who vouches for a live update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Vouched {
    /// The control plane, which may send any update.
    ControlPlane,
    /// The data plane, which may send only the updates it raises.
    DataPlane,
    /// Nobody: the seal holds under neither key.
    Nobody,
}

/// The check a listener makes on a live update before it hands it on.
#[derive(Debug, Clone)]
pub struct BroadcastCheck {
    control_plane: BroadcastSeal,
    data_plane: BroadcastSeal,
}

impl BroadcastCheck {
    /// A check holding both kinds of publisher's seals.
    #[must_use]
    pub fn new(control_plane: BroadcastSeal, data_plane: BroadcastSeal) -> Self {
        Self {
            control_plane,
            data_plane,
        }
    }

    /// Who `seal` says vouches for `update` broadcast on `subject`.
    pub(crate) fn vouched(&self, subject: &str, update: &[u8], seal: &str) -> Vouched {
        if self.control_plane.holds(subject, update, seal) {
            return Vouched::ControlPlane;
        }
        if self.data_plane.holds(subject, update, seal) {
            return Vouched::DataPlane;
        }
        Vouched::Nobody
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    const SUBJECT: &str = "realtime.operator.0190aa";

    fn check() -> BroadcastCheck {
        BroadcastCheck::new(
            BroadcastSeal::control_plane(&test_root()),
            BroadcastSeal::data_plane(&test_root()),
        )
    }

    /// The control plane's seal vouches for the update it sealed, and not
    /// once the subject or the update is changed.
    #[test]
    fn a_seal_vouches_for_its_own_update_only() {
        let seal = BroadcastSeal::control_plane(&test_root()).seal(SUBJECT, b"{}");

        assert_eq!(
            check().vouched(SUBJECT, b"{}", &seal),
            Vouched::ControlPlane
        );
        assert_eq!(
            check().vouched(SUBJECT, b"{\"x\":1}", &seal),
            Vouched::Nobody
        );
        assert_eq!(
            check().vouched("realtime.operator.0190bb", b"{}", &seal),
            Vouched::Nobody
        );
    }

    /// The gateway's seal is told apart from the control plane's, so the
    /// listener can hold it to the updates the gateway raises.
    #[test]
    fn the_data_plane_is_told_apart() {
        let seal = BroadcastSeal::data_plane(&test_root()).seal(SUBJECT, b"{}");

        assert_eq!(check().vouched(SUBJECT, b"{}", &seal), Vouched::DataPlane);
    }

    /// Neither an event seal nor an invented seal authenticates a live update.
    #[test]
    fn a_seal_of_another_use_vouches_for_nothing() {
        let event_key = crate::crypto::EventSeal::control_plane(&test_root()).seal(SUBJECT, b"{}");

        assert_eq!(check().vouched(SUBJECT, b"{}", &event_key), Vouched::Nobody);
        assert_eq!(check().vouched(SUBJECT, b"{}", "forged"), Vouched::Nobody);
    }
}
