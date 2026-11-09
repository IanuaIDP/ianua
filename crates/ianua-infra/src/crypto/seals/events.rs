//! The seal on every event put on the message bus, and the check a consumer
//! makes before it acts on one.
//!
//! The worker acts on what it reads: a `tenant.deleted` event tears a tenant
//! down. Who may connect to the bus says nothing of who wrote a message, so
//! each publisher seals the subject and payload under a key of its kind, and
//! a consumer drops an event whose seal does not hold.
//!
//! Two kinds of publisher, two keys. The data plane (the gateway) faces the
//! internet, so its key vouches only for the few events it raises; every
//! other event is sealed under the control plane's key, derived from a root
//! secret the data plane is never given. A compromised gateway cannot forge
//! a `tenant.deleted`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_domain::types::event_type::{AgentsEvent, AuthenticationEvent, ProxyEvent};
use ianua_domain::types::{EventType, TokenHash};

use crate::crypto::keys::{Purpose, PurposeKey, RootSecret, hmac_sha256};

/// The header an event's seal travels in.
pub const SEAL_HEADER: &str = "Ianua-Event-Seal";

/// The seal one kind of publisher puts on its events.
#[derive(Debug, Clone)]
pub struct EventSeal {
    key: PurposeKey,
}

impl EventSeal {
    /// The control plane's seal, under the key `root` derives for it. The
    /// root must be one the data plane is never given.
    #[must_use]
    pub fn control_plane(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::EventSeals),
        }
    }

    /// The data plane's seal, under the key `root` derives for it.
    #[must_use]
    pub fn data_plane(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::DataPlaneEventSeals),
        }
    }

    /// The seal on `payload` published on `subject`, as URL-safe base64.
    #[must_use]
    pub fn seal(&self, subject: &str, payload: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(hmac_sha256(
            self.key.bytes(),
            &[subject.as_bytes(), b"\0", payload],
        ))
    }

    /// Whether `seal` is this publisher's seal on `payload` published on
    /// `subject`, compared in constant time.
    pub(crate) fn holds(&self, subject: &str, payload: &[u8], seal: &str) -> bool {
        TokenHash::from_stored(self.seal(subject, payload))
            == TokenHash::from_stored(seal.to_owned())
    }
}

/// The check a consumer makes on an event before it acts on it.
#[derive(Debug, Clone)]
pub struct EventCheck {
    control_plane: EventSeal,
    data_plane: EventSeal,
}

impl EventCheck {
    /// A check holding both kinds of publisher's seals.
    #[must_use]
    pub fn new(control_plane: EventSeal, data_plane: EventSeal) -> Self {
        Self {
            control_plane,
            data_plane,
        }
    }

    /// Whether `seal` vouches for `payload` published on `subject`: the
    /// control plane's for any event, the data plane's only for an event
    /// the data plane raises.
    #[must_use]
    pub fn holds(&self, subject: &str, payload: &[u8], seal: &str) -> bool {
        if self.control_plane.holds(subject, payload, seal) {
            return true;
        }
        names_a_data_plane_event(subject) && self.data_plane.holds(subject, payload, seal)
    }
}

/// Whether the event a subject names is one the data plane raises.
fn names_a_data_plane_event(subject: &str) -> bool {
    event_type_of(subject).is_some_and(raised_by_the_data_plane)
}

/// Whether `event_type` is one the data plane raises, the only events its
/// seal vouches for: an agent's action allowed or denied, egress denied, an
/// agent's key-bound token presented without its key's proof, a honeypot
/// hit, automation caught, a canary token presented or leaking, a session
/// that stopped looking like its holder frozen or ended. The gateway's
/// inbox holds these and no others, and its CHECK names the same list.
pub(crate) fn raised_by_the_data_plane(event_type: EventType) -> bool {
    matches!(
        event_type,
        EventType::Authentication(
            AuthenticationEvent::SessionSuspended | AuthenticationEvent::SessionRevoked
        ) | EventType::Agents(
            AgentsEvent::ActionAuthorized
                | AgentsEvent::ActionDenied
                | AgentsEvent::EgressDenied
                | AgentsEvent::TokenAttackRefused
        ) | EventType::Proxy(
            ProxyEvent::HoneypotHit
                | ProxyEvent::PersonTurnedAway
                | ProxyEvent::AutomatedThreatDetected
                | ProxyEvent::CanaryTokenTriggered
                | ProxyEvent::CanaryTokenLeaked
        )
    )
}

/// The event type a subject names: what follows `tenant.<id>.`,
/// `org.<id>.` or `platform.`, the subject read under the deployment's
/// namespace.
fn event_type_of(subject: &str) -> Option<EventType> {
    let (scope, rest) = subject.split_once('.')?;
    let named = match scope {
        "tenant" | "org" => rest.split_once('.')?.1,
        "platform" => rest,
        _ => return None,
    };
    EventType::parse(named)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    const DELETED: &str = "tenant.0190aa.tenant.deleted";
    const HONEYPOT: &str = "tenant.0190aa.proxy.honeypot_hit";

    fn check() -> EventCheck {
        EventCheck::new(
            EventSeal::control_plane(&test_root()),
            EventSeal::data_plane(&test_root()),
        )
    }

    /// The control plane's seal holds for the event it sealed, and not once
    /// the subject or the payload is changed.
    #[test]
    fn a_seal_holds_for_its_own_event_only() {
        let seal = EventSeal::control_plane(&test_root()).seal(DELETED, b"{}");

        assert!(check().holds(DELETED, b"{}", &seal));
        assert!(!check().holds(DELETED, b"{\"x\":1}", &seal));
        assert!(!check().holds("tenant.0190bb.tenant.deleted", b"{}", &seal));
        assert!(!check().holds(DELETED, b"{}", "forged"));
    }

    /// The gateway seals a honeypot hit with the data plane's key. It holds.
    #[test]
    fn the_data_plane_vouches_for_its_own_events() {
        let seal = EventSeal::data_plane(&test_root()).seal(HONEYPOT, b"{}");

        assert!(check().holds(HONEYPOT, b"{}", &seal));
    }

    /// The gateway seals a leaked canary token with the data plane's key,
    /// so the leak reaches the tenant's trail. It holds, as do automation
    /// caught and a canary token presented.
    #[test]
    fn the_data_plane_vouches_for_threats_and_canaries() {
        let data_plane = EventSeal::data_plane(&test_root());

        for subject in [
            "tenant.0190aa.proxy.automated_threat_detected",
            "tenant.0190aa.proxy.canary_token_triggered",
            "tenant.0190aa.proxy.canary_token_leaked",
        ] {
            let seal = data_plane.seal(subject, b"{}");

            assert!(check().holds(subject, b"{}", &seal), "{subject}");
        }
    }

    /// The gateway seals a key-bound task token presented without its
    /// key's proof as a token attack, so the people who run the tenant hear
    /// of the stolen copy. It holds.
    #[test]
    fn the_data_plane_vouches_for_a_stolen_binding() {
        let subject = "tenant.0190aa.agents.token_attack_refused";
        let seal = EventSeal::data_plane(&test_root()).seal(subject, b"{}");

        assert!(check().holds(subject, b"{}", &seal));
    }

    /// A data-plane seal cannot authenticate a canary-token creation event.
    #[test]
    fn the_data_plane_cannot_vouch_for_a_canary_it_did_not_see() {
        let subject = "tenant.0190aa.proxy.canary_token_generated";
        let forged = EventSeal::data_plane(&test_root()).seal(subject, b"{}");

        assert!(!check().holds(subject, b"{}", &forged));
    }

    /// A tenant-deletion event sealed with the data-plane key fails verification.
    #[test]
    fn the_data_plane_cannot_vouch_for_a_tenant_deletion() {
        let forged = EventSeal::data_plane(&test_root()).seal(DELETED, b"{}");

        assert!(!check().holds(DELETED, b"{}", &forged));
    }

    /// A subject's event type is read after its scope, for each scope.
    #[test]
    fn a_subject_names_its_event_type() {
        let deleted = EventType::parse("tenant.deleted");

        assert_eq!(event_type_of(DELETED), deleted);
        assert_eq!(event_type_of("org.0190aa.tenant.deleted"), deleted);
        assert_eq!(event_type_of("platform.tenant.deleted"), deleted);
        assert_eq!(event_type_of("realtime.tenant.0190aa.tenant.deleted"), None);
    }
}
