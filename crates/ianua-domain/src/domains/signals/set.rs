//! Builds the Security Event Token (SET) claims for a signal push.
//!
//! The payload follows RFC 8417 and the CAEP/SSE event types. Signing
//! happens behind the `JwtSigner` port, as for
//! [`IdTokenClaims`](crate::domains::oauth::grants::id_token::IdTokenClaims).
//! Claims are a plain `serde::Serialize` struct, so the domain needs no
//! `serde_json`.

use std::collections::HashMap;

use crate::domains::signals::signal::{
    SecuritySignal, SignalAssuranceLevel, SignalEvent, SignalSubject,
};
use crate::domains::signals::stream::EndpointChallenge;
use crate::domains::signals::verification::{
    ReceiverState, VERIFICATION_EVENT_TYPE, VerificationEvent, VerificationState,
};
use crate::types::{AgentId, HttpsUrl, Issuer, PermissionName, SignalId, SignalStreamId, UserId};

/// A CAEP subject identifier in opaque format.
///
/// The subject is the `IdP`'s own id for the user or agent, since no stable
/// external id is known here. A receiver matches it against an id it already
/// holds, such as the OIDC `sub` claim from an earlier sign-in. A
/// verification event names the stream itself.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SetSubject {
    /// Always `"opaque"`. No other subject format is used.
    pub format: &'static str,
    /// The `IdP`'s opaque identifier for the subject.
    pub id: SubjectId,
}

/// The id a SET names its subject by, written as the bare id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
pub enum SubjectId {
    /// A user of the tenant.
    User(UserId),
    /// An agent of the tenant.
    Agent(AgentId),
    /// The stream a verification event goes down.
    Stream(SignalStreamId),
}

impl From<SignalSubject> for SubjectId {
    fn from(subject: SignalSubject) -> Self {
        match subject {
            SignalSubject::User(id) => Self::User(id),
            SignalSubject::Agent(id) => Self::Agent(id),
        }
    }
}

impl SetSubject {
    /// `id` in the opaque format.
    fn opaque(id: SubjectId) -> Self {
        Self {
            format: "opaque",
            id,
        }
    }
}

/// A single entry in the SET `events` claim, keyed by its CAEP URN.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SetEvent {
    /// The user the event concerns.
    pub subject: SetSubject,
    /// When it happened (seconds since epoch).
    pub event_timestamp: i64,
    /// The fields its event type requires.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub detail: SetEventDetail,
}

/// The fields an event type's specification makes mandatory, spelled as it
/// spells them.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
pub enum SetEventDetail {
    /// The event type requires nothing beyond the subject.
    Bare {},
    /// CAEP `credential-change`.
    CredentialChange {
        /// Which kind of credential.
        credential_type: &'static str,
        /// What happened to it.
        change_type: &'static str,
    },
    /// CAEP `token-claims-change`.
    TokenClaimsChange {
        /// The claims with their new values.
        claims: ChangedClaims,
    },
    /// CAEP `device-compliance-change`.
    DeviceComplianceChange {
        /// What the device was.
        previous_status: &'static str,
        /// What it is now.
        current_status: &'static str,
    },
    /// RISC `credential-compromise`.
    CredentialCompromise {
        /// Which kind of credential.
        credential_type: &'static str,
    },
    /// CAEP `assurance-level-change`.
    AssuranceLevelChange {
        /// The scheme the level is written in.
        namespace: &'static str,
        /// The level now.
        current_level: &'static str,
    },
    /// CAEP `risk-level-change`.
    RiskLevelChange {
        /// What the level is about.
        principal: &'static str,
        /// The level now.
        current_level: &'static str,
    },
    /// SSF `verification`, carrying a challenge or the receiver's state.
    Verification {
        /// The value to carry back, as the specification names it.
        state: CarriedState,
    },
}

/// The `state` a verification event carries, written as the bare text.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
pub enum CarriedState {
    /// The challenge a newly set endpoint must echo.
    Challenge(EndpointChallenge),
    /// The state the receiver asked for.
    Receiver(ReceiverState),
}

/// The token claims a permissions change rewrites, with their new values.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ChangedClaims {
    /// The permissions the user holds now.
    pub permissions: Vec<PermissionName>,
}

impl SetEventDetail {
    // One arm per signal, with no catch-all: a new signal must say which
    // fields its event type carries before it builds. Splitting the table
    // would bring a catch-all back.
    #[allow(clippy::too_many_lines)]
    fn of(event: &SignalEvent) -> Self {
        match event {
            SignalEvent::SessionRevoked
            | SignalEvent::SessionSuspended
            | SignalEvent::TokenCompromised
            | SignalEvent::AccountLocked
            | SignalEvent::AccountDisabled
            | SignalEvent::AccountPurged
            | SignalEvent::IdentifierChanged => Self::Bare {},
            SignalEvent::CredentialCompromised { credential } => Self::CredentialCompromise {
                credential_type: credential.as_str(),
            },
            SignalEvent::AssuranceChanged { current } => Self::AssuranceLevelChange {
                namespace: SignalAssuranceLevel::NAMESPACE,
                current_level: current.as_str(),
            },
            SignalEvent::CredentialChanged { credential, change } => Self::CredentialChange {
                credential_type: credential.as_str(),
                change_type: change.as_str(),
            },
            SignalEvent::PermissionsChanged { permissions } => Self::TokenClaimsChange {
                claims: ChangedClaims {
                    permissions: permissions.clone(),
                },
            },
            SignalEvent::DeviceCompromised => Self::DeviceComplianceChange {
                previous_status: "compliant",
                current_status: "not-compliant",
            },
            SignalEvent::RiskLevelChanged { current } => Self::RiskLevelChange {
                principal: "USER",
                current_level: current.as_str(),
            },
        }
    }

    /// The fields of a verification event carrying `state`. One that
    /// carries none has no field beyond its subject.
    fn of_verification(state: &VerificationState) -> Self {
        match state {
            VerificationState::Challenge(challenge) => Self::Verification {
                state: CarriedState::Challenge(challenge.clone()),
            },
            VerificationState::Echo(state) => Self::Verification {
                state: CarriedState::Receiver(state.clone()),
            },
            VerificationState::Omitted => Self::Bare {},
        }
    }
}

/// Security Event Token claims (RFC 8417) for a single security signal.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SecurityEventTokenClaims {
    /// The tenant's issuer URL, the same `iss` as in its OIDC and SAML tokens.
    pub iss: Issuer,
    /// The signal's own id. A receiver can match a SET to an entry in
    /// `GET .../streams/{id}/deliveries`.
    pub jti: SignalId,
    /// Issued at (seconds since epoch).
    pub iat: i64,
    /// The receiving stream's endpoint.
    pub aud: HttpsUrl,
    /// Exactly one entry, keyed by the signal type's CAEP URN.
    pub events: HashMap<&'static str, SetEvent>,
}

impl SecurityEventTokenClaims {
    /// Builds SET claims for a single signal, addressed to one stream.
    #[must_use]
    pub fn from_signal(issuer: Issuer, audience: HttpsUrl, signal: &SecuritySignal) -> Self {
        let mut events = HashMap::with_capacity(1);
        events.insert(
            signal.signal_type().as_urn(),
            SetEvent {
                subject: SetSubject::opaque((*signal.subject()).into()),
                event_timestamp: signal.occurred_at().unix_timestamp(),
                detail: SetEventDetail::of(signal.event()),
            },
        );

        Self {
            iss: issuer,
            jti: *signal.id(),
            iat: signal.occurred_at().unix_timestamp(),
            aud: audience,
            events,
        }
    }

    /// Builds the claims of a Shared Signals verification event, sent now
    /// down the stream `event` names, to its endpoint, with the stream as
    /// its subject. Each gets a fresh `jti`.
    #[must_use]
    pub fn verification(issuer: Issuer, event: &VerificationEvent) -> Self {
        let now = crate::shared::clock::now().unix_timestamp();
        let mut events = HashMap::with_capacity(1);
        events.insert(
            VERIFICATION_EVENT_TYPE,
            SetEvent {
                subject: SetSubject::opaque(SubjectId::Stream(*event.stream_id())),
                event_timestamp: now,
                detail: SetEventDetail::of_verification(event.state()),
            },
        );

        Self {
            iss: issuer,
            jti: SignalId::new(),
            iat: now,
            aud: event.endpoint().as_https().clone(),
            events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "serde")]
    use crate::domains::signals::signal::{CredentialChangeType, CredentialKind};
    use crate::domains::signals::signal::{NewSecuritySignal, SecuritySignalType};
    use crate::domains::signals::verification::{ReceiverState, RequestedState};
    use crate::types::{PublicHttpsUrl, TenantId};

    /// A signal of `event` about a fresh user, raised now.
    fn signal_about(event: SignalEvent) -> SecuritySignal {
        signal_of(SignalSubject::User(UserId::new()), event)
    }

    /// A signal of `event` about `subject`, raised now.
    fn signal_of(subject: SignalSubject, event: SignalEvent) -> SecuritySignal {
        SecuritySignal::new(NewSecuritySignal {
            tenant_id: TenantId::new(),
            subject,
            event,
            occurred_at: crate::shared::clock::now(),
        })
        .unwrap()
    }

    /// A session-revoked signal for one user is turned into SET claims. The
    /// `jti` is the signal's id, the `aud` is the stream's endpoint, and the
    /// one event sits under the session-revoked URN with an opaque subject.
    #[test]
    fn builds_claims_keyed_by_urn() {
        let user_id = UserId::new();
        let signal = signal_of(SignalSubject::User(user_id), SignalEvent::SessionRevoked);

        let claims = SecurityEventTokenClaims::from_signal(
            Issuer::new("https://idp.example.com/api/v1/organizations/acme/tenants/prod").unwrap(),
            HttpsUrl::new("https://app.acme.com/.well-known/sse").unwrap(),
            &signal,
        );

        assert_eq!(claims.jti, *signal.id());
        assert_eq!(claims.aud.as_str(), "https://app.acme.com/.well-known/sse");
        let event = claims
            .events
            .get(SecuritySignalType::SessionRevoked.as_urn())
            .unwrap();
        assert_eq!(event.subject.format, "opaque");
        assert_eq!(event.subject.id, SubjectId::User(user_id));
    }

    /// Ann suspends the billing agent. Its signal names the agent's own id
    /// as the subject, so the receiver drops the agent's tokens.
    #[test]
    fn a_signal_about_an_agent_names_the_agent() {
        let agent = AgentId::new();
        let signal = signal_of(SignalSubject::Agent(agent), SignalEvent::AccountDisabled);

        let claims = SecurityEventTokenClaims::from_signal(
            Issuer::new("https://idp.example.com").unwrap(),
            HttpsUrl::new("https://app.acme.com/sse").unwrap(),
            &signal,
        );

        let event = claims
            .events
            .get(SecuritySignalType::AccountDisabled.as_urn())
            .unwrap();
        assert_eq!(event.subject.id, SubjectId::Agent(agent));
    }

    /// The payroll app asks its stream for a verification event with the
    /// state `req-42`. The event goes to the stream's endpoint under the
    /// verification type, names the stream as its subject and carries the
    /// state back.
    #[test]
    fn a_verification_event_names_the_stream_and_carries_the_state() {
        let stream = SignalStreamId::new();
        let state = ReceiverState::new("req-42").unwrap();
        let event = VerificationEvent::new(
            stream,
            PublicHttpsUrl::new("https://app.acme.com/sse").unwrap(),
            RequestedState::Given(state.clone()).into(),
        );

        let claims = SecurityEventTokenClaims::verification(
            Issuer::new("https://idp.example.com").unwrap(),
            &event,
        );

        let sent = claims.events.get(VERIFICATION_EVENT_TYPE).unwrap();
        assert_eq!(claims.aud.as_str(), "https://app.acme.com/sse");
        assert_eq!(sent.subject.id, SubjectId::Stream(stream));
        assert!(matches!(
            &sent.detail,
            SetEventDetail::Verification { state: CarriedState::Receiver(carried) } if *carried == state
        ));
    }

    /// The payroll app asks for a verification event with no state. The
    /// event carries no field beyond its subject.
    #[test]
    fn a_verification_event_without_a_state_carries_none() {
        let event = VerificationEvent::new(
            SignalStreamId::new(),
            PublicHttpsUrl::new("https://app.acme.com/sse").unwrap(),
            RequestedState::NotGiven.into(),
        );

        let claims = SecurityEventTokenClaims::verification(
            Issuer::new("https://idp.example.com").unwrap(),
            &event,
        );

        let sent = claims.events.get(VERIFICATION_EVENT_TYPE).unwrap();
        assert!(matches!(sent.detail, SetEventDetail::Bare {}));
    }

    /// An account-locked signal is written to JSON. The output holds the
    /// account-locked URN as a key and the subject's `"opaque"` format.
    #[cfg(feature = "serde")]
    #[test]
    fn serializes_events_keyed_by_urn() {
        let signal = signal_about(SignalEvent::AccountLocked);
        let claims = SecurityEventTokenClaims::from_signal(
            Issuer::new("https://idp.example.com").unwrap(),
            HttpsUrl::new("https://app.acme.com/sse").unwrap(),
            &signal,
        );

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains(SecuritySignalType::AccountLocked.as_urn()));
        assert!(json.contains("\"format\":\"opaque\""));
    }

    /// A user deletes a roaming security key. The JSON carries
    /// `credential_type`, `change_type` and `event_timestamp`, which CAEP
    /// requires and a receiver checks for.
    #[cfg(feature = "serde")]
    #[test]
    fn a_credential_change_carries_the_fields_caep_requires() {
        let signal = signal_about(SignalEvent::CredentialChanged {
            credential: CredentialKind::Fido2Roaming,
            change: CredentialChangeType::Delete,
        });
        let claims = SecurityEventTokenClaims::from_signal(
            Issuer::new("https://idp.example.com").unwrap(),
            HttpsUrl::new("https://app.acme.com/sse").unwrap(),
            &signal,
        );

        let json = serde_json::to_string(&claims).unwrap();

        assert!(json.contains("\"credential_type\":\"fido2-roaming\""));
        assert!(json.contains("\"change_type\":\"delete\""));
        assert!(json.contains("\"event_timestamp\":"));
    }

    /// A device-compromised signal is written to JSON. It reads as a change
    /// from `compliant` to `not-compliant`, the fields CAEP requires.
    #[cfg(feature = "serde")]
    #[test]
    fn a_compromised_device_reads_as_no_longer_compliant() {
        let signal = signal_about(SignalEvent::DeviceCompromised);
        let claims = SecurityEventTokenClaims::from_signal(
            Issuer::new("https://idp.example.com").unwrap(),
            HttpsUrl::new("https://app.acme.com/sse").unwrap(),
            &signal,
        );

        let json = serde_json::to_string(&claims).unwrap();

        assert!(json.contains("\"previous_status\":\"compliant\""));
        assert!(json.contains("\"current_status\":\"not-compliant\""));
    }

    /// Ann proves her authenticator on a session. The signal carries the
    /// `NIST-AAL` namespace and the level the session stands at now, the
    /// fields CAEP requires.
    #[cfg(feature = "serde")]
    #[test]
    fn an_assurance_change_carries_the_namespace_and_the_level() {
        let signal = signal_about(SignalEvent::AssuranceChanged {
            current: SignalAssuranceLevel::Aal2,
        });
        let claims = SecurityEventTokenClaims::from_signal(
            Issuer::new("https://idp.example.com").unwrap(),
            HttpsUrl::new("https://app.acme.com/sse").unwrap(),
            &signal,
        );

        let json = serde_json::to_string(&claims).unwrap();

        assert!(json.contains(SecuritySignalType::AssuranceChanged.as_urn()));
        assert!(json.contains("\"namespace\":\"NIST-AAL\""));
        assert!(json.contains("\"current_level\":\"nist-aal2\""));
    }

    /// Ann's password turns up in a breach. The signal names the password
    /// as the compromised credential, the field RISC requires.
    #[cfg(feature = "serde")]
    #[test]
    fn a_compromised_credential_names_its_kind() {
        let signal = signal_about(SignalEvent::CredentialCompromised {
            credential: CredentialKind::Password,
        });
        let claims = SecurityEventTokenClaims::from_signal(
            Issuer::new("https://idp.example.com").unwrap(),
            HttpsUrl::new("https://app.acme.com/sse").unwrap(),
            &signal,
        );

        let json = serde_json::to_string(&claims).unwrap();

        assert!(json.contains(SecuritySignalType::CredentialCompromised.as_urn()));
        assert!(json.contains("\"credential_type\":\"password\""));
        assert!(!json.contains("change_type"));
    }
}
