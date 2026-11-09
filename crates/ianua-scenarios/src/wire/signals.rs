//! A tenant's security signal streams, as Shared Signals receivers and the
//! tenant's administrators use them: registering a receiver, the signed
//! events it polls, the subjects it hears about and its deliveries.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `POST …/streams`: a new receiver.
#[derive(Clone, Serialize)]
pub struct NewStream {
    /// The receiver's endpoint: HTTPS, on the public internet.
    pub endpoint: String,
    /// `Push` or `Poll`.
    pub delivery_method: String,
    /// The signal types received, such as `PermissionsChanged`.
    pub signal_types: Vec<String>,
    /// What each push sends in the `Authorization` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_header: Option<String>,
    /// `ALL` the tenant's users and agents, or `NONE` until subjects are
    /// added.
    pub default_subjects: String,
}

/// A stream just registered.
#[derive(Clone, Deserialize)]
pub struct StreamRegistered {
    /// The id the stream's endpoints take in their path.
    pub id: String,
    /// The key its receiver presents as a bearer, shown this once.
    pub receiver_key: String,
}

/// A signal stream as read back: never its receiver key or header value.
#[derive(Debug, Clone, Deserialize)]
pub struct SignalStream {
    /// The id the stream's endpoints take in their path.
    pub id: String,
    /// The receiver's endpoint.
    pub endpoint: String,
    /// `Pending` until the endpoint echoes its challenge, then `Verified`.
    pub verification: String,
    /// `Active`, `Paused` or `Disabled`.
    pub status: String,
    /// Whether pushes carry an `Authorization` header.
    pub sends_authorization: bool,
    /// Deliveries that failed in a row.
    pub consecutive_failures: u32,
}

/// `PATCH …/streams/{id}`: a field left out keeps its value.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StreamChange {
    /// A new endpoint, which must confirm itself again before it is sent
    /// anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// A stream's status, as a receiver reads it.
#[derive(Debug, Clone, Deserialize)]
pub struct StreamStatus {
    /// `enabled`, `paused` or `disabled`.
    pub status: String,
}

/// `POST …/streams/{id}/confirm`: the challenge the endpoint was sent,
/// echoed back.
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmEndpoint {
    /// The challenge, as received.
    pub challenge: String,
}

/// `POST …/streams/{id}/verify`: the state the verification event carries
/// back.
#[derive(Debug, Clone, Serialize)]
pub struct AskVerification {
    /// A value the receiver matches the event by.
    pub state: String,
}

/// `POST …/streams/{id}/poll`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PollAsk {
    /// The `jti` of each event received since the last poll, which the
    /// stream then drops.
    pub ack: Vec<String>,
    /// The most events to hand back.
    #[serde(rename = "maxEvents", skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u16>,
}

/// The events a poll hands back.
#[derive(Debug, Clone, Deserialize)]
pub struct PollAnswer {
    /// Each event not yet acknowledged, by its `jti`: the signed token.
    pub sets: BTreeMap<String, String>,
    /// Whether more wait beyond these.
    #[serde(rename = "moreAvailable")]
    pub more_available: bool,
}

/// `POST …/streams/{id}/subjects/add` or `…/remove`.
#[derive(Debug, Clone, Serialize)]
pub struct StreamSubject {
    /// Whom it names, by the opaque id its tokens use.
    pub subject: OpaqueSubject,
    /// `User` or `Agent`.
    pub kind: String,
}

/// A subject identifier in the Shared Signals opaque format.
#[derive(Debug, Clone, Serialize)]
pub struct OpaqueSubject {
    /// Always `opaque`.
    pub format: String,
    /// The user's or agent's id.
    pub id: String,
}

impl StreamSubject {
    /// The tenant user `id`.
    #[must_use]
    pub fn user(id: &str) -> Self {
        Self {
            subject: OpaqueSubject {
                format: "opaque".to_owned(),
                id: id.to_owned(),
            },
            kind: "User".to_owned(),
        }
    }
}

/// One signal delivery attempt.
#[derive(Debug, Clone, Deserialize)]
pub struct StreamDelivery {
    /// The signal, the `jti` of its token.
    pub signal_id: String,
    /// `Success`, `Failed`, `Timeout`, `Unreachable`, or `Queued` for a
    /// poll stream.
    pub status: String,
    /// The signal's type.
    pub signal_type: String,
}

/// The transmitter's metadata, as `/.well-known/ssf-configuration` serves
/// it.
#[derive(Debug, Clone, Deserialize)]
pub struct TransmitterConfiguration {
    /// The issuer its tokens carry.
    pub issuer: String,
    /// Where the keys are published.
    pub jwks_uri: String,
    /// The push and poll delivery URNs.
    pub delivery_methods_supported: Vec<String>,
    /// Where streams are registered.
    pub configuration_endpoint: String,
    /// Where a stream is asked for a verification event, with
    /// `{stream_id}` in it.
    pub verification_endpoint: String,
}
