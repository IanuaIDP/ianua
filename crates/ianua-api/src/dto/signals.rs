//! Signal stream bodies: a receiver of the tenant's security signals, the
//! subjects it hears about, its verification events and status, the events
//! it polls, its delivery history, the echo that confirms its endpoint, and
//! the transmitter's configuration.

use std::collections::BTreeMap;

use ianua_app::error::AppError;
use ianua_app::ports::signals::{Backlog, PollBatch, PolledEvents};
use ianua_app::use_cases::signals::delivery::PollEventsRequest;
use ianua_app::use_cases::signals::streams::{
    AddSubjectRequest, ConfirmEndpointRequest, ReceiverHeader, RegisterRequest, Registered,
    RemoveSubjectRequest, RequestVerificationRequest, TransmitterConfiguration, UpdateRequest,
};
use ianua_domain::domains::signals::delivery::{
    ReceiverAuthorization, SignalDeliveryAttempt, SignalDeliveryStatus,
};
use ianua_domain::domains::signals::signal::{SecuritySignalType, SignalSubject};
use ianua_domain::domains::signals::stream::{
    DeliveryMethod, EndpointChallenge, SignalStream, StreamStatus, StreamVerificationStatus,
};
use ianua_domain::domains::signals::subjects::DefaultSubjects;
use ianua_domain::domains::signals::verification::{ReceiverState, RequestedState};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentId, Issuer, PublicHttpsUrl, SignalId, SignalStreamId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// Request body for registering a signal stream.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RegisterStreamBody {
    /// The receiver's endpoint URL: HTTPS, on the public internet.
    pub endpoint: String,
    /// How signals are delivered: `Push` or `Poll`.
    #[schema(schema_with = crate::dto::schemas::delivery_method)]
    pub delivery_method: DeliveryMethod,
    /// Which signal types to receive, at least one.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::security_signal_type_list)]
    pub signal_types: Vec<SecuritySignalType>,
    /// What each push sends in the `Authorization` header, such as
    /// `Bearer` and the receiver's own token. Kept sealed and never shown
    /// again. Left out, pushes carry no such header.
    pub authorization_header: Option<String>,
    /// Whom the stream starts hearing about: `ALL` the tenant's users and
    /// agents (the default), or `NONE` until subjects are added.
    #[serde(default)]
    pub default_subjects: DefaultSubjectsBody,
}

/// Whom a new stream starts hearing about, as the Shared Signals framework
/// names it.
#[derive(Deserialize, utoipa::ToSchema, Default, Clone, Copy)]
pub(crate) enum DefaultSubjectsBody {
    /// Every user and agent of the tenant.
    #[default]
    #[serde(rename = "ALL")]
    All,
    /// None, until subjects are added.
    #[serde(rename = "NONE")]
    None,
}

impl From<DefaultSubjectsBody> for DefaultSubjects {
    fn from(body: DefaultSubjectsBody) -> Self {
        match body {
            DefaultSubjectsBody::All => Self::All,
            DefaultSubjectsBody::None => Self::None,
        }
    }
}

impl TryFrom<RegisterStreamBody> for RegisterRequest {
    type Error = ApiError;

    fn try_from(body: RegisterStreamBody) -> Result<Self, Self::Error> {
        Ok(Self {
            endpoint: PublicHttpsUrl::new(body.endpoint).map_err(ApiError::validation)?,
            delivery_method: body.delivery_method,
            authorization: receiver_header(body.authorization_header),
            signal_types: body.signal_types,
            default_subjects: body.default_subjects.into(),
        })
    }
}

/// What pushes send in the `Authorization` header: `value`, or none.
fn receiver_header(value: Option<String>) -> ReceiverHeader {
    value.map_or(ReceiverHeader::NotRequired, |value| {
        ReceiverHeader::Header(Secret::new(value))
    })
}

/// Request body for changing a signal stream. A field left out keeps what
/// the stream has.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateStreamBody {
    /// A new endpoint URL: HTTPS, on the public internet. It must confirm
    /// itself again before it is sent anything.
    pub endpoint: Option<String>,
    /// A new delivery method.
    #[schema(schema_with = crate::dto::schemas::delivery_method)]
    pub delivery_method: Option<DeliveryMethod>,
    /// New signal types, at least one.
    #[schema(value_type = Option<Vec<String>>)]
    pub signal_types: Option<Vec<SecuritySignalType>>,
    /// What pushes send in the `Authorization` header from now on, or
    /// `null` for none.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    #[schema(value_type = Option<String>)]
    pub authorization_header: Option<Option<String>>,
}

impl UpdateStreamBody {
    /// The change this body makes to `stream_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the endpoint is not a public HTTPS URL.
    pub(crate) fn update_of(self, stream_id: SignalStreamId) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            stream_id,
            endpoint: self
                .endpoint
                .map(PublicHttpsUrl::new)
                .transpose()
                .map_err(ApiError::validation)?,
            delivery_method: self.delivery_method,
            authorization: self.authorization_header.map(receiver_header),
            signal_types: self.signal_types,
        })
    }
}

/// Request body the receiver sends to confirm its endpoint.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ConfirmEndpointBody {
    /// The challenge the endpoint was sent, echoed back as received.
    pub challenge: String,
}

impl ConfirmEndpointBody {
    /// The echo for `stream_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the echo is not shaped like a challenge.
    pub(crate) fn echo_for(
        self,
        stream_id: SignalStreamId,
    ) -> Result<ConfirmEndpointRequest, ApiError> {
        Ok(ConfirmEndpointRequest {
            stream_id,
            echoed: EndpointChallenge::new(self.challenge).map_err(ApiError::validation)?,
        })
    }
}

/// Request body naming a subject to add to or remove from a stream.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SubjectBody {
    /// The subject, in the opaque format the stream's tokens name it by.
    pub subject: SubjectIdentifierBody,
    /// What the subject is: `User` (the default) or `Agent`.
    #[serde(default)]
    pub kind: SubjectKindBody,
}

/// A subject identifier in the Shared Signals opaque format.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SubjectIdentifierBody {
    /// Always `opaque`: subjects are named by ianua's own id for them.
    pub format: String,
    /// The user's or agent's id.
    pub id: Uuid,
}

/// What kind of subject a body names.
#[derive(Deserialize, utoipa::ToSchema, Default, Clone, Copy)]
pub(crate) enum SubjectKindBody {
    /// A user of the tenant.
    #[default]
    User,
    /// An agent of the tenant.
    Agent,
}

impl SubjectBody {
    /// The subject this body names.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the format is not `opaque`.
    fn subject(&self) -> Result<SignalSubject, ApiError> {
        if self.subject.format != "opaque" {
            return Err(ApiError::validation(message!(
                "api-subjects-are-named-in-the-opaque",
                "subjects are named in the opaque format"
            )));
        }
        Ok(match self.kind {
            SubjectKindBody::User => SignalSubject::User(UserId::from_uuid(self.subject.id)),
            SubjectKindBody::Agent => SignalSubject::Agent(AgentId::from_uuid(self.subject.id)),
        })
    }

    /// Adding this subject to `stream_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the format is not `opaque`.
    pub(crate) fn addition_to(
        &self,
        stream_id: SignalStreamId,
    ) -> Result<AddSubjectRequest, ApiError> {
        Ok(AddSubjectRequest {
            stream_id,
            subject: self.subject()?,
        })
    }

    /// Removing this subject from `stream_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the format is not `opaque`.
    pub(crate) fn removal_from(
        &self,
        stream_id: SignalStreamId,
    ) -> Result<RemoveSubjectRequest, ApiError> {
        Ok(RemoveSubjectRequest {
            stream_id,
            subject: self.subject()?,
        })
    }
}

/// Request body asking a stream for a verification event.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct VerifyStreamBody {
    /// A value the verification event carries back, so the receiver can
    /// match it to its request.
    pub state: Option<String>,
}

impl VerifyStreamBody {
    /// The verification of `stream_id` `body` asks for: with no body, or
    /// no `state`, the event carries none.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the state is not a short token.
    pub(crate) fn verification_of(
        stream_id: SignalStreamId,
        body: Option<Self>,
    ) -> Result<RequestVerificationRequest, ApiError> {
        let state = match body.and_then(|body| body.state) {
            Some(state) => {
                RequestedState::Given(ReceiverState::new(state).map_err(ApiError::validation)?)
            }
            None => RequestedState::NotGiven,
        };
        Ok(RequestVerificationRequest { stream_id, state })
    }
}

/// Request body of a poll, as RFC 8936 lays it out.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PollBody {
    /// The most events to hand back, from 1 to 100; 100 when left out.
    #[serde(rename = "maxEvents")]
    pub max_events: Option<u16>,
    /// The `jti` of each event received since the last poll, which the
    /// stream then drops.
    #[serde(default)]
    pub ack: Vec<Uuid>,
    /// Accepted for RFC 8936; a poll always answers at once.
    #[serde(rename = "returnImmediately")]
    pub _return_immediately: Option<bool>,
}

impl PollBody {
    /// The poll of `stream_id` `body` asks for: with no body, the largest
    /// batch and nothing acknowledged.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when `maxEvents` is 0 or above 100.
    pub(crate) fn poll_of(
        stream_id: SignalStreamId,
        body: Option<Self>,
    ) -> Result<PollEventsRequest, ApiError> {
        let Some(body) = body else {
            return Ok(PollEventsRequest {
                stream_id,
                acknowledged: Vec::new(),
                batch: PollBatch::largest(),
            });
        };
        let batch = body
            .max_events
            .map(PollBatch::new)
            .transpose()
            .map_err(AppError::from_domain)?
            .unwrap_or_else(PollBatch::largest);
        Ok(PollEventsRequest {
            stream_id,
            acknowledged: body.ack.into_iter().map(SignalId::from_uuid).collect(),
            batch,
        })
    }
}

/// The events a poll hands back, as RFC 8936 lays them out.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PollResponse {
    /// Each event not yet acknowledged, by its `jti`: the signed security
    /// event token.
    pub sets: BTreeMap<String, String>,
    /// Whether more events wait beyond these.
    #[serde(rename = "moreAvailable")]
    pub more_available: bool,
}

impl From<PolledEvents> for PollResponse {
    fn from(polled: PolledEvents) -> Self {
        Self {
            sets: polled
                .events
                .into_iter()
                .map(|event| (event.jti.to_string(), event.token.as_str().to_owned()))
                .collect(),
            more_available: matches!(polled.backlog, Backlog::MoreWaiting),
        }
    }
}

/// A stream's status, as a Shared Signals receiver reads it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StreamStatusResponse {
    /// The delivery channel whose receiver status is being reported.
    pub stream_id: Uuid,
    /// `enabled`, `paused` or `disabled`.
    pub status: &'static str,
}

impl StreamStatusResponse {
    /// The status `status` of `stream_id`, in the framework's words.
    #[must_use]
    pub(crate) fn of(stream_id: SignalStreamId, status: StreamStatus) -> Self {
        Self {
            stream_id: *stream_id.as_uuid(),
            status: match status {
                StreamStatus::Active => "enabled",
                StreamStatus::Paused => "paused",
                StreamStatus::Disabled => "disabled",
            },
        }
    }
}

/// Query parameters for filtering a signal stream listing.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct StreamFilterParams {
    /// Only streams in this status: `Active`, `Paused` or `Disabled`. Left
    /// out for every status.
    #[param(value_type = Option<String>)]
    pub status: Option<StreamStatus>,
}

/// A signal stream.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StreamResponse {
    /// Unique stream identifier.
    pub id: Uuid,
    /// The receiver's endpoint URL.
    pub endpoint: String,
    /// Whether the endpoint confirmed it belongs to the receiver: `Pending`
    /// or `Verified`. A pending endpoint is sent nothing.
    pub verification: &'static str,
    /// How signals are delivered.
    #[schema(schema_with = crate::dto::schemas::delivery_method)]
    pub delivery_method: DeliveryMethod,
    /// Which signal types this stream receives.
    #[schema(schema_with = crate::dto::schemas::security_signal_type_list)]
    pub signal_types: Vec<SecuritySignalType>,
    /// Whether pushes carry an `Authorization` header. Its value is never
    /// shown.
    pub sends_authorization: bool,
    /// Current stream status.
    #[schema(schema_with = crate::dto::schemas::stream_status)]
    pub status: StreamStatus,
    /// Deliveries that failed in a row. A count close to the threshold
    /// explains a stream that turned `Disabled` by itself.
    pub consecutive_failures: u32,
    /// When this stream was registered.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When this stream was last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<SignalStream<ResolvedTenant>> for StreamResponse {
    fn from(stream: SignalStream<ResolvedTenant>) -> Self {
        Self {
            id: *stream.id().as_uuid(),
            endpoint: stream.endpoint().as_str().to_owned(),
            verification: match stream.verification() {
                StreamVerificationStatus::Pending => "Pending",
                StreamVerificationStatus::Verified => "Verified",
            },
            delivery_method: stream.delivery_method(),
            signal_types: stream.signal_types().to_vec(),
            sends_authorization: matches!(stream.authorization(), ReceiverAuthorization::Header(_)),
            status: stream.status(),
            consecutive_failures: stream.consecutive_failures(),
            created_at: stream.created_at(),
            updated_at: stream.updated_at(),
        }
    }
}

/// Answer to registering a stream, with the key its receiver manages it
/// with.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RegisterStreamResponse {
    /// The new stream's identifier.
    pub id: Uuid,
    /// The key the receiver presents as its bearer to poll the stream, ask
    /// it for verification events and say whom it hears about. It is shown
    /// this once; only its digest is kept.
    pub receiver_key: String,
}

impl From<Registered> for RegisterStreamResponse {
    fn from(registered: Registered) -> Self {
        Self {
            id: *registered.stream_id.as_uuid(),
            receiver_key: registered.receiver_key.expose().to_owned(),
        }
    }
}

/// One signal delivery attempt.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StreamDeliveryResponse {
    /// Unique attempt identifier.
    pub id: Uuid,
    /// The stream this delivery was for.
    pub stream_id: Uuid,
    /// The signal that was delivered.
    pub signal_id: Uuid,
    /// The signal type that caused the delivery.
    #[schema(schema_with = crate::dto::schemas::security_signal_type)]
    pub signal_type: SecuritySignalType,
    /// How the attempt ended: `Success`, `Failed`, `Timeout`,
    /// `Unreachable`, or `Queued` for a poll stream.
    #[schema(schema_with = crate::dto::schemas::signal_delivery_status)]
    pub status: SignalDeliveryStatus,
    /// The HTTP status code the receiver answered with, if it answered.
    pub response_status: Option<u16>,
    /// How long the request took, in milliseconds.
    pub duration_ms: u32,
    /// Which try this is (0 is the first, and the only one made).
    pub attempt_number: u8,
    /// When the attempt was made.
    #[serde(with = "time::serde::rfc3339")]
    pub attempted_at: OffsetDateTime,
}

impl From<SignalDeliveryAttempt> for StreamDeliveryResponse {
    fn from(attempt: SignalDeliveryAttempt) -> Self {
        Self {
            id: *attempt.id.as_uuid(),
            stream_id: *attempt.stream_id.as_uuid(),
            signal_id: *attempt.signal_id.as_uuid(),
            signal_type: attempt.signal_type,
            status: attempt.delivery.status(),
            response_status: attempt.delivery.response_code(),
            duration_ms: attempt.duration_ms,
            attempt_number: attempt.attempt_number,
            attempted_at: attempt.attempted_at,
        }
    }
}

/// How a receiver authorizes itself to the transmitter's endpoints.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuthorizationScheme {
    /// The specification the scheme follows.
    pub spec_urn: &'static str,
}

/// The transmitter's metadata, as `/.well-known/ssf-configuration` serves
/// it.
///
/// The status, subject and verification endpoints are per stream: each
/// names `{stream_id}` where a receiver puts its stream's id.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TransmitterConfigurationResponse {
    /// The version of the Shared Signals framework followed.
    pub spec_version: &'static str,
    /// The issuer the transmitter's tokens carry.
    pub issuer: String,
    /// Where the keys the tokens are signed with are published.
    pub jwks_uri: String,
    /// How the transmitter delivers: the push and poll URNs.
    pub delivery_methods_supported: Vec<&'static str>,
    /// Where streams are registered and listed.
    pub configuration_endpoint: String,
    /// Where a stream's status is read.
    pub status_endpoint: String,
    /// Where a subject is added to a stream.
    pub add_subject_endpoint: String,
    /// Where a subject is removed from a stream.
    pub remove_subject_endpoint: String,
    /// Where a stream is asked for a verification event.
    pub verification_endpoint: String,
    /// How a receiver authorizes itself: a bearer, as OAuth 2 sends one.
    pub authorization_schemes: Vec<AuthorizationScheme>,
    /// Whom a stream hears about unless it says otherwise.
    pub default_subjects: &'static str,
    /// Every event type a stream may ask for, each once.
    pub events_supported: Vec<&'static str>,
}

impl TransmitterConfigurationResponse {
    /// The metadata of `configuration`, with every endpoint under `base`,
    /// the API address of the tenant's own routes.
    #[must_use]
    pub(crate) fn of(configuration: TransmitterConfiguration, base: &Issuer) -> Self {
        let base = base.as_str();
        let stream = format!("{base}/streams/{{stream_id}}");
        let mut events: Vec<&'static str> = configuration
            .signal_types
            .iter()
            .map(SecuritySignalType::as_urn)
            .collect();
        events.sort_unstable();
        events.dedup();
        Self {
            spec_version: "1_0",
            issuer: configuration.issuer.as_str().to_owned(),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            delivery_methods_supported: configuration
                .delivery_methods
                .into_iter()
                .map(delivery_urn)
                .collect(),
            configuration_endpoint: format!("{base}/streams"),
            status_endpoint: format!("{stream}/status"),
            add_subject_endpoint: format!("{stream}/subjects/add"),
            remove_subject_endpoint: format!("{stream}/subjects/remove"),
            verification_endpoint: format!("{stream}/verify"),
            authorization_schemes: vec![AuthorizationScheme {
                spec_urn: "urn:ietf:rfc:6749",
            }],
            default_subjects: "ALL",
            events_supported: events,
        }
    }
}

/// The URN the Shared Signals framework names `method` by.
fn delivery_urn(method: DeliveryMethod) -> &'static str {
    match method {
        DeliveryMethod::Push => "urn:ietf:rfc:8935",
        DeliveryMethod::Poll => "urn:ietf:rfc:8936",
    }
}

#[cfg(test)]
mod tests {
    use utoipa::PartialSchema as _;

    use super::*;

    /// Polling accepts the ignored RFC parameter and documents its original wire name.
    #[test]
    fn polling_keeps_return_immediately_on_wire() {
        let body: PollBody = serde_json::from_value(serde_json::json!({
            "returnImmediately": true,
            "maxEvents": 7,
        }))
        .unwrap();
        let schema = serde_json::to_value(PollBody::schema()).unwrap();

        assert_eq!(body._return_immediately, Some(true));
        assert_eq!(body.max_events, Some(7));
        assert!(schema["properties"].get("returnImmediately").is_some());
        assert!(schema["properties"].get("_return_immediately").is_none());
    }
}
