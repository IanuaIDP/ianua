//! Signal stream lifecycle events.

use time::OffsetDateTime;

use crate::domains::signals::report::ReportedSignal;
use crate::domains::signals::signal::SignalSubject;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, SignalStreamId, UrlOrigin, UserId};

/// The reference kind for a signal stream receiver.
///
/// A stream is not a messaging schema or a plan subscription, so it has a
/// kind of its own. Links to it resolve in the signals context.
const SIGNAL_STREAM: RefKind = RefKind::new("signal_stream");

/// A person, or a workflow step for them, reported a signal about a person
/// of the tenant: a risk level, a compromised credential or device.
///
/// It names the person and what was reported, so the signals planner
/// sends it to every stream that takes it.
#[derive(Debug)]
pub struct SignalReported {
    /// The person it is about.
    pub(crate) person: UserId,
    /// Their name when it was reported.
    pub(crate) label: EventLabel,
    /// What was reported.
    pub(crate) signal: ReportedSignal,
    /// When.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalReported => crate::types::event_type::SignalsEvent::SignalReported,
    fn payload(&self) -> EventData {
        let data = EventData::new().reference(
            "user",
            Reference::new(RefKind::USER, self.person.to_string(), self.label.as_str()),
        );
        match self.signal {
            ReportedSignal::RiskLevel(level) => data
                .field("signal", "risk_level")
                .field("level", level.as_str()),
            ReportedSignal::CredentialCompromised(credential) => data
                .field("signal", "credential_compromise")
                .field("credential", credential.as_str()),
            ReportedSignal::DeviceCompromised => data.field("signal", "device_compromise"),
        }
    }
}

/// A signal stream receiver was registered for a tenant.
///
/// From now on a relying party receives the security signals the stream
/// asks for.
#[derive(Debug)]
pub(crate) struct SignalStreamRegistered {
    /// The newly registered stream.
    pub(crate) stream_id: SignalStreamId,
    /// Where the receiver is, as its origin only.
    pub(crate) endpoint: UrlOrigin,
    /// When the stream was registered.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalStreamRegistered => crate::types::event_type::SignalsEvent::StreamRegistered,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream",
            Reference::new(
                SIGNAL_STREAM,
                self.stream_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A signal stream was paused.
///
/// Signals raised while it is paused are dropped, not queued.
#[derive(Debug)]
pub(crate) struct SignalStreamPaused {
    /// The paused stream.
    pub(crate) stream_id: SignalStreamId,
    /// Where the receiver is, as its origin only, captured at write time so
    /// the audit entry stays readable after the stream is changed or removed.
    pub(crate) endpoint: UrlOrigin,
    /// When the stream was paused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalStreamPaused => crate::types::event_type::SignalsEvent::StreamPaused,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream",
            Reference::new(
                SIGNAL_STREAM,
                self.stream_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A signal stream's endpoint, delivery method or signal-type filter was
/// changed.
#[derive(Debug)]
pub(crate) struct SignalStreamUpdated {
    /// The updated stream.
    pub(crate) stream_id: SignalStreamId,
    /// Where the receiver is, as its origin only, captured at write time so
    /// the audit entry stays readable after the stream is changed or removed.
    pub(crate) endpoint: UrlOrigin,
    /// When the stream was updated.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalStreamUpdated => crate::types::event_type::SignalsEvent::StreamUpdated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream",
            Reference::new(
                SIGNAL_STREAM,
                self.stream_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A paused signal stream was resumed.
///
/// Signals raised from now on are delivered. None raised during the pause
/// are.
#[derive(Debug)]
pub(crate) struct SignalStreamResumed {
    /// The resumed stream.
    pub(crate) stream_id: SignalStreamId,
    /// Where the receiver is, as its origin only, captured at write time so
    /// the audit entry stays readable after the stream is changed or removed.
    pub(crate) endpoint: UrlOrigin,
    /// When the stream was resumed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalStreamResumed => crate::types::event_type::SignalsEvent::StreamResumed,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream",
            Reference::new(
                SIGNAL_STREAM,
                self.stream_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A signal stream was permanently disabled.
///
/// The receiver gets no more signals through this stream. Delivery starts
/// again only with a newly registered stream.
#[derive(Debug)]
pub(crate) struct SignalStreamDisabled {
    /// The disabled stream.
    pub(crate) stream_id: SignalStreamId,
    /// Where the receiver is, as its origin only, captured at write time so
    /// the audit entry stays readable after the stream is changed or removed.
    pub(crate) endpoint: UrlOrigin,
    /// When the stream was disabled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalStreamDisabled => crate::types::event_type::SignalsEvent::StreamDisabled,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream",
            Reference::new(
                SIGNAL_STREAM,
                self.stream_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A disabled signal stream was permanently deleted, along with its
/// registration.
#[derive(Debug)]
pub(crate) struct SignalStreamDeleted {
    /// The deleted stream.
    pub(crate) stream_id: SignalStreamId,
    /// Where the receiver is, as its origin only, captured at write time so
    /// the audit entry stays readable after the stream is changed or removed.
    pub(crate) endpoint: UrlOrigin,
    /// When the stream was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalStreamDeleted => crate::types::event_type::SignalsEvent::StreamDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream",
            Reference::new(
                SIGNAL_STREAM,
                self.stream_id.to_string(),
                self.endpoint.as_str(),
            ),
        )
    }
}

/// A user or agent was added to what a signal stream hears about.
///
/// Its receiver now learns when that subject's sessions are revoked or its
/// account is shut.
#[derive(Debug)]
pub(crate) struct SignalSubjectAdded {
    /// The delivery channel that now includes this subject's security changes.
    pub(crate) stream_id: SignalStreamId,
    /// Where the receiver is, as its origin only, captured at write time so
    /// the audit entry stays readable after the stream is changed or removed.
    pub(crate) endpoint: UrlOrigin,
    /// The user or agent added.
    pub(crate) subject: SignalSubject,
    /// When it was added.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalSubjectAdded => crate::types::event_type::SignalsEvent::SubjectAdded,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("stream", stream_reference(&self.stream_id, &self.endpoint))
            .reference("subject", subject_reference(&self.subject))
    }
}

/// A user or agent was removed from what a signal stream hears about.
///
/// Its receiver no longer learns of that subject's revoked sessions or shut
/// account, so the record shows who chose that.
#[derive(Debug)]
pub(crate) struct SignalSubjectRemoved {
    /// The delivery channel that no longer includes this subject's security changes.
    pub(crate) stream_id: SignalStreamId,
    /// Where the receiver is, as its origin only, captured at write time so
    /// the audit entry stays readable after the stream is changed or removed.
    pub(crate) endpoint: UrlOrigin,
    /// The user or agent removed.
    pub(crate) subject: SignalSubject,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalSubjectRemoved => crate::types::event_type::SignalsEvent::SubjectRemoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("stream", stream_reference(&self.stream_id, &self.endpoint))
            .reference("subject", subject_reference(&self.subject))
    }
}

/// A stream's receiver, or a person managing the stream, asked for a
/// verification event, and one was sent down the stream.
///
/// Each request makes the platform call the receiver's endpoint, so how
/// often one asks shows in the trail.
#[derive(Debug)]
pub(crate) struct SignalVerificationRequested {
    /// The delivery channel used to prove the receiver can accept events.
    pub(crate) stream_id: SignalStreamId,
    /// Where the receiver is, as its origin only, captured at write time so
    /// the audit entry stays readable after the stream is changed or removed.
    pub(crate) endpoint: UrlOrigin,
    /// When it was asked for.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignalVerificationRequested => crate::types::event_type::SignalsEvent::VerificationRequested,
    fn payload(&self) -> EventData {
        EventData::new().reference("stream", stream_reference(&self.stream_id, &self.endpoint))
    }
}

/// How a record links to the stream `stream_id`, labelled by `endpoint`.
fn stream_reference(stream_id: &SignalStreamId, endpoint: &UrlOrigin) -> Reference {
    Reference::new(SIGNAL_STREAM, stream_id.to_string(), endpoint.as_str())
}

/// How a record links to `subject`, by its id, since the stream knows no
/// name for it.
fn subject_reference(subject: &SignalSubject) -> Reference {
    match subject {
        SignalSubject::User(id) => Reference::new(RefKind::USER, id.to_string(), id.to_string()),
        SignalSubject::Agent(id) => Reference::new(RefKind::AGENT, id.to_string(), id.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn origin(url: &str) -> UrlOrigin {
        crate::types::HttpsUrl::new(url).unwrap().origin()
    }

    fn stream_reference(payload: &EventData) -> (String, String) {
        match payload.value("stream") {
            Some(FieldValue::Reference(reference)) => {
                assert_eq!(reference.kind(), SIGNAL_STREAM);
                (reference.id().to_owned(), reference.label().to_owned())
            }
            other => panic!("stream is not an entity reference: {other:?}"),
        }
    }

    /// Registration, pause and update records name the stream by origin,
    /// excluding the key in its receiver address.
    #[test]
    fn every_stream_event_names_the_stream_by_its_origin() {
        let stream = SignalStreamId::new();
        let endpoint = "https://rp.acme.com/sse?key=s3cret";

        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(SignalStreamRegistered {
                stream_id: stream,
                endpoint: origin(endpoint),
                occurred_at: now(),
            }),
            Box::new(SignalStreamPaused {
                stream_id: stream,
                endpoint: origin(endpoint),
                occurred_at: now(),
            }),
            Box::new(SignalStreamUpdated {
                stream_id: stream,
                endpoint: origin(endpoint),
                occurred_at: now(),
            }),
        ];

        assert_stream_origins(events, stream);
    }

    /// Resume, disable and delete records keep the stream's origin without its key.
    #[test]
    fn stream_transitions_keep_only_the_origin() {
        let stream = SignalStreamId::new();
        let endpoint = "https://rp.acme.com/sse?key=s3cret";
        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(SignalStreamResumed {
                stream_id: stream,
                endpoint: origin(endpoint),
                occurred_at: now(),
            }),
            Box::new(SignalStreamDisabled {
                stream_id: stream,
                endpoint: origin(endpoint),
                occurred_at: now(),
            }),
            Box::new(SignalStreamDeleted {
                stream_id: stream,
                endpoint: origin(endpoint),
                occurred_at: now(),
            }),
        ];

        assert_stream_origins(events, stream);
    }

    /// Every supplied event must keep the stream ID and the receiver's origin alone.
    fn assert_stream_origins(events: Vec<Box<dyn DomainEventCore>>, stream: SignalStreamId) {
        for event in events {
            let kind = event.event_type();
            assert_eq!(
                stream_reference(&event.payload()),
                (stream.to_string(), "https://rp.acme.com".to_owned()),
                "{kind}"
            );
        }
    }

    /// The payroll app's stream has the billing agent added and Ann
    /// removed. Each record names the stream and links the subject as an
    /// agent or a user.
    #[test]
    fn a_subject_record_names_the_stream_and_links_the_subject() {
        let stream = SignalStreamId::new();
        let agent = crate::types::AgentId::new();
        let ann = crate::types::UserId::new();

        let added = SignalSubjectAdded {
            stream_id: stream,
            endpoint: origin("https://rp.acme.com/sse"),
            subject: SignalSubject::Agent(agent),
            occurred_at: now(),
        }
        .payload();
        let removed = SignalSubjectRemoved {
            stream_id: stream,
            endpoint: origin("https://rp.acme.com/sse"),
            subject: SignalSubject::User(ann),
            occurred_at: now(),
        }
        .payload();

        assert_eq!(stream_reference(&added).0, stream.to_string());
        assert!(matches!(
            added.value("subject"),
            Some(FieldValue::Reference(r)) if r.kind() == RefKind::AGENT && r.id() == agent.to_string()
        ));
        assert!(matches!(
            removed.value("subject"),
            Some(FieldValue::Reference(r)) if r.kind() == RefKind::USER && r.id() == ann.to_string()
        ));
    }
}
