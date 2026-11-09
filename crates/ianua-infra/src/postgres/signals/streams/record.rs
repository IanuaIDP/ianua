//! A signal stream as its rows hold it, the stream's own and one per
//! subject it lists: read back into the aggregate, and written out from
//! it.
//!
//! The endpoint's challenge is never read from the stream, which does not
//! hand it out: a save names the one just issued, or keeps the stored one,
//! and the row holds it until the endpoint is verified.

use std::collections::HashMap;

use ianua_domain::domains::signals::delivery::ReceiverAuthorization;
use ianua_domain::domains::signals::signal::{SecuritySignalType, SignalSubject};
use ianua_domain::domains::signals::stream::{
    EndpointChallenge, EndpointVerification, SignalStream, SignalStreamRow,
    StreamVerificationStatus,
};
use ianua_domain::domains::signals::subjects::{DefaultSubjects, StreamSubjects};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AgentId, PublicHttpsUrl, SealedSecret, SignalStreamId, TokenHash, UserId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const STREAM: Stored = Stored("signal stream");

/// A stream as it is read, without the subjects it lists. The store's
/// checked queries fill it.
pub(super) struct StreamRecord {
    pub(super) id: Uuid,
    pub(super) endpoint: String,
    pub(super) endpoint_challenge: Option<String>,
    pub(super) delivery_method: String,
    pub(super) authorization_sealed: Option<String>,
    pub(super) receiver_key_hash: String,
    pub(super) signal_types: Vec<String>,
    pub(super) default_subjects: String,
    pub(super) status: String,
    pub(super) consecutive_failures: i64,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

/// One subject a stream lists, as it is read.
pub(super) struct SubjectRecord {
    pub(super) stream_id: Uuid,
    pub(super) user_id: Option<Uuid>,
    pub(super) agent_id: Option<Uuid>,
}

impl SubjectRecord {
    /// The user or agent the record names.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it names both or neither.
    fn into_subject(self) -> Result<SignalSubject, DomainError> {
        match (self.user_id, self.agent_id) {
            (Some(user), None) => Ok(SignalSubject::User(UserId::from_uuid(user))),
            (None, Some(agent)) => Ok(SignalSubject::Agent(AgentId::from_uuid(agent))),
            (Some(_), Some(_)) | (None, None) => Err(DomainError::corrupt_row(
                STREAM.0,
                "a listed subject that is not one user or one agent",
            )),
        }
    }
}

/// The subjects of every stream read, each stream's in the order it lists
/// them.
pub(super) struct Listed(HashMap<Uuid, Vec<SubjectRecord>>);

impl Listed {
    /// `records`, by the stream each belongs to, keeping their order.
    pub(super) fn of(records: Vec<SubjectRecord>) -> Self {
        let mut by_stream: HashMap<Uuid, Vec<SubjectRecord>> = HashMap::new();
        for record in records {
            by_stream.entry(record.stream_id).or_default().push(record);
        }
        Self(by_stream)
    }

    /// The subjects the stream `id` lists, taken out, or none.
    pub(super) fn take(&mut self, id: &Uuid) -> Vec<SubjectRecord> {
        self.0.remove(id).unwrap_or_default()
    }
}

impl StreamRecord {
    /// The stream the record holds, listing `listed`, its own subjects in
    /// order, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the stream
    /// keeps, such as naming no signal type.
    pub(super) fn into_stream(
        self,
        listed: Vec<SubjectRecord>,
    ) -> Result<SignalStream<ResolvedTenant>, DomainError> {
        let listed = listed
            .into_iter()
            .map(SubjectRecord::into_subject)
            .collect::<Result<Vec<_>, _>>()?;
        let subjects = match STREAM.choice(&self.default_subjects)? {
            DefaultSubjects::All => StreamSubjects::AllExcept(listed),
            DefaultSubjects::None => StreamSubjects::Only(listed),
        };
        let signal_types = self
            .signal_types
            .iter()
            .map(|word| STREAM.choice::<SecuritySignalType>(word))
            .collect::<Result<Vec<_>, _>>()?;
        SignalStream::reconstitute(SignalStreamRow {
            id: SignalStreamId::from_uuid(self.id),
            endpoint: STREAM.value("endpoint", PublicHttpsUrl::new(self.endpoint))?,
            verification: verification_from(self.endpoint_challenge)?,
            delivery_method: STREAM.choice(&self.delivery_method)?,
            authorization: authorization_from(self.authorization_sealed)?,
            receiver_key: TokenHash::from_stored(self.receiver_key_hash),
            signal_types,
            subjects,
            status: STREAM.choice(&self.status)?,
            consecutive_failures: u32::try_from(self.consecutive_failures)
                .map_err(|_| DomainError::corrupt_row(STREAM.0, "a failure count out of range"))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Whether the endpoint is verified, from the challenge the row holds for
/// it: pending on one while it holds one.
fn verification_from(challenge: Option<String>) -> Result<EndpointVerification, DomainError> {
    let Some(challenge) = challenge else {
        return Ok(EndpointVerification::Verified);
    };
    Ok(EndpointVerification::Pending(STREAM.value(
        "endpoint challenge",
        EndpointChallenge::new(challenge),
    )?))
}

/// What a push sends in the `Authorization` header, from its sealed
/// column: none when it is empty.
fn authorization_from(sealed: Option<String>) -> Result<ReceiverAuthorization, DomainError> {
    let Some(sealed) = sealed else {
        return Ok(ReceiverAuthorization::NotRequired);
    };
    Ok(ReceiverAuthorization::Header(STREAM.value(
        "authorization header",
        SealedSecret::new(sealed),
    )?))
}

/// A stream's columns, as they are written. The challenge is the one just
/// issued, if any; the save keeps the stored one otherwise.
pub(super) struct StreamColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) endpoint: &'a str,
    pub(super) verification: &'static str,
    pub(super) issued_challenge: Option<&'a str>,
    pub(super) delivery_method: &'static str,
    pub(super) authorization_sealed: Option<&'a str>,
    pub(super) receiver_key_hash: &'a str,
    pub(super) signal_types: Vec<String>,
    pub(super) default_subjects: &'static str,
    pub(super) status: &'static str,
    pub(super) consecutive_failures: i64,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> StreamColumns<'a> {
    /// The columns `stream` is written to, with `issued` the challenge just
    /// handed out for its endpoint, if one was.
    pub(super) fn of(stream: &'a SignalStream<ResolvedTenant>, issued: Option<&'a str>) -> Self {
        let (default_subjects, _) = subject_list(stream.subjects());
        Self {
            id: stream.id().as_uuid(),
            endpoint: stream.endpoint().as_str(),
            verification: verification_word(stream.verification()),
            issued_challenge: issued,
            delivery_method: stream.delivery_method().word(),
            authorization_sealed: match stream.authorization() {
                ReceiverAuthorization::NotRequired => None,
                ReceiverAuthorization::Header(sealed) => Some(sealed.as_str()),
            },
            receiver_key_hash: stream.receiver_key().as_str(),
            signal_types: stream
                .signal_types()
                .iter()
                .map(|signal| signal.word().to_owned())
                .collect(),
            default_subjects: default_subjects.word(),
            status: stream.status().word(),
            consecutive_failures: i64::from(stream.consecutive_failures()),
            created_at: stream.created_at(),
            updated_at: stream.updated_at(),
        }
    }
}

/// The word the save tells a verified endpoint from a pending one by.
fn verification_word(status: StreamVerificationStatus) -> &'static str {
    match status {
        StreamVerificationStatus::Pending => "pending",
        StreamVerificationStatus::Verified => "verified",
    }
}

/// Which subjects a stream starts from, and the ones it lists.
fn subject_list(subjects: &StreamSubjects) -> (DefaultSubjects, &[SignalSubject]) {
    match subjects {
        StreamSubjects::AllExcept(removed) => (DefaultSubjects::All, removed),
        StreamSubjects::Only(added) => (DefaultSubjects::None, added),
    }
}

/// The subjects a stream lists, one list per column and one place per
/// subject, in order, as one statement writes them.
pub(super) struct SubjectColumns {
    pub(super) users: Vec<Option<Uuid>>,
    pub(super) agents: Vec<Option<Uuid>>,
}

impl SubjectColumns {
    /// The columns the subjects `stream` lists are written to.
    pub(super) fn of(stream: &SignalStream<ResolvedTenant>) -> Self {
        let (_, listed) = subject_list(stream.subjects());
        Self {
            users: listed
                .iter()
                .map(|subject| match subject {
                    SignalSubject::User(user) => Some(*user.as_uuid()),
                    SignalSubject::Agent(_) => None,
                })
                .collect(),
            agents: listed
                .iter()
                .map(|subject| match subject {
                    SignalSubject::Agent(agent) => Some(*agent.as_uuid()),
                    SignalSubject::User(_) => None,
                })
                .collect(),
        }
    }
}
